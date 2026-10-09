#include <winsock2.h>
#include <ws2tcpip.h>
#include "https_client.h"
#include "mbed_tls_min.h"
#include "mbedtls/build_info.h"
#include "tf-psa-crypto/build_info.h"
#include <winhttp.h>
#include <shlwapi.h>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <functional>
#include <cstring>
#include <cwchar>
#include <vector>
#define SECURITY_WIN32
#include <security.h>
#include <wincrypt.h>
#include <psa/crypto.h>

namespace ttp::https {
namespace {
constexpr size_t body_limit = 2 * 1024 * 1024;
constexpr size_t header_limit = 65536;
using Clock = std::chrono::steady_clock;
struct Canceled : std::exception { const char* what() const noexcept override { return "Canceled"; } };
struct Guard {
    const std::function<bool()>& canceled;
    Clock::time_point deadline{Clock::now() + std::chrono::seconds(65)};
    void operator()() const {
        if (canceled && canceled()) throw Canceled{};
        if (Clock::now() >= deadline) throw std::runtime_error("HTTPS timeout");
    }
};
std::string WideToUtf8(std::wstring_view text) {
    if (text.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("Invalid UTF-16 input");
    std::string result(count, '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr))
        throw std::runtime_error("UTF-8 conversion failed");
    return result;
}
std::wstring Utf8ToWide(std::string_view text) {
    if (text.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!count) throw std::runtime_error("Invalid UTF-8 input");
    std::wstring result(count, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count))
        throw std::runtime_error("UTF-16 conversion failed");
    return result;
}
bool ValidServiceUrl(std::wstring_view value) {
    if (value.empty() || value.size() > 8192 ||
        std::any_of(value.begin(),value.end(),[](wchar_t c){return c<=L' ' || c==L'\\';})) return false;
    URL_COMPONENTS u{sizeof(u)};
    u.dwHostNameLength=u.dwUserNameLength=u.dwPasswordLength=static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(value.data(),static_cast<DWORD>(value.size()),0,&u)) return false;
    return u.nScheme==INTERNET_SCHEME_HTTPS && u.dwHostNameLength &&
        !u.dwUserNameLength && !u.dwPasswordLength && value.find(L'#')==value.npos;
}
struct TlsError : std::runtime_error {
    int code; uint32_t flags;
    TlsError(std::string message,int value,uint32_t verify) : std::runtime_error(std::move(message)),code(value),flags(verify) {}
};
struct Url {
    std::string host, authority, path;
    INTERNET_PORT port{};
    explicit Url(const std::wstring& value) {
        if (!ValidServiceUrl(value)) throw std::runtime_error("Invalid HTTPS URL");
        URL_COMPONENTS p{sizeof(p)};
        p.dwHostNameLength = p.dwUrlPathLength = p.dwExtraInfoLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(value.c_str(), static_cast<DWORD>(value.size()), 0, &p) || p.nScheme != INTERNET_SCHEME_HTTPS)
            throw std::runtime_error("HTTPS redirect cannot downgrade to HTTP");
        host = WideToUtf8(std::wstring_view(p.lpszHostName, p.dwHostNameLength));
        if (host.starts_with('[') && host.ends_with(']')) host = host.substr(1, host.size()-2);
        if (std::any_of(host.begin(), host.end(), [](unsigned char c) { return c <= 32 || c >= 127; }))
            throw std::runtime_error("HTTPS host must use an ASCII/IDNA name");
        port = p.nPort;
        authority = host.find(':') == host.npos ? host : "[" + host + "]";
        if (port != 443) authority += ":" + std::to_string(port);
        std::wstring target = p.dwUrlPathLength ? std::wstring(p.lpszUrlPath, p.dwUrlPathLength) : L"/";
        if (p.dwExtraInfoLength) target.append(p.lpszExtraInfo, p.dwExtraInfoLength);
        constexpr char hex[] = "0123456789ABCDEF";
        for (unsigned char c : WideToUtf8(target)) {
            if (c >= 127) { path += '%'; path += hex[c >> 4]; path += hex[c & 15]; }
            else path += static_cast<char>(c);
        }
    }
};
std::string Lower(std::string value) {
    for (auto& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return value;
}
std::string Trim(std::string_view value) {
    auto a = value.find_first_not_of(" \t");
    return a == value.npos ? std::string{} : std::string(value.substr(a, value.find_last_not_of(" \t")-a+1));
}
struct InternetHandle {
    HINTERNET h{};
    ~InternetHandle() { if (h) WinHttpCloseHandle(h); }
};
// nullopt preserves WinHTTP's existing PAC handling; an empty
// string means an explicitly resolved direct connection.
std::optional<std::wstring> Proxy(const std::wstring& url, const Url& target, const ttp_https_request& n) {
    if (n.proxy_type == 0) return L"";
    if (n.proxy_type > 1 && n.proxy_server && *n.proxy_server) {
        return std::wstring(n.proxy_server);
    }
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie{};
    struct FreeIE { WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& p; ~FreeIE() {
        GlobalFree(p.lpszAutoConfigUrl); GlobalFree(p.lpszProxy); GlobalFree(p.lpszProxyBypass);
    }} free_ie{ie};
    std::wstring proxy, bypass;
    if (!WinHttpGetIEProxyConfigForCurrentUser(&ie)) return std::nullopt;
    if (ie.lpszProxy) proxy = ie.lpszProxy;
    if (ie.lpszProxyBypass) bypass = ie.lpszProxyBypass;
    if (ie.fAutoDetect || ie.lpszAutoConfigUrl) {
        InternetHandle h{WinHttpOpen(L"TTPlayerRebuild/Lyrics", WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0)};
        if (!h.h) return std::nullopt;
        WinHttpSetTimeouts(h.h, 5000, 10000, 10000, 10000);
        WINHTTP_AUTOPROXY_OPTIONS options{};
        options.dwFlags = (ie.fAutoDetect ? WINHTTP_AUTOPROXY_AUTO_DETECT : 0) |
            (ie.lpszAutoConfigUrl ? WINHTTP_AUTOPROXY_CONFIG_URL : 0);
        options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        options.lpszAutoConfigUrl = ie.lpszAutoConfigUrl;
        WINHTTP_PROXY_INFO info{};
        BOOL ok = WinHttpGetProxyForUrl(h.h, url.c_str(), &options, &info);
        auto proxy_error = GetLastError();
        if (ok) {
            proxy = info.lpszProxy ? info.lpszProxy : L"";
            bypass = info.lpszProxyBypass ? info.lpszProxyBypass : L"";
        }
        GlobalFree(info.lpszProxy); GlobalFree(info.lpszProxyBypass);
        if (!ok && proxy_error != ERROR_WINHTTP_AUTODETECTION_FAILED) return std::nullopt;
    }
    auto host = Utf8ToWide(target.host);
    for (size_t start = 0; start < bypass.size();) {
        auto end = bypass.find_first_of(L"; ", start);
        auto rule = bypass.substr(start, end == bypass.npos ? bypass.npos : end-start);
        if ((rule == L"<local>" && host.find(L'.') == host.npos && host.find(L':') == host.npos) ||
            (!rule.empty() && rule != L"<local>" && PathMatchSpecW(host.c_str(), rule.c_str()))) return L"";
        if (end == bypass.npos) break;
        start = end + 1;
    }
    if (proxy.find(L'=') == proxy.npos) {
        if (proxy.find_first_of(L"; ") != proxy.npos) return std::nullopt;
        return proxy;
    }
    std::wstring socks;
    for (size_t start = 0; start < proxy.size();) {
        auto end = proxy.find_first_of(L"; ", start);
        auto entry = proxy.substr(start, end == proxy.npos ? proxy.npos : end-start);
        if (_wcsnicmp(entry.c_str(), L"https=", 6) == 0) return entry.substr(6);
        if (_wcsnicmp(entry.c_str(), L"socks=", 6) == 0) socks=L"socks4://"+entry.substr(6);
        if (end == proxy.npos) break;
        start = end + 1;
    }
    return socks;
}
struct Socket {
    SOCKET s{INVALID_SOCKET};
    ~Socket() { if (s != INVALID_SOCKET) closesocket(s); }
    bool Wait(bool write, const Guard& guard) const {
        guard(); fd_set set, errors; FD_ZERO(&set); FD_SET(s, &set); FD_ZERO(&errors); FD_SET(s, &errors);
        timeval wait{0, 100000};
        int r = select(0, write ? nullptr : &set, write ? &set : nullptr, &errors, &wait);
        if (r == SOCKET_ERROR || FD_ISSET(s, &errors)) throw std::runtime_error("HTTPS socket error");
        return r > 0;
    }
    void Connect(const std::string& host, INTERNET_PORT port, const Guard& guard) {
        if (s != INVALID_SOCKET) { closesocket(s); s=INVALID_SOCKET; }
        addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        addrinfo* list{};
        guard();
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &list))
            throw std::runtime_error("HTTPS DNS resolution failed");
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(list, freeaddrinfo);
        for (auto a = list; a; a = a->ai_next) {
            guard(); s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
            if (s == INVALID_SOCKET) continue;
            u_long nonblocking = 1;
            if (ioctlsocket(s, FIONBIO, &nonblocking)) throw std::runtime_error("HTTPS nonblocking socket failed");
            int r = connect(s, a->ai_addr, static_cast<int>(a->ai_addrlen));
            if (r == 0) return;
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                const auto until = std::min(guard.deadline, Clock::now() + std::chrono::seconds(10));
                while (Clock::now() < until) {
                    // A failed connect may be reported in exceptfds. Try the next address.
                    fd_set write, failed; FD_ZERO(&write); FD_SET(s,&write); FD_ZERO(&failed); FD_SET(s,&failed);
                    timeval timeout{0,100000}; guard();
                    r = select(0,nullptr,&write,&failed,&timeout);
                    if (r == SOCKET_ERROR || FD_ISSET(s,&failed)) break;
                    if (FD_ISSET(s,&write)) {
                        int error{}; int size = sizeof(error);
                        if (!getsockopt(s,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&size) && !error) return;
                        break;
                    }
                }
            }
            closesocket(s); s = INVALID_SOCKET;
        }
        throw std::runtime_error("HTTPS connection failed");
    }
    static int __cdecl Send(void* p, const unsigned char* b, size_t n) {
        auto s = static_cast<Socket*>(p)->s;
        int r = send(s, reinterpret_cast<const char*>(b), static_cast<int>(n), 0);
        return r != SOCKET_ERROR ? r : WSAGetLastError() == WSAEWOULDBLOCK ? MTM_IO_AGAIN : MTM_IO_ERROR;
    }
    static int __cdecl Receive(void* p, unsigned char* b, size_t n) {
        auto s = static_cast<Socket*>(p)->s;
        int r = recv(s, reinterpret_cast<char*>(b), static_cast<int>(n), 0);
        return r != SOCKET_ERROR ? r : WSAGetLastError() == WSAEWOULDBLOCK ? MTM_IO_AGAIN : MTM_IO_ERROR;
    }
};
struct Stream {
    Socket socket;
    const mtm_api& api;
    const Guard& guard;
    const ttp_https_request& request;
    mtm_session* tls{};
    std::string buffered;
    size_t header_bytes{};
    Stream(const mtm_api& a, const Guard& g, const ttp_https_request& r) : api(a), guard(g), request(r) {}
    ~Stream() { api.destroy(tls); }
    [[noreturn]] void Error(int r) const {
        char text[256]{}; api.describe_error(r, text, sizeof(text));
        mtm_info info{}; info.size=sizeof(info); if (tls && api.info) api.info(tls,&info);
        throw TlsError("Mbed TLS " + std::to_string(r) + ": " + text,r,info.verify_flags);
    }
    void Want(int r) const { socket.Wait(r == MTM_WANT_WRITE, guard); }
    void StartTls(const std::string& host) {
        mtm_config c{}; c.size=sizeof(c); c.hostname=host.c_str(); c.send=Socket::Send; c.recv=Socket::Receive; c.io_context=&socket;
        c.ca_pem=request.ca_pem; c.ca_pem_size=request.ca_pem_size;
        c.min_version=request.min_tls_version; c.max_version=request.max_tls_version;
        int r=api.create(&c,&tls); if (r) Error(r);
        do {
            guard(); r=api.handshake(tls);
            if (r==MTM_WANT_READ || r==MTM_WANT_WRITE) Want(r);
            else if (r) Error(r);
        } while(r);
    }
    void Write(std::string_view data) {
        while (!data.empty()) {
            guard();
            int r = tls ? api.write(tls,reinterpret_cast<const unsigned char*>(data.data()),data.size()) :
                Socket::Send(&socket,reinterpret_cast<const unsigned char*>(data.data()),data.size());
            if (r==MTM_WANT_READ || r==MTM_WANT_WRITE || (!tls && r==MTM_IO_AGAIN)) { Want(r==MTM_IO_AGAIN ? MTM_WANT_WRITE : r); continue; }
            if (r <= 0) Error(r);
            data.remove_prefix(static_cast<size_t>(r));
        }
    }
    bool More() {
        unsigned char bytes[8192];
        for (;;) {
            guard();
            int r=tls ? api.read(tls,bytes,sizeof(bytes)) : Socket::Receive(&socket,bytes,sizeof(bytes));
            if (r==MTM_WANT_READ || r==MTM_WANT_WRITE || (!tls && r==MTM_IO_AGAIN)) { Want(r==MTM_IO_AGAIN ? MTM_WANT_READ : r); continue; }
            if (r<0) Error(r);
            if (!r) return false;
            buffered.append(reinterpret_cast<char*>(bytes),r); return true;
        }
    }
    std::string Line() {
        for (;;) {
            auto end=buffered.find("\r\n");
            if (end!=buffered.npos) {
                header_bytes+=end+2;
                if(header_bytes>header_limit) throw std::runtime_error("HTTPS headers too large");
                auto line=buffered.substr(0,end); buffered.erase(0,end+2); return line;
            }
            if (buffered.size()+header_bytes>header_limit) throw std::runtime_error("HTTPS headers too large");
            if (!More()) throw std::runtime_error("Truncated HTTPS headers");
        }
    }
    void Take(size_t n, std::string& out) {
        if (n>body_limit-out.size()) throw std::runtime_error("Lyric response exceeds 2 MiB");
        while(n) {
            if(buffered.empty() && !More()) throw std::runtime_error("Truncated HTTPS body");
            size_t take=std::min(n,buffered.size()); out.append(buffered,0,take); buffered.erase(0,take); n-=take;
        }
    }
};
int Headers(Stream& stream, std::map<std::string,std::string>& headers,
    std::vector<std::string>* cookies=nullptr) {
    auto line=stream.Line(); int status{};
    if ((!line.starts_with("HTTP/1.1 ") && !line.starts_with("HTTP/1.0 ")) || line.size()<12 ||
        std::any_of(line.begin()+9,line.begin()+12,[](char c){return c<'0'||c>'9';}) ||
        std::from_chars(line.data()+9,line.data()+12,status).ec != std::errc{} || status<100 || status>599 ||
        (line.size()>12 && line[12]!=' ')) throw std::runtime_error("Invalid HTTPS status line");
    for (;;) {
        line=stream.Line(); if(line.empty()) break;
        auto colon=line.find(':');
        if(colon==line.npos || !colon) throw std::runtime_error("Invalid HTTPS header");
        auto name=Lower(line.substr(0,colon));
        if(name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")!=name.npos ||
            std::any_of(line.begin(),line.end(),[](unsigned char c){return (c<32 && c!='\t') || c==127;}))
            throw std::runtime_error("Invalid HTTPS header bytes");
        auto value=Trim(std::string_view(line).substr(colon+1));
        if(cookies && name=="set-cookie") {
            if(cookies->size()>=64) throw std::runtime_error("Too many HTTPS cookies");
            cookies->push_back(value);
        }
        auto [at,inserted]=headers.emplace(name,value);
        if(!inserted && (name=="proxy-authenticate" || name=="connection" || name=="proxy-connection"))
            at->second+=", "+value;
        if(!inserted && (name=="content-length" || name=="transfer-encoding" || name=="location"))
            throw std::runtime_error("Ambiguous HTTPS response headers");
    }
    return status;
}
size_t Number(std::string_view value,int base,size_t limit=body_limit) {
    size_t n{}; auto parsed=std::from_chars(value.data(),value.data()+value.size(),n,base);
    if (value.empty() || parsed.ec!=std::errc{} || parsed.ptr!=value.data()+value.size() || n>limit)
        throw std::runtime_error("Invalid or excessive HTTPS body length");
    return n;
}
void ReadBody(Stream& stream, PortableHttpResponse& result) {
    auto coding=result.headers.find("content-encoding");
    if(coding!=result.headers.end() && Lower(coding->second)!="identity") throw std::runtime_error("Unexpected HTTPS content encoding");
    auto transfer=result.headers.find("transfer-encoding"), length=result.headers.find("content-length");
    if(transfer!=result.headers.end()) {
        if(length!=result.headers.end() || Lower(transfer->second)!="chunked") throw std::runtime_error("Ambiguous HTTPS body framing");
        for(;;) {
            auto size=stream.Line(); auto n=Number(std::string_view(size).substr(0,size.find(';')),16);
            if(!n) {
                while(!stream.Line().empty()) {} // bounded trailers; never replace response headers
                break;
            }
            stream.Take(n,result.body);
            std::string ending; stream.Take(2,ending);
            if(ending!="\r\n") throw std::runtime_error("Invalid HTTPS chunk terminator");
        }
    } else if(length!=result.headers.end()) stream.Take(Number(length->second,10),result.body);
    else {
        do { stream.Take(stream.buffered.size(),result.body); } while(stream.More());
    }
}
void ReadDownloadBody(Stream& stream, PortableHttpResponse& result,
                      const ttp_https_download_request& request) {
    const auto coding=result.headers.find("content-encoding");
    if(coding!=result.headers.end() && Lower(coding->second)!="identity")
        throw std::runtime_error("Unexpected HTTPS content encoding");
    const auto transfer=result.headers.find("transfer-encoding"), length=result.headers.find("content-length");
    const auto limit=static_cast<size_t>(request.max_size);
    const uint64_t total=length==result.headers.end() ? 0 : Number(length->second,10,limit);
    uint64_t received=0;
    auto take=[&](size_t n) {
        if(n>request.max_size-received) throw std::runtime_error("HTTPS download exceeds limit");
        while(n) {
            stream.guard();
            if(stream.buffered.empty() && !stream.More()) throw std::runtime_error("Truncated HTTPS body");
            const size_t count=std::min(n,stream.buffered.size());
            if(!request.write(request.write_context,
                reinterpret_cast<const unsigned char*>(stream.buffered.data()),count,received+count,total))
                throw std::runtime_error("HTTPS download write failed");
            received+=count; stream.buffered.erase(0,count); n-=count;
        }
    };
    if(transfer!=result.headers.end()) {
        if(length!=result.headers.end() || Lower(transfer->second)!="chunked")
            throw std::runtime_error("Ambiguous HTTPS body framing");
        for(;;) {
            const auto line=stream.Line();
            const auto n=Number(std::string_view(line).substr(0,line.find(';')),16,limit);
            if(!n) { while(!stream.Line().empty()) {} break; }
            take(n);
            std::string ending;stream.Take(2,ending);
            if(ending!="\r\n") throw std::runtime_error("Invalid HTTPS chunk terminator");
        }
    } else if(length!=result.headers.end()) take(static_cast<size_t>(total));
    else do { take(stream.buffered.size()); } while(stream.More());
}
#include "https_proxy.inl"
std::wstring Redirect(const std::wstring& base,const Url& target,const std::string& location) {
    auto value=Utf8ToWide(location);
    if(value.find(L"://")!=value.npos) return value;
    auto origin=L"https://"+Utf8ToWide(target.authority);
    if(value.starts_with(L"//")) return L"https:"+value;
    if(value.starts_with(L"/")) return origin+value;
    auto start=base.find(L'/',8);
    auto path=start==base.npos ? std::wstring(L"/") : base.substr(start);
    if(value.starts_with(L"?")) return origin+path.substr(0,path.find(L'?'))+value;
    path=path.substr(0,path.find(L'?'));
    return origin+path.substr(0,path.rfind(L'/')+1)+value;
}
}
std::optional<PortableHttpResponse> FetchPortableHttps(const std::wstring& address,
    const ttp_https_request& network,const std::function<bool()>& canceled,
    const ttp_https_download_request* download, const ttp_https_http_request* http,
    const ttp_https_exchange_request* exchange) {
    const auto* tls_api=mtm_get_api(MTM_ABI_VERSION);
    Guard guard{canceled};
    if(download) guard.deadline=Clock::now()+std::chrono::minutes(10);
    guard();
    WSADATA data{};
    if(WSAStartup(MAKEWORD(2,2),&data)) throw std::runtime_error("Cannot initialize HTTPS sockets");
    struct Cleanup { ~Cleanup(){WSACleanup();} } cleanup;
    std::wstring address_now=address;
    for(int redirects=0; redirects<=5; ++redirects) {
        Url url(address_now);
        auto proxy=Proxy(address_now,url,network); guard();
        if(!proxy) {
            if(!redirects) return std::nullopt;
            throw std::runtime_error("HTTPS redirect requires native proxy resolution");
        }
        Stream stream(*tls_api,guard,network);
        if(proxy->empty()) stream.socket.Connect(url.host,url.port,guard);
        else {
            ProxyEndpoint endpoint(*proxy,network.proxy_type>1 ? network.proxy_port : 0);
            stream.socket.Connect(endpoint.host,endpoint.port,guard);
            if(endpoint.kind==ProxyKind::Http) {
                if(!HttpTunnel(stream,endpoint,url,network)) {
                    if(!redirects) return std::nullopt;
                    throw std::runtime_error("System proxy requires native authentication");
                }
            } else SocksTunnel(stream,endpoint,url,network);
            if(!stream.buffered.empty()) throw std::runtime_error("Unexpected proxy tunnel data");
            stream.header_bytes=0;
        }
        stream.StartTls(url.host);
        stream.Write("GET "+url.path+" HTTP/1.1\r\nHost: "+url.authority+
            "\r\nUser-Agent: "+(http ? std::string(http->user_agent) : "TTPlayerRebuild/Lyrics")+
            "\r\nAccept: "+(http ? std::string(http->accept) : "*/*")+
            "\r\nAccept-Encoding: identity\r\nConnection: close\r\n"+
            (exchange && exchange->cookie && *exchange->cookie ? "Cookie: "+std::string(exchange->cookie)+"\r\n" : "")+"\r\n");
        PortableHttpResponse result; result.info.size=sizeof(result.info);
        tls_api->info(stream.tls,&result.info); int status;
        do { result.headers.clear(); result.cookies.clear(); status=Headers(stream,result.headers,exchange?&result.cookies:nullptr); } while(status>=100 && status<200 && status!=101);
        if(!exchange && (status==301 || status==302 || status==303 || status==307 || status==308)) {
            auto location=result.headers.find("location");
            if(location==result.headers.end() || location->second.empty()) throw std::runtime_error("Missing HTTPS redirect target");
            address_now=Redirect(address_now,url,location->second); continue;
        }
        result.status=static_cast<unsigned>(status);
        if(status!=200 && !http && !exchange) throw std::runtime_error("HTTP status "+std::to_string(status));
        if(download) ReadDownloadBody(stream,result,*download);
        else ReadBody(stream,result);
        guard(); return result;
    }
    throw std::runtime_error("Too many HTTPS redirects");
}
}

namespace ttp::https {
namespace {
void CopyError(const char* message,char* out,size_t size) noexcept {
    if (!out || !size) return;
    const auto n=std::min(size-1,std::strlen(message));
    std::memcpy(out,message,n);out[n]=0;
}
void __cdecl Release(ttp_https_response* response) noexcept {
    if (!response || response->size!=sizeof(*response)) return;
    delete static_cast<PortableHttpResponse*>(response->owner);
    *response={};response->size=sizeof(*response);
}
int __cdecl Get(const ttp_https_request* request,ttp_https_response* response,char* error,size_t error_size) noexcept {
    CopyError("",error,error_size);
    if (!response || response->size!=sizeof(*response) || response->owner) {
        CopyError("Invalid/unreleased HTTPS response",error,error_size);return TTP_HTTPS_ERROR;
    }
    *response={};response->size=sizeof(*response);
    if (!request || request->size!=sizeof(*request) || !request->url ||
        request->proxy_type<0 || request->proxy_port<0 || request->proxy_port>65535) {
        CopyError("Invalid HTTPS request",error,error_size);return TTP_HTTPS_ERROR;
    }
    try {
        std::function<bool()> canceled=[&]{return request->canceled && request->canceled(request->cancel_context)!=0;};
        auto value=FetchPortableHttps(request->url,*request,canceled);
        if (!value) return TTP_HTTPS_USE_WINHTTP;
        auto owner=std::make_unique<PortableHttpResponse>(std::move(*value));
        const auto* title=owner->headers["tt-title"].c_str();
        const auto* url=owner->headers["tt-url"].c_str();
        response->body=reinterpret_cast<const unsigned char*>(owner->body.data());
        response->body_size=owner->body.size();
        response->title_header=title;response->url_header=url;
        response->tls_version=owner->info.protocol;response->verify_flags=owner->info.verify_flags;
        std::memcpy(response->ciphersuite,owner->info.ciphersuite,sizeof(response->ciphersuite));
        response->owner=owner.release();return TTP_HTTPS_OK;
    } catch (const Canceled&) {
        CopyError("Canceled",error,error_size);return TTP_HTTPS_CANCELED;
    } catch (const TlsError& failure) {
        response->tls_error=failure.code;response->verify_flags=failure.flags;
        CopyError(failure.what(),error,error_size);
    } catch (const std::bad_alloc&) {
        CopyError("HTTPS allocation failed",error,error_size);
    } catch (const std::exception& failure) {
        CopyError(failure.what(),error,error_size);
    } catch (...) {
        CopyError("HTTPS operation failed",error,error_size);
    }
    return TTP_HTTPS_ERROR;
}
void __cdecl ReleaseHttp(ttp_https_http_response* response) noexcept {
    if(!response || response->size!=sizeof(*response))return;
    Release(&response->response);*response={};response->size=sizeof(*response);
    response->response.size=sizeof(response->response);
}
int __cdecl GetHttp(const ttp_https_http_request* value,ttp_https_http_response* response,char* error,size_t error_size) noexcept {
    CopyError("",error,error_size);
    const auto header=[](const char* text) noexcept {
        if(!text || !*text)return false;
        for(size_t i=0;i<=512;++i) {unsigned char c=static_cast<unsigned char>(text[i]);if(!c)return true;if(c<32 || c>126)return false;}
        return false;
    };
    if(!value || value->size!=sizeof(*value) || !response || response->size!=sizeof(*response) ||
       response->response.size!=sizeof(response->response) || response->response.owner ||
       value->request.size!=sizeof(ttp_https_request) || !value->request.url ||
       value->request.proxy_type<0 || value->request.proxy_port<0 || value->request.proxy_port>65535 ||
       !header(value->user_agent) || !header(value->accept)) {
        CopyError("Invalid HTTPS HTTP request",error,error_size);return TTP_HTTPS_ERROR;
    }
    *response={};response->size=sizeof(*response);response->response.size=sizeof(response->response);
    try {
        const auto& r=value->request;
        std::function<bool()> canceled=[&]{return r.canceled && r.canceled(r.cancel_context)!=0;};
        auto fetched=FetchPortableHttps(r.url,r,canceled,nullptr,value);
        if(!fetched)return TTP_HTTPS_USE_WINHTTP;
        auto owner=std::make_unique<PortableHttpResponse>(std::move(*fetched));
        auto& base=response->response;
        base.body=reinterpret_cast<const unsigned char*>(owner->body.data());base.body_size=owner->body.size();
        base.title_header=owner->headers["tt-title"].c_str();base.url_header=owner->headers["tt-url"].c_str();
        base.tls_version=owner->info.protocol;base.verify_flags=owner->info.verify_flags;
        std::memcpy(base.ciphersuite,owner->info.ciphersuite,sizeof(base.ciphersuite));
        response->http_status=owner->status;response->retry_after=owner->headers["retry-after"].c_str();
        base.owner=owner.release();return TTP_HTTPS_OK;
    } catch(const Canceled&) {CopyError("Canceled",error,error_size);return TTP_HTTPS_CANCELED;
    } catch(const TlsError& e) {response->response.tls_error=e.code;response->response.verify_flags=e.flags;CopyError(e.what(),error,error_size);
    } catch(const std::exception& e) {CopyError(e.what(),error,error_size);
    } catch(...) {CopyError("HTTPS HTTP operation failed",error,error_size);}
    return TTP_HTTPS_ERROR;
}
void __cdecl ReleaseExchange(ttp_https_exchange_response* response) noexcept {
    if(!response || response->size!=sizeof(*response))return;
    Release(&response->response);*response={};response->size=sizeof(*response);
    response->response.size=sizeof(response->response);
}
int __cdecl Exchange(const ttp_https_exchange_request* value,ttp_https_exchange_response* response,char* error,size_t error_size) noexcept {
    CopyError("",error,error_size);
    bool cookie_ok=true;
    if(value && value->size==sizeof(*value) && value->cookie) {
        cookie_ok=false;
        for(size_t i=0;i<=16384;++i){auto c=static_cast<unsigned char>(value->cookie[i]);if(!c){cookie_ok=true;break;}if(c<32 || c>126)break;}
    }
    if(!value || value->size!=sizeof(*value) || !response || response->size!=sizeof(*response) ||
       response->response.size!=sizeof(response->response) || response->response.owner ||
       value->request.size!=sizeof(ttp_https_request) || !value->request.url ||
       value->request.proxy_type<0 || value->request.proxy_port<0 || value->request.proxy_port>65535 || !cookie_ok) {
        CopyError("Invalid HTTPS exchange request",error,error_size);return TTP_HTTPS_ERROR;
    }
    *response={};response->size=sizeof(*response);response->response.size=sizeof(response->response);
    try {
        const auto& r=value->request;
        std::function<bool()> canceled=[&]{return r.canceled && r.canceled(r.cancel_context)!=0;};
        auto fetched=FetchPortableHttps(r.url,r,canceled,nullptr,nullptr,value);
        if(!fetched)return TTP_HTTPS_USE_WINHTTP;
        auto owner=std::make_unique<PortableHttpResponse>(std::move(*fetched));
        auto& base=response->response;
        base.body=reinterpret_cast<const unsigned char*>(owner->body.data());base.body_size=owner->body.size();
        base.title_header=owner->headers["tt-title"].c_str();base.url_header=owner->headers["tt-url"].c_str();
        base.tls_version=owner->info.protocol;base.verify_flags=owner->info.verify_flags;
        std::memcpy(base.ciphersuite,owner->info.ciphersuite,sizeof(base.ciphersuite));
        response->http_status=owner->status;response->location=owner->headers["location"].c_str();
        for(const auto& c:owner->cookies)owner->cookie_pointers.push_back(c.c_str());
        response->set_cookies=owner->cookie_pointers.data();response->cookie_count=static_cast<uint32_t>(owner->cookies.size());
        base.owner=owner.release();return TTP_HTTPS_OK;
    } catch(const Canceled&) {CopyError("Canceled",error,error_size);return TTP_HTTPS_CANCELED;
    } catch(const TlsError& e) {response->response.tls_error=e.code;response->response.verify_flags=e.flags;CopyError(e.what(),error,error_size);
    } catch(const std::exception& e) {CopyError(e.what(),error,error_size);
    } catch(...) {CopyError("HTTPS exchange failed",error,error_size);}
    return TTP_HTTPS_ERROR;
}
int __cdecl GetLegacy(const ttp_https_request* request,ttp_https_response* response,char* error,size_t error_size) noexcept {
    // ABI 1 ends before username/password. Never read the appended fields.
    if(!request || request->size!=offsetof(ttp_https_request,proxy_username)) return Get(nullptr,response,error,error_size);
    ttp_https_request upgraded{};
    std::memcpy(&upgraded,request,offsetof(ttp_https_request,proxy_username));upgraded.size=sizeof(upgraded);
    if(upgraded.proxy_type>1 && upgraded.proxy_has_credentials) {
        if(!response || response->size!=sizeof(*response) || response->owner) return Get(nullptr,response,error,error_size);
        *response={};response->size=sizeof(*response);CopyError("",error,error_size);return TTP_HTTPS_USE_WINHTTP;
    }
    return Get(&upgraded,response,error,error_size);
}
int __cdecl Download(const ttp_https_download_request* value,char* error,size_t error_size) noexcept {
    CopyError("",error,error_size);
    if(!value || value->size!=sizeof(*value) || !value->write ||
        !value->max_size || value->max_size>256ULL*1024*1024 ||
        value->request.size!=sizeof(ttp_https_request) || !value->request.url ||
        value->request.proxy_type<0 || value->request.proxy_port<0 || value->request.proxy_port>65535) {
        CopyError("Invalid HTTPS download request",error,error_size);return TTP_HTTPS_ERROR;
    }
    try {
        const auto& r=value->request;
        std::function<bool()> canceled=[&]{return r.canceled && r.canceled(r.cancel_context)!=0;};
        return FetchPortableHttps(r.url,r,canceled,value) ? TTP_HTTPS_OK : TTP_HTTPS_USE_WINHTTP;
    } catch(const Canceled&) { CopyError("Canceled",error,error_size);return TTP_HTTPS_CANCELED;
    } catch(const std::exception& e) { CopyError(e.what(),error,error_size);
    } catch(...) { CopyError("HTTPS download failed",error,error_size); }
    return TTP_HTTPS_ERROR;
}
}
}
extern "C" const ttp_https_api* __cdecl ttp_https_get_api(uint32_t version) {
    // Both tables must be constant-initialized. A dynamically initialized local
    // static can retain zero function pointers when this DLL is loaded on XP.
    static constexpr ttp_https_api api={sizeof(ttp_https_api),TTP_HTTPS_ABI_VERSION,
        MBEDTLS_VERSION_STRING_FULL " / " TF_PSA_CRYPTO_VERSION_STRING_FULL,
        "Mozilla/curl 2026-08-13",ttp::https::Get,ttp::https::Release};
    static constexpr ttp_https_api legacy={sizeof(ttp_https_api),1,api.library_version,api.ca_bundle_version,ttp::https::GetLegacy,ttp::https::Release};
    static constexpr ttp_https_api_v3 streaming={{sizeof(ttp_https_api_v3),TTP_HTTPS_DOWNLOAD_ABI_VERSION,
        api.library_version,api.ca_bundle_version,ttp::https::Get,ttp::https::Release},ttp::https::Download};
    static constexpr ttp_https_api_v4 http={{{sizeof(ttp_https_api_v4),TTP_HTTPS_HTTP_ABI_VERSION,
        api.library_version,api.ca_bundle_version,ttp::https::Get,ttp::https::Release},ttp::https::Download},
        ttp::https::GetHttp,ttp::https::ReleaseHttp};
    static constexpr ttp_https_api_v5 exchange={{{{sizeof(ttp_https_api_v5),TTP_HTTPS_EXCHANGE_ABI_VERSION,
        api.library_version,api.ca_bundle_version,ttp::https::Get,ttp::https::Release},ttp::https::Download},
        ttp::https::GetHttp,ttp::https::ReleaseHttp},ttp::https::Exchange,ttp::https::ReleaseExchange};
    return version==TTP_HTTPS_EXCHANGE_ABI_VERSION ? &exchange.base.base.base :
        version==TTP_HTTPS_HTTP_ABI_VERSION ? &http.base.base :
        version==TTP_HTTPS_DOWNLOAD_ABI_VERSION ? &streaming.base :
        version==TTP_HTTPS_ABI_VERSION ? &api : version==1 ? &legacy : nullptr;
}
