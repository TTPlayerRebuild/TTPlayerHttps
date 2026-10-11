// Private transport implementation, included after Stream/HTTP framing helpers.
// Authentication runs on the proxy socket BEFORE end-to-end Mbed TLS starts.
enum class ProxyKind { Http, Socks4, Socks4a, Socks5 };
struct ProxyEndpoint {
    ProxyKind kind{ProxyKind::Http};
    std::string host;
    INTERNET_PORT port{};
    ProxyEndpoint(std::wstring_view value,int override_port) {
        auto address=WideToUtf8(value);
        auto sep=address.find("://");
        if(sep!=address.npos) {
            auto scheme=Lower(address.substr(0,sep));address.erase(0,sep+3);
            if(scheme=="socks4") kind=ProxyKind::Socks4;
            else if(scheme=="socks4a") kind=ProxyKind::Socks4a;
            else if(scheme=="socks5" || scheme=="socks5h") kind=ProxyKind::Socks5;
            else if(scheme!="http") throw std::runtime_error("Unsupported proxy scheme");
        }
        if(address.ends_with('/')) address.pop_back();
        if(address.empty() || address.find_first_of("/@?#\\;= \t\r\n")!=address.npos)
            throw std::runtime_error("Invalid proxy address");
        port=kind==ProxyKind::Http ? 80 : 1080;
        std::string port_text;
        if(address.starts_with('[')) {
            auto end=address.find(']');
            if(end==address.npos) throw std::runtime_error("Invalid proxy IPv6 address");
            host=address.substr(1,end-1);
            if(end+1<address.size()) {
                if(address[end+1]!=':') throw std::runtime_error("Invalid proxy port");
                port_text=address.substr(end+2);
                if(port_text.empty()) throw std::runtime_error("Empty proxy port");
            }
        } else {
            auto colon=address.find(':');
            host=address.substr(0,colon);
            if(colon!=address.npos) {
                port_text=address.substr(colon+1);
                if(port_text.empty()) throw std::runtime_error("Empty proxy port");
            }
        }
        if(!port_text.empty()) {
            unsigned n{};auto parsed=std::from_chars(port_text.data(),port_text.data()+port_text.size(),n);
            if(parsed.ec!=std::errc{} || parsed.ptr!=port_text.data()+port_text.size() || !n || n>65535)
                throw std::runtime_error("Invalid proxy port");
            port=static_cast<INTERNET_PORT>(n);
        }
        if(override_port>0) port=static_cast<INTERNET_PORT>(override_port);
        if(host.empty() || host.size()>253 || std::any_of(host.begin(),host.end(),[](unsigned char c){return c<=32 || c>=127;}))
            throw std::runtime_error("Invalid proxy hostname");
    }
};
bool ExplicitCredentials(const ttp_https_request& n) {
    return n.proxy_type>1 && n.proxy_username && *n.proxy_username;
}
std::wstring_view Password(const ttp_https_request& n) { return n.proxy_password ? n.proxy_password : L""; }
std::string Base64(std::string_view bytes) {
    constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for(size_t i=0;i<bytes.size();i+=3) {
        unsigned n=static_cast<unsigned char>(bytes[i])<<16;
        if(i+1<bytes.size()) n|=static_cast<unsigned char>(bytes[i+1])<<8;
        if(i+2<bytes.size()) n|=static_cast<unsigned char>(bytes[i+2]);
        out+=alphabet[n>>18];out+=alphabet[(n>>12)&63];
        out+=i+1<bytes.size() ? alphabet[(n>>6)&63] : '=';
        out+=i+2<bytes.size() ? alphabet[n&63] : '=';
    }
    return out;
}
std::string Unbase64(std::string_view text) {
    if(text.size()%4 || text.size()>header_limit) throw std::runtime_error("Invalid proxy authentication token");
    std::string out;
    for(size_t i=0;i<text.size();i+=4) {
        unsigned n=0;int pad=0;
        for(size_t j=0;j<4;++j) {
            char c=text[i+j];unsigned v;
            if(c>='A' && c<='Z') v=c-'A';
            else if(c>='a' && c<='z') v=c-'a'+26;
            else if(c>='0' && c<='9') v=c-'0'+52;
            else if(c=='+') v=62;else if(c=='/') v=63;
            else if(c=='=' && j>=2 && i+4==text.size()) {++pad;v=0;}
            else throw std::runtime_error("Invalid proxy authentication token");
            if(pad && c!='=') throw std::runtime_error("Invalid proxy authentication padding");
            n=(n<<6)|v;
        }
        if((pad==1 && (n&255)) || (pad==2 && (n&65535))) throw std::runtime_error("Invalid proxy authentication padding");
        out+=static_cast<char>(n>>16);
        if(pad<2) out+=static_cast<char>(n>>8);
        if(!pad) out+=static_cast<char>(n);
    }
    return out;
}
std::vector<std::string> CommaParts(std::string_view text) {
    std::vector<std::string> parts;bool quoted=false,escape=false;size_t start=0;
    for(size_t i=0;i<text.size();++i) {
        char c=text[i];
        if(escape) {escape=false;continue;}
        if(quoted && c=='\\') {escape=true;continue;}
        if(c=='"') quoted=!quoted;
        if(c==',' && !quoted) {parts.push_back(Trim(text.substr(start,i-start)));start=i+1;}
    }
    if(quoted || escape) throw std::runtime_error("Invalid proxy challenge quoting");
    parts.push_back(Trim(text.substr(start)));return parts;
}
struct Challenge { std::string scheme,data; };
std::vector<Challenge> Challenges(std::string_view text) {
    std::vector<Challenge> out;
    for(const auto& part:CommaParts(text)) {
        if(part.empty()) continue;
        auto end=part.find_first_of(" \t=");
        auto rest=end==part.npos ? std::string{} : Trim(std::string_view(part).substr(end));
        if(!rest.starts_with('=')) out.push_back({Lower(part.substr(0,end)),rest});
        else {
            if(out.empty()) throw std::runtime_error("Invalid proxy challenge");
            out.back().data+=", "+part;
        }
    }
    return out;
}
std::map<std::string,std::string> Parameters(std::string_view text) {
    std::map<std::string,std::string> result;
    if(Trim(text).empty()) return result;
    for(const auto& part:CommaParts(text)) {
        auto eq=part.find('=');
        if(eq==part.npos) throw std::runtime_error("Invalid proxy authentication parameter");
        auto key=Lower(Trim(std::string_view(part).substr(0,eq)));
        auto raw=Trim(std::string_view(part).substr(eq+1));std::string value;
        if(raw.starts_with('"') && raw.ends_with('"') && raw.size()>=2) {
            for(size_t i=1;i+1<raw.size();++i) {
                if(raw[i]=='\\' && ++i+1>=raw.size()) throw std::runtime_error("Invalid proxy escape");
                value+=raw[i];
            }
        } else value=raw;
        if(key.empty() || !result.emplace(key,value).second) throw std::runtime_error("Duplicate proxy authentication parameter");
    }
    return result;
}
bool ContainsToken(std::string_view value,std::string_view token) {
    for(const auto& part:CommaParts(value)) if(Lower(part)==token) return true;
    return false;
}
std::string Quoted(std::string_view text) {
    std::string out="\"";
    for(unsigned char c:text) {
        if(c<32 || c==127) throw std::runtime_error("Invalid proxy authentication text");
        if(c=='"' || c=='\\') out+='\\';out+=static_cast<char>(c);
    }
    return out+'"';
}
std::string CredentialText(std::wstring_view value,bool utf8) {
    if(value.size()>4096) throw std::runtime_error("Proxy credentials too long");
    if(utf8) return WideToUtf8(value);
    std::string out;
    for(wchar_t c:value) {
        if(c>255) throw std::runtime_error("Proxy must advertise UTF-8 for these credentials");
        out+=static_cast<char>(c);
    }
    return out;
}
struct CryptoProvider {
    HCRYPTPROV value{};
    CryptoProvider() {
        if(!CryptAcquireContextW(&value,nullptr,nullptr,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT|CRYPT_SILENT))
            throw std::runtime_error("Cannot initialize proxy authentication crypto");
    }
    ~CryptoProvider() { if(value) CryptReleaseContext(value,0); }
};
std::string Hex(std::string_view data) {
    constexpr char hex[]="0123456789abcdef";std::string out;
    for(unsigned char c:data) {out+=hex[c>>4];out+=hex[c&15];}return out;
}
std::string DigestHash(std::string_view input,bool sha256) {
    unsigned char out[32];size_t count=sizeof(out);
    if(sha256) {
        if(mtm_initialize() || psa_hash_compute(PSA_ALG_SHA_256,reinterpret_cast<const unsigned char*>(input.data()),input.size(),out,sizeof(out),&count))
            throw std::runtime_error("Proxy SHA-256 failed");
    } else {
        // MD5 is restricted to legacy HTTP Digest. It is not enabled for TLS.
        CryptoProvider provider;HCRYPTHASH hash{};
        if(!CryptCreateHash(provider.value,CALG_MD5,0,0,&hash)) throw std::runtime_error("Proxy MD5 unavailable");
        struct Cleanup { HCRYPTHASH h;~Cleanup(){CryptDestroyHash(h);} } cleanup{hash};
        DWORD n=sizeof(out);
        if(!CryptHashData(hash,reinterpret_cast<const BYTE*>(input.data()),static_cast<DWORD>(input.size()),0) ||
            !CryptGetHashParam(hash,HP_HASHVAL,out,&n,0)) throw std::runtime_error("Proxy MD5 failed");
        count=n;
    }
    return Hex(std::string_view(reinterpret_cast<char*>(out),count));
}
int DigestRank(const Challenge& challenge) {
    auto p=Parameters(challenge.data);auto algorithm=Lower(p.count("algorithm") ? p["algorithm"] : "MD5");
    if(!p.count("realm") || !p.count("nonce") || p["nonce"].empty()) return 0;
    if(p.count("charset") && Lower(p["charset"])!="utf-8") return 0;
    if(p.count("qop") && !ContainsToken(p["qop"],"auth") && !ContainsToken(p["qop"],"auth-int")) return 0;
    if(algorithm=="sha-256" || algorithm=="sha-256-sess") return 2;
    return algorithm=="md5" || algorithm=="md5-sess" ? 1 : 0;
}
std::string DigestAuthorization(const Challenge& challenge,const ttp_https_request& n,const std::string& authority,
    std::string_view method = "CONNECT") {
    auto p=Parameters(challenge.data);
    auto algorithm=p.count("algorithm") ? p["algorithm"] : "MD5";
    bool sha256=Lower(algorithm).starts_with("sha-256"),utf8=Lower(p["charset"])=="utf-8";
    auto user=CredentialText(n.proxy_username,utf8),password=CredentialText(Password(n),utf8);
    auto hash=[&](std::string_view s){return DigestHash(s,sha256);};
    CryptoProvider random;char bytes[16];
    if(!CryptGenRandom(random.value,sizeof(bytes),reinterpret_cast<BYTE*>(bytes))) throw std::runtime_error("Proxy random failed");
    auto cnonce=Hex(std::string_view(bytes,sizeof(bytes)));
    std::string qop=p.count("qop") ? (ContainsToken(p["qop"],"auth") ? "auth" : "auth-int") : "";
    auto ha1=hash(user+":"+p["realm"]+":"+password);
    SecureZeroMemory(password.data(),password.size());
    if(Lower(algorithm).ends_with("-sess")) ha1=hash(ha1+":"+p["nonce"]+":"+cnonce);
    auto ha2=hash(std::string(method)+":"+authority+(qop=="auth-int" ? ":"+hash("") : ""));
    auto response=hash(ha1+":"+p["nonce"]+":"+(qop.empty() ? "" : "00000001:"+cnonce+":"+qop+":")+ha2);
    bool userhash=Lower(p["userhash"])=="true";
    std::string out="Digest username="+Quoted(userhash ? hash(user+":"+p["realm"]) : user)+
        ", realm="+Quoted(p["realm"])+", nonce="+Quoted(p["nonce"])+", uri="+Quoted(authority)+
        ", response="+Quoted(response)+", algorithm="+algorithm;
    if(p.count("opaque")) out+=", opaque="+Quoted(p["opaque"]);
    if(!qop.empty()) out+=", qop="+qop+", nc=00000001";
    if(!qop.empty() || Lower(algorithm).ends_with("-sess")) out+=", cnonce="+Quoted(cnonce);
    if(userhash) out+=", userhash=true";
    return out;
}
struct SspiAuth {
    CredHandle credentials{};CtxtHandle context{};bool acquired{},started{},done{};
    SspiAuth(const std::string& scheme,const ttp_https_request& n) {
        SecInvalidateHandle(&credentials);SecInvalidateHandle(&context);
        if(std::wcslen(n.proxy_username)>4096 || Password(n).size()>4096) throw std::runtime_error("Proxy credentials too long");
        std::wstring user=n.proxy_username,domain,password(Password(n));
        auto slash=user.find(L'\\');
        if(slash!=user.npos) {domain=user.substr(0,slash);user.erase(0,slash+1);}
        SEC_WINNT_AUTH_IDENTITY_W identity{};
        identity.User=reinterpret_cast<unsigned short*>(user.data());identity.UserLength=static_cast<ULONG>(user.size());
        identity.Domain=reinterpret_cast<unsigned short*>(domain.data());identity.DomainLength=static_cast<ULONG>(domain.size());
        identity.Password=reinterpret_cast<unsigned short*>(password.data());identity.PasswordLength=static_cast<ULONG>(password.size());
        identity.Flags=SEC_WINNT_AUTH_IDENTITY_UNICODE;
        auto package=Utf8ToWide(scheme);TimeStamp expiry{};
        auto status=AcquireCredentialsHandleW(nullptr,package.data(),SECPKG_CRED_OUTBOUND,nullptr,&identity,nullptr,nullptr,&credentials,&expiry);
        SecureZeroMemory(password.data(),password.size()*sizeof(wchar_t));
        if(status!=SEC_E_OK) throw std::runtime_error("Cannot acquire proxy credentials: "+std::to_string(status));
        acquired=true;
    }
    ~SspiAuth() { if(SecIsValidHandle(&context)) DeleteSecurityContext(&context);if(acquired) FreeCredentialsHandle(&credentials); }
    std::string Step(const std::string& token,const std::string& host) {
        if(done) throw std::runtime_error("Proxy rejected credentials");
        auto decoded=Unbase64(token);
        SecBuffer input{static_cast<ULONG>(decoded.size()),SECBUFFER_TOKEN,decoded.data()},output{0,SECBUFFER_TOKEN,nullptr};
        SecBufferDesc in{SECBUFFER_VERSION,1,&input},out{SECBUFFER_VERSION,1,&output};
        struct Cleanup { SecBuffer& b;~Cleanup(){if(b.pvBuffer) FreeContextBuffer(b.pvBuffer);} } cleanup{output};
        auto target=Utf8ToWide("HTTP/"+host);ULONG flags{};TimeStamp expiry{};
        auto status=InitializeSecurityContextW(&credentials,started ? &context : nullptr,target.data(),
            ISC_REQ_CONNECTION|ISC_REQ_ALLOCATE_MEMORY,0,SECURITY_NATIVE_DREP,decoded.empty() ? nullptr : &in,
            0,&context,&out,&flags,&expiry);
        if(status==SEC_I_COMPLETE_NEEDED || status==SEC_I_COMPLETE_AND_CONTINUE) {
            auto complete=CompleteAuthToken(&context,&out);
            if(complete!=SEC_E_OK) throw std::runtime_error("Cannot complete proxy authentication");
            status=status==SEC_I_COMPLETE_NEEDED ? SEC_E_OK : SEC_I_CONTINUE_NEEDED;
        }
        if(status!=SEC_E_OK && status!=SEC_I_CONTINUE_NEEDED) throw std::runtime_error("Proxy SSPI authentication failed: "+std::to_string(status));
        started=true;done=status==SEC_E_OK;
        if(output.cbBuffer>header_limit) throw std::runtime_error("Proxy authentication token too large");
        return Base64(std::string_view(static_cast<char*>(output.pvBuffer),output.cbBuffer));
    }
};
bool HttpTunnel(Stream& stream,const ProxyEndpoint& endpoint,const Url& target,const ttp_https_request& n) {
    std::string authority=(target.host.find(':')==target.host.npos ? target.host : "["+target.host+"]")+":"+std::to_string(target.port);
    std::string authorization,scheme;std::unique_ptr<SspiAuth> sspi;bool sent=false;
    for(int round=0;round<8;++round) {
        stream.guard();
        stream.Write("CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+
            "\r\nProxy-Connection: Keep-Alive\r\n"+(authorization.empty() ? "" : "Proxy-Authorization: "+authorization+"\r\n")+"\r\n");
        PortableHttpResponse reply;int status;
        do {reply.headers.clear();status=Headers(stream,reply.headers);} while(status>=100 && status<200 && status!=101);
        if(status>=200 && status<300) {
            if(sspi && !sspi->done) {
                bool completed=false;
                for(const auto& c:Challenges(reply.headers["proxy-authenticate"])) if(c.scheme==scheme && !c.data.empty()) {
                    auto extra=sspi->Step(c.data,endpoint.host);completed=sspi->done && extra.empty();break;
                }
                if(!completed) throw std::runtime_error("Incomplete proxy authentication");
            }
            return true;
        }
        if(status!=407) throw std::runtime_error("HTTPS proxy status "+std::to_string(status));
        if(!ExplicitCredentials(n)) {
            if(n.proxy_type==1) return false; // Preserve the system's integrated-logon policy.
            throw std::runtime_error("Proxy requires a username and password");
        }
        auto challenges=Challenges(reply.headers["proxy-authenticate"]);
        Challenge selected;int rank=0;
        for(const auto& c:challenges) {
            if(!scheme.empty() && c.scheme!=scheme) continue;
            int score=c.scheme=="negotiate" ? 6 : c.scheme=="ntlm" ? 5 : c.scheme=="digest" ? DigestRank(c)+1 : c.scheme=="basic" ? 1 : 0;
            if(c.scheme=="digest" && !DigestRank(c)) score=0;
            if(score>rank) {selected=c;rank=score;}
        }
        if(!rank) throw std::runtime_error("Unsupported proxy authentication challenge");
        bool closed=ContainsToken(reply.headers["connection"],"close") || ContainsToken(reply.headers["proxy-connection"],"close");
        bool framed=reply.headers.count("content-length") || reply.headers.count("transfer-encoding");
        if(framed) ReadBody(stream,reply); // Drain 407 before reusing the same NTLM connection.
        if(closed || !framed) {
            stream.socket.Connect(endpoint.host,endpoint.port,stream.guard);stream.buffered.clear();
            sspi.reset();
            if(selected.scheme=="ntlm" || selected.scheme=="negotiate") selected.data.clear();
        } else if(!stream.buffered.empty()) throw std::runtime_error("Unexpected data after proxy challenge");
        // header_bytes deliberately accumulates across authentication rounds.
        scheme=selected.scheme;
        if(scheme=="ntlm" || scheme=="negotiate") {
            if(!sspi) sspi=std::make_unique<SspiAuth>(scheme,n);
            auto token=sspi->Step(selected.data,endpoint.host);
            if(token.empty()) throw std::runtime_error("Empty proxy authentication response");
            authorization=(scheme=="ntlm" ? "NTLM " : "Negotiate ")+token;
        } else if(scheme=="digest") {
            if(sent && Lower(Parameters(selected.data)["stale"])!="true") throw std::runtime_error("Proxy rejected Digest credentials");
            authorization=DigestAuthorization(selected,n,authority);
        } else {
            if(sent) throw std::runtime_error("Proxy rejected Basic credentials");
            auto p=Parameters(selected.data);bool utf8=Lower(p["charset"])=="utf-8";
            auto user=CredentialText(n.proxy_username,utf8),password=CredentialText(Password(n),utf8);
            if(user.find(':')!=user.npos) throw std::runtime_error("Basic proxy username cannot contain a colon");
            authorization="Basic "+Base64(user+":"+password);SecureZeroMemory(password.data(),password.size());
        }
        sent=true;
    }
    throw std::runtime_error("Too many proxy authentication rounds");
}
std::string ReadProxyBytes(Stream& stream,size_t count) { std::string bytes;stream.Take(count,bytes);return bytes; }
void SocksTunnel(Stream& stream,const ProxyEndpoint& endpoint,const Url& target,const ttp_https_request& n) {
    bool credentials=ExplicitCredentials(n);
    auto user=credentials ? CredentialText(n.proxy_username,true) : std::string{};
    auto password=credentials ? CredentialText(Password(n),true) : std::string{};
    std::string request;
    if(endpoint.kind==ProxyKind::Socks5) {
        stream.Write(credentials ? std::string_view("\5\2\0\2",4) : std::string_view("\5\1\0",3));
        auto choice=ReadProxyBytes(stream,2);
        if(choice[0]!=5) throw std::runtime_error("Invalid SOCKS5 greeting");
        if(choice[1]==2 && credentials) {
            if(user.size()>255 || password.empty() || password.size()>255) throw std::runtime_error("SOCKS5 credentials must contain 1..255 UTF-8 bytes");
            std::string auth(1,'\1');auth+=static_cast<char>(user.size());auth+=user;auth+=static_cast<char>(password.size());auth+=password;
            stream.Write(auth);SecureZeroMemory(auth.data(),auth.size());
            auto reply=ReadProxyBytes(stream,2);
            if(reply[0]!=1 || reply[1]!=0) throw std::runtime_error("SOCKS5 rejected credentials");
        } else if(choice[1]!=0) throw std::runtime_error("Unsupported SOCKS5 authentication method");
        request.assign("\5\1\0",3);
        addrinfo hints{};hints.ai_flags=AI_NUMERICHOST;hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
        addrinfo* result{};
        if(!getaddrinfo(target.host.c_str(),nullptr,&hints,&result)) {
            std::unique_ptr<addrinfo,decltype(&freeaddrinfo)> numeric(result,freeaddrinfo);
            if(result->ai_family==AF_INET) {request+='\1';request.append(reinterpret_cast<char*>(&reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr),4);}
            else if(result->ai_family==AF_INET6) {request+='\4';request.append(reinterpret_cast<char*>(&reinterpret_cast<sockaddr_in6*>(result->ai_addr)->sin6_addr),16);}
            else throw std::runtime_error("Unsupported SOCKS address family");
        } else {
            if(target.host.size()>255) throw std::runtime_error("SOCKS hostname too long");
            request+='\3';request+=static_cast<char>(target.host.size());request+=target.host;
        }
        request+=static_cast<char>(target.port>>8);request+=static_cast<char>(target.port&255);stream.Write(request);
        auto reply=ReadProxyBytes(stream,4);
        if(reply[0]!=5 || reply[2]!=0 || reply[1]!=0) throw std::runtime_error("SOCKS5 connect rejected: "+std::to_string(static_cast<unsigned char>(reply[1])));
        size_t length=reply[3]==1 ? 4 : reply[3]==4 ? 16 : reply[3]==3 ? static_cast<unsigned char>(ReadProxyBytes(stream,1)[0]) : 0;
        if(!length) throw std::runtime_error("Invalid SOCKS5 bound address");
        ReadProxyBytes(stream,length+2);
    } else {
        request.assign("\4\1",2);request+=static_cast<char>(target.port>>8);request+=static_cast<char>(target.port&255);
        if(endpoint.kind==ProxyKind::Socks4a) request.append("\0\0\0\1",4);
        else {
            addrinfo hints{};hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;addrinfo* result{};stream.guard();
            if(getaddrinfo(target.host.c_str(),nullptr,&hints,&result)) throw std::runtime_error("SOCKS4 requires a resolvable IPv4 destination");
            std::unique_ptr<addrinfo,decltype(&freeaddrinfo)> addresses(result,freeaddrinfo);
            request.append(reinterpret_cast<char*>(&reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr),4);
        }
        request+=user;request+='\0';
        if(endpoint.kind==ProxyKind::Socks4a) {request+=target.host;request+='\0';}
        stream.Write(request);auto reply=ReadProxyBytes(stream,8);
        if(reply[0]!=0 || static_cast<unsigned char>(reply[1])!=90) throw std::runtime_error("SOCKS4 connect rejected");
    }
    SecureZeroMemory(password.data(),password.size());stream.guard();
}
