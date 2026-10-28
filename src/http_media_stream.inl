// ABI 7 is deliberately separate from the bounded lyric/update contracts.
// The caller owns the read thread and controls response/redirect lifetimes.
struct NativeTransportRequired {};
struct MediaStream {
    std::wstring url, proxy, username, password;
    std::vector<unsigned char> ca;
    ttp_https_request request{};
    std::function<bool()> canceled;
    Guard guard;
    struct Sockets {
        Sockets() { WSADATA data{}; if (WSAStartup(MAKEWORD(2,2), &data)) throw std::runtime_error("Sockets unavailable"); }
        ~Sockets() { WSACleanup(); }
    } sockets;
    Stream stream;
    std::map<std::string, std::string> headers;
    uint32_t status{}, timeout{};
    std::optional<uint64_t> remaining;
    uint64_t chunk{};
    bool chunked{}, chunk_ending{}, ended{}, failed{};

    explicit MediaStream(const ttp_https_stream_request& value, const ttp_https_stream_request_ex* extended=nullptr)
        : url(value.request.url), request(value.request),
          canceled([fn=value.request.canceled, context=value.request.cancel_context] { return fn && fn(context); }),
          guard{canceled}, stream(*mtm_get_api(MTM_ABI_VERSION), guard, request) {
        auto copy=[](const wchar_t* text) { return text ? std::wstring(text) : std::wstring{}; };
        proxy=copy(request.proxy_server); username=copy(request.proxy_username); password=copy(request.proxy_password);
        request.url=url.c_str(); request.proxy_server=proxy.c_str();
        request.proxy_username=username.c_str(); request.proxy_password=password.c_str();
        if (request.ca_pem_size) {
            if (!request.ca_pem || request.ca_pem_size>16*1024*1024 || request.ca_pem[request.ca_pem_size-1])
                throw std::runtime_error("Invalid private CA");
            ca.assign(request.ca_pem,request.ca_pem+request.ca_pem_size); request.ca_pem=ca.data();
        }
        timeout=std::clamp(value.timeout_ms ? value.timeout_ms : 15000u,100u,60000u);
        ResetBudget();
        const Url target(url, true);
        auto resolved=Proxy(url,target,request,guard,copy(value.auto_config_url),value.auto_detect);
        if (!resolved) {
            if(extended) throw NativeTransportRequired{};
            throw std::runtime_error("Automatic proxy resolution failed");
        }
        std::unique_ptr<ProxyEndpoint> endpoint;
        if (!resolved->empty()) {
            // WinHTTP returns ordered PAC candidates separated with semicolons.
            // Only an explicit DIRECT entry authorizes a direct fallback.
            size_t first=0;
            for (;;) {
                const auto next=resolved->find(L';',first);
                auto candidate=resolved->substr(first,next==resolved->npos ? next : next-first);
                const auto a=candidate.find_first_not_of(L" \t"), b=candidate.find_last_not_of(L" \t");
                candidate=a==candidate.npos ? L"" : candidate.substr(a,b-a+1);
                try {
                    if (_wcsicmp(candidate.c_str(),L"DIRECT")==0) {
                        stream.socket.Connect(target.host,target.port,guard); endpoint.reset();
                    } else {
                        endpoint=std::make_unique<ProxyEndpoint>(candidate,request.proxy_type>1?request.proxy_port:0);
                        stream.socket.Connect(endpoint->host,endpoint->port,guard);
                    }
                    break;
                } catch (const Canceled&) { throw; } catch (const Timeout&) { throw; }
                catch (...) { if(next==resolved->npos) throw; first=next+1; }
            }
        } else stream.socket.Connect(target.host,target.port,guard);
        const bool forward=endpoint && endpoint->kind==ProxyKind::Http && !target.secure;
        if (endpoint && !forward) {
            if(endpoint->kind==ProxyKind::Http) {
                if (!HttpTunnel(stream,*endpoint,target,request)) {
                    if(extended) throw NativeTransportRequired{};
                    throw std::runtime_error("Proxy credentials required");
                }
            } else SocksTunnel(stream,*endpoint,target,request);
            if (!stream.buffered.empty()) throw std::runtime_error("Unexpected proxy tunnel data");
            stream.header_bytes=0;
        }
        if(target.secure) stream.StartTls(target.host);
        const auto resource=forward ? "http://"+target.authority+target.path : target.path;
        const std::string validator=value.if_range ? value.if_range : "";
        if(validator.size()>512 || std::any_of(validator.begin(),validator.end(),[](unsigned char c){return c<32 || c>=127;}))
            throw std::runtime_error("Invalid If-Range value");
        const std::string method=extended && extended->method ? extended->method : "GET";
        const std::string fields=extended ? "\r\nHost: "+target.authority+
            "\r\nUser-Agent: "+std::string(extended->user_agent ? extended->user_agent : "TTPlayerRebuild/Media")+
            "\r\nAccept: "+std::string(extended->accept ? extended->accept : "*/*")+
            "\r\nAccept-Encoding: identity\r\n"+
            (extended->content_type && *extended->content_type ? "Content-Type: "+std::string(extended->content_type)+"\r\n" : "")+
            (extended->authorization && *extended->authorization ? "Authorization: "+std::string(extended->authorization)+"\r\n" : "")+
            (method=="POST" ? "Content-Length: "+std::to_string(extended->body_size)+"\r\n" : "") : "\r\nHost: "+target.authority+
            "\r\nUser-Agent: TTPlayerRebuild/5.7.9\r\nAccept: */*\r\nAccept-Encoding: identity\r\n"+
            "Range: bytes="+std::to_string(value.offset)+"-\r\n"+
            (validator.empty()?"":"If-Range: "+validator+"\r\n")+
            (value.icy_metadata?"Icy-MetaData: 1\r\n":"");
        std::string authorization,scheme;
        std::unique_ptr<SspiAuth> sspi;
        for(int round=0;;++round) {
            stream.Write(method+" "+resource+" HTTP/1.1"+fields+
                (authorization.empty()?"":"Proxy-Authorization: "+authorization+"\r\n")+
                (forward?"Proxy-Connection: Keep-Alive\r\n":"Connection: close\r\n")+"\r\n");
            if(extended && extended->body_size)
                stream.Write(std::string_view(reinterpret_cast<const char*>(extended->body),extended->body_size));
            do {headers.clear();status=Headers(stream,headers,nullptr,true);} while(status<200 && status!=101);
            if(!forward || status!=407) {
                if(sspi && !sspi->done) {
                    bool completed=false;
                    for(const auto& c:Challenges(headers["proxy-authenticate"]))
                        if(c.scheme==scheme && !c.data.empty()) {
                            const auto extra=sspi->Step(c.data,endpoint->host);
                            completed=sspi->done && extra.empty();break;
                        }
                    if(!completed) throw std::runtime_error("Incomplete proxy authentication");
                }
                break;
            }
            if(round>=7 || !ExplicitCredentials(request)) throw std::runtime_error("Proxy authentication failed");
            Challenge selected; int rank=0;
            for(const auto& c:Challenges(headers["proxy-authenticate"])) {
                if(!scheme.empty() && scheme!=c.scheme) continue;
                const int score=c.scheme=="negotiate"?6:c.scheme=="ntlm"?5:
                    c.scheme=="digest" && DigestRank(c)?DigestRank(c)+1:c.scheme=="basic"?1:0;
                if(score>rank) {rank=score;selected=c;}
            }
            if(!rank) throw std::runtime_error("Unsupported proxy challenge");
            const bool closed=ContainsToken(headers["connection"],"close") || ContainsToken(headers["proxy-connection"],"close");
            const bool framed=headers.count("content-length") || headers.count("transfer-encoding");
            if(framed) {PortableHttpResponse reply;reply.headers=headers;ReadBody(stream,reply);}
            if(closed || !framed) {
                stream.socket.Connect(endpoint->host,endpoint->port,guard);stream.buffered.clear();sspi.reset();
                if(selected.scheme=="ntlm" || selected.scheme=="negotiate") selected.data.clear();
            } else if(!stream.buffered.empty()) throw std::runtime_error("Unexpected proxy response data");
            scheme=selected.scheme;
            if(scheme=="ntlm" || scheme=="negotiate") {
                if(!sspi) sspi=std::make_unique<SspiAuth>(scheme,request);
                const auto token=sspi->Step(selected.data,endpoint->host);
                if(token.empty()) throw std::runtime_error("Empty proxy authentication response");
                authorization=(scheme=="ntlm"?"NTLM ":"Negotiate ")+token;
            } else if(scheme=="digest") {
                if(round && Lower(Parameters(selected.data)["stale"])!="true") throw std::runtime_error("Proxy rejected credentials");
                authorization=DigestAuthorization(selected,request,resource,method);
            } else {
                if(round) throw std::runtime_error("Proxy rejected credentials");
                const bool utf8=Lower(Parameters(selected.data)["charset"])=="utf-8";
                auto u=CredentialText(username,utf8), p=CredentialText(password,utf8);
                if(u.find(':')!=u.npos) throw std::runtime_error("Invalid Basic username");
                authorization="Basic "+Base64(u+":"+p); SecureZeroMemory(p.data(),p.size());
            }
        }
        if(status<200 || status==204 || status==304) ended=true;
        auto get=[&](const char* key){auto it=headers.find(key);return it==headers.end()?std::string{}:it->second;};
        const auto coding=Lower(get("content-encoding")), transfer=Lower(get("transfer-encoding"));
        if(!coding.empty() && coding!="identity") throw std::runtime_error("Unsupported Content-Encoding");
        if(!transfer.empty()) {
            if(transfer!="chunked" || headers.count("content-length")) throw std::runtime_error("Ambiguous HTTP framing");
            chunked=true;
        } else if(headers.count("content-length")) remaining=Number64(get("content-length"),10);
    }
    ~MediaStream() { SecureZeroMemory(password.data(),password.size()*sizeof(wchar_t)); }
    void ResetBudget() { guard.deadline=Clock::now()+std::chrono::milliseconds(timeout);guard(); }
    static uint64_t Number64(std::string_view text,int base) {
        uint64_t n{};auto p=std::from_chars(text.data(),text.data()+text.size(),n,base);
        if(text.empty() || p.ec!=std::errc{} || p.ptr!=text.data()+text.size()) throw std::runtime_error("Invalid HTTP length");
        return n;
    }
    uint32_t Read(void* out,uint32_t capacity) {
        ResetBudget();
        if(failed) throw std::runtime_error("Media stream already failed");
        if(!capacity || ended) return 0;
        if(chunked && !chunk) {
            if(chunk_ending) {
                stream.header_bytes=0;
                if(!stream.Line().empty()) throw std::runtime_error("Invalid chunk terminator");
                chunk_ending=false;
            }
            stream.header_bytes=0; const auto line=stream.Line();
            chunk=Number64(std::string_view(line).substr(0,line.find(';')),16);
            if(!chunk) {
                stream.header_bytes=0;
                while(!stream.Line().empty()) {}
                ended=true;return 0;
            }
        }
        if(remaining && !*remaining) {ended=true;return 0;}
        if(stream.buffered.empty() && !stream.More()) {
            if(chunked || remaining) throw Truncated{};
            ended=true;return 0;
        }
        auto n=std::min<uint64_t>(capacity,stream.buffered.size());
        if(chunked) n=std::min(n,chunk);
        if(remaining) n=std::min(n,*remaining);
        memcpy(out,stream.buffered.data(),static_cast<size_t>(n));stream.buffered.erase(0,static_cast<size_t>(n));
        if(chunked) {chunk-=n;chunk_ending=chunk==0;}
        if(remaining) *remaining-=n;
        return static_cast<uint32_t>(n);
    }
};
template<class F> int StreamCall(F action,char* error,size_t size) noexcept {
    try {action();return TTP_HTTPS_OK;}
    catch(const Canceled& e){CopyError(e.what(),error,size);return TTP_HTTPS_CANCELED;}
    catch(const Timeout& e){CopyError(e.what(),error,size);return TTP_HTTPS_TIMEOUT;}
    catch(const Truncated& e){CopyError(e.what(),error,size);return TTP_HTTPS_TRUNCATED;}
    catch(const std::exception& e){CopyError(e.what(),error,size);return TTP_HTTPS_ERROR;}
    catch(...){CopyError("Media transport failed",error,size);return TTP_HTTPS_ERROR;}
}
int __cdecl StreamOpen(const ttp_https_stream_request* request,ttp_https_stream** output,
    uint32_t* status,char* error,size_t size) noexcept {
    if(output) *output=nullptr;
    if(status) *status=0;
    return StreamCall([&]{
        if(!request || request->size<sizeof(*request) || request->request.size<sizeof(ttp_https_request) ||
           !request->request.url || !output || !status) throw std::runtime_error("Invalid stream request");
        auto owner=std::make_unique<MediaStream>(*request);
        *status=owner->status; *output=reinterpret_cast<ttp_https_stream*>(owner.release());
    },error,size);
}
int __cdecl StreamOpenEx(const ttp_https_stream_request_ex* value,ttp_https_stream** output,
    uint32_t* status,char* error,size_t size) noexcept {
    if(output) *output=nullptr;
    if(status) *status=0;
    CopyError("",error,size);
    const auto header=[](const char* text,size_t limit) {
        if(!text)return true;
        for(size_t n=0;n<=limit;++n){const auto c=static_cast<unsigned char>(text[n]);if(!c)return true;if(c<32 || c>126)return false;}
        return false;
    };
    // Validate before proxy resolution, connecting, or transmitting any bytes.
    if(!value || value->size<sizeof(*value) || value->stream.size<sizeof(value->stream) ||
       value->stream.request.size<sizeof(ttp_https_request) || !value->stream.request.url || !output || !status ||
       (value->method && strcmp(value->method,"GET") && strcmp(value->method,"POST")) ||
       value->body_size>1024*1024 || (value->body_size && !value->body) ||
       ((!value->method || !strcmp(value->method,"GET")) && value->body_size) ||
       value->stream.offset || value->stream.if_range || value->stream.icy_metadata ||
       value->stream.request.proxy_type<0 || value->stream.request.proxy_port<0 || value->stream.request.proxy_port>65535 ||
       !header(value->user_agent,512) || !header(value->accept,512) ||
       !header(value->content_type,512) || !header(value->authorization,16384)) {
        CopyError("Invalid HTTP request",error,size);return TTP_HTTPS_ERROR;
    }
    bool native=false;
    const auto result=StreamCall([&]{
        try {
            auto owner=std::make_unique<MediaStream>(value->stream,value);
            *status=owner->status;*output=reinterpret_cast<ttp_https_stream*>(owner.release());
        } catch(const NativeTransportRequired&) {native=true;}
    },error,size);
    return native ? TTP_HTTPS_USE_WINHTTP : result;
}
const char* __cdecl StreamHeader(ttp_https_stream* opaque,const char* name) noexcept {
    if(!opaque || !name) return "";
    const auto& headers=reinterpret_cast<MediaStream*>(opaque)->headers;
    const auto it=headers.find(name);return it==headers.end()?"":it->second.c_str();
}
int __cdecl StreamRead(ttp_https_stream* opaque,void* output,uint32_t capacity,
    uint32_t* read,char* error,size_t size) noexcept {
    if(read) *read=0;
    auto* stream=reinterpret_cast<MediaStream*>(opaque);
    const int result=StreamCall([&]{
        if(!stream || !read || (!output && capacity)) throw std::runtime_error("Invalid stream read");
        *read=stream->Read(output,capacity);
    },error,size);
    if(result && stream) stream->failed=true;
    return result;
}
void __cdecl StreamClose(ttp_https_stream* opaque) noexcept { delete reinterpret_cast<MediaStream*>(opaque); }
