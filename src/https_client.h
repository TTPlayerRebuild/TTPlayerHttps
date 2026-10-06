#pragma once
#include "ttp_https.h"
#include "mbed_tls_min.h"
#include <string>
#include <string_view>
#include <map>
#include <optional>
#include <functional>
namespace ttp::https {
struct PortableHttpResponse {
    std::string body;
    std::map<std::string,std::string> headers;
    mtm_info info{};
    unsigned status{};
};
std::optional<PortableHttpResponse> FetchPortableHttps(const std::wstring&,
    const ttp_https_request&,const std::function<bool()>&,
    const ttp_https_download_request* download = nullptr,
    const ttp_https_http_request* http = nullptr);
}
