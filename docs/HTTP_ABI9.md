# ABI 9：WebDAV 与带认证的音频 Range

`2026.10.29` 新增 `ttp_https_api_v9::stream_open_ex2`。ABI 1～8 保持原有大小、版本和函数；静态能力资源报告最高 ABI 9，新增 WebDAV 能力位 `0x80`，总掩码 `0xff`。

请求结构 `ttp_https_stream_request_ex2` 包含自身 size、ABI 8 请求、可选 Depth 和 flags。调用方仍使用 ABI 7 的 header/read/close 操作响应，并保证 DLL 和取消回调存活。

- `PROPFIND` 必须指定 Depth `0` 或 `1`，允许 XML 正文，发送 Content-Length；不接受无限深度。
- GET 可设置 `TTP_HTTPS_REQUEST_RANGE`，同时发送原有 offset、If-Range 和新增的 origin Authorization，用于受保护音频的读取与定位。
- 普通 GET/POST 保持 ABI 8 语义。ABI 8 本身仍拒绝 PROPFIND 与 Range。
- 复用原有头部、1 MiB 请求体限制、TLS 验证、超时、取消、HTTP framing 与 EOF 校验。不自动跟随重定向或重试 origin 请求。
- `TTP_HTTPS_USE_WINHTTP` 仍表示调用方可以使用系统网络实现；证书或传输失败不返回此信号。

音乐窗用 ABI 9 查询目录；主程序通过浏览器 DLL 的 `resolve_source_ex` 分别取得真实 URL 和临时 Authorization。凭据不加入持久化媒体 URL。缺少 ABI 9 时，对应操作回退 WinINet，TLS 能力取决于系统。

独立 WsgiDAV 服务在 XP IE8 / Win7 IE11 测试环境中验证了 HTTPS PROPFIND、认证 Range、完整字节比较、非法头/Depth 拒绝与取消。ABI 8 回归覆盖 HTTP、TLS 1.2/1.3 和错误分支，19/19 通过。详细结果位于相邻 ttpbrowser 的 `docs/WEBDAV.md`，私有测试数据不随包发行。
