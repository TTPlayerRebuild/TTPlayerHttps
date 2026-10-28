# ABI 8：音乐窗 HTTP 请求

`2026.10.28` 增加 `ttp_https_api_v8::stream_open_ex`，ABI 1～7 的表、结构和行为保持兼容。静态能力资源报告最高 ABI 8，新增功能位 `0x40`。公开头文件为 `include/ttp_https.h`。

请求使用 `ttp_https_stream_request_ex`，包含原有网络、代理、取消和超时参数，以及 GET/POST、User-Agent、Accept、Content-Type、Authorization 和正文。正文最多 1 MiB；请求头只接受可打印 ASCII，Authorization 最多 16384 字节，其它头最多 512 字节。参数在连接前检查。POST 支持空正文，自动生成 Content-Length。该接口不发送 Range、ICY 或 Cookie，不自动跟随重定向。

打开成功后，沿用 ABI 7 的 `stream_header`、`stream_read` 和 `stream_close`。所有状态码交给调用者判断，响应大小由调用者限制。调用者必须先关闭流再卸载 DLL，并让取消回调存活到关闭为止。正文仅在同步 open 期间借用，函数返回后可释放。

HTTP forward 及 HTTPS CONNECT、SOCKS、PAC 和 TLS 验证继续使用已有实现。Digest 代理认证使用实际 GET/POST 方法。仅在发送源站请求之前发现需要系统代理处理时返回 `TTP_HTTPS_USE_WINHTTP`。TLS/证书错误、HTTP 状态、超时、取消或正文读取失败都不要求回退；调用方不可因此重发 POST。

音乐窗从 EXE 同目录的 `AddIn/ttp_https.dll` 加载 ABI 8；组件缺失、损坏、接口不足或明确要求原生处理时回退 WinINet。它不共享浏览器 Cookie，不追踪认证请求重定向；使用系统代理，20 秒总期限、5 秒单次 I/O 预算和 8 MiB 响应限制。音频播放/下载仍通过主程序的 ABI 7 网络流。

DLL 入口使用 YY-Thunks 的 `DllMainCRTStartupForYY_Thunks`，使 XP 动态加载时正确初始化 TLS；只链接兼容 API 对象并不足以处理编译器/运行库的静态 TLS。

## 验证

- 本机传输矩阵 19/19：真实 HTTP、TLS 1.2/1.3 GET/POST、空 POST、认证头和正文；旧组件/缺失组件/显式回退；错误、取消、超时、读取中断不重试；重定向、401、8 MiB 限制、截断和头注入。未信任 TLS 的连接计数为 1，没有原生重试。
- XP SP3、Win7 SP1：同一 DLL 通过 HTTP、TLS 1.2/1.3 ABI 检查，每种 30 项；音乐窗真实 GET/POST 两项及响应边界七项通过。使用测试私有 CA，没有修改系统信任库。
- 本机真实 Navidrome/OpenList 登录、浏览、搜索、封面及 WebView2 操作通过；音频 ABI 7 的 Read/Seek、FLAC/M4A 解码、下载和关闭回归通过。
- 静态导入审计：8 个 DLL / 121 个导入，符合 XP/Win7 清单。没有据此声称所有企业代理认证环境均已实测。

可重复工具位于相邻 `ttpbrowser/tests/run_https_transport_tests.py`、`https_api8_tests.cpp`；测试资料位于 `ttpbrowser/out/https-20261028p3` 和 `out/media-source-paint-20261028p3/{xp,win7}`。

依据：[YY-Thunks DLL 入口配置](https://github.com/Chuyu-Team/YY-Thunks/blob/master/Readme.md#241-using-obj-file-msvc-link)。
