# ABI 7：可取消的媒体流

## 用途与兼容边界

`ttp_https_get_api(7)` 返回 `ttp_https_api_v7`，在 ABI 6 表尾追加
`stream_open`、`stream_header`、`stream_read`、`stream_close`。
版本 1～6 保持原有布局和用途；歌词、MusicBrainz、更新下载不受媒体流大小和生命周期的规则影响。

ABI 7 用于重建播放器的 HTTP／HTTPS 音频输入。调用者先验证表大小、版本和四个函数指针。
能力资源的最大 ABI 为 7，新增 `0x20` 媒体流位；播放器 Actions 下载器要求六项能力位 `0x3f`。
应先发布此组件，再让播放器 Actions 拉取最新版。不要用旧 ABI 6 DLL 搭配新增媒体流的播放器。

## 生命周期与结果

1. `stream_open` 打开一个响应并返回 HTTP 状态；接口本身不跟随重定向。
2. `stream_header` 返回小写名称对应的响应头。指针只在此流关闭前有效。
3. `stream_read` 可返回短读；成功且读取字节数为零才表示正常 EOF。
4. `stream_close` 释放响应、TLS、socket 和请求副本。

同一个句柄由调用者串行操作，不允许同时 `read` 和 `close`。
URL、代理、凭据、CA 在打开期间复制；取消回调的上下文必须存活到关闭之后。
调用者负责管理读取线程和重定向。请求携带字节偏移、可选 `If-Range`、ICY 请求标志、超时和可选 PAC 配置。

| 返回值 | 含义 |
| --- | --- |
| `TTP_HTTPS_OK` | 成功；零字节表示 EOF |
| `TTP_HTTPS_ERROR` | 协议、TLS 验证、认证或其他失败 |
| `TTP_HTTPS_CANCELED` | 调用者取消 |
| `TTP_HTTPS_TIMEOUT` | 本次打开／读取超时 |
| `TTP_HTTPS_TRUNCATED` | 声明长度或 chunked 正文未完整结束 |

超时按一次打开／读取计算，默认 15 秒，允许 100～60000 毫秒。
接口没有旧下载 API 的整响应大小和十分钟总时限，适用于持续广播。
关闭定界的正文仍要求合法传输结束；不把缺失 TLS `close_notify` 的异常断开直接当作正常 EOF。

## 网络实现

- HTTP、TLS 1.2／1.3 共用增量读取；接受 HTTP 状态行及广播 `ICY 200 OK`。
- 读取 64 位 Content-Length、chunked 及关闭定界响应；拒绝冲突长度和不支持的 Content-Encoding。
- 请求 `Accept-Encoding: identity`，不改变音频字节位置。
- 支持直接连接、HTTP forward／CONNECT、现有 SOCKS 代理。
- HTTP forward 复用 Basic／Digest／SSPI 认证实现；仅使用显式提供的凭据，不隐式提交登录身份。
- 原有证书链、主机名、有效期验证保留。测试使用显式私有 CA，不修改系统信任库。

XP 的 PAC／WPAD、DNS 接口可能同步阻塞。解析工作放入最多四个工作线程，等待者每 25 ms 检查取消和期限。
取消后，工作线程只保留自己复制的参数和 DLL 引用，完成后自行释放；不会终止正在 WinHTTP/JScript/Winsock 中运行的线程。
这是**取消调用者等待**，不保证 XP 的系统 PAC 解释器立即停止。
候选代理依次尝试；只有明确的 DIRECT 项才允许直接连接。
旧整响应接口继续让 WinHTTP 处理多代理列表。

设计依据：[Microsoft 的 WinHTTP AutoProxy 限制](https://learn.microsoft.com/en-us/windows/win32/winhttp/autoproxy-issues-in-winhttp)、
[异步代理解析接口](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetproxyforurlex)。

## 验证

本地私有夹具位于播放器的 `rebuild/tests/skin/network20`，不加入仓库或 Actions。
覆盖 HTTP、TLS 1.2／1.3、Range、chunked、代理认证、PAC 取消、证书错误、断流、超时、广播及多格式解码。
原有 HTTP framing 契约测试也通过。系统、数量、产物哈希见播放器皮肤审计文档第 20 节。
本轮代理端到端验收覆盖直接代理、PAC、HTTP Basic 和 CONNECT；不据此声称所有企业域环境的 NTLM／Kerberos／WPAD 均已实测。
