# Lyrics HTTP exchange ABI 5

2026-10-09。为独立 TTPlayerLrcsh 提供单次 HTTPS 请求。

`ttp_https_get_api(5)` 返回 `ttp_https_api_v5`。旧 ABI 1..4 的布局、查询和行为不变。

- `exchange` 接受最长 16 KiB 的 ASCII Cookie 值，拒绝控制字符及 CR/LF。
- 返回结构化 HTTP 状态、Location 和最多 64 个独立 Set-Cookie。302 等状态不自动跳转，由调用方确定下一请求的 Cookie。
- 响应体沿用 2 MiB 限制；传输成功与 HTTP 200 不等价。
- 所有响应指针由组件持有，必须用 `release_exchange` 释放，释放后清零；重复释放安全。
- 取消、证书验证、TLS 1.2/1.3 与代理沿用现有实现。TLS 错误不作为系统回退信号。

私有测试 `rebuild/tests/lrcsh_rebuild/tls.py`：TLS 1.2/1.3 下的双 Cookie 302、后续请求、证书拒绝、取消及释放通过。未向系统安装测试 CA，Actions 不运行测试。
