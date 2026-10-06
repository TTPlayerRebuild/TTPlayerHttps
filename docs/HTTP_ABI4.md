# ABI 4：结构化 HTTP GET

日期：2026-10-06。用途：供 TTPlayerRebuild 的 MusicBrainz 客户端使用。

## 兼容约定

`ttp_https_get_api(1/2/3)` 仍返回原版本和原尺寸的函数表；原歌词 `get()` 和更新器 `download()` 的布局、所有权与错误处理不改变。查询 `4` 后必须核对 `abi_version == 4` 与 `size == sizeof(ttp_https_api_v4)`，再使用扩展表。

新请求和响应采用独立结构，不在旧调用者传入的结构尾部写新字段。没有增加导出名称；仍只有 `ttp_https_get_api`。

## 调用方式

1. 清零 `ttp_https_http_request`，填写外层 `size` 及内层 `request.size`。
2. 内层请求使用既有 HTTPS URL、代理认证和取消参数。
3. `user_agent`、`accept` 必须为非空 ASCII 字符串，最长 512 字节，不含控制字符。
4. 清零 `ttp_https_http_response`，填写外层 `size` 和内层 `response.size`。
5. 工作线程调用 `get_http()`；传输成功时返回 `TTP_HTTPS_OK`，不代表 HTTP 200。
6. 检查 `http_status`，读取内层 body、TLS 校验信息和 `retry_after`。404、429、503 等响应保留状态和受限大小的响应体。
7. 无论成功或失败，使用 **`release_http()`** 释放整个响应；完成全部调用和释放前不要卸载 DLL。

响应所有指针归 DLL 管理。复用响应前必须释放，不能跨 CRT 释放 body。`release_http()` 会恢复结构尺寸并清空指针。旧版本 `release()` 仅用于其对应的旧响应结构。

## 保持的网络边界

继续验证 TLS 证书链、有效期和主机名；禁止 HTTPS 降级，限制重定向、头和响应体。MusicBrainz 的请求排队、缓存、Retry-After 等待和重试属于宿主业务逻辑，不放进通用 DLL。

旧 `get()` 继续将非 200 当作错误；新 `get_http()` 返回结构化 HTTP 状态。`TTP_HTTPS_USE_WINHTTP` 仍只表示显式的系统代理回退要求；证书错误不会产生该返回值。

## 本地验证

测试源码仅位于 `../rebuild/tests/freedb_analysis`，不提交、不分发、不进入 Actions。

已测试 ABI 1～4 的版本与函数表尺寸、未知 ABI 拒绝、请求头 CR/LF 注入拒绝、连接前取消和响应释放。真实 MusicBrainz 请求验证查询、发行版详情和非成功 HTTP 404 状态能够到达宿主。

Windows 11、Win7 真实请求已成功。XP 的虚拟机直连路由失败，临时 CONNECT 转发下请求与证书验证成功；TLS 仍在 XP DLL 内终止，转发器不解密，也没有修改系统代理或 DNS。详细测试矩阵见播放器仓库的 `docs/CDA_MUSICBRAINZ_IMPLEMENTATION.md`。

本地 Release 大小为 424,448 字节，静态导入检查通过 XP／Win7 基线。此记录不替代实体旧电脑网络或所有代理认证方式的验证。
