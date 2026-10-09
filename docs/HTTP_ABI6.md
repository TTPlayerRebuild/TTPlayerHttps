# ABI 6：旧歌词宿主的 HTTPS 交换

日期：2026-10-09。配套歌词插件 `2026.10.09p2`，本地 HTTPS 组件 `2026.10.09`。

## 接口及所有权

仍只导出 `ttp_https_get_api`，按版本查询 ABI 1～6。ABI 1～5 的结构布局和调用入口保留。

ABI 6 新增 `exchange_ex` / `release_exchange_ex`。扩展请求嵌套 ABI 5 的交换请求，扩展响应嵌套 ABI 5 的交换响应；调用者须置零并填写每一层的 `size`，不能将旧结构强制转换为扩展结构。检查返回 API 的版本和大小后再调用。响应所有权仍属于 DLL；失败也应释放，重复释放安全，有未释放 owner 的响应不能再次用于请求。

- `user_agent` / `accept`：可选，最长 512 个 ASCII 字符；空指针使用默认值。
- `referer`：可选，最长 8192 个 ASCII 字符；空值省略。
- 三个字段拒绝控制字符、非 ASCII 和 CR/LF 注入。
- `body_policy=BODY_ALL`：读取普通响应正文，兼容通用交换。
- `body_policy=BODY_SUCCESS`：只读取成功状态的正文，重定向和错误状态仍返回状态码、Location、Set-Cookie。
- `content_range`：返回原始 Content-Range，由消费方判断能否作为完整文件；指针有效期到释放响应为止。重复 Content-Range 拒绝为歧义头。

204／304 在头结束处完成，不等待连接关闭。这一协议修正也用于旧 ABI。ABI 5 仍保留读取普通重定向／错误正文的行为；要求忽略这些正文的客户端应使用 ABI 6。成功正文仍受 2 MiB 上限和编码／完整性验证约束。

## 原版播放器调用链

```text
原版 TTPlayer.exe（保留原版 ttpcomm.dll）
  → 旧 Search 接口
  → 重建 ttp_lrcsh.dll：协议、目录、候选、Cookie、歌词回调
  → ttp_https.dll ABI 6：TCP／代理、TLS、HTTP 交换
```

歌词插件为每个 Search 缓存 helper，响应先释放，helper 再卸载。UA、Accept、Referer 由歌词插件按原版设置。私有 CA 由明确的本地服务配置提供；不会自动读取 Windows 证书库，也不接受远端目录增加信任。

## 不执行 DLL 的发行能力检查

PE 资源 `RT_RCDATA(10) / 100 / LANG_NEUTRAL(0)` 包含四个 little-endian DWORD：

| 字段 | 当前值 |
|---|---|
| magic | `0x48505454`（TTPH） |
| 格式版本 | 1 |
| 最高 ABI | 6 |
| 能力位 | `0x1f`：交换、Cookie、范围、请求头、正文策略 |

播放器 Action 在验证发布 ZIP 和 DLL SHA-256 后，静态解析该资源以及 XP／Win7 导入表，不执行下载的 DLL，不运行私有测试。此资源是随制品摘要校验的能力声明，不是独立数字签名或行为证明；运行时仍检查实际 API。

需要先发布支持 ABI 6 的 HTTPS 组件，再运行依赖它的播放器 Action。仅旧版本 helper 将被明确拒绝。本轮只完成本地构建／打包和静态检查，未发布远端版本。

测试详情见歌词插件的 `docs/HTTPS_ORIGINAL_PLAYER_FIXES_20261009.md`，私有代码位于 `../rebuild/tests/lrcsh_rebuild`。
