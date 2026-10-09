# 2026-10-09 ABI 6 补充

当前本地候选 `2026.10.09` 为 430,080 字节，SHA-256 `4eee95ef0a51f42b65645dff36a930e3f0099d797f87e95338bf46850aff637e`。新增 ABI 6 不改变 ABI 1～5 结构；18 项 TLS 响应边界、4 次旧 ABI 兼容运行和 12 项静态发行包检查通过。配套歌词插件在 XP／Win7 通过 20 项旧接口 HTTPS 测试；原版播放器 EXE 在 XP／Win7／Win11 的 HTTPS 歌词正常流程已实测。详情见 [ABI 6](HTTP_ABI6.md) 及歌词插件 `docs/HTTPS_ORIGINAL_PLAYER_FIXES_20261009.md`。以下保留先前版本验证记录。

# ttp_https.dll 首次封装实测（代理扩展前的基线）

日期：2026-09-25。Mbed TLS 4.2.0 / TF-PSA-Crypto 1.2.0。

## 构建与架构

- portable_https 的传输实现迁至 mbedtlsmin/src/https_client.cpp。
- DLL 包含 DNS、TCP、代理／CONNECT、TLS、HTTP 解析、重定向和响应存储。
- 唯一导出 ttp_https_get_api；底层 mtm_get_api 不导出。
- 播放器只编入 https_provider.cpp，通过 EXE/AddIn/ttp_https.dll 加载。
- DLL 不可用时恢复原 WinHTTP；其请求函数主体与改动前 HEAD 逐段比较一致。
- 音频插件扫描排除 ttp_https.dll，避免报告缺少 ttpGetSoundAddIn。

本次基线 x86 Release 为 **390,144 字节（381 KiB）**，SHA-256：

```text
676a1d2e71fde8e33f9b8b7c4f8bd5c535e3496c4642a5304622283b6dd50e3b
```

DLL 导入检查：6 个系统 DLL、99 个导入，通过 XP 5.1.2600、Win7 6.1.7600 清单。
旧系统播放器：19 个系统 DLL、656 个导入，通过。
无需 VC Redistributable、TF-PSA-Crypto DLL 或旧 mbed_tls_min.dll。

## 实测矩阵

XP 和 Win7 在 VirtualBox 内实际执行，使用隔离目录 C:\https-test。
TLS 探针通过公开 HTTP ABI 发起完整 GET，没有绕过高层传输实现。

| 项目 | 本机 Windows | XP 5.1.2600 | Win7 6.1.7601 |
|---|---|---|---|
| AddIn DLL 加载后真实搜索／下载 | 通过 | 通过 | 通过 |
| TLS 1.2／TLS 1.3 GET | 通过 | 通过 | 通过 |
| 未知 CA／名称不匹配／过期证书拒绝 | 通过 | 通过 | 通过 |
| 取消请求 | 通过 | 通过 | 通过 |
| 同进程首次初始化及并发 GET | 32/32 | 32/32 | 32/32 |
| DLL 缺失时原 WinHTTP 回退 | 通过 | 通过 | 通过 |
| DLL 文件损坏时回退 | 通过 | 通过 | 通过 |
| ABI 999 时卸载并回退 | 通过 | 通过 | 通过 |
| DLL 仅放在 EXE 同目录时回退 | 通过 | 通过 | 通过 |
| 音频插件扫描忽略 HTTPS DLL | 通过 | 通过 | 通过 |
| 碎片化 HTTP、长度限制、截断等回归 | 通过 | 通过 | 通过 |

指定服务器：[https://lyrics.qianqian.plus/api/search/](https://lyrics.qianqian.plus/api/search/)。
搜索“周杰伦／晴天”返回一个结果，随后下载成功：

```text
PASS: live lyric search 1 result(s), download 1388 wchar(s)
```

直接 HTTP ABI 探针强制 TLS 1.3，得到 protocol=0x0304、verify=0、响应体 130 字节。
私有证书测试分别确认 X.509 名称、信任和过期错误。测试 CA 只提供给测试请求，没有安装到系统证书库。

本机原 WinHTTP 可以访问真实服务器。来宾回退负例通过独立证书服务器确认进入 HTTP/TLS 原路径。
回退后仍受系统 TLS／证书能力限制；不保证 XP 在无 DLL 时能访问现代 HTTPS。

## 本地验证代码

代码仅位于 rebuild/tests/lyrics，不上传、不进发行包，Actions 没有新增测试步骤。

- ttp_https_probe.c：C ABI、完整 GET、协议／证书、释放和 32 线程。
- portable_https_contract_tests.cpp：DLL 内的生产 HTTP 解析器。
- ttp_https_invalid.c/.def：不兼容 ABI 测试组件。
- service_catalog_tests.cpp：播放器加载、回退、扫描排除、真实歌词搜索下载。
- mtm_tls_fixture.py：回环地址 TLS 服务，VirtualBox NAT 通过 10.0.2.2 访问。

日志保存于本地 rebuild/tests/lyrics/https-results。
该基线未验证企业 NTLM／Negotiate／Digest 代理，当时这些场景使用原 WinHTTP。
后续新增的代理功能及验证状态见 [PROXY_SUPPORT.md](PROXY_SUPPORT.md)。
旧低层 TLS DLL 的历史验证见 MBED_TLS_MIN_VALIDATION.md。
