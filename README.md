# ttp_https.dll

独立 x86 HTTPS 请求库，支持 Windows XP SP3、Win7 到 Windows 11。
使用 **Mbed TLS 4.2.0 + TF-PSA-Crypto 1.2.0**，源码仍放在 `mbedtlsmin` 项目。
原 TLS DLL 和重建版新增的 portable_https 传输代码现已合并。

## 安装与回退

```text
TTPlayerRebuild.exe
AddIn/
  ttp_https.dll
```

首次 HTTPS 请求从 EXE 的绝对目录加载 `AddIn/ttp_https.dll`。DLL 缺失、损坏、缺少入口或 ABI 不兼容时，播放器使用原 WinHTTP 请求。
EXE 同目录、工作目录和 PATH 中的同名 DLL 不参与该适配器的查找。
成功加载后，TLS／证书错误按请求错误返回；自定义代理认证在 DLL 内完成；IE 自动登录策略或无法处理的系统 PAC 结果才允许明确回退。
回退后，HTTPS 能力仍受系统 WinHTTP／TLS 能力限制。
成功加载的 DLL 保留到进程结束；替换或改变 DLL 可用性后请重启。
音频插件扫描忽略这个文件，由 HTTPS 适配器单独管理。

## 独立构建

需要现代 MSVC、Windows SDK、CMake 3.24+（VS 2026 需 4.2+）、PowerShell、Python 3：

```powershell
cmake -S . -B build -A Win32
cmake --build build --config Release --target ttp_https --parallel
cmake --install build --config Release --component Runtime --prefix out/ttp_https
```

输出 `build/Release/AddIn/ttp_https.dll` 和 `build/Release/SHA256SUMS.txt`。
Runtime 组件及发行 ZIP 均只包含 `AddIn/ttp_https.dll` 和 `SHA256SUMS.txt`。源码、说明、验证记录、许可证和原始 CA PEM 保留在本仓库。
目标系统无需安装 VC 运行库。

rebuild 仅复制已独立构建的 DLL：

```powershell
cmake -S rebuild -B rebuild/build -A Win32 -DTTPLAYER_HTTPS_DLL=D:/Projects/Backup/TTPlayer/mbedtlsmin/build/Release/AddIn/ttp_https.dll
cmake --build rebuild/build --config Release --target ttplayer_rebuild --parallel
```

Actions 工作流只构建本仓库的 DLL，不构建播放器或 AAC 插件，不运行测试。播放器只接收预编译 DLL。

## 封装范围与体积

DLL 负责 HTTPS URL、DNS、套接字、系统代理解析、HTTP CONNECT、TLS、HTTP 响应解析、重定向、取消检查和响应内存管理。
播放器只保留 C ABI 适配器及原 WinHTTP。歌词协议参数、校验码、XML 和 LRC 处理仍在播放器中。
HTTP 明文歌词服务和原歌词插件自己的网络实现不变。

Release 使用 `/O1 /Os /Gy /Gw`、`/GL /LTCG`、`/OPT:REF /OPT:ICF`。
只编入 TLS 1.2／1.3 客户端、所需密码算法及 X.509；不编入 TLS 服务器、DTLS、PSK、0-RTT 或上游程序。
121 个 Mozilla 根证书转为 DER 内嵌，PSA 密钥存储按需增长。
当前 DLL 为 **423,424 字节（413.5 KiB）**，包含完整 HTTPS 传输、HTTP/SOCKS 代理及流式下载支持。
原 331 KiB 的 mbed_tls_min.dll 仅包含 TLS 层。

## C ABI

公开头文件 `include/ttp_https.h`，唯一导出 `ttp_https_get_api`；当前请求版本为 `2`，同时保留版本 `1` 的旧调用布局。
更新器还可查询版本 `3`，获得向后兼容的流式 `download()` 扩展；先核对 `abi_version` 与 `size`，再转换为 `ttp_https_api_v3`。请求指定最大字节数和写入回调，回调同步执行，可报告已接收字节数与总长度（未知长度为 0）。下载接口上限 256 MiB、期限 10 分钟，播放器更新包另限制为 64 MiB；不会改变歌词 `get()` 的 2 MiB 上限。
底层 mtm_get_api 仅供 DLL 内部调用，不再导出。

1. 请求结构清零，填写 size、HTTPS URL、代理信息和取消回调。
2. 响应结构清零并填写 size。
3. 在工作线程调用函数表的 get。
4. 读取响应体、tt-title／tt-url 原始头、TLS 协议和验证信息。
5. 无论成功或失败，都调用 release。响应内存由 DLL 分配和释放。

接口不跨边界传递 STL 对象、异常或 CRT 内存所有权。
不同请求可并发；重用响应前必须先释放，DLL 卸载前须完成全部调用及释放。
取消回调不能抛异常。播放器提供的回调会将异常转换为取消。

默认 TLS 1.2～1.3，必须校验证书链、有效期和主机名称。
私有 CA 参数仅用于调用方显式信任配置，播放器不设置它；没有关闭验证的选项。
随机数来自 XP CryptoAPI；TF-PSA-Crypto 1.2 的互斥锁／条件变量通过 Windows 和 YY-Thunks 适配。

响应体限 2 MiB，头部／分块元数据限 64 KiB。支持 Content-Length、chunked 和正常 TLS 关闭定界。
拒绝截断、歧义长度、HTTPS 降级及过多重定向。网络等待时检查取消和 65 秒期限；同步 DNS／PAC 还受系统超时约束。
自定义代理支持 Basic、Digest、NTLM、Negotiate 以及 SOCKS4/4a/5；IE 集成登录策略仍交给 WinHTTP。内嵌证书不会随 Windows 更新，也不执行在线 OCSP／CRL 查询。

## 固定依赖

| 文件 | SHA-256 |
|---|---|
| mbedtls-4.2.0.tar.bz2（含 TF-PSA-Crypto 1.2.0） | `2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea` |
| cacert-2026-08-13.pem | `f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9` |

VC-LTL 5.3.1、YY-Thunks 1.2.2 的固定下载及哈希见 cmake/xp_runtime.cmake。
依赖源代码存于忽略的 build 目录；编译时检查密码库实际版本宏。
更新信任证书时需固定新包和哈希并重新构建。

测试只放在 `../rebuild/tests/lyrics`，默认不构建、不下载、不在 Actions 运行。
本地可设置 TTP_HTTPS_TEST_SOURCE、TTP_HTTPS_CODEC_TEST_SOURCE 后手动构建相应测试目标。
实测见 [docs/VALIDATION.md](docs/VALIDATION.md)。

来源：[Mbed TLS 4.2.0](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.2.0)、[Mozilla CA / curl](https://curl.se/docs/caextract.html)。

## 代理配置

沿用播放器“网络连接”中的代理类型、服务器、端口、用户名及密码字段。
服务器不带协议前缀时按 HTTP 代理处理；支持 `http://`、`socks4://`、`socks4a://`、`socks5://`（或 `socks5h://`）。
SOCKS5 将目标域名交给代理解析；SOCKS4 本机解析 IPv4，SOCKS4a 交给代理解析。
端口栏填 0 时使用服务器地址中的端口或协议默认值 HTTP 80、SOCKS 1080；正数端口栏优先。
详细实现、限制和验证状态见 [代理支持](docs/PROXY_SUPPORT.md)。

## GitHub Actions

在本仓库 Actions → **Build HTTPS plugin** → **Run workflow** 手动运行。
默认仅生成构建产物；勾选 **Release a Version (GitHub)** 后创建标签和 GitHub Release。
版本采用北京时间 `yyyy.MM.dd`，同日重复发布递增为 `yyyy.MM.ddp1`、`p2` 等，并在编译前写入 DLL 文件版本。
GitHub 构建产物及 Release ZIP 解压后均严格为两个文件：`AddIn/ttp_https.dll`、`SHA256SUMS.txt`。
完整说明见 [独立构建与 Actions](docs/ACTIONS.md)。

本地生成同样的包：

```powershell
./build.ps1 -Package
# 重建指定发布版本，文件版本与 ZIP 名称保持一致：
./build.ps1 -Package -PackageVersion 2026.09.25p1
```

输出位于 `build/Release/ttp_https-版本号.zip`。`PACKAGE_SHA256SUMS.txt` 是 ZIP 的本地校验文件，
ZIP 内的 `SHA256SUMS.txt` 校验 DLL；Actions 上传的运行文件只有 DLL 和其校验文件。

## 日期版本与 Release 体积优先构建

DLL 的文件版本和产品版本使用北京时间 `yyyy.MM.dd`，同日发布补丁使用 `pN`；
例如 `2026.10.06p1` 对应固定数字版本 `2026.10.6.1`。Actions 在编译前确定最终版本，
DLL、发行包和发布标签使用同一版本。各项目继续独立构建。

Release 的统一配置见 [cmake/size_release.cmake](cmake/size_release.cmake)：
`/O1 /Os /Gy /Gw /GF`、跨模块优化和链接去除未引用代码／折叠相同代码，关闭 Release 调试信息。
本项目经 `/Ob0`、`/Ob1`、`/Ob2` 对比，默认选择 `/Ob1`；
可用 `-DTTP_SIZE_INLINE_LEVEL=0|1|2` 重新测量不同内联策略。
保留正常浮点语义、异常处理及 VC-LTL／YY-Thunks 的 XP／Win7 兼容配置。
Actions 不编译、不运行测试；本次新增的测试仅位于本地 `rebuild/tests/dll_size_versions`，不进入发行包。
