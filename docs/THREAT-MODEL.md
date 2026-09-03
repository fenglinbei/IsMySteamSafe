# 威胁模型与产品边界

## 保护目标

本工具试图回答：本机 Steam 客户端目录、前端关键逻辑、客服入口与启动链是否出现了可观测的非原始状态。

它不回答：某个任意文件属于哪个木马家族、整台 Windows 是否完全干净、账户资金能否追回。

## v0.2.2-evidence 覆盖

### P0 · 决定性或强篡改证据

- Steam 根目录、`bin`、CEF 版本目录、`steamui`、`clientui` 与 `win64` 中的目标侧载名称。
- `version.dll + versionOrg.dll` 转发结构；单独出现 `versionOrg.dll` 也按明确篡改信号呈现。
- 非 Valve 签名的 `version.dll` / `msacm32.drv` 出现在 CEF 敏感目录。
- `BMustShowSupportAlertDialog` / `BHasActiveSupportAlerts` 被改成常量假值。
- `OnGameActionUserRequest` 在正常分支前强制执行 `steam://open/supportalert` 并返回。
- 客服路由键直接映射到 `steampowered.com` 之外的 HTTP/HTTPS 主机。

### P1 · 强相关、需结合上下文

- Steam/steamwebhelper 当前加载的目标侧载模块。
- Steam 进程从用户可写目录加载的未签名模块（仅“需要核对”）。
- 指向 Steam 或其扩展的非标准 Run/RunOnce 项。
- 任意已发现 Steam 库的 Wallpaper Workshop 或本地项目目录中正在运行的可执行文件；未签名/签名无效时为“高度可疑”，有效签名时仍要求核对来源。
- 指向 Wallpaper Workshop 或本地项目目录的 Run/RunOnce 项按“高度可疑”呈现。判定基于垂直领域路径与行为，不依赖可变的单一文件名。
- Steam 目标进程的 IFEO Debugger 与 SilentProcessExit/GlobalFlag 0x200 配置。
- 当前用户 WinINET 代理/PAC 状态。代理存在只作信息呈现，不单独影响结论；本地 Clash 等属于常见合法场景。

### P2 · 来源提示，不作判定

- Wallpaper Engine 工坊项目数量、声明类型与近期修改项目。
- `type=application` 只说明内容具备可执行能力，不表示恶意。

## 明确不覆盖

- 内核态 rootkit、受保护进程绕过、离线磁盘取证。
- 历史上哪个进程访问过 `localconfig.vdf` 或 ssfn；可靠历史审计需要预先启用 ETW/审计策略或驱动，不适合按需只读 MVP。
- `libcef.dll` 进程内存逐字节比对与 Inline Hook 归因。
- 所有未来 Steam 版本的运行时 URL 映射。新版客户端通过 `SteamClient.URL.GetSteamURLList` 下发部分映射；本版只审计静态路由键、直接映射与语义篡改，并在报告中保留覆盖说明。
- 任意压缩包、加密安装包、MP4 或工坊内容的病毒判定和解包。
- 恶意程序清除、账户恢复、支付追回。

## 误报控制

- 只检查 Steam 客户端目录中的侧载名称，不扫描游戏目录中的 ReShade/SKSE 等正常 MOD。
- 用户可声明主动安装 Millennium 或客户端注入工具；匹配到其加载器时降为“需要核对”，但插件内容不会自动白名单化。
- 代理、仅存在的工坊项目和已签名第三方组件不作为“确认中毒”依据；但工坊内容建立系统自启动仍是高度异常行为。
- 时间戳只作辅助证据，不单独升级结论。
- 结果用“明确篡改 / 高度可疑 / 需要核对 / 客观信息 / 未完整检查”表达，不使用简单的“安全/有毒”二分。

## 链接检查安全性

- 只接受和解析 HTTP/HTTPS 文本，输入上限 1 MiB、最多显示 50 个去重链接。
- 使用 URI 解析器取实际 Host，并进行 IDN ASCII 规范化。
- `help.steampowered.com@evil.example` 的实际主机是 `evil.example`，会被拒绝。
- `help.steampowered.com.evil.example` 不属于 `steampowered.com`，会被拒绝。
- 不进行 DNS、HTTP、WebView 或浏览器导航，避免 SSRF、跟踪与误触恶意页面。

## 状态修改面

常规体检仅执行读取。唯一写入路径是用户主动选择“导出报告”后写入其指定文件；“复制交接清单”只写系统剪贴板。打开 Windows 安全中心或 Steam 官方页面只在用户点击对应按钮时发生。

应用不包含删除、移动、隔离、注册表写入、证书写入、代理修改、防火墙修改、驱动、服务或提权清单。
