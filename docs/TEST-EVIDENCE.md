# v0.2.2-evidence 测试证据

测试日期：2026-09-03
环境：Windows 11（10.0.26200）x64；.NET SDK 10.0.400；Microsoft.WindowsDesktop.App 10.0.11。

## 自动测试

命令：

```powershell
dotnet run --project .\IsMySteamSafe.SelfTest\IsMySteamSafe.SelfTest.csproj -c Debug
```

结果：**31/31 通过，0 失败**。

覆盖：

- 官方客服域名、大小写、裸域名与 HTTPS 要求。
- `@` 用户信息欺骗、相似后缀、非 Steam 域名、多链接与无效输入。
- Steam 域名边界判断。
- 正常 steamui 语义不告警。
- 客服弹窗固定真/假值的正确解释、游戏启动重定向、第三方客服路由检测。
- 路由直接赋值、局部变量间接映射与“附近无关 URL”误报控制。
- Steam URLBar 隐藏与 `steam.cfg` 成对禁更检测。
- 用户目录、SteamID 和 URL 参数脱敏。
- 路径前缀边界。
- 非主 Steam 库 Workshop、本地 Wallpaper 项目、Run 命令与相似前缀拒绝的关联回归。
- `version.dll + versionOrg.dll` 决定性转发结构。
- 已声明 Millennium 加载器降级为人工核对。
- 本机 `steam.exe` 的 Authenticode 链有效且签名者为 Valve Corp.
- Markdown/JSON 报告导出。
- 只读取证 ZIP 的生成、必需清单和“不复制 EXE/DLL”边界。
- 本机完整审计在 45 秒上限内完成。

## 本机真实 Steam 审计

- 结论：未发现 Steam 客户端篡改迹象。
- 检查项：8。
- 客户端敏感目录：9 个。
- steamui JavaScript：368 个。
- 目标客服路由键：3/3。
- Steam 相关进程：8 个。
- 信息项：本地 WinINET 代理 `127.0.0.1:7890`，按设计识别为常见 Clash 场景，只作客观信息，不影响结论。
- 覆盖说明：新版 Steam 的部分 URL 映射由运行时 IPC 提供，静态审计不会伪称读取了全部运行时映射。

## Windows UI 实机验收

使用真实 WPF 进程完成：

1. 初始页中文布局、普通权限/只读提示、Steam 路径显示正常。
2. 点击“开始本地体检”，进度与取消状态更新正常。
3. 完成后显示 8 张检查卡、分级颜色与证据三段式详情。
4. 在“红信判真伪”中输入 `https://help.steampowered.com@pay-verify.example/qr`。
5. 工具正确显示实际主机 `pay-verify.example`、结果“非 Steam 域名”，并解释 `@` 前内容不是实际主机。
6. 选择“只有这台电脑有”后，界面给出强本地异常提示，但没有使用“100% 中毒”的绝对措辞。
7. “下一步怎么做”“只读取证”与“边界与隐私”页面布局、滚动与中文显示正常。

UI 验收过程中没有点击 Windows 安全中心或外部网页按钮，避免把安全软件 UI 自动化纳入测试。

## 静态边界检查

发布前需再次搜索并人工复核：网络客户端、注册表写入、文件删除/移动、UAC 清单、Broker/Worker 引用。预期 v0.2.2 App/Core 不包含处置路径；报告/证据导出与用户点击的可信页面启动属于明确例外。证据收集会读取当前连接，但不会主动连接远端。
