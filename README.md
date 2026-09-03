# 我的 Steam 安全吗？

> 不是杀毒软件，而是一个回答“我的 Steam 到底被没被动过手脚”的本地审计工具。

当前版本：**v0.2.2-evidence**。这是供产品所有者和受控染毒环境取证的临时构建，尚未代码签名。

## 它会做什么

- 检查 Steam 客户端敏感目录中的 `version.dll`、`versionOrg.dll`、`msacm32.drv` 与 `wsock32.dll`，验证数字签名并记录 SHA-256。
- 检查 steamui 中与客服告警、游戏启动、隐藏地址栏和客服路由有关的语义级篡改迹象，支持局部变量间接路由。
- 检查 `steam.cfg` 是否成对抑制 Steam 自更新。
- 只读枚举 Steam 相关进程模块，以及 Run、IFEO、SilentProcessExit 等启动链配置。
- 关联所有 Steam 库中的 Wallpaper Engine Workshop 路径，发现其中正在运行的程序，以及指向这些路径的 Windows 启动项。未签名运行映像或 Workshop 自启动会提升为高度可疑。
- 客观显示系统代理状态，本地 Clash 等代理本身不参与风险结论。
- 只列出 Wallpaper Engine 工坊项目类型与近期变化，不把“存在应用程序壁纸”判为中毒。
- 在本地解析用户粘贴的客服链接，显示真正主机，不会打开链接或进行 DNS 查询。
- 导出 Markdown/JSON 体检报告，并生成可交给专业杀毒软件的核对清单。
- 无需 CMD/PowerShell 生成只读取证 ZIP，包括进程树、相关模块、当前 IPv4 TCP、启动链、服务、任务、代理/DNS、证书元数据和关键文件哈希，同时记录多库/Workshop 根，并为正在运行的 Wallpaper 内容程序计算哈希。

## 它明确不做什么

- 不常驻后台，不安装服务或驱动。
- 不联网扫描，不上传文件、报告、账号信息或链接，证据包只写到用户选择的位置。
- 不维护病毒家族特征库，不宣称识别所有恶意程序。
- 不解包或执行创意工坊内容，不对任意 MP4/压缩包作“有毒/无毒”结论。
- 不删除、隔离、修复文件，不修改注册表、代理、证书或防火墙。
- 不请求管理员权限，不包含 v0.1 的处置 Broker 与归档 Worker。

## 如何使用

1. 运行 `IsMySteamSafe.exe`，点击“开始本地体检”。
2. 如果你主动安装过 Millennium 或其他 Steam 客户端注入工具，先勾选对应说明，游戏 MOD、ReShade 不需要勾选。
3. 查看检查卡和每条证据的“发现什么 / 意味着什么 / 建议怎么做”。
4. 看到红信时，复制“联系客服”按钮地址到“红信判真伪”，不要直接打开可疑链接。
5. 若出现强篡改信号，按“下一步怎么做”交给已更新的专业杀毒软件处理。
6. 若系统工具受限，在“只读取证”页立即生成 ZIP。可以选择一个样本目录补充元数据和哈希，工具不会执行或解包其中内容。

重要顺序：**先断网并完成全盘查杀，确认环境干净后，再在干净设备上修改密码。** 客户端被改动时，完整重装 Steam 通常比逐个修补文件更可靠。

## 结论怎么理解

- **明确篡改信号**：例如 Steam 敏感目录出现 `versionOrg.dll` 转发结构，或客服路由被直接写向第三方域名。
- **高度可疑**：与已知侧载/劫持手法强相关，但仍交由专业安全软件确认具体恶意程序。
- **需要核对**：可能来自用户主动安装的客户端插件、覆盖层或调试配置。
- **客观信息**：例如本地代理或工坊来源，只做事实呈现，不影响总体结论。
- **未完整检查**：权限、格式或版本差异造成覆盖不足，不会把未检查部分冒充成安全。

“未发现 Steam 客户端篡改迹象”只表示没有命中当前支持的证据，不等于整台电脑绝对安全。

## 构建

需要 Windows 与 .NET 10 SDK：

```powershell
dotnet build .\IsMySteamSafe.slnx -c Release
dotnet run --project .\IsMySteamSafe.SelfTest\IsMySteamSafe.SelfTest.csproj -c Release
```

生成独立审查包：

```powershell
.\scripts\build-release.ps1
```

## 文档

- `docs/THREAT-MODEL.md`：覆盖范围、信任边界与误报策略。
- `docs/TEST-EVIDENCE.md`：自动测试、实机扫描与 UI 验收证据。
- `docs/EVIDENCE-CHANGESET.md`：本次真实样本如何转化为检测与取证规则。
- `docs/RELEASE-CHECKLIST.md`：正式公开发布前仍需完成的事项。
- `LICENSE-STATUS.md`：许可证范围与发行要求。

## 隐私

默认体检不产生上传行为。只有用户主动选择“导出报告/只读取证”时才写入指定路径。证据包默认脱敏当前用户目录、17 位 SteamID 及 URL 的 `u=`/`d=` 参数，但仍可能包含进程名、域名、任务动作和注册表值，公开分享前请自行审阅。

## 许可证

本项目由 fenglinbei 按 [Apache License 2.0](LICENSE) 授权，SPDX 标识符为 `Apache-2.0`。版权与归属信息见 [NOTICE](NOTICE)，第三方组件的独立许可证见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
