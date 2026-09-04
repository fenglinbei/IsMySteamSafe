# 我的 Steam 安全吗？

<img src="IsMySteamSafe.App/Assets/App.png" width="96" height="96" alt="我的 Steam 安全吗？应用图标" />

> 不是杀毒软件，而是一个回答“我的 Steam 到底被没被动过手脚”的本地审计工具。

当前版本：**v0.2.6**。提供当前用户安装包和便携包，保留客户端检查与只读取证能力。签名类型以包内 `SIGNING.txt` 为准，自签名构建不等于公开受信任的发布者签名。

使用 `IsMySteamSafe-0.2.6-setup.exe` 安装，默认目录为当前用户的 `%LOCALAPPDATA%\Programs\IsMySteamSafe`，不要求管理员权限。卸载只移除程序和快捷方式，不删除另行保存的报告与证据包。源码、程序、安装器和卸载器分别打包验证，签名及信任说明见 [SIGNING.md](docs/SIGNING.md)。

## 它会做什么

已加入本地全 AppID 工坊、MOD 与插件的轻量检查，范围与验收见 [COVERAGE-0.2.6.md](docs/COVERAGE-0.2.6.md)，后续事项见 [ROADMAP.md](docs/ROADMAP.md)。图标来源与重建方式见 [ICONS.md](docs/ICONS.md)。

- 检查 Steam 客户端敏感目录中的 `version.dll`、`versionOrg.dll`、`msacm32.drv` 与 `wsock32.dll`，验证数字签名并记录 SHA-256。
- 检查 steamui 中与客服告警、游戏启动、隐藏地址栏和客服路由有关的语义级篡改迹象，支持局部变量间接路由。
- 检查 `steam.cfg` 是否成对抑制 Steam 自更新。
- 只读枚举 Steam 相关进程模块，以及 Run、IFEO、SilentProcessExit 等启动链配置。
- 关联所有 Steam 库的工坊 AppID、已适配 MOD 与 Steam 插件目录，对关键小文件核对已知内容规则和可疑脚本组合。单凭普通 MOD 的 DLL、脚本、未签名程序或缺少 project.json 不判病毒。
- 区分文件存在、已知恶意文件启动链、模块运行关联与 Steam 篡改，未展开归档明确标记内部未检查。
- 客观显示系统代理状态，本地 Clash 等代理本身不参与风险结论。
- 列出全部工坊的项目数量与 AppID，Wallpaper 单独展示项目类型，不把“存在应用程序壁纸”判为中毒。
- 新增上次 JSON 报告对比，未再观察到不等于彻底清除。内容检查上限为 5000 条目、256 MiB、单文件 64 MiB、遍历约 12 秒，后续关联检查与客户端审计另计，不保证总耗时不超过 12 秒。
- 取证时可勾选运行历史摘要，不导出完整运行命令。报告与证据包脱敏 URL 查询参数、常见秘密字段、用户名路径和 SteamID，分享前仍应人工检查。
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
