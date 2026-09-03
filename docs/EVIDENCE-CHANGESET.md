# v0.2.2-evidence 证据驱动改动

本文件记录此次规则变更的本地证据来源。所有样本仅做静态读取、哈希和字符串/结构分析，未执行。

## 证据包

- 原始 `Evidence.zip` SHA-256：`2DEB8E62441215DAFA1EF742FEBBB4F2ED1719C27A307BC141C5F431659D4F12`
- ZIP 内路径已先做穿越检查，再释放到隔离工作目录。
- 证据中的 Steam 账号名、SteamID 和用户目录不写入本文。

后续云电脑只读取证包 `Steam只读取证-20260903-175837.zip` 的 SHA-256 为 `4216B6985526C1034440697DFF069B5DD0F1D938DE3219C4B99D0A24E179B0D7`。其时间快照确认：

- PID 10916 与 2616 均从非主库 `L:\SteamLibrary\steamapps\workshop\content\431960\3437694514\vid_720p\ServiceApp.exe` 运行，且未签名；
- HKCU Run 值 `ServiceAppMscopiAuto` 指向同一 Workshop 映像；
- 当时 v0.2.1 记录了原始进程路径与注册表值，但没有把该非主库 Workshop 路径关联为风险，也没有为这两个进程生成 SHA-256。这正是 v0.2.2 的覆盖修复来源。

样本归档 `wallpaper假红信盗号8月25.rar` 的 SHA-256 为 `0A77F7AFF584E1DE476D6058013926170691B34C4895EA56DB12F5C392AB3FAB`。仅使用既有样本密码将唯一 `ServiceApp.exe` 条目解压到内存流，未写盘、未执行；条目大小 865,792 字节，SHA-256 为 `B0F17D38174E22DCB175663A7B904C3C532BDC9AA93531F988DE3F19DDEE2B7A`。

## 已确认组件

| 文件 | SHA-256 | 静态/运行证据 |
|---|---|---|
| `DesktopNotify.exe` | `8AAABE3F1039D3525D08BF2311A0A9A6D2AE75BCB84FA3C6499D4DE52C86F63F` | 未签名；系统信息记录 PID 1256；加载同目录桥接 DLL；TCPView 记录该 PID 到 `222.167.32.209:443` 的已建立连接。 |
| `notify_bridge.dll` | `439E72A88B48A6B303B0DED2F85CAB07D180700C6DAC3D2D6A5F3BFB8BC31714` | 未签名；导出 `NbHostRun/NbHostSync/NbHostUrls`；包含 Steam 路径、`steam.cfg`、客服告警与补丁字符串。 |
| `_svc_launch.bat` | `449DC31A62C915233365A743EA6C45D661FB93AB105895E3CC4ECD40BFC45401` | 指向随机样式 `%LOCALAPPDATA%\Programs` 目录中的 `SilentFrontier.exe`。 |
| `chunk~2dcc5aaf7.js` | `AB3EEBF86F59EA0F1E597647D3DE097C5BB36A596512F2D858AAAB613FCFAC77` | 客服状态固定真值、游戏动作重定向、第三方客服路由、隐藏地址栏。 |
| `steam.cfg` | `C9799659EC6E3E786F68D73EEC26E7EB1190708CAAD875711096C98F1AAC4E24` | `BootStrapperInhibitAll=enable` 与 `BootStrapperForceSelfUpdate=disable` 成对出现。 |

`WebView2Loader.dll` 的 SHA-256 为 `1AC87267E52CCDF5621678697F948030307A650CA56F38F69E74C7CFAF9605C6`，签名链有效且签名者为 Microsoft。它作为共享运行库出现，不加入恶意哈希规则。

## Steam UI 篡改语义

被改写脚本可稳定提取以下四组相互独立的信号：

1. `BMustShowSupportAlertDialog(){return!0}` 与 `BHasActiveSupportAlerts(){return!0}`。JavaScript 中 `!0` 是 `true`，含义是强制开启，而不是关闭。
2. `OnGameActionUserRequest` 在正常分支前调用 `steam://open/supportalert` 并立即 `return`。
3. `SupportMessages`、`HelpAppPage`、`HelpFrontPage` 经局部变量映射到 `luminovastella.top`。URL 中的账户参数在报告中默认脱敏。
4. 内置浏览器 `URLBar` 在 HTTPS/证书状态绘制逻辑附近被设置为 `display:none`，阻止用户核对实际主机。

因此 v0.2.2 不依赖单一域名或单一文件哈希：哈希用于取证关联，语义与 Steam/Wallpaper 路径行为规则用于覆盖同一手法的重打包变体。

## 未作恶意归因的证据

- TCPView 中 Steam 到 `127.0.0.1:1111` 的连接由 `uu_netbar.exe` 监听，与 `DesktopNotify.exe` 的外联不是同一条连接；本版不将该本地端口归因给样本。
- `libraries~2dcc5aaf7.js` 未命中本版四组决定性语义，暂不加入恶意哈希规则。
- 代理、证书存在、Wallpaper Engine 应用程序壁纸以及单独的同名进程均不足以自动定罪。

## 产品边界

v0.2.2-evidence 仍为只读审计与取证工具。它不会终止进程、删除/隔离文件、修改注册表、代理、证书、防火墙或 hosts。证据包不复制二进制样本，权限或瞬时数据缺失会写入覆盖说明。
