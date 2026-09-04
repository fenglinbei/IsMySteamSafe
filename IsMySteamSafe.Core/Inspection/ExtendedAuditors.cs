using System.Diagnostics;
using System.Globalization;
using Microsoft.Win32;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.Core.Inspection;

public static class ProcessModuleAuditor
{
    private static readonly HashSet<string> SideLoadNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "versionOrg.dll", "msacm32.drv", "wsock32.dll"
    };

    public static AuditCheckResult Audit(SteamLayout layout, AuditReport report, CancellationToken cancellationToken)
    {
        int findingsBefore = report.Findings.Count;
        int processCount = 0;
        int wallpaperProcessCount = 0;
        int inaccessible = 0;
        HashSet<string> seenModules = new(StringComparer.OrdinalIgnoreCase);
        string windowsRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string temp = Path.GetTempPath();

        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    string? path = process.MainModule?.FileName;
                    if (!SteamPathClassifier.IsWallpaperContentPath(layout, path)) continue;
                    wallpaperProcessCount++;
                    SignatureResult signature = AuthenticodeVerifier.Verify(path!);
                    bool unsignedOrInvalid = signature.Status != SignatureStatus.Valid;
                    report.Findings.Add(new AuditFinding
                    {
                        Id = "P1.PROCESS.WALLPAPER_CONTENT",
                        Priority = AuditPriority.P1,
                        Level = unsignedOrInvalid ? AuditLevel.HighlySuspicious : AuditLevel.NeedsReview,
                        Area = AuditArea.RunningProcesses,
                        Title = unsignedOrInvalid
                            ? "Wallpaper 内容目录中的未签名程序正在运行"
                            : "Wallpaper 内容目录中的程序正在运行",
                        WhatFound = $"{process.ProcessName} (PID {process.Id}) 的映像位于 {path}。",
                        Meaning = unsignedOrInvalid
                            ? "创意工坊内容中的未签名可执行文件已被启动，这与已观察到的假红信投递链一致，但仍需由专业杀毒软件确认。"
                            : "创意工坊或 Wallpaper 项目通常不应注册独立常驻程序，有效签名降低风险，但仍需核对来源。",
                        Recommendation = "先断网并退出 Steam，不要付款或登录。导出证据包后，使用专业杀毒软件扫描该路径及全盘。",
                        Target = path,
                        Evidence = [new("进程", $"{process.ProcessName} (PID {process.Id})"), new("签名", signature.Detail), new("签名者", signature.Subject ?? "无")]
                    });
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    // Inaccessible unrelated processes are expected for a standard-user audit.
                }
            }
        }

        foreach (string processName in new[] { "steam", "steamwebhelper" })
        {
            foreach (Process process in Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    processCount++;
                    try
                    {
                        foreach (ProcessModule module in process.Modules)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            string path = module.FileName;
                            if (!seenModules.Add(path)) continue;
                            report.Metrics.ProcessModulesChecked++;
                            string name = Path.GetFileName(path);
                            bool inSteam = layout.SteamRoots.Any(root => FileUtilities.IsWithin(path, root));
                            bool inWindows = FileUtilities.IsWithin(path, windowsRoot);

                            if (SideLoadNames.Contains(name) && !inWindows)
                            {
                                SignatureResult signature = AuthenticodeVerifier.Verify(path);
                                report.Findings.Add(new AuditFinding
                                {
                                    Id = $"P1.MODULE.{name.ToUpperInvariant()}",
                                    Priority = AuditPriority.P1,
                                    Level = name.Equals("versionOrg.dll", StringComparison.OrdinalIgnoreCase)
                                        ? AuditLevel.ConfirmedTampering
                                        : AuditLevel.HighlySuspicious,
                                    Area = AuditArea.RunningProcesses,
                                    Title = $"{process.ProcessName} 已加载 {name}",
                                    WhatFound = $"运行中的 Steam 相关进程加载了侧载高风险名称模块：{path}",
                                    Meaning = "动态加载证据说明该文件不仅存在，还进入了 Steam 进程。合法客户端扩展也可能注入模块，因此仍应结合安装来源核对。",
                                    Recommendation = "先退出 Steam、断网，再使用专业杀毒软件扫描该路径及全盘，不要在当前会话中修改密码。",
                                    Target = path,
                                    Evidence = [new("进程", $"{process.ProcessName} (PID {process.Id})"), new("签名", signature.Detail), new("签名者", signature.Subject ?? "无")]
                                });
                                continue;
                            }

                            bool userWritableLocation = FileUtilities.IsWithin(path, appData) ||
                                                        FileUtilities.IsWithin(path, localAppData) ||
                                                        FileUtilities.IsWithin(path, temp);
                            if (!inSteam && !inWindows && userWritableLocation)
                            {
                                SignatureResult signature = AuthenticodeVerifier.Verify(path);
                                if (signature.Status == SignatureStatus.Valid) continue;
                                report.Findings.Add(new AuditFinding
                                {
                                    Id = "P1.MODULE.USER_WRITABLE",
                                    Priority = AuditPriority.P1,
                                    Level = AuditLevel.NeedsReview,
                                    Area = AuditArea.RunningProcesses,
                                    Title = "Steam 进程加载了用户可写目录中的未签名模块",
                                    WhatFound = $"{process.ProcessName} 加载了 {path}。",
                                    Meaning = "覆盖层、无障碍工具或客户端插件也可能这样工作，这一项不能单独说明电脑中毒。",
                                    Recommendation = "请核对它是否来自你主动安装的软件，无法确认时，把路径交给专业杀毒软件复核。",
                                    Target = path,
                                    Evidence = [new("进程", $"{process.ProcessName} (PID {process.Id})"), new("签名", signature.Detail)]
                                });
                            }
                        }
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                    {
                        inaccessible++;
                    }
                }
            }
        }

        int count = report.Findings.Count - findingsBefore;
        int relatedProcessCount = processCount + wallpaperProcessCount;
        AuditLevel level = count > 0
            ? report.Findings.Skip(findingsBefore).OrderByDescending(item => AuditLabels.RiskRank(item.Level)).First().Level
            : relatedProcessCount == 0 ? AuditLevel.Information
            : inaccessible == processCount ? AuditLevel.Incomplete
            : AuditLevel.Passed;
        if (inaccessible > 0) report.CoverageNotes.Add($"有 {inaccessible} 个 Steam 相关进程无法读取模块，通常与权限不足或进程已退出有关。");
        return new AuditCheckResult
        {
            Id = "running-processes",
            Priority = AuditPriority.P1,
            Area = AuditArea.RunningProcesses,
            Name = "运行进程与模块",
            Level = level,
            Summary = relatedProcessCount == 0
                ? "Steam 与 Wallpaper 内容程序当前未运行，静态检查仍会继续，动态检查已跳过。"
                : count == 0
                    ? $"检查了 {processCount} 个 Steam 进程与 {wallpaperProcessCount} 个 Wallpaper 内容进程，未见目标异常。"
                    : $"发现 {count} 项需要核对的运行进程或已加载模块。",
            EvidenceCount = count
        };
    }
}

public static class RegistryPersistenceAuditor
{
    private static readonly string[] TargetExecutables = ["steam.exe", "steamwebhelper.exe", "steamservice.exe"];

    public static AuditCheckResult Audit(SteamLayout layout, AuditReport report)
    {
        int before = report.Findings.Count;
        foreach ((RegistryHive hive, RegistryView view, string label) in RegistryViews())
        {
            InspectRunKey(hive, view, label, @"Software\Microsoft\Windows\CurrentVersion\Run", layout, report);
            InspectRunKey(hive, view, label, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", layout, report);
        }

        foreach (RegistryView view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
        {
            foreach (string executable in TargetExecutables)
            {
                InspectIfeo(view, executable, report);
                InspectSilentExit(view, executable, report);
            }
        }

        int count = report.Findings.Count - before;
        AuditLevel level = count == 0
            ? AuditLevel.Passed
            : report.Findings.Skip(before).OrderByDescending(item => AuditLabels.RiskRank(item.Level)).First().Level;
        return new AuditCheckResult
        {
            Id = "persistence",
            Priority = AuditPriority.P1,
            Area = AuditArea.Persistence,
            Name = "Steam 相关启动项",
            Level = level,
            Summary = count == 0 ? "未发现通过 Run、IFEO 或 SilentProcessExit 劫持 Steam 进程的配置。" : $"发现 {count} 项 Steam 相关启动配置需要核对。",
            EvidenceCount = count
        };
    }

    private static void InspectRunKey(RegistryHive hive, RegistryView view, string hiveLabel, string keyPath, SteamLayout layout, AuditReport report)
    {
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(keyPath, writable: false);
            if (key is null) return;
            foreach (string valueName in key.GetValueNames())
            {
                report.Metrics.PersistenceValuesChecked++;
                string command = key.GetValue(valueName)?.ToString() ?? string.Empty;
                bool wallpaperStartup = SteamPathClassifier.CommandReferencesWallpaperContent(layout, command);
                bool steamRelated = SteamPathClassifier.CommandReferencesSteamInstallation(layout, command) ||
                                    wallpaperStartup ||
                                    command.Contains("steamwebhelper", StringComparison.OrdinalIgnoreCase) ||
                                    command.Contains("millennium", StringComparison.OrdinalIgnoreCase);
                if (!steamRelated || IsExpectedSteamAutostart(command, layout)) continue;
                bool scriptHost = command.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                                  command.Contains("pwsh", StringComparison.OrdinalIgnoreCase) ||
                                  command.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                                  command.Contains("rundll32", StringComparison.OrdinalIgnoreCase);
                report.Findings.Add(new AuditFinding
                {
                    Id = "P1.REGISTRY.RUN",
                    Priority = AuditPriority.P1,
                    Level = scriptHost || wallpaperStartup ? AuditLevel.HighlySuspicious : AuditLevel.NeedsReview,
                    Area = AuditArea.Persistence,
                    Title = wallpaperStartup ? "Wallpaper 内容被注册为 Windows 启动项" : "发现非标准 Steam 相关启动项",
                    WhatFound = wallpaperStartup
                        ? $"{hiveLabel}\\{keyPath} 中的“{valueName}”会从 Wallpaper/创意工坊内容目录启动程序。"
                        : $"{hiveLabel}\\{keyPath} 中的“{valueName}”指向 Steam 或其扩展。",
                    Meaning = wallpaperStartup
                        ? "创意工坊内容通常不应创建 Windows 自启动，这与已观察到的假红信病毒驻留方式一致。"
                        : scriptHost
                            ? "该启动项借助脚本宿主或系统加载器运行，与正常的 Steam -silent 自启动不同。"
                            : "客户端插件也可能创建此项，需要由用户确认来源。",
                    Recommendation = "本工具不会删除该启动项，请先在任务管理器的“启动应用”或专业杀毒软件中核对。若不认识，请按完整处理步骤排查。",
                    Target = $"{hiveLabel}\\{keyPath}\\{valueName}",
                    Evidence = [new("命令", command), new("路径关联", wallpaperStartup ? "Wallpaper/Workshop 内容目录" : "Steam 安装目录或扩展"), new("注册表视图", view.ToString())]
                });
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            report.CoverageNotes.Add($"无法读取 {hiveLabel}\\{keyPath}（{view}）：{ex.Message}");
        }
    }

    private static void InspectIfeo(RegistryView view, string executable, AuditReport report)
    {
        const string basePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using RegistryKey? key = baseKey.OpenSubKey($@"{basePath}\{executable}", writable: false);
            report.Metrics.PersistenceValuesChecked++;
            string? debugger = key?.GetValue("Debugger")?.ToString();
            if (string.IsNullOrWhiteSpace(debugger)) return;
            report.Findings.Add(new AuditFinding
            {
                Id = "P1.REGISTRY.IFEO",
                Priority = AuditPriority.P1,
                Level = AuditLevel.HighlySuspicious,
                Area = AuditArea.Persistence,
                Title = $"{executable} 配置了 IFEO Debugger",
                WhatFound = "Windows 被配置为在启动目标 Steam 进程时先运行另一个程序。",
                Meaning = "开发调试工具可能会合法使用 IFEO，但普通 Steam 安装不需要它，恶意程序也可能借此劫持 Steam 启动。",
                Recommendation = "请记录该值并交给专业杀毒软件处理，如果这是你主动配置的调试器，可在报告中注明。",
                Target = $@"HKLM\{basePath}\{executable}\Debugger",
                Evidence = [new("Debugger", debugger), new("注册表视图", view.ToString())]
            });
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            report.CoverageNotes.Add($"无法读取 {executable} 的 IFEO 配置（{view}）：{ex.Message}");
        }
    }

    private static void InspectSilentExit(RegistryView view, string executable, AuditReport report)
    {
        const string ifeoBase = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        const string silentBase = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using RegistryKey? ifeo = baseKey.OpenSubKey($@"{ifeoBase}\{executable}", writable: false);
            using RegistryKey? silent = baseKey.OpenSubKey($@"{silentBase}\{executable}", writable: false);
            report.Metrics.PersistenceValuesChecked += 2;
            int globalFlag = ParseInteger(ifeo?.GetValue("GlobalFlag"));
            string? monitor = silent?.GetValue("MonitorProcess")?.ToString();
            if ((globalFlag & 0x200) == 0 && string.IsNullOrWhiteSpace(monitor)) return;
            report.Findings.Add(new AuditFinding
            {
                Id = "P1.REGISTRY.SILENT_EXIT",
                Priority = AuditPriority.P1,
                Level = AuditLevel.HighlySuspicious,
                Area = AuditArea.Persistence,
                Title = $"{executable} 配置了 SilentProcessExit 触发器",
                WhatFound = "检测到 GlobalFlag 0x200 或退出监控程序配置。",
                Meaning = "该机制能在目标进程退出时启动另一个程序，普通 Steam 安装不需要。",
                Recommendation = "不要自行猜测并删除注册表项，请将键路径与监控命令交给专业杀毒软件复核。",
                Target = $@"HKLM\{silentBase}\{executable}",
                Evidence = [new("GlobalFlag", $"0x{globalFlag:X}"), new("MonitorProcess", monitor ?? "未设置"), new("注册表视图", view.ToString())]
            });
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            report.CoverageNotes.Add($"无法读取 {executable} 的 SilentProcessExit 配置（{view}）：{ex.Message}");
        }
    }

    private static int ParseInteger(object? value)
    {
        if (value is int integer) return integer;
        if (value is long longValue) return unchecked((int)longValue);
        string text = value?.ToString()?.Trim() ?? string.Empty;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && int.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int hex)) return hex;
        return int.TryParse(text, out int parsed) ? parsed : 0;
    }

    private static bool IsExpectedSteamAutostart(string command, SteamLayout layout)
    {
        foreach (string root in layout.SteamRoots)
        {
            string executable = Path.Combine(root, "steam.exe");
            if (!command.Contains(executable, StringComparison.OrdinalIgnoreCase)) continue;
            string withoutPath = command.Replace($"\"{executable}\"", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace(executable, string.Empty, StringComparison.OrdinalIgnoreCase)
                .Trim();
            if (withoutPath.Length == 0 || withoutPath.Equals("-silent", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static IEnumerable<(RegistryHive Hive, RegistryView View, string Label)> RegistryViews()
    {
        yield return (RegistryHive.CurrentUser, RegistryView.Default, "HKCU");
        yield return (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM");
        yield return (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM");
    }
}

public static class NetworkConfigurationAuditor
{
    public static AuditCheckResult Audit(AuditReport report)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: false);
            bool enabled = Convert.ToInt32(key?.GetValue("ProxyEnable") ?? 0, CultureInfo.InvariantCulture) != 0;
            string server = key?.GetValue("ProxyServer")?.ToString() ?? string.Empty;
            string pac = key?.GetValue("AutoConfigURL")?.ToString() ?? string.Empty;
            if (!enabled && string.IsNullOrWhiteSpace(pac))
            {
                return new AuditCheckResult
                {
                    Id = "network-proxy",
                    Priority = AuditPriority.P1,
                    Area = AuditArea.NetworkConfiguration,
                    Name = "系统代理（仅供参考）",
                    Level = AuditLevel.Passed,
                    Summary = "未启用 WinINET 手动代理或 PAC 地址。",
                    EvidenceCount = 0
                };
            }

            bool local = server.Contains("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                         server.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
                         server.Contains("[::1]", StringComparison.OrdinalIgnoreCase);
            report.Findings.Add(new AuditFinding
            {
                Id = "P1.NETWORK.PROXY_INFO",
                Priority = AuditPriority.P1,
                Level = AuditLevel.Information,
                Area = AuditArea.NetworkConfiguration,
                Title = "系统当前配置了代理",
                WhatFound = enabled ? $"WinINET 手动代理已启用：{server}" : $"配置了 PAC 地址：{pac}",
                Meaning = local
                    ? "本地代理常见于 Clash 等用户主动安装的网络工具，本身不代表异常，也不会影响本工具的风险结论。"
                    : "企业网络、VPN 和调试工具也可能配置代理，仅凭代理存在不能判断为恶意。",
                Recommendation = "如果这是你主动配置的网络工具，无需处理。如果完全不认识该配置，请使用专业杀毒软件检查，并核对系统网络设置。",
                Target = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                Evidence = [new("ProxyEnable", enabled.ToString()), new("ProxyServer", string.IsNullOrWhiteSpace(server) ? "未设置" : server), new("AutoConfigURL", string.IsNullOrWhiteSpace(pac) ? "未设置" : pac)]
            });
            return new AuditCheckResult
            {
                Id = "network-proxy",
                Priority = AuditPriority.P1,
                Area = AuditArea.NetworkConfiguration,
                Name = "系统代理（仅供参考）",
                Level = AuditLevel.Information,
                Summary = local ? "发现本地代理配置，这一项本身不构成风险结论。" : "发现代理/PAC 配置，已客观列出供核对。",
                EvidenceCount = 1
            };
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            report.CoverageNotes.Add($"无法读取当前用户代理配置：{ex.Message}");
            return new AuditCheckResult
            {
                Id = "network-proxy",
                Priority = AuditPriority.P1,
                Area = AuditArea.NetworkConfiguration,
                Name = "系统代理（仅供参考）",
                Level = AuditLevel.Incomplete,
                Summary = "当前用户代理配置无法读取。",
                EvidenceCount = 0
            };
        }
    }
}

public static class WorkshopSourceObserver
{
    public static AuditCheckResult Observe(SteamLayout layout, AuditReport report, CancellationToken cancellationToken)
    {
        List<WallpaperProject> projects = [];
        int errors = 0;
        foreach (string root in layout.WorkshopRoots)
        {
            IEnumerable<string> directories;
            try { directories = Directory.EnumerateDirectories(root).Take(20_000); }
            catch { errors++; continue; }
            foreach (string directory in directories)
            {
                cancellationToken.ThrowIfCancellationRequested();
                projects.Add(SteamLocator.ReadWallpaperProject(directory));
                report.Metrics.WorkshopItemsObserved++;
            }
        }

        List<WallpaperProject> applications = projects
            .Where(item => item.Type?.Equals("application", StringComparison.OrdinalIgnoreCase) == true)
            .OrderByDescending(item => item.LastWriteTime)
            .ToList();
        if (projects.Count > 0)
        {
            List<EvidenceItem> evidence =
            [
                new("Wallpaper Engine 工坊项目", projects.Count.ToString("N0")),
                new("其中应用程序壁纸", applications.Count.ToString("N0"))
            ];
            foreach (WallpaperProject project in projects.OrderByDescending(item => item.LastWriteTime).Take(8))
            {
                evidence.Add(new EvidenceItem(
                    $"近期项目 {project.WorkshopId}",
                    $"{project.LastWriteTime:yyyy-MM-dd HH:mm} · {project.Type ?? "未知类型"} · {project.Title ?? "未命名"}"));
            }
            report.Findings.Add(new AuditFinding
            {
                Id = "P2.WORKSHOP.OBSERVATION",
                Priority = AuditPriority.P2,
                Level = AuditLevel.Information,
                Area = AuditArea.ContentSources,
                Title = "创意工坊内容来源概览",
                WhatFound = $"发现 {projects.Count:N0} 个 Wallpaper Engine 工坊项目，其中 {applications.Count:N0} 个声明为应用程序壁纸。",
                Meaning = "应用程序壁纸可以包含可执行内容，但存在此类内容不等于中毒。本项只帮助定位来源，不参与篡改结论。",
                Recommendation = "若专业杀毒软件报告了具体文件，请根据工坊 ID 核对来源，不要批量删除正常壁纸。",
                Target = layout.WorkshopRoots.FirstOrDefault(),
                Evidence = evidence
            });
        }
        if (errors > 0) report.CoverageNotes.Add($"有 {errors} 个 Wallpaper Engine 工坊目录无法枚举。");

        return new AuditCheckResult
        {
            Id = "content-sources",
            Priority = AuditPriority.P2,
            Area = AuditArea.ContentSources,
            Name = "内容来源（不判毒）",
            Level = projects.Count > 0 ? AuditLevel.Information : errors > 0 ? AuditLevel.Incomplete : AuditLevel.Passed,
            Summary = projects.Count > 0
                ? $"仅列出 {projects.Count:N0} 个项目的类型与近期变更，不读取压缩包、不执行内容。"
                : "未发现 Wallpaper Engine 工坊项目，或当前未安装该内容。",
            EvidenceCount = projects.Count > 0 ? 1 : 0
        };
    }
}
