using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;
using IsMySteamSafe.Core.Utilities;
using Microsoft.Win32;

namespace IsMySteamSafe.Core.Reporting;

public static class EvidenceBundleExporter
{
    private const long MaximumHashFileBytes = 128L * 1024 * 1024;
    private const long MaximumHashTotalBytes = 2L * 1024 * 1024 * 1024;
    private const int MaximumAdditionalFiles = 5000;
    private static readonly string[] ExecutableExtensions = [".exe", ".dll", ".sys", ".ocx", ".scr"];
    private static readonly string[] SmallTextExtensions = [".bat", ".cmd", ".ps1", ".vbs", ".js", ".lua", ".cfg", ".ini", ".txt"];
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task<EvidenceExportResult> ExportAsync(
        AuditReport? audit,
        EvidenceBundleOptions options,
        string outputPath,
        IProgress<EvidenceProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string fullPath = Path.GetFullPath(outputPath);
        string? parent = Path.GetDirectoryName(fullPath);
        if (parent is null) throw new ArgumentException("证据包保存路径无效。", nameof(outputPath));
        Directory.CreateDirectory(parent);
        string partialPath = fullPath + $".partial-{Guid.NewGuid():N}";

        EvidenceBundle bundle = await CollectAsync(audit, options, progress, cancellationToken);
        progress?.Report(new EvidenceProgress(92, "写入证据包", "生成 JSON、Markdown 和 CSV 清单"));
        try
        {
            await using (FileStream stream = new(partialPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            using (ZipArchive archive = new(stream, ZipArchiveMode.Create, leaveOpen: false, Encoding.UTF8))
            {
                WriteText(archive, "README.txt", BuildReadme(bundle));
                WriteText(archive, "manifest.json", JsonSerializer.Serialize(bundle, JsonOptions));
                WriteText(archive, "coverage.csv", CoverageCsv(bundle.Coverage));
                WriteText(archive, "processes.csv", ProcessesCsv(bundle.Processes));
                WriteText(archive, "loaded-modules.csv", ModulesCsv(bundle.Modules));
                WriteText(archive, "tcp-ipv4.csv", ConnectionsCsv(bundle.Connections));
                WriteText(archive, "registry.csv", RegistryCsv(bundle.RegistryValues));
                WriteText(archive, "services.csv", ServicesCsv(bundle.Services));
                WriteText(archive, "scheduled-tasks.csv", TasksCsv(bundle.ScheduledTasks));
                WriteText(archive, "certificates-metadata.csv", CertificatesCsv(bundle.Certificates));
                WriteText(archive, "files.csv", FilesCsv(bundle.Files));
                WriteText(archive, "network-settings.csv", NetworkCsv(bundle.NetworkSettings));
                if (audit is not null) WriteText(archive, "content-sources.txt", string.Join(Environment.NewLine, audit.ContentSources));
                WriteText(archive, "text-snapshots.txt", TextSnapshots(bundle.TextSnapshots));
                if (audit is not null)
                {
                    WriteText(archive, "audit-report.md", ReportExporter.BuildMarkdown(audit));
                    WriteText(archive, "audit-report.json", ReportExporter.BuildJson(audit));
                }
            }

            File.Move(partialPath, fullPath, overwrite: true);
            string sha256 = await FileUtilities.Sha256Async(fullPath, cancellationToken);
            FileInfo info = new(fullPath);
            progress?.Report(new EvidenceProgress(100, "证据提取完成", "证据包已写入，未复制任何二进制样本"));
            return new EvidenceExportResult(fullPath, sha256, info.Length, bundle.BundleId);
        }
        catch
        {
            try
            {
                if (File.Exists(partialPath)) File.Delete(partialPath);
            }
            catch
            {
                // A failed cleanup must not hide the original export error.
            }
            throw;
        }
    }

    public static async Task<EvidenceBundle> CollectAsync(
        AuditReport? audit,
        EvidenceBundleOptions options,
        IProgress<EvidenceProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        SteamLayout layout = SteamLocator.Discover();
        EvidenceBundle bundle = new()
        {
            Audit = audit,
            Environment = BuildEnvironment(layout)
        };
        HashBudget processHashBudget = new(512L * 1024 * 1024);
        HashBudget fileHashBudget = new(MaximumHashTotalBytes);

        progress?.Report(new EvidenceProgress(8, "记录进程", "读取 PID、父 PID、程序路径、签名和相关模块"));
        await CollectProcessesAsync(bundle, layout, processHashBudget, cancellationToken);

        progress?.Report(new EvidenceProgress(24, "记录网络", "通过 Windows API 读取 IPv4 TCP 连接、代理和 DNS 配置"));
        CollectConnections(bundle);
        CollectNetworkSettings(bundle);

        progress?.Report(new EvidenceProgress(38, "记录启动链", "读取 Run/RunOnce、Steam IFEO 与 SilentProcessExit"));
        CollectRegistry(bundle);
        CollectServices(bundle);
        if (options.IncludeRunHistory) CollectRunHistory(bundle);

        progress?.Report(new EvidenceProgress(53, "记录计划任务", "读取任务文件元数据、哈希与动作字段"));
        await CollectScheduledTasksAsync(bundle, fileHashBudget, cancellationToken);

        progress?.Report(new EvidenceProgress(66, "记录证书信息", "仅保存证书元数据，不导出证书或私钥"));
        CollectCertificates(bundle);

        progress?.Report(new EvidenceProgress(76, "记录 Steam 文件", "计算关键客户端文件哈希，不复制文件内容"));
        await CollectSteamFilesAsync(bundle, layout, fileHashBudget, cancellationToken);

        if (options.AdditionalRoots.Count > 0)
        {
            progress?.Report(new EvidenceProgress(84, "记录补充目录", "仅读取用户所选目录的文件元数据并计算哈希"));
            await CollectAdditionalRootsAsync(bundle, options.AdditionalRoots, fileHashBudget, cancellationToken);
        }

        bundle.Coverage.Add(new EvidenceCoverage("样本文件", "未收集", "证据包不会复制 EXE、DLL、压缩包或大型脚本，仅保存路径、元数据、签名、SHA-256 和少量文本配置。"));
        bundle.Coverage.Add(new EvidenceCoverage("隐私", "已脱敏", "默认脱敏用户目录、SteamID、URL 查询参数和常见凭据字段，运行历史仅在勾选时输出信号摘要。分享前仍需自行检查文本。"));
        return bundle;
    }

    private static void CollectRunHistory(EvidenceBundle bundle)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
            int found = 0;
            if (key is not null)
                foreach (string name in key.GetValueNames().Where(name => name.Length == 1).Take(26))
                {
                    IReadOnlyList<string> signals = ScriptSignals.Analyze(key.GetValue(name)?.ToString() ?? "");
                    if (signals.Count == 0) continue;
                    found++;
                    bundle.Coverage.Add(new EvidenceCoverage("运行历史 " + name, "可疑信号", string.Join("，", signals)));
                }
            bundle.Coverage.Add(new EvidenceCoverage("运行历史", "有限检查", $"发现 {found} 条可疑执行链摘要，未输出完整命令，缺失记录不能证明未执行。"));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        { bundle.Coverage.Add(new EvidenceCoverage("运行历史", "未完成", "无法读取当前用户记录。")); }
    }

    private static EvidenceEnvironment BuildEnvironment(SteamLayout layout)
    {
        string machineSeed = Environment.MachineName;
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", writable: false);
            machineSeed += "|" + (key?.GetValue("MachineGuid")?.ToString() ?? string.Empty);
        }
        catch
        {
            // The machine name still gives this local bundle a stable-enough pseudonymous correlation value.
        }

        string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(machineSeed))).ToLowerInvariant()[..16];
        bool isAdministrator = false;
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            isAdministrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            // Report false rather than assuming elevated coverage.
        }

        return new EvidenceEnvironment(
            fingerprint,
            RuntimeInformation.OSDescription,
            RuntimeInformation.OSArchitecture.ToString(),
            RuntimeInformation.ProcessArchitecture.ToString(),
            RuntimeInformation.FrameworkDescription,
            isAdministrator,
            CultureInfo.CurrentCulture.Name,
            TimeZoneInfo.Local.Id,
            layout.SteamRoots,
            layout.LibraryRoots,
            layout.WorkshopRoots,
            layout.WallpaperProjectRoots);
    }

    private static async Task CollectProcessesAsync(
        EvidenceBundle bundle,
        SteamLayout layout,
        HashBudget hashBudget,
        CancellationToken cancellationToken)
    {
        Dictionary<int, int> parentPids = NativeMethods.GetParentProcessIds(out string? parentError);
        if (parentError is not null) bundle.Coverage.Add(new EvidenceCoverage("进程树", "部分完成", parentError));
        int pathFailures = 0;
        int moduleFailures = 0;
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string temp = Path.GetTempPath();
        Dictionary<string, SignatureResult> signatureCache = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string?> hashCache = new(StringComparer.OrdinalIgnoreCase);

        foreach (Process process in Process.GetProcesses().OrderBy(item => item.Id).Take(4096))
        {
            using (process)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string name;
                try { name = process.ProcessName; }
                catch { name = "<unavailable>"; }

                string? path = null;
                DateTimeOffset? startTime = null;
                string? readError = null;
                try { path = process.MainModule?.FileName; }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    pathFailures++;
                    readError = ex.Message;
                }
                try { startTime = process.StartTime; }
                catch { }

                SignatureResult signature = path is not null && File.Exists(path)
                    ? GetSignature(path, signatureCache)
                    : new SignatureResult(SignatureStatus.Error, "路径不可读，未校验签名。", null, false);
                bool userWritable = path is not null && (FileUtilities.IsWithin(path, profile) || FileUtilities.IsWithin(path, temp));
                bool wallpaperContentProcess = SteamPathClassifier.IsSteamContentPath(layout, path) ||
                    path is not null && layout.Games.Any(game => ContentDiscovery.IsWithin(path, game.Directory));
                bool steamProcess = name.Equals("steam", StringComparison.OrdinalIgnoreCase) ||
                                    name.Equals("steamwebhelper", StringComparison.OrdinalIgnoreCase);
                string? hash = null;
                if (path is not null && (userWritable || steamProcess || wallpaperContentProcess))
                    hash = await GetHashAsync(path, hashBudget, hashCache, cancellationToken);

                bundle.Processes.Add(new EvidenceProcess(
                    process.Id,
                    parentPids.TryGetValue(process.Id, out int parent) ? parent : null,
                    name,
                    path,
                    startTime,
                    hash,
                    signature.Detail,
                    signature.Subject,
                    readError));

                bool collectModules = steamProcess || userWritable ||
                                      wallpaperContentProcess ||
                                      (path is not null && layout.SteamRoots.Any(root => FileUtilities.IsWithin(path, root)));
                if (!collectModules) continue;
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string modulePath = module.FileName;
                        bool relevantModule = steamProcess ||
                                              FileUtilities.IsWithin(modulePath, profile) ||
                                              layout.SteamRoots.Any(root => FileUtilities.IsWithin(modulePath, root)) ||
                                              SteamPathClassifier.IsSteamContentPath(layout, modulePath);
                        if (!relevantModule) continue;
                        SignatureResult moduleSignature = GetSignature(modulePath, signatureCache);
                        string? moduleHash = await GetHashAsync(modulePath, hashBudget, hashCache, cancellationToken);
                        bundle.Modules.Add(new EvidenceModule(process.Id, name, modulePath, moduleHash, moduleSignature.Detail, moduleSignature.Subject));
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    moduleFailures++;
                    bundle.Coverage.Add(new EvidenceCoverage("进程模块", "部分完成", $"无法读取 {name} (PID {process.Id}) 的模块：{ex.Message}"));
                }
            }
        }

        bundle.Coverage.Add(new EvidenceCoverage("进程列表", pathFailures == 0 ? "完整" : "部分完成", $"记录 {bundle.Processes.Count} 个进程，{pathFailures} 个进程路径无法读取。"));
        bundle.Coverage.Add(new EvidenceCoverage("相关进程模块", moduleFailures == 0 ? "完整" : "部分完成", $"记录 {bundle.Modules.Count} 个与 Steam、Wallpaper 内容或用户目录相关的模块，{moduleFailures} 个进程无法读取模块。"));
        bundle.Coverage.Add(new EvidenceCoverage("进程命令行", "未收集", "普通权限下不会使用 WMI 或命令行工具，本版记录 PID、父 PID、程序路径、签名和哈希。"));
    }

    private static void CollectConnections(EvidenceBundle bundle)
    {
        try
        {
            Dictionary<int, string> names = bundle.Processes.ToDictionary(item => item.ProcessId, item => item.Name);
            foreach (NativeMethods.TcpRow row in NativeMethods.GetTcp4Rows())
            {
                bundle.Connections.Add(new EvidenceConnection(
                    row.ProcessId,
                    names.GetValueOrDefault(row.ProcessId, "<exited-or-unavailable>"),
                    row.State,
                    row.LocalAddress,
                    row.LocalPort,
                    row.RemoteAddress,
                    row.RemotePort));
            }
            bundle.Coverage.Add(new EvidenceCoverage("TCP 连接", "部分完成", $"通过 GetExtendedTcpTable 记录 {bundle.Connections.Count} 条 IPv4 TCP 状态，本版暂不包含 IPv6 和已关闭的历史连接。"));
        }
        catch (Exception ex)
        {
            bundle.Coverage.Add(new EvidenceCoverage("TCP 连接", "不可用", ex.Message));
        }
    }

    private static void CollectNetworkSettings(EvidenceBundle bundle)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: false);
            foreach (string name in new[] { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect" })
                bundle.NetworkSettings.Add(new EvidenceNetworkSetting("WinINET", name, RegistryValueText(key?.GetValue(name))));
            bundle.Coverage.Add(new EvidenceCoverage("WinINET 代理", "完整", "已读取当前用户代理、PAC 和自动检测字段。"));
        }
        catch (Exception ex)
        {
            bundle.Coverage.Add(new EvidenceCoverage("WinINET 代理", "不可用", ex.Message));
        }

        if (NativeMethods.TryGetWinHttpProxy(out string winHttp, out string? winHttpError))
        {
            bundle.NetworkSettings.Add(new EvidenceNetworkSetting("WinHTTP", "DefaultProxy", winHttp));
            bundle.Coverage.Add(new EvidenceCoverage("WinHTTP 代理", "完整", "已通过 WinHTTP API 读取机器默认代理。"));
        }
        else
        {
            bundle.Coverage.Add(new EvidenceCoverage("WinHTTP 代理", "不可用", winHttpError ?? "未知错误"));
        }

        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                IPInterfaceProperties properties = adapter.GetIPProperties();
                foreach (IPAddress address in properties.DnsAddresses)
                    bundle.NetworkSettings.Add(new EvidenceNetworkSetting("DNS", adapter.Name, address.ToString()));
            }
            bundle.Coverage.Add(new EvidenceCoverage("DNS 配置", "完整", "已读取各网络适配器当前 DNS 地址。"));
        }
        catch (Exception ex)
        {
            bundle.Coverage.Add(new EvidenceCoverage("DNS 配置", "不可用", ex.Message));
        }

        string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        try
        {
            string text = File.ReadAllText(hosts);
            string activeLines = string.Join(Environment.NewLine, text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith('#')));
            bundle.TextSnapshots.Add(new EvidenceTextSnapshot("hosts 非注释行", hosts, activeLines, false));
            bundle.NetworkSettings.Add(new EvidenceNetworkSetting("hosts", "SHA-256", Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(hosts))).ToLowerInvariant()));
            bundle.Coverage.Add(new EvidenceCoverage("hosts", "完整", "已记录文件哈希与非注释行。"));
        }
        catch (Exception ex)
        {
            bundle.Coverage.Add(new EvidenceCoverage("hosts", "不可用", ex.Message));
        }
    }

    private static void CollectRegistry(EvidenceBundle bundle)
    {
        foreach ((RegistryHive hive, RegistryView view, string label) in new[]
        {
            (RegistryHive.CurrentUser, RegistryView.Default, "HKCU"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM")
        })
        {
            CollectRegistryKey(bundle, hive, view, label, @"Software\Microsoft\Windows\CurrentVersion\Run");
            CollectRegistryKey(bundle, hive, view, label, @"Software\Microsoft\Windows\CurrentVersion\RunOnce");
        }

        foreach (RegistryView view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
        {
            foreach (string executable in new[] { "steam.exe", "steamwebhelper.exe", "steamservice.exe" })
            {
                CollectRegistryKey(bundle, RegistryHive.LocalMachine, view, "HKLM", $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{executable}");
                CollectRegistryKey(bundle, RegistryHive.LocalMachine, view, "HKLM", $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{executable}");
            }
        }
        bundle.Coverage.Add(new EvidenceCoverage("注册表启动链", "部分完成", $"记录 {bundle.RegistryValues.Count} 个目标值，覆盖 Run/RunOnce 和三个 Steam 进程的 IFEO/SilentProcessExit 配置。"));
    }

    private static void CollectRegistryKey(EvidenceBundle bundle, RegistryHive hive, RegistryView view, string label, string keyPath)
    {
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(keyPath, writable: false);
            if (key is null) return;
            foreach (string valueName in key.GetValueNames())
            {
                object? value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                bundle.RegistryValues.Add(new EvidenceRegistryValue(label, view.ToString(), keyPath, valueName, key.GetValueKind(valueName).ToString(), RegistryValueText(value)));
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            bundle.Coverage.Add(new EvidenceCoverage("注册表", "部分完成", $"无法读取 {label}\\{keyPath} ({view})：{ex.Message}"));
        }
    }

    private static void CollectServices(EvidenceBundle bundle)
    {
        const string serviceRoot = @"SYSTEM\CurrentControlSet\Services";
        int errors = 0;
        try
        {
            using RegistryKey? root = Registry.LocalMachine.OpenSubKey(serviceRoot, writable: false);
            if (root is null) throw new IOException("服务注册表根不存在。");
            foreach (string serviceName in root.GetSubKeyNames().Take(10000))
            {
                try
                {
                    using RegistryKey? key = root.OpenSubKey(serviceName, writable: false);
                    using RegistryKey? parameters = key?.OpenSubKey("Parameters", writable: false);
                    bundle.Services.Add(new EvidenceService(
                        serviceName,
                        RegistryValueText(key?.GetValue("DisplayName")),
                        RegistryValueText(key?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)),
                        RegistryValueText(parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames)),
                        RegistryValueText(key?.GetValue("Start")),
                        RegistryValueText(key?.GetValue("Type"))));
                }
                catch { errors++; }
            }
            bundle.Coverage.Add(new EvidenceCoverage("服务", errors == 0 ? "完整" : "部分完成", $"从注册表记录 {bundle.Services.Count} 个服务，{errors} 个子项无法读取。"));
        }
        catch (Exception ex)
        {
            bundle.Coverage.Add(new EvidenceCoverage("服务", "不可用", ex.Message));
        }
    }

    private static async Task CollectScheduledTasksAsync(EvidenceBundle bundle, HashBudget hashBudget, CancellationToken cancellationToken)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        int errors = 0;
        foreach (string path in EnumerateFilesSafe(root, 10000, () => errors++))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                FileInfo info = new(path);
                string? hash = await TryHashAsync(path, hashBudget, cancellationToken);
                string? command = null;
                string? arguments = null;
                string? readError = null;
                try
                {
                    if (info.Length <= 2 * 1024 * 1024)
                    {
                        XDocument document = XDocument.Parse(await File.ReadAllTextAsync(path, cancellationToken));
                        command = string.Join(" | ", document.Descendants().Where(item => item.Name.LocalName == "Command").Select(item => item.Value));
                        arguments = string.Join(" | ", document.Descendants().Where(item => item.Name.LocalName == "Arguments").Select(item => item.Value));
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
                {
                    readError = ex.Message;
                }
                bundle.ScheduledTasks.Add(new EvidenceTask(Path.GetRelativePath(root, path), info.Length, info.LastWriteTimeUtc, hash, command, arguments, readError));
            }
            catch { errors++; }
        }
        bundle.Coverage.Add(new EvidenceCoverage("计划任务", errors == 0 ? "完整" : "部分完成", $"记录 {bundle.ScheduledTasks.Count} 个任务文件，{errors} 个目录或文件无法读取。"));
    }

    private static void CollectCertificates(EvidenceBundle bundle)
    {
        int errors = 0;
        foreach (StoreLocation location in Enum.GetValues<StoreLocation>())
        {
            foreach (StoreName storeName in new[] { StoreName.Root, StoreName.CertificateAuthority, StoreName.TrustedPublisher, StoreName.My })
            {
                try
                {
                    using X509Store store = new(storeName, location);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    foreach (X509Certificate2 certificate in store.Certificates)
                    {
                        bundle.Certificates.Add(new EvidenceCertificate(
                            location.ToString(),
                            storeName.ToString(),
                            certificate.Thumbprint ?? string.Empty,
                            certificate.Subject,
                            certificate.Issuer,
                            certificate.NotBefore,
                            certificate.NotAfter,
                            certificate.SerialNumber,
                            certificate.SignatureAlgorithm?.FriendlyName ?? certificate.SignatureAlgorithm?.Value ?? string.Empty));
                    }
                }
                catch { errors++; }
            }
        }
        bundle.Coverage.Add(new EvidenceCoverage("证书元数据", errors == 0 ? "完整" : "部分完成", $"记录 {bundle.Certificates.Count} 张证书的主题、颁发者、指纹和有效期，未导出证书或私钥。另有 {errors} 个证书存储区无法读取。"));
    }

    private static async Task CollectSteamFilesAsync(EvidenceBundle bundle, SteamLayout layout, HashBudget hashBudget, CancellationToken cancellationToken)
    {
        HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase);
        foreach (string root in layout.SteamRoots)
        {
            paths.Add(Path.Combine(root, "steam.exe"));
            paths.Add(Path.Combine(root, "steam.cfg"));
            foreach (string scriptsRoot in new[] { Path.Combine(root, "steamui"), Path.Combine(root, "clientui") })
            {
                foreach (string path in EnumerateFilesSafe(scriptsRoot, 2500, null).Where(path => Path.GetExtension(path).Equals(".js", StringComparison.OrdinalIgnoreCase)))
                    paths.Add(path);
            }
            foreach (string directory in SteamClientFileAuditor.GetSensitiveDirectories(root))
            {
                try
                {
                    foreach (string path in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
                    {
                        string name = Path.GetFileName(path);
                        if (name.Equals("version.dll", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("versionOrg.dll", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("wsock32.dll", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("msacm32.drv", StringComparison.OrdinalIgnoreCase)) paths.Add(path);
                    }
                }
                catch { }
            }
        }

        int failures = 0;
        foreach (string path in paths.Where(File.Exists).Take(6000))
        {
            cancellationToken.ThrowIfCancellationRequested();
            EvidenceFile evidence = await DescribeFileAsync("Steam", path, hashBudget, cancellationToken);
            bundle.Files.Add(evidence);
            if (evidence.ReadError is not null) failures++;
            if (Path.GetFileName(path).Equals("steam.cfg", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string text = await FileUtilities.ReadTextBoundedAsync(path, 1024 * 1024, cancellationToken);
                    bundle.TextSnapshots.Add(new EvidenceTextSnapshot("Steam 配置", path, text, false));
                }
                catch (Exception ex)
                {
                    bundle.Coverage.Add(new EvidenceCoverage("steam.cfg 内容", "不可用", $"{path}：{ex.Message}"));
                }
            }
        }
        bundle.Coverage.Add(new EvidenceCoverage("Steam 关键文件", failures == 0 ? "完整" : "部分完成", $"记录 {bundle.Files.Count(item => item.Source == "Steam")} 个 Steam 主程序、配置、前端脚本和侧载敏感文件，未复制文件。"));
    }

    private static async Task CollectAdditionalRootsAsync(
        EvidenceBundle bundle,
        IReadOnlyList<string> roots,
        HashBudget hashBudget,
        CancellationToken cancellationToken)
    {
        int count = 0;
        int errors = 0;
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (string rootValue in roots)
        {
            string root;
            try { root = Path.GetFullPath(rootValue); }
            catch { errors++; continue; }
            if (!Directory.Exists(root)) { errors++; continue; }
            foreach (string path in EnumerateFilesSafe(root, MaximumAdditionalFiles - count, () => errors++))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (count >= MaximumAdditionalFiles || !seen.Add(path)) break;
                count++;
                EvidenceFile evidence = await DescribeFileAsync("用户选择目录", path, hashBudget, cancellationToken);
                bundle.Files.Add(evidence);
                if (evidence.ReadError is not null) errors++;

                string extension = Path.GetExtension(path);
                if (!SmallTextExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase)) continue;
                try
                {
                    FileInfo info = new(path);
                    if (info.Length > 256 * 1024) continue;
                    string text = await FileUtilities.ReadTextBoundedAsync(path, 256 * 1024, cancellationToken);
                    bundle.TextSnapshots.Add(new EvidenceTextSnapshot("用户选择的小型文本/脚本", path, text, false));
                }
                catch { }
            }
            if (count >= MaximumAdditionalFiles) break;
        }
        bundle.Coverage.Add(new EvidenceCoverage("补充目录", errors == 0 ? "完整" : "部分完成", $"记录 {count} 个文件，上限为 {MaximumAdditionalFiles} 个。大型文件仅保留元数据，不超过 {MaximumHashFileBytes / 1024 / 1024} MiB 的文件才会计算哈希。"));
    }

    private static async Task<EvidenceFile> DescribeFileAsync(string source, string path, HashBudget hashBudget, CancellationToken cancellationToken)
    {
        try
        {
            FileInfo info = new(path);
            string? hash = await TryHashAsync(path, hashBudget, cancellationToken);
            SignatureResult signature = ExecutableExtensions.Contains(info.Extension, StringComparer.OrdinalIgnoreCase)
                ? AuthenticodeVerifier.Verify(path)
                : new SignatureResult(SignatureStatus.Error, "非 PE 文件，未检查 Authenticode。", null, false);
            return new EvidenceFile(source, path, info.Length, info.CreationTimeUtc, info.LastWriteTimeUtc, hash, signature.Detail, signature.Subject, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new EvidenceFile(source, path, 0, DateTimeOffset.MinValue, DateTimeOffset.MinValue, null, "未检查", null, ex.Message);
        }
    }

    private static async Task<string?> TryHashAsync(string path, HashBudget budget, CancellationToken cancellationToken)
    {
        try
        {
            FileInfo info = new(path);
            if (info.Length > MaximumHashFileBytes || !budget.TryReserve(info.Length)) return null;
            return await FileUtilities.Sha256Async(path, cancellationToken);
        }
        catch
        {
            return null;
        }
    }

    private static SignatureResult GetSignature(string path, IDictionary<string, SignatureResult> cache)
    {
        if (cache.TryGetValue(path, out SignatureResult? result)) return result;
        result = AuthenticodeVerifier.Verify(path);
        cache[path] = result;
        return result;
    }

    private static async Task<string?> GetHashAsync(
        string path,
        HashBudget budget,
        IDictionary<string, string?> cache,
        CancellationToken cancellationToken)
    {
        if (cache.TryGetValue(path, out string? hash)) return hash;
        hash = await TryHashAsync(path, budget, cancellationToken);
        cache[path] = hash;
        return hash;
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, int maximum, Action? onError)
    {
        if (maximum <= 0 || !Directory.Exists(root)) yield break;
        Stack<string> pending = new();
        pending.Push(root);
        int yielded = 0;
        while (pending.Count > 0 && yielded < maximum)
        {
            string directory = pending.Pop();
            string[] files;
            try { files = Directory.GetFiles(directory); }
            catch { onError?.Invoke(); continue; }
            foreach (string file in files)
            {
                yield return file;
                yielded++;
                if (yielded >= maximum) yield break;
            }

            string[] children;
            try { children = Directory.GetDirectories(directory); }
            catch { onError?.Invoke(); continue; }
            foreach (string child in children.Reverse())
            {
                try
                {
                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) pending.Push(child);
                }
                catch { onError?.Invoke(); }
            }
        }
    }

    private static string BuildReadme(EvidenceBundle bundle) => $"""
        我的 Steam 安全吗？ v{ProductInfo.Version} 证据包

        证据包编号：{bundle.BundleId:N}
        收集时间：{bundle.CollectedAt:O}

        此 ZIP 仅包含 JSON、Markdown、CSV 和 TXT 清单，不包含原始 EXE、DLL、压缩包、证书或私钥，也不会执行发现的文件。
        默认脱敏：当前用户目录、17 位 SteamID、URL 中的 u= 和 d= 参数。
        注意：进程和网络连接是瞬时快照，已退出的进程和已关闭的连接无法追溯。权限不足的项目会写入 coverage.csv，不会标记为“已检查”。
        分享前，请检查 text-snapshots.txt、registry.csv 和 scheduled-tasks.csv 中是否包含不希望公开的信息。
        """;

    private static void WriteText(ZipArchive archive, string name, string content)
    {
        ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using StreamWriter writer = new(entry.Open(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        writer.Write(name.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? JsonRedaction.Redact(content) : FileUtilities.RedactSensitiveText(content));
    }

    private static string CsvRow(params object?[] values) => string.Join(',', values.Select(value =>
    {
        string text = Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
        return $"\"{text.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }));

    private static string CoverageCsv(IEnumerable<EvidenceCoverage> values) => Csv(
        CsvRow("area", "status", "detail"),
        values.Select(item => CsvRow(item.Area, item.Status, item.Detail)));
    private static string ProcessesCsv(IEnumerable<EvidenceProcess> values) => Csv(
        CsvRow("pid", "parentPid", "name", "path", "startTime", "sha256", "signature", "signer", "readError"),
        values.Select(item => CsvRow(item.ProcessId, item.ParentProcessId, item.Name, item.Path, item.StartTime?.ToString("O"), item.Sha256, item.Signature, item.Signer, item.ReadError)));
    private static string ModulesCsv(IEnumerable<EvidenceModule> values) => Csv(
        CsvRow("pid", "process", "path", "sha256", "signature", "signer"),
        values.Select(item => CsvRow(item.ProcessId, item.ProcessName, item.Path, item.Sha256, item.Signature, item.Signer)));
    private static string ConnectionsCsv(IEnumerable<EvidenceConnection> values) => Csv(
        CsvRow("pid", "process", "state", "localAddress", "localPort", "remoteAddress", "remotePort"),
        values.Select(item => CsvRow(item.ProcessId, item.ProcessName, item.State, item.LocalAddress, item.LocalPort, item.RemoteAddress, item.RemotePort)));
    private static string RegistryCsv(IEnumerable<EvidenceRegistryValue> values) => Csv(
        CsvRow("hive", "view", "key", "name", "kind", "value"),
        values.Select(item => CsvRow(item.Hive, item.View, item.Key, item.Name, item.Kind, item.Value)));
    private static string ServicesCsv(IEnumerable<EvidenceService> values) => Csv(
        CsvRow("name", "displayName", "imagePath", "serviceDll", "start", "type"),
        values.Select(item => CsvRow(item.Name, item.DisplayName, item.ImagePath, item.ServiceDll, item.Start, item.Type)));
    private static string TasksCsv(IEnumerable<EvidenceTask> values) => Csv(
        CsvRow("relativePath", "size", "lastWriteTime", "sha256", "command", "arguments", "readError"),
        values.Select(item => CsvRow(item.RelativePath, item.Size, item.LastWriteTime.ToString("O"), item.Sha256, item.Command, item.Arguments, item.ReadError)));
    private static string CertificatesCsv(IEnumerable<EvidenceCertificate> values) => Csv(
        CsvRow("location", "store", "thumbprint", "subject", "issuer", "notBefore", "notAfter", "serialNumber", "signatureAlgorithm"),
        values.Select(item => CsvRow(item.Location, item.Store, item.Thumbprint, item.Subject, item.Issuer, item.NotBefore.ToString("O"), item.NotAfter.ToString("O"), item.SerialNumber, item.SignatureAlgorithm)));
    private static string FilesCsv(IEnumerable<EvidenceFile> values) => Csv(
        CsvRow("source", "path", "size", "creationTime", "lastWriteTime", "sha256", "signature", "signer", "readError"),
        values.Select(item => CsvRow(item.Source, item.Path, item.Size, item.CreationTime.ToString("O"), item.LastWriteTime.ToString("O"), item.Sha256, item.Signature, item.Signer, item.ReadError)));
    private static string NetworkCsv(IEnumerable<EvidenceNetworkSetting> values) => Csv(
        CsvRow("area", "name", "value"),
        values.Select(item => CsvRow(item.Area, item.Name, item.Value)));

    private static string Csv(string header, IEnumerable<string> rows) => header + Environment.NewLine + string.Join(Environment.NewLine, rows);

    private static string TextSnapshots(IEnumerable<EvidenceTextSnapshot> snapshots)
    {
        StringBuilder text = new();
        foreach (EvidenceTextSnapshot snapshot in snapshots)
        {
            text.AppendLine($"===== {snapshot.Kind} · {snapshot.Path} · truncated={snapshot.Truncated} =====");
            text.AppendLine(snapshot.Content);
            text.AppendLine();
        }
        return text.ToString();
    }

    private static string RegistryValueText(object? value) => value switch
    {
        null => string.Empty,
        string[] strings => string.Join(" | ", strings),
        byte[] bytes => $"<binary length={bytes.Length} sha256={Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}>",
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
    };

    private sealed class HashBudget(long remaining)
    {
        private long _remaining = remaining;

        public bool TryReserve(long bytes)
        {
            if (bytes < 0 || bytes > _remaining) return false;
            _remaining -= bytes;
            return true;
        }
    }

    private static class NativeMethods
    {
        private const uint Th32csSnapProcess = 0x00000002;
        private const int AfInet = 2;
        private const int ErrorInsufficientBuffer = 122;
        private const int TcpTableOwnerPidAll = 5;

        public sealed record TcpRow(int ProcessId, string State, string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort);

        public static Dictionary<int, int> GetParentProcessIds(out string? error)
        {
            Dictionary<int, int> result = [];
            error = null;
            IntPtr snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
            if (snapshot == new IntPtr(-1))
            {
                error = $"CreateToolhelp32Snapshot 失败：{Marshal.GetLastWin32Error()}";
                return result;
            }
            try
            {
                ProcessEntry32 entry = new() { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
                if (!Process32First(snapshot, ref entry))
                {
                    error = $"Process32First 失败：{Marshal.GetLastWin32Error()}";
                    return result;
                }
                do
                {
                    result[(int)entry.ProcessId] = (int)entry.ParentProcessId;
                    entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
                } while (Process32Next(snapshot, ref entry));
                return result;
            }
            finally
            {
                CloseHandle(snapshot);
            }
        }

        public static IReadOnlyList<TcpRow> GetTcp4Rows()
        {
            int size = 0;
            int result = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
            if (result != ErrorInsufficientBuffer && result != 0) throw new System.ComponentModel.Win32Exception(result);
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
                if (result != 0) throw new System.ComponentModel.Win32Exception(result);
                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                List<TcpRow> rows = new(count);
                for (int i = 0; i < count; i++)
                {
                    IntPtr pointer = IntPtr.Add(buffer, sizeof(int) + i * rowSize);
                    MibTcpRowOwnerPid row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(pointer);
                    rows.Add(new TcpRow(
                        (int)row.OwningPid,
                        ((MibTcpState)row.State).ToString(),
                        new IPAddress(row.LocalAddress).ToString(),
                        NetworkPort(row.LocalPort),
                        new IPAddress(row.RemoteAddress).ToString(),
                        NetworkPort(row.RemotePort)));
                }
                return rows;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static bool TryGetWinHttpProxy(out string value, out string? error)
        {
            value = string.Empty;
            error = null;
            if (!WinHttpGetDefaultProxyConfiguration(out WinHttpProxyInfo info))
            {
                error = $"WinHttpGetDefaultProxyConfiguration 失败：{Marshal.GetLastWin32Error()}";
                return false;
            }
            try
            {
                string proxy = Marshal.PtrToStringUni(info.Proxy) ?? string.Empty;
                string bypass = Marshal.PtrToStringUni(info.ProxyBypass) ?? string.Empty;
                value = $"AccessType={info.AccessType}; Proxy={proxy}; Bypass={bypass}";
                return true;
            }
            finally
            {
                if (info.Proxy != IntPtr.Zero) GlobalFree(info.Proxy);
                if (info.ProxyBypass != IntPtr.Zero) GlobalFree(info.ProxyBypass);
            }
        }

        private static int NetworkPort(uint value) => (int)(((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8));

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);

        [DllImport("winhttp.dll", SetLastError = true)]
        private static extern bool WinHttpGetDefaultProxyConfiguration(out WinHttpProxyInfo proxyInfo);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalFree(IntPtr memory);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProcessEntry32
        {
            public uint Size;
            public uint Usage;
            public uint ProcessId;
            public IntPtr DefaultHeapId;
            public uint ModuleId;
            public uint Threads;
            public uint ParentProcessId;
            public int BasePriority;
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExecutableFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MibTcpRowOwnerPid
        {
            public uint State;
            public uint LocalAddress;
            public uint LocalPort;
            public uint RemoteAddress;
            public uint RemotePort;
            public uint OwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WinHttpProxyInfo
        {
            public uint AccessType;
            public IntPtr Proxy;
            public IntPtr ProxyBypass;
        }

        private enum MibTcpState : uint
        {
            Closed = 1,
            Listen = 2,
            SynSent = 3,
            SynReceived = 4,
            Established = 5,
            FinWait1 = 6,
            FinWait2 = 7,
            CloseWait = 8,
            Closing = 9,
            LastAck = 10,
            TimeWait = 11,
            DeleteTcb = 12
        }
    }
}
