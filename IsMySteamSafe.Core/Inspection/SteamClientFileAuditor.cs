using System.Diagnostics;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.Core.Inspection;

public static class SteamClientFileAuditor
{
    private static readonly string[] CandidateNames =
    [
        "version.dll",
        "versionOrg.dll",
        "msacm32.drv",
        "wsock32.dll"
    ];

    public static async Task<AuditCheckResult> AuditAsync(
        string steamRoot,
        SteamAuditOptions options,
        AuditReport report,
        CancellationToken cancellationToken)
    {
        List<string> directories = GetSensitiveDirectories(steamRoot);
        report.Metrics.SensitiveDirectoriesChecked += directories.Count;
        HashSet<string> handled = new(StringComparer.OrdinalIgnoreCase);
        int findingsBefore = report.Findings.Count;
        DateTime? steamAnchor = TryGetSteamAnchor(steamRoot);

        foreach (string directory in directories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string versionPath = Path.Combine(directory, "version.dll");
            string originalPath = Path.Combine(directory, "versionOrg.dll");
            if (File.Exists(originalPath))
            {
                List<EvidenceItem> evidence = [];
                if (File.Exists(versionPath))
                {
                    evidence.Add(new EvidenceItem("文件对", "version.dll + versionOrg.dll"));
                    handled.Add(versionPath);
                }
                else
                {
                    evidence.Add(new EvidenceItem("异常文件", "versionOrg.dll（未见同目录 version.dll）"));
                }

                handled.Add(originalPath);
                evidence.AddRange(await DescribeFilesAsync([versionPath, originalPath], steamAnchor, cancellationToken));
                report.Findings.Add(new AuditFinding
                {
                    Id = "P0.DLL.VERSION_FORWARDER",
                    Priority = AuditPriority.P0,
                    Level = AuditLevel.ConfirmedTampering,
                    Area = AuditArea.ClientFiles,
                    Title = "发现 versionOrg.dll 转发结构",
                    WhatFound = File.Exists(versionPath)
                        ? "Steam 客户端敏感目录内同时存在 version.dll 与 versionOrg.dll。"
                        : "Steam 客户端敏感目录内出现正常安装不应包含的 versionOrg.dll。",
                    Meaning = "这是常见的 DLL 侧载或转发结构，说明 Steam 客户端目录已被改动，但本工具不会据此判断具体病毒。",
                    Recommendation = "请立即停止付款或登录，断开网络，并使用已更新的专业杀毒软件做全盘扫描。确认查杀完成后，再从 Steam 官网重装客户端。本工具不会直接删除证据。",
                    Target = directory,
                    Evidence = evidence
                });
            }

            foreach (string name in CandidateNames)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string path = Path.Combine(directory, name);
                if (!File.Exists(path) || handled.Contains(path)) continue;
                report.Metrics.CandidateFilesChecked++;

                SignatureResult signature = AuthenticodeVerifier.Verify(path);
                string lowerName = name.ToLowerInvariant();
                bool cefLocation = directory.Contains($"{Path.DirectorySeparatorChar}cef", StringComparison.OrdinalIgnoreCase);
                bool millenniumPresent = Directory.Exists(Path.Combine(steamRoot, "millennium"));
                bool userModContext = options.UserAcknowledgesClientMods && lowerName == "wsock32.dll" && millenniumPresent;

                AuditLevel level;
                string title;
                if ((lowerName is "version.dll" or "msacm32.drv") && cefLocation && !signature.IsValveSigner)
                {
                    level = AuditLevel.HighlySuspicious;
                    title = $"CEF 目录出现非 Valve 的 {name}";
                }
                else if (!signature.IsValveSigner)
                {
                    level = userModContext ? AuditLevel.NeedsReview : AuditLevel.HighlySuspicious;
                    title = userModContext ? $"发现已声明的客户端注入组件 {name}" : $"Steam 客户端目录出现非 Valve 的 {name}";
                }
                else
                {
                    level = AuditLevel.NeedsReview;
                    title = $"Steam 敏感目录出现额外的 {name}";
                }

                FileInfo info = new(path);
                FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
                List<EvidenceItem> evidence =
                [
                    new("路径", path),
                    new("签名", signature.Detail),
                    new("签名者", signature.Subject ?? "无"),
                    new("公司名", string.IsNullOrWhiteSpace(version.CompanyName) ? "未提供" : version.CompanyName),
                    new("修改时间", info.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss zzz")),
                    new("SHA-256", await FileUtilities.Sha256Async(path, cancellationToken))
                ];
                if (steamAnchor is not null)
                {
                    evidence.Add(new EvidenceItem("相对 Steam 主程序时间", info.LastWriteTime > steamAnchor.Value.AddMinutes(2) ? "晚于 steam.exe（辅助证据）" : "未明显晚于 steam.exe"));
                }
                if (millenniumPresent) evidence.Add(new EvidenceItem("客户端扩展", "检测到 Millennium 目录，合法安装与恶意插件都可能使用这一加载位置。"));

                report.Findings.Add(new AuditFinding
                {
                    Id = $"P0.DLL.{lowerName.ToUpperInvariant()}",
                    Priority = AuditPriority.P0,
                    Level = level,
                    Area = AuditArea.ClientFiles,
                    Title = title,
                    WhatFound = $"在 Steam 客户端敏感目录发现 {name}，其签名状态为“{signature.Detail}”。",
                    Meaning = userModContext
                        ? "你已声明主动安装客户端插件，因此这里只标记为需要核对，合法加载器也可能承载来历不明的插件。"
                        : "这类名称可被 Windows DLL 搜索顺序用于侧载。游戏目录中的同名 MOD 不在本检查范围，只有 Steam 客户端目录会触发提示。",
                    Recommendation = userModContext
                        ? "请核对该组件是否来自你亲自安装的官方项目，并检查插件列表。无法确认时，请交给专业杀毒软件扫描。"
                        : "不要双击或移动该文件，请将路径与 SHA-256 交给专业杀毒软件复核，并优先按完整处理步骤排查。",
                    Target = path,
                    Evidence = evidence
                });
            }
        }

        int count = report.Findings.Count - findingsBefore;
        AuditLevel resultLevel = count == 0
            ? AuditLevel.Passed
            : report.Findings.Skip(findingsBefore).OrderByDescending(item => AuditLabels.RiskRank(item.Level)).First().Level;
        return new AuditCheckResult
        {
            Id = "client-files",
            Priority = AuditPriority.P0,
            Area = AuditArea.ClientFiles,
            Name = "客户端 DLL 侧载",
            Level = resultLevel,
            Summary = count == 0 ? $"已检查 {directories.Count} 个 Steam 客户端敏感目录，未见已知侧载文件名。" : $"发现 {count} 组需要核对的客户端文件。",
            EvidenceCount = count
        };
    }

    public static List<string> GetSensitiveDirectories(string steamRoot)
    {
        HashSet<string> directories = new(StringComparer.OrdinalIgnoreCase);
        AddIfExists(steamRoot, directories);
        foreach (string relative in new[] { "bin", "win64", "steamui", "clientui", Path.Combine("bin", "cef") })
        {
            AddIfExists(Path.Combine(steamRoot, relative), directories);
        }

        string cef = Path.Combine(steamRoot, "bin", "cef");
        if (Directory.Exists(cef))
        {
            try
            {
                foreach (string child in Directory.EnumerateDirectories(cef)) AddIfExists(child, directories);
            }
            catch
            {
                // The parent directory itself remains covered.
            }
        }

        return directories.Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static DateTime? TryGetSteamAnchor(string steamRoot)
    {
        try
        {
            string path = Path.Combine(steamRoot, "steam.exe");
            return File.Exists(path) ? File.GetLastWriteTime(path) : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<List<EvidenceItem>> DescribeFilesAsync(IEnumerable<string> paths, DateTime? steamAnchor, CancellationToken cancellationToken)
    {
        List<EvidenceItem> evidence = [];
        foreach (string path in paths.Where(File.Exists))
        {
            SignatureResult signature = AuthenticodeVerifier.Verify(path);
            FileInfo info = new(path);
            evidence.Add(new EvidenceItem(Path.GetFileName(path), path));
            evidence.Add(new EvidenceItem($"{Path.GetFileName(path)} 签名", signature.Detail));
            evidence.Add(new EvidenceItem($"{Path.GetFileName(path)} SHA-256", await FileUtilities.Sha256Async(path, cancellationToken)));
            evidence.Add(new EvidenceItem($"{Path.GetFileName(path)} 修改时间", info.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss zzz")));
            if (steamAnchor is not null && info.LastWriteTime > steamAnchor.Value.AddMinutes(2))
                evidence.Add(new EvidenceItem($"{Path.GetFileName(path)} 时间关系", "晚于 steam.exe（辅助证据）"));
        }
        return evidence;
    }

    private static void AddIfExists(string path, ISet<string> directories)
    {
        try
        {
            if (Directory.Exists(path)) directories.Add(Path.GetFullPath(path));
        }
        catch
        {
            // Ignore malformed or inaccessible path.
        }
    }
}
