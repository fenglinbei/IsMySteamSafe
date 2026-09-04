using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.Core.Inspection;

public sealed record KnownContentRule(string Id, string Sha256, string Label, bool Malware);

public static class LightContentAuditor
{
    private static readonly Lazy<Dictionary<string, KnownContentRule>> Rules = new(() =>
    {
        using Stream stream = typeof(LightContentAuditor).Assembly.GetManifestResourceStream("IsMySteamSafe.Core.Inspection.known-content.json")!;
        return JsonSerializer.Deserialize<List<KnownContentRule>>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!
            .ToDictionary(item => item.Sha256, StringComparer.OrdinalIgnoreCase);
    });
    private static readonly HashSet<string> CandidateExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".js", ".lua", ".vbs", ".ps1", ".bat", ".cmd", ".lnk", ".msi", ".zip", ".rar", ".7z", ".mp4", ".bin", ".py", ".pyc", ".idx" };

    public static KnownContentRule? MatchHash(string hash) => Rules.Value.GetValueOrDefault(hash);

    public static async Task<AuditCheckResult> AuditAsync(SteamLayout layout, AuditReport report, CancellationToken token,
        int maximumEntries = 5000, long maximumBytes = 256L * 1024 * 1024, TimeSpan? maximumTime = null,
        IReadOnlyDictionary<string, KnownContentRule>? knownRules = null)
    {
        Stopwatch clock = Stopwatch.StartNew();
        int before = report.Findings.Count, visited = 0;
        long bytes = 0;
        bool limited = false;
        bool readFailed = false;
        List<string> notes = [];
        Dictionary<string, string> maliciousFiles = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (ContentRoot root in layout.ContentRoots.OrderBy(r => r.Kind == "plugin" ? 0 : r.Kind == "mod" ? 1 : 2))
        {
            report.ContentSources.Add($"{root.Kind} · AppID {root.AppId ?? "—"} · {root.Path}");
            foreach (string path in ContentDiscovery.Files(root.Path, notes, maximumEntries, 8, token))
            {
                token.ThrowIfCancellationRequested();
                if (!seen.Add(path)) continue;
                if (++visited > maximumEntries || clock.Elapsed > (maximumTime ?? TimeSpan.FromSeconds(12)))
                {
                    limited = true;
                    report.ContentLimitations.Add(new("达到数量或时间上限", root.Path,
                        "该位置的剩余条目及后续内容根目录尚未全部检查，以下数量表示说明条数，不是未检查文件总数。"));
                    break;
                }
                if (!CandidateExtensions.Contains(Path.GetExtension(path))) continue;
                try
                {
                    long size = new FileInfo(path).Length;
                    await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    byte[] header = new byte[32];
                    int count = await stream.ReadAsync(header, token);
                    bool container = count >= 4 && (header.AsSpan(0, 2).SequenceEqual("PK"u8) || header.AsSpan(0, 4).SequenceEqual("Rar!"u8) ||
                        header[0] == 0x37 && header[1] == 0x7a || header.AsSpan(0, 4).SequenceEqual("MSCF"u8) || header[0] == 0xd0 && header[1] == 0xcf);
                    if (Path.GetExtension(path).Equals(".mp4", StringComparison.OrdinalIgnoreCase))
                    {
                        if (container || count >= 2 && header[0] == 'M' && header[1] == 'Z')
                            report.Findings.Add(ContentFinding(path, AuditLevel.NeedsReview, "视频扩展名与真实格式不符",
                                "内容实际为压缩包或可执行文件，请不要直接运行。格式异常不是最终判毒结论。", "未计算", root));
                        else if (count >= 12 && header.AsSpan(4, 4).SequenceEqual("ftyp"u8))
                        {
                            MediaProbe media = await MediaStructureProbe.InspectAsync(stream, token);
                            if (media.TrailingBytes > 0 && media.TailKind is not null)
                                report.Findings.Add(ContentFinding(path, AuditLevel.NeedsReview, "媒体结构后存在额外内容",
                                    $"尾部识别到{media.TailKind}，需要进一步扫描，文件存在不等于已经执行。", "未计算", root));
                            report.ContentLimitations.Add(new(media.Complete ? "视频已做结构检查，未做完整比对" : "媒体结构或尾随内容需进一步检查",
                                path, media.Complete ? "未读取全部媒体数据进行哈希比对，不保证媒体内容绝对安全。" : "未完成媒体内容的深度检查。"));
                            limited = true;
                            continue;
                        }
                    }
                    if (size > 64L * 1024 * 1024 || size > maximumBytes - bytes)
                    {
                        limited = true;
                        report.ContentLimitations.Add(new("达到文件大小或读取预算", path, "已读取文件头，尚未完整读取和比对内容。"));
                        continue;
                    }
                    stream.Position = 0;
                    string hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));
                    bytes += size;
                    KnownContentRule? rule = knownRules is null ? MatchHash(hash) : knownRules.GetValueOrDefault(hash);
                    if (rule is not null)
                    {
                        report.Findings.Add(ContentFinding(path, rule.Malware ? AuditLevel.HighlySuspicious : AuditLevel.NeedsReview,
                            rule.Label, "文件内容与内置规则匹配，只证明文件存在，不证明已经执行或 Steam 已被篡改。", hash, root));
                        if (rule.Malware && !container) maliciousFiles[path] = hash;
                    }
                    else if (!container && size <= 2 * 1024 * 1024 && Path.GetExtension(path).ToLowerInvariant() is ".js" or ".lua" or ".vbs" or ".ps1" or ".bat" or ".cmd" or ".py")
                    {
                        stream.Position = 0;
                        using StreamReader reader = new(stream, leaveOpen: true);
                        string text = await reader.ReadToEndAsync(token);
                        IReadOnlyList<string> signals = ScriptSignals.Analyze(text);
                        if (signals.Count > 0) report.Findings.Add(ContentFinding(path, AuditLevel.NeedsReview,
                            "内容脚本含可疑组合逻辑", string.Join("，", signals) + "。静态规则不是最终判毒结论。", hash, root));
                    }
                    if (container)
                    {
                        limited = true;
                        report.ContentLimitations.Add(new("压缩内容未展开", path, "仅检查外层内容，未解压、未索取密码，也未执行安装包。"));
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { readFailed = true; report.ContentLimitations.Add(new("文件读取失败", path, "文件可能被占用、访问受限或已发生变化，请核对后重试。", true)); }
            }
            if (visited > maximumEntries || clock.Elapsed > (maximumTime ?? TimeSpan.FromSeconds(12))) break;
        }
        if (maliciousFiles.Count > 0)
        {
            ObserveLoadedMalware(maliciousFiles, report, token);
            ContentPersistenceAuditor.Observe(maliciousFiles, report, token);
        }
        foreach (string note in notes.Distinct())
        {
            bool failure = !note.Contains("上限");
            readFailed |= failure; limited = true;
            report.ContentLimitations.Add(new(failure ? "目录读取受限" : "达到目录枚举上限", "内容来源", note, failure));
        }
        int countFound = report.Findings.Count - before;
        return new AuditCheckResult { Id = "content-risk", Priority = AuditPriority.P1, Area = AuditArea.ContentSources,
            Name = "工坊、MOD 与插件", Level = countFound > 0 ? report.Findings.Skip(before).MaxBy(f => AuditLabels.RiskRank(f.Level))!.Level :
                readFailed ? AuditLevel.Incomplete : limited ? AuditLevel.Information : AuditLevel.Passed,
            Summary = $"检查 {visited:N0} 个条目，读取 {bytes / 1024 / 1024:N0} MiB，发现 {countFound} 条内容或运行证据。", EvidenceCount = countFound };
    }

    private static AuditFinding ContentFinding(string path, AuditLevel level, string title, string meaning, string hash, ContentRoot root) => new()
    {
        Id = "CONTENT." + (hash.Length == 64 ? hash[..16] : Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path + title)))[..16]), Priority = AuditPriority.P1, Area = AuditArea.ContentSources, Level = level,
        Title = title, WhatFound = hash.Length == 64 ? "在本机内容目录发现匹配文件。" : "在本机内容目录发现需要核对的格式或结构特征。", Meaning = meaning,
        Recommendation = "不要打开可疑文件，核对来源后用 SteamSentinel 或专业杀毒软件隔离，随后重新体检。",
        Target = path, EvidenceState = "file-present", Evidence = [new("SHA-256", hash), new("AppID", root.AppId ?? "未知"), new("内容来源", root.Kind)]
    };

    private static void ObserveLoadedMalware(Dictionary<string, string> files, AuditReport report, CancellationToken token)
    {
        int inaccessible = 0;
        foreach (Process process in Process.GetProcesses())
        using (process)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                string? image = process.MainModule?.FileName;
                foreach (ProcessModule module in process.Modules)
                {
                    if (!files.TryGetValue(module.FileName, out string? expected)) continue;
                    // Recheck the file under a deny-write handle before claiming this exact content is loaded.
                    using FileStream stream = new(module.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
                    if (!Convert.ToHexString(SHA256.HashData(stream)).Equals(expected, StringComparison.OrdinalIgnoreCase)) continue;
                    report.Findings.Add(new AuditFinding { Id = "CONTENT.ACTIVE." + process.Id, Priority = AuditPriority.P1,
                        Area = AuditArea.RunningProcesses, Level = AuditLevel.HighlySuspicious, EvidenceState = "active-malware",
                        Title = "进程加载了已知恶意组件", WhatFound = $"PID {process.Id}：{image}",
                        Meaning = "模块路径与当前恶意文件内容相符，这是运行关联证据，无法单独确认账户数据是否已经外泄。",
                        Recommendation = "停止登录和交易，先处理本机威胁，再从可信设备更换凭据并撤销其他会话。", Target = module.FileName,
                        Evidence = [new("SHA-256", expected), new("进程启动时间", process.StartTime.ToUniversalTime().ToString("O"))] });
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { inaccessible++; }
        }
        if (inaccessible > 0) report.CoverageNotes.Add($"有 {inaccessible} 个进程无法核对模块，不能排除其中存在关联运行活动。");
    }
}
