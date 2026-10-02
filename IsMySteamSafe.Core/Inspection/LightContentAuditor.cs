using System.Diagnostics;
using System.Security.Cryptography;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.Core.Inspection;

public static class LightContentAuditor
{
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".js", ".mjs", ".cjs", ".lua", ".luau", ".vbs", ".ps1", ".bat", ".cmd", ".py", ".pyw", ".cs", ".csx" };
    private static readonly HashSet<string> ContainerExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".zip", ".rar", ".7z", ".cab", ".msi", ".tar", ".gz", ".bz2", ".xz", ".pak", ".vpk" };

    public static KnownContentRule? MatchHash(string hash) => KnownContentCatalog.LoadSnapshot().Rules.GetValueOrDefault(hash);

    public static async Task<AuditCheckResult> AuditAsync(SteamLayout layout, AuditReport report, CancellationToken token,
        int maximumEntries = 5000, long maximumBytes = 256L * 1024 * 1024, TimeSpan? maximumTime = null,
        IReadOnlyDictionary<string, KnownContentRule>? knownRules = null)
    {
        Stopwatch clock = Stopwatch.StartNew();
        int before = report.Findings.Count, visited = 0, hashed = 0;
        long bytes = 0;
        bool limited = false;
        bool readFailed = false;
        List<string> notes = [];
        KnownContentSnapshot snapshot = KnownContentCatalog.LoadSnapshot();
        report.RuleSet = snapshot.Metadata;
        if (!string.IsNullOrEmpty(snapshot.Metadata.Notice))
        {
            report.CoverageNotes.Add(snapshot.Metadata.Notice);
            readFailed = true;
        }
        IReadOnlyDictionary<string, KnownContentRule> rules = knownRules ?? snapshot.Rules;
        Dictionary<string, string> maliciousFiles = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        TimeSpan duration = maximumTime ?? TimeSpan.FromSeconds(12);
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(duration > TimeSpan.Zero ? duration : TimeSpan.Zero);
        List<RootCursor> cursors = FairRoots(layout.ContentRoots).Select(root => new RootCursor(root,
            ContentDiscovery.Files(root.Path, notes, Math.Max(0, maximumEntries), 8, deadline.Token).GetEnumerator())).ToList();
        foreach (RootCursor cursor in cursors)
            report.ContentSources.Add($"{cursor.Root.Kind} · AppID {cursor.Root.AppId ?? "—"} · {cursor.Root.Path}");
        bool budgetStopped = false;
        try
        {
            while (!budgetStopped && cursors.Any(cursor => !cursor.Complete))
            foreach (RootCursor cursor in cursors.Where(cursor => !cursor.Complete))
            {
                token.ThrowIfCancellationRequested();
                if (visited >= maximumEntries || clock.Elapsed >= duration || deadline.IsCancellationRequested)
                { budgetStopped = true; break; }
                if (!cursor.Files.MoveNext()) { cursor.Complete = true; continue; }
                ContentRoot root = cursor.Root;
                string path = cursor.Files.Current;
                if (!seen.Add(path)) continue;
                visited++; cursor.Visited++;
                try
                {
                    await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    long size = stream.Length;
                    string extension = Path.GetExtension(path);
                    byte[] header = new byte[32];
                    int count = await stream.ReadAsync(header, deadline.Token);
                    bool container = ContainerExtensions.Contains(extension) || count >= 4 && (header.AsSpan(0, 2).SequenceEqual("PK"u8) || header.AsSpan(0, 4).SequenceEqual("Rar!"u8) ||
                        header[0] == 0x37 && header[1] == 0x7a || header.AsSpan(0, 4).SequenceEqual("MSCF"u8) || header[0] == 0xd0 && header[1] == 0xcf || header[0] == 0x1f && header[1] == 0x8b);
                    bool mediaInspected = false;
                    if (extension.Equals(".mp4", StringComparison.OrdinalIgnoreCase))
                    {
                        if (container || count >= 2 && header[0] == 'M' && header[1] == 'Z')
                            report.Findings.Add(ContentFinding(path, AuditLevel.NeedsReview, "视频扩展名与真实格式不符",
                                "内容实际为压缩包或可执行文件，请不要直接运行。格式异常不是最终判毒结论。", "未计算", root));
                        else if (count >= 12 && header.AsSpan(4, 4).SequenceEqual("ftyp"u8))
                        {
                            MediaProbe media = await MediaStructureProbe.InspectAsync(stream, deadline.Token);
                            if (media.TrailingBytes > 0 && media.TailKind is not null)
                                report.Findings.Add(ContentFinding(path, AuditLevel.NeedsReview, "媒体结构后存在额外内容",
                                    $"尾部识别到{media.TailKind}，需要进一步扫描，文件存在不等于已经执行。", "未计算", root));
                            bool canHash = size <= 64L * 1024 * 1024 && size <= maximumBytes - bytes;
                            report.ContentLimitations.Add(new(media.Complete ? "视频已做结构检查，未做深度内容分析" : "媒体结构或尾随内容需进一步检查",
                                path, canHash ? "仍会比对完整文件 SHA-256，但未解析媒体中的全部内容，不保证绝对安全。" : "文件大小或预算限制导致未完整计算 SHA-256，仅做格式与结构检查。"));
                            limited = true;
                            mediaInspected = true;
                            if (!canHash) continue;
                        }
                    }
                    if (size > 64L * 1024 * 1024 || size > maximumBytes - bytes)
                    {
                        limited = true;
                        report.ContentLimitations.Add(new("达到文件大小或读取预算", path, "已读取文件头，尚未完整读取和比对内容。"));
                        continue;
                    }
                    stream.Position = 0;
                    string hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, deadline.Token));
                    bytes += size; hashed++;
                    KnownContentRule? rule = rules.GetValueOrDefault(hash);
                    if (rule is not null)
                    {
                        report.Findings.Add(ContentFinding(path, rule.Malware ? AuditLevel.HighlySuspicious : AuditLevel.NeedsReview,
                            rule.Label, "文件内容与已加载的可信指纹规则匹配，只证明文件存在，不证明已经执行或 Steam 已被篡改。", hash, root, rule));
                        if (rule.Malware && !container) maliciousFiles[path] = hash;
                    }
                    else if (!container && size <= 2 * 1024 * 1024 && ScriptExtensions.Contains(extension))
                    {
                        stream.Position = 0;
                        using StreamReader reader = new(stream, leaveOpen: true);
                        string text = await reader.ReadToEndAsync(deadline.Token);
                        if (text.Contains('\0') || text.Contains('\uFFFD'))
                        {
                            limited = true;
                            report.ContentLimitations.Add(new("脚本编码或实际格式不支持静态分析", path, "已完整计算 SHA-256，文本包含无法可靠解码的字节或二进制内容，未把解析失败当作安全。"));
                        }
                        else
                        {
                            IReadOnlyList<string> signals = ScriptSignals.Analyze(text, extension);
                            if (signals.Count > 0) report.Findings.Add(ContentFinding(path, AuditLevel.NeedsReview,
                                "内容脚本含可疑组合逻辑", string.Join("，", signals) + "。静态规则只提示需要核对，不能证明恶意、已执行或已外泄。", hash, root));
                        }
                    }
                    if (container)
                    {
                        limited = true;
                        report.ContentLimitations.Add(new("压缩内容未展开", path, "仅检查外层内容，未解压、未索取密码，也未执行安装包。"));
                    }
                    else if (!mediaInspected && (!ScriptExtensions.Contains(extension) || size > 2 * 1024 * 1024))
                    {
                        limited = true;
                        string kind = extension.Equals(".pyc", StringComparison.OrdinalIgnoreCase) ? "Python 字节码未反编译" :
                            extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase) ? "快捷方式未解析或执行" :
                            ScriptExtensions.Contains(extension) ? "脚本超过静态分析大小上限" : "此格式仅做指纹比对，未做语义分析";
                        report.ContentLimitations.Add(new(kind, path, "已完整计算 SHA-256。未命中已知指纹不代表内容安全；未进行此格式的完整语义或行为分析。"));
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { readFailed = true; report.ContentLimitations.Add(new("文件读取失败", path, "文件可能被占用、访问受限或已发生变化，请核对后重试。", true)); }
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { budgetStopped = true; }
        finally { foreach (RootCursor cursor in cursors) cursor.Files.Dispose(); }
        token.ThrowIfCancellationRequested();
        if (budgetStopped)
        {
            limited = true;
            foreach (RootCursor cursor in cursors.Where(cursor => !cursor.Complete))
                report.ContentLimitations.Add(new("达到数量或时间上限", cursor.Root.Path,
                    $"此来源已访问 {cursor.Visited:N0} 个文件，剩余内容尚未完成检查；来源按轮次交替检查，此数不是未检查文件总数。"));
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
            Name = "游戏、工坊、MOD 与插件", Level = countFound > 0 ? report.Findings.Skip(before).MaxBy(f => AuditLabels.RiskRank(f.Level))!.Level :
                readFailed ? AuditLevel.Incomplete : limited ? AuditLevel.Information : AuditLevel.Passed,
            Summary = $"访问 {visited:N0} 个文件，完成 {hashed:N0} 个 SHA-256 比对，哈希读取 {bytes / 1024 / 1024:N0} MiB，发现 {countFound} 条内容或运行证据；格式和预算限制见覆盖说明。", EvidenceCount = countFound };
    }

    private sealed class RootCursor(ContentRoot root, IEnumerator<string> files)
    {
        public ContentRoot Root { get; } = root;
        public IEnumerator<string> Files { get; } = files;
        public bool Complete { get; set; }
        public int Visited { get; set; }
    }

    // Interleave source categories, then visit one file per root per round. A busy workshop
    // must not make all installed-game roots disappear from either the scan or its report.
    private static IEnumerable<ContentRoot> FairRoots(IEnumerable<ContentRoot> roots)
    {
        Queue<ContentRoot>[] groups = roots.DistinctBy(root => root.Path, StringComparer.OrdinalIgnoreCase)
            .GroupBy(root => root.Kind).OrderBy(group => group.Key switch { "game" => 0, "plugin" => 1, "mod" => 2, "workshop" => 3, _ => 4 })
            .Select(group => new Queue<ContentRoot>(group.OrderBy(root => root.Path, StringComparer.OrdinalIgnoreCase))).ToArray();
        while (groups.Any(group => group.Count > 0))
            foreach (Queue<ContentRoot> group in groups)
                if (group.TryDequeue(out ContentRoot? root)) yield return root;
    }

    private static AuditFinding ContentFinding(string path, AuditLevel level, string title, string meaning, string hash, ContentRoot root, KnownContentRule? matchedRule = null)
    {
        List<EvidenceItem> evidence = [new("SHA-256", hash), new("AppID", root.AppId ?? "未知"), new("内容来源", root.Kind)];
        if (matchedRule is not null)
        {
            evidence.Add(new("指纹规则", matchedRule.Id));
            if (!string.IsNullOrWhiteSpace(matchedRule.SourceUrl)) evidence.Add(new("公开分析来源", matchedRule.SourceUrl));
        }
        return new()
        {
            Id = "CONTENT." + (hash.Length == 64 ? hash[..16] : Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path + title)))[..16]), Priority = AuditPriority.P1, Area = AuditArea.ContentSources, Level = level,
            Title = title, WhatFound = matchedRule is not null ? "在本机内容目录发现与已加载指纹匹配的文件。" : "在本机内容目录发现需要核对的静态组合、格式或结构特征。", Meaning = meaning,
            Recommendation = "不要打开可疑文件，核对来源后用 SteamSentinel 或专业杀毒软件隔离，随后重新体检。",
            Target = path, EvidenceState = "file-present", Evidence = evidence
        };
    }

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
