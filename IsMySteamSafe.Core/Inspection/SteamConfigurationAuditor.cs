using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.Core.Inspection;

public static class SteamConfigurationAuditor
{
    private const string EvidenceSampleHash = "c9799659ec6e3e786f68d73eec26e7eb1190708caad875711096c98f1aac4e24";

    public static async Task<AuditCheckResult> AuditAsync(
        string steamRoot,
        AuditReport report,
        CancellationToken cancellationToken)
    {
        string path = Path.Combine(steamRoot, "steam.cfg");
        if (!File.Exists(path))
        {
            return Result(AuditLevel.Passed, "未发现 steam.cfg 更新抑制配置。", 0);
        }

        string text;
        try
        {
            text = await FileUtilities.ReadTextBoundedAsync(path, 1024 * 1024, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            report.CoverageNotes.Add($"无法读取 {path}：{ex.Message}");
            return Result(AuditLevel.Incomplete, "发现 steam.cfg，但内容无法读取。", 0);
        }

        Dictionary<string, string> values = Parse(text);
        List<string> matched = [];
        AddIf(values, "BootStrapperInhibitAll", IsEnabled, matched);
        AddIf(values, "BootStrapperForceSelfUpdate", IsDisabled, matched);
        AddIf(values, "ForceOfflineMode", IsEnabled, matched);

        if (matched.Count == 0)
        {
            return Result(AuditLevel.Passed, "发现 steam.cfg，但未命中会抑制更新或强制离线的目标设置。", 0);
        }

        bool updatePair = Has(values, "BootStrapperInhibitAll", IsEnabled) &&
                          Has(values, "BootStrapperForceSelfUpdate", IsDisabled);
        string hash = await FileUtilities.Sha256Async(path, cancellationToken);
        FileInfo info = new(path);
        List<EvidenceItem> evidence =
        [
            new("发现的设置", string.Join("；", matched)),
            new("SHA-256", hash),
            new("文件大小", $"{info.Length:N0} 字节"),
            new("创建时间", info.CreationTimeUtc.ToString("O")),
            new("修改时间", info.LastWriteTimeUtc.ToString("O")),
            new("与已分析样本的配置哈希一致", hash.Equals(EvidenceSampleHash, StringComparison.OrdinalIgnoreCase) ? "是" : "否")
        ];

        report.Findings.Add(new AuditFinding
        {
            Id = updatePair ? "P1.CONFIG.STEAM_UPDATE_SUPPRESSED" : "P1.CONFIG.STEAM_CONTROL_SETTING",
            Priority = AuditPriority.P1,
            Level = updatePair ? AuditLevel.HighlySuspicious : AuditLevel.NeedsReview,
            Area = AuditArea.ClientConfiguration,
            Title = updatePair ? "Steam 自更新被成对抑制" : "steam.cfg 包含需要核对的控制设置",
            WhatFound = updatePair
                ? "steam.cfg 同时启用了 BootStrapperInhibitAll，并禁用了 BootStrapperForceSelfUpdate。"
                : $"steam.cfg 命中 {matched.Count} 项更新/离线控制设置。",
            Meaning = updatePair
                ? "这会阻止 Steam 正常自动更新，使被篡改的前端文件继续存在。已分析的真实样本也使用了相同配置，但仅凭这一项不能判断具体木马。"
                : "高级维护场景可能主动使用 steam.cfg，但普通客户端通常不需要这些设置。",
            Recommendation = "不要只删除这一文件就认定系统安全，请先保留报告并使用专业杀毒软件查杀。确认查杀完成后，再从 Steam 官网重装客户端。",
            Target = path,
            Evidence = evidence
        });

        return Result(
            updatePair ? AuditLevel.HighlySuspicious : AuditLevel.NeedsReview,
            updatePair ? "发现阻止 Steam 自更新的成对配置。" : $"发现 {matched.Count} 项需要核对的 steam.cfg 设置。",
            1);
    }

    private static Dictionary<string, string> Parse(string text)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);
        foreach (string rawLine in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string line = rawLine.Trim();
            if (line.StartsWith('#') || line.StartsWith(';') || line.StartsWith("//", StringComparison.Ordinal)) continue;
            int separator = line.IndexOf('=');
            if (separator <= 0) continue;
            values[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }
        return values;
    }

    private static void AddIf(
        IReadOnlyDictionary<string, string> values,
        string key,
        Func<string, bool> predicate,
        ICollection<string> matched)
    {
        if (values.TryGetValue(key, out string? value) && predicate(value)) matched.Add($"{key}={value}");
    }

    private static bool Has(IReadOnlyDictionary<string, string> values, string key, Func<string, bool> predicate) =>
        values.TryGetValue(key, out string? value) && predicate(value);

    private static bool IsEnabled(string value) => value.Equals("enable", StringComparison.OrdinalIgnoreCase) ||
                                                    value.Equals("enabled", StringComparison.OrdinalIgnoreCase) ||
                                                    value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                                                    value.Equals("1", StringComparison.Ordinal);

    private static bool IsDisabled(string value) => value.Equals("disable", StringComparison.OrdinalIgnoreCase) ||
                                                     value.Equals("disabled", StringComparison.OrdinalIgnoreCase) ||
                                                     value.Equals("false", StringComparison.OrdinalIgnoreCase) ||
                                                     value.Equals("0", StringComparison.Ordinal);

    private static AuditCheckResult Result(AuditLevel level, string summary, int evidenceCount) => new()
    {
        Id = "client-configuration",
        Priority = AuditPriority.P1,
        Area = AuditArea.ClientConfiguration,
        Name = "Steam 更新配置",
        Level = level,
        Summary = summary,
        EvidenceCount = evidenceCount
    };
}
