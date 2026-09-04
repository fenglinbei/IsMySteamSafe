using System.Text.Json.Serialization;

namespace IsMySteamSafe.Core.Models;

public static class ProductInfo
{
    public const string Name = "我的 Steam 安全吗？";
    public const string Version = "0.2.4";
    public const string Edition = "v0.2.4";
    public const string OfficialSupportUrl = "https://help.steampowered.com/";
    public const string OfficialInstallerUrl = "https://store.steampowered.com/about/";
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuditPriority
{
    P0,
    P1,
    P2
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuditLevel
{
    Passed,
    Information,
    NeedsReview,
    HighlySuspicious,
    ConfirmedTampering,
    Incomplete
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuditArea
{
    ClientFiles,
    ClientConfiguration,
    InterfaceCode,
    SupportRoutes,
    RunningProcesses,
    Persistence,
    NetworkConfiguration,
    ContentSources
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuditConclusion
{
    NotRun,
    NoTamperingFound,
    ReviewNeeded,
    StrongTamperingSignal,
    Incomplete
}

public sealed record EvidenceItem(string Name, string Value);

public sealed class AuditFinding
{
    public required string Id { get; init; }
    public required AuditPriority Priority { get; init; }
    public required AuditLevel Level { get; init; }
    public required AuditArea Area { get; init; }
    public required string Title { get; init; }
    public required string WhatFound { get; init; }
    public required string Meaning { get; init; }
    public required string Recommendation { get; init; }
    public string? Target { get; init; }
    public List<EvidenceItem> Evidence { get; init; } = [];
}

public sealed class AuditCheckResult
{
    public required string Id { get; init; }
    public required AuditPriority Priority { get; init; }
    public required AuditArea Area { get; init; }
    public required string Name { get; init; }
    public required AuditLevel Level { get; set; }
    public required string Summary { get; set; }
    public int EvidenceCount { get; set; }
}

public sealed class AuditMetrics
{
    public int SensitiveDirectoriesChecked { get; set; }
    public int CandidateFilesChecked { get; set; }
    public int JavaScriptFilesChecked { get; set; }
    public long JavaScriptBytesChecked { get; set; }
    public int RouteKeysObserved { get; set; }
    public int ProcessModulesChecked { get; set; }
    public int PersistenceValuesChecked { get; set; }
    public int WorkshopItemsObserved { get; set; }
}

public sealed class AuditReport
{
    public Guid AuditId { get; init; } = Guid.NewGuid();
    public string ProductVersion { get; init; } = ProductInfo.Version;
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.Now;
    public DateTimeOffset? CompletedAt { get; set; }
    public AuditConclusion Conclusion { get; set; } = AuditConclusion.NotRun;
    public List<string> SteamRoots { get; init; } = [];
    public List<AuditCheckResult> Checks { get; init; } = [];
    public List<AuditFinding> Findings { get; init; } = [];
    public List<string> CoverageNotes { get; init; } = [];
    public AuditMetrics Metrics { get; init; } = new();

    public void RecalculateConclusion()
    {
        if (Findings.Any(item => item.Level is AuditLevel.ConfirmedTampering or AuditLevel.HighlySuspicious))
        {
            Conclusion = AuditConclusion.StrongTamperingSignal;
        }
        else if (Findings.Any(item => item.Level == AuditLevel.NeedsReview))
        {
            Conclusion = AuditConclusion.ReviewNeeded;
        }
        else if (Checks.Any(item => item.Level == AuditLevel.Incomplete))
        {
            Conclusion = AuditConclusion.Incomplete;
        }
        else
        {
            Conclusion = AuditConclusion.NoTamperingFound;
        }
    }
}

public sealed record SteamAuditOptions(bool UserAcknowledgesClientMods = false, bool IncludeExtendedChecks = true);

public sealed record AuditProgress(int Percent, string Stage, string Message, string? CurrentItem = null);

public static class AuditLabels
{
    public static string Level(AuditLevel level) => level switch
    {
        AuditLevel.Passed => "未见异常",
        AuditLevel.Information => "信息",
        AuditLevel.NeedsReview => "需要核对",
        AuditLevel.HighlySuspicious => "高度可疑",
        AuditLevel.ConfirmedTampering => "发现明显篡改",
        _ => "检查不完整"
    };

    public static string Conclusion(AuditConclusion conclusion) => conclusion switch
    {
        AuditConclusion.NoTamperingFound => "未发现 Steam 客户端篡改迹象",
        AuditConclusion.ReviewNeeded => "有几项需要你核对",
        AuditConclusion.StrongTamperingSignal => "发现强篡改信号",
        AuditConclusion.Incomplete => "体检未完成",
        _ => "待检查"
    };

    public static string Priority(AuditPriority priority) => priority switch
    {
        AuditPriority.P0 => "P0 · 决定性",
        AuditPriority.P1 => "P1 · 强相关",
        _ => "P2 · 仅提示"
    };

    public static int RiskRank(AuditLevel level) => level switch
    {
        AuditLevel.ConfirmedTampering => 50,
        AuditLevel.HighlySuspicious => 40,
        AuditLevel.NeedsReview => 30,
        AuditLevel.Incomplete => 20,
        AuditLevel.Information => 10,
        _ => 0
    };
}

public enum UrlTrustLevel
{
    OfficialSupport,
    SteamOwnedDomain,
    NotSteamOwned,
    Invalid
}

public sealed record InspectedUrl(
    string Original,
    string NormalizedUrl,
    string DisplayHost,
    string AsciiHost,
    UrlTrustLevel Trust,
    bool UsesHttps,
    bool HasUserInfo,
    string Explanation);

public sealed record UrlInspectionResult(
    string Summary,
    UrlTrustLevel OverallTrust,
    IReadOnlyList<InspectedUrl> Urls,
    IReadOnlyList<string> Notes);
