using System.Windows.Media;
using IsMySteamSafe.Core.Models;

namespace IsMySteamSafe.App.ViewModels;

public sealed class CheckCardViewModel
{
    public required AuditCheckResult Check { get; init; }
    public string Name => Check.Name;
    public string Status => AuditLabels.Level(Check.Level);
    public string Summary => Check.Summary;
    public string Priority => AuditLabels.Priority(Check.Priority);
    public Brush Accent => Palette.Accent(Check.Level);
    public Brush Tint => Palette.Tint(Check.Level);
}

public sealed class FindingViewModel
{
    public required AuditFinding Finding { get; init; }
    public string Title => Finding.Title;
    public string Level => AuditLabels.Level(Finding.Level);
    public string Priority => AuditLabels.Priority(Finding.Priority);
    public string WhatFound => Finding.WhatFound;
    public string Meaning => Finding.Meaning;
    public string Recommendation => Finding.Recommendation;
    public string Target => Finding.Target ?? "—";
    public string EvidenceText => Finding.Evidence.Count == 0
        ? "无附加信息"
        : string.Join(Environment.NewLine, Finding.Evidence.Select(item => $"{item.Name}：{item.Value}"));
    public Brush Accent => Palette.Accent(Finding.Level);
    public Brush Tint => Palette.Tint(Finding.Level);
}

public sealed class UrlViewModel
{
    public required InspectedUrl Url { get; init; }
    public string Host => Url.DisplayHost;
    public string Result => Url.Trust switch
    {
        UrlTrustLevel.OfficialSupport => "官方客服主机",
        UrlTrustLevel.SteamOwnedDomain => "Steam 域名，非标准客服主机",
        UrlTrustLevel.NotSteamOwned => "非 Steam 域名",
        _ => "无法解析"
    };
    public string Details => Url.Explanation;
    public string NormalizedUrl => Url.NormalizedUrl;
    public Brush Accent => Url.Trust switch
    {
        UrlTrustLevel.OfficialSupport => Palette.Green,
        UrlTrustLevel.SteamOwnedDomain => Palette.Amber,
        UrlTrustLevel.NotSteamOwned => Palette.Red,
        _ => Palette.Gray
    };
    public Brush Tint => Url.Trust switch
    {
        UrlTrustLevel.OfficialSupport => Palette.GreenTint,
        UrlTrustLevel.SteamOwnedDomain => Palette.AmberTint,
        UrlTrustLevel.NotSteamOwned => Palette.RedTint,
        _ => Palette.GrayTint
    };
}

public static class Palette
{
    public static readonly Brush Green = Brush("#177D76");
    public static readonly Brush GreenTint = Brush("#E6F5F2");
    public static readonly Brush Blue = Brush("#175CD3");
    public static readonly Brush BlueTint = Brush("#EFF8FF");
    public static readonly Brush Amber = Brush("#B54708");
    public static readonly Brush AmberTint = Brush("#FFF4E5");
    public static readonly Brush Red = Brush("#B42318");
    public static readonly Brush RedTint = Brush("#FFF0EE");
    public static readonly Brush Gray = Brush("#667085");
    public static readonly Brush GrayTint = Brush("#F2F4F7");

    public static Brush Accent(AuditLevel level) => level switch
    {
        AuditLevel.Passed => Green,
        AuditLevel.Information => Blue,
        AuditLevel.NeedsReview => Amber,
        AuditLevel.HighlySuspicious or AuditLevel.ConfirmedTampering => Red,
        _ => Gray
    };

    public static Brush Tint(AuditLevel level) => level switch
    {
        AuditLevel.Passed => GreenTint,
        AuditLevel.Information => BlueTint,
        AuditLevel.NeedsReview => AmberTint,
        AuditLevel.HighlySuspicious or AuditLevel.ConfirmedTampering => RedTint,
        _ => GrayTint
    };

    private static Brush Brush(string hex)
    {
        SolidColorBrush brush = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        brush.Freeze();
        return brush;
    }
}
