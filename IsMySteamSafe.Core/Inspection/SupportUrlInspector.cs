using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using IsMySteamSafe.Core.Models;

namespace IsMySteamSafe.Core.Inspection;

public static partial class SupportUrlInspector
{
    private const int MaximumInputLength = 1024 * 1024;

    [GeneratedRegex("https?://[^\\s\\\"'<>]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:[/?#].*)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BareHostRegex();

    public static UrlInspectionResult Inspect(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new UrlInspectionResult("还没有可检查的链接", UrlTrustLevel.Invalid, [], ["请粘贴“联系客服”按钮的实际链接，工具不会打开它。"]);
        }

        string bounded = input.Length <= MaximumInputLength ? input : input[..MaximumInputLength];
        string decoded = WebUtility.HtmlDecode(bounded).Trim();
        List<string> candidates = UrlRegex().Matches(decoded)
            .Select(match => TrimCandidate(match.Value))
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToList();

        if (candidates.Count == 0 && BareHostRegex().IsMatch(decoded)) candidates.Add("https://" + decoded);

        List<InspectedUrl> inspected = [];
        foreach (string candidate in candidates)
        {
            inspected.Add(InspectOne(candidate));
        }

        if (inspected.Count == 0)
        {
            return new UrlInspectionResult(
                "没有识别到 HTTP/HTTPS 链接",
                UrlTrustLevel.Invalid,
                [],
                ["请复制按钮地址，而不是只复制“联系客服”几个字。", "不会进行联网、DNS 查询或打开页面。"]);
        }

        UrlTrustLevel overall = inspected.Any(item => item.Trust == UrlTrustLevel.NotSteamOwned)
            ? UrlTrustLevel.NotSteamOwned
            : inspected.All(item => item.Trust == UrlTrustLevel.OfficialSupport)
                ? UrlTrustLevel.OfficialSupport
                : inspected.Any(item => item.Trust == UrlTrustLevel.SteamOwnedDomain)
                    ? UrlTrustLevel.SteamOwnedDomain
                    : UrlTrustLevel.Invalid;

        string summary = overall switch
        {
            UrlTrustLevel.OfficialSupport => "域名是 Steam 官方客服主机",
            UrlTrustLevel.SteamOwnedDomain => "属于 steampowered.com，但不是标准客服主机",
            UrlTrustLevel.NotSteamOwned => "发现不属于 steampowered.com 的链接",
            _ => "链接格式无法确认"
        };

        List<string> notes = [
            "官方客服主机应为 help.steampowered.com。",
            "本次只在本地解析文本，没有访问、解析 DNS 或打开任何链接。"
        ];
        if (input.Length > MaximumInputLength) notes.Add("输入过长，仅检查了前 1 MiB 文本。");
        if (inspected.Count > 1) notes.Add("检测到多个链接，请逐条核对，网页源码可能包含正常的第三方静态资源。");
        return new UrlInspectionResult(summary, overall, inspected, notes);
    }

    public static bool IsSteamPoweredHost(string host)
    {
        string normalized = host.Trim().TrimEnd('.');
        return normalized.Equals("steampowered.com", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".steampowered.com", StringComparison.OrdinalIgnoreCase);
    }

    private static InspectedUrl InspectOne(string candidate)
    {
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return new InspectedUrl(candidate, candidate, "无法解析", "", UrlTrustLevel.Invalid, false, false, "不是有效的 HTTP/HTTPS 链接。");
        }

        string displayHost = uri.DnsSafeHost.TrimEnd('.');
        string asciiHost;
        try
        {
            asciiHost = new IdnMapping().GetAscii(displayHost).ToLowerInvariant();
        }
        catch
        {
            asciiHost = displayHost.ToLowerInvariant();
        }

        bool officialSupport = asciiHost.Equals("help.steampowered.com", StringComparison.OrdinalIgnoreCase);
        bool steamOwned = IsSteamPoweredHost(asciiHost);
        bool https = uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        bool userInfo = !string.IsNullOrEmpty(uri.UserInfo);
        UrlTrustLevel trust = userInfo
            ? UrlTrustLevel.NotSteamOwned
            : officialSupport && https
                ? UrlTrustLevel.OfficialSupport
                : steamOwned ? UrlTrustLevel.SteamOwnedDomain : UrlTrustLevel.NotSteamOwned;

        string explanation = userInfo
            ? "链接包含 @ 前的用户信息，容易伪装真实域名，实际主机以 @ 后为准。"
            : trust switch
            {
                UrlTrustLevel.OfficialSupport when https => "标准 Steam 客服主机，且使用 HTTPS。",
                UrlTrustLevel.OfficialSupport => "主机正确，但链接不是 HTTPS，需要谨慎。",
                UrlTrustLevel.SteamOwnedDomain => "主机属于 steampowered.com，但并非标准客服主机 help.steampowered.com。",
                _ => "主机不属于 steampowered.com，不要付款、扫码或输入凭据。"
            };

        return new InspectedUrl(candidate, uri.AbsoluteUri, displayHost, asciiHost, trust, https, userInfo, explanation);
    }

    private static string TrimCandidate(string value) => value.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}', '，', '。', '；', '！', '？');
}
