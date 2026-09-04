using System.Text.RegularExpressions;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.Core.Inspection;

public sealed record ScriptSignal(string Id, AuditLevel Level, string Title, string Detail, int Index);

public sealed record ScriptAnalysis(
    IReadOnlyList<ScriptSignal> Signals,
    bool HasSupportPopupReference,
    bool HasSupportActiveReference,
    bool HasGameActionHandler,
    bool HasHttpsRenderingCheck,
    IReadOnlySet<string> RouteKeys,
    IReadOnlyList<(string Key, string Url)> RouteUrls);

public static partial class JavaScriptAuditor
{
    private const long MaximumScriptBytes = 32L * 1024 * 1024;
    private const long MaximumTotalBytes = 256L * 1024 * 1024;
    private static readonly string[] RouteKeyNames = ["SupportMessages", "HelpAppPage", "HelpFrontPage"];

    [GeneratedRegex(@"return\s*(?<expr>!!?\s*[01]|[01]|true|false)\s*(?:[;,}])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ConstantReturnRegex();

    [GeneratedRegex("ExecuteSteamURL\\s*\\(\\s*[\\\"']steam://open/supportalert[\\\"']\\s*\\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SupportAlertCallRegex();

    [GeneratedRegex("(?<key>SupportMessages|HelpAppPage|HelpFrontPage)(?:[\\\"']?\\s*[:=]\\s*|[\\\"']?\\s*,\\s*(?:url|strURL)?\\s*[:=]?\\s*)[\\\"'](?<url>https?://[^\\\"'<>\\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RouteAssignmentRegex();

    [GeneratedRegex(@"[""']?(?<key>SupportMessages|HelpAppPage|HelpFrontPage)[""']?\s*:\s*(?<var>[$A-Z_a-z][$\w]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RouteVariableMapRegex();

    [GeneratedRegex(@"(?<![$\w])(?<var>[$A-Z_a-z][$\w]*)\s*=\s*[""'](?<url>https?://[^""'<>\s]+)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlVariableAssignmentRegex();

    [GeneratedRegex(@"style\s*:\s*\{\s*display\s*:\s*[""']none[""']\s*\}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HiddenDisplayRegex();

    public static async Task<(AuditCheckResult InterfaceCheck, AuditCheckResult RouteCheck)> AuditAsync(
        string steamRoot,
        AuditReport report,
        CancellationToken cancellationToken)
    {
        List<string> files = EnumerateScripts(steamRoot).Take(2000).ToList();
        bool popup = false;
        bool active = false;
        bool gameAction = false;
        bool httpsCheck = false;
        HashSet<string> routeKeys = new(StringComparer.Ordinal);
        List<(string Key, string Url, string Path)> routeUrls = [];
        int interfaceFindings = 0;
        int routeFindings = 0;
        long totalBytes = 0;
        int skipped = 0;

        foreach (string path in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FileInfo info;
            try { info = new FileInfo(path); }
            catch { skipped++; continue; }
            if (info.Length > MaximumScriptBytes || totalBytes + info.Length > MaximumTotalBytes)
            {
                skipped++;
                continue;
            }

            string text;
            try
            {
                text = await FileUtilities.ReadTextBoundedAsync(path, MaximumScriptBytes, cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                skipped++;
                continue;
            }

            totalBytes += info.Length;
            report.Metrics.JavaScriptFilesChecked++;
            report.Metrics.JavaScriptBytesChecked += info.Length;
            ScriptAnalysis analysis = AnalyzeText(text);
            popup |= analysis.HasSupportPopupReference;
            active |= analysis.HasSupportActiveReference;
            gameAction |= analysis.HasGameActionHandler;
            httpsCheck |= analysis.HasHttpsRenderingCheck;
            routeKeys.UnionWith(analysis.RouteKeys);
            routeUrls.AddRange(analysis.RouteUrls.Select(item => (item.Key, item.Url, path)));

            foreach (ScriptSignal signal in analysis.Signals)
            {
                interfaceFindings++;
                report.Findings.Add(new AuditFinding
                {
                    Id = signal.Id,
                    Priority = AuditPriority.P0,
                    Level = signal.Level,
                    Area = AuditArea.InterfaceCode,
                    Title = signal.Title,
                    WhatFound = signal.Detail,
                    Meaning = "Steam 前端逻辑出现了与已知假红信手法一致的修改，这是客户端被改动的证据，但不能据此判断具体木马家族。",
                    Recommendation = "停止在当前 Steam 界面付款或输入凭据，使用专业杀毒软件全盘扫描。确认查杀完成后，再从官网下载并重装 Steam。",
                    Target = path,
                    Evidence = [new("代码片段", FileUtilities.CompactSnippet(text, signal.Index))]
                });
            }
        }

        foreach ((string key, string url, string path) in routeUrls.Distinct())
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)) continue;
            if (SupportUrlInspector.IsSteamPoweredHost(uri.Host)) continue;
            routeFindings++;
            report.Findings.Add(new AuditFinding
            {
                Id = $"P0.ROUTE.{key.ToUpperInvariant()}",
                Priority = AuditPriority.P0,
                Level = AuditLevel.ConfirmedTampering,
                Area = AuditArea.SupportRoutes,
                Title = $"{key} 附近出现第三方域名",
                WhatFound = $"在 Steam 客服路由代码附近提取到 {uri.Host}。",
                Meaning = "客服入口指向 steampowered.com 之外的主机，说明 Steam 客户端已被修改。",
                Recommendation = "不要访问该地址，不要扫码或付款，请断开网络并使用专业杀毒软件查杀，随后重装 Steam。",
                Target = path,
                Evidence = [new("路由键", key), new("提取 URL（参数已脱敏）", FileUtilities.RedactSensitiveText(url)), new("实际主机", uri.Host)]
            });
        }

        report.Metrics.RouteKeysObserved += routeKeys.Count;
        if (skipped > 0) report.CoverageNotes.Add($"有 {skipped} 个 Steam JavaScript 文件因权限不足或超过大小上限而未读取，这部分不会标为已检查。");
        report.CoverageNotes.Add("新版 Steam 的部分 URL 映射由 SteamClient.URL.GetSteamURLList 在运行时提供，本版会检查直接赋值和局部变量路由映射，但无法覆盖全部运行时映射。");

        bool invariantsPresent = popup && active && gameAction;
        AuditCheckResult interfaceCheck = new()
        {
            Id = "interface-code",
            Priority = AuditPriority.P0,
            Area = AuditArea.InterfaceCode,
            Name = "steamui 关键逻辑",
            Level = interfaceFindings > 0 ? AuditLevel.ConfirmedTampering : invariantsPresent ? AuditLevel.Passed : AuditLevel.Incomplete,
            Summary = interfaceFindings > 0
                ? $"命中 {interfaceFindings} 处与假红信一致的语义篡改。"
                : invariantsPresent
                    ? $"已读取 {report.Metrics.JavaScriptFilesChecked} 个脚本，关键动态逻辑仍可见。"
                    : "未发现已支持的篡改特征，但当前 Steam 版本的部分关键结构未能定位。",
            EvidenceCount = interfaceFindings
        };
        if (!httpsCheck)
        {
            report.CoverageNotes.Add("未能稳定定位当前 Steam 版本的 HTTPS 锁图标绘制结构，该项不参与安全结论。");
        }

        AuditCheckResult routeCheck = new()
        {
            Id = "support-routes",
            Priority = AuditPriority.P0,
            Area = AuditArea.SupportRoutes,
            Name = "客服路由域名",
            Level = routeFindings > 0 ? AuditLevel.ConfirmedTampering : routeKeys.Count == RouteKeyNames.Length ? AuditLevel.Passed : AuditLevel.Incomplete,
            Summary = routeFindings > 0
                ? $"发现 {routeFindings} 个指向第三方域名的客服路由证据。"
                : $"观察到 {routeKeys.Count}/{RouteKeyNames.Length} 个目标路由键，未发现其附近写死到第三方域名。",
            EvidenceCount = routeFindings
        };
        return (interfaceCheck, routeCheck);
    }

    public static ScriptAnalysis AnalyzeText(string text)
    {
        List<ScriptSignal> signals = [];
        bool popup = text.Contains("bSupportPopupMessage", StringComparison.Ordinal);
        bool active = text.Contains("bSupportAlertActive", StringComparison.Ordinal);
        bool gameAction = text.Contains("OnGameActionUserRequest", StringComparison.Ordinal);
        bool httpsCheck = text.Contains("startsWith(\"https://\")", StringComparison.Ordinal) ||
                          text.Contains("startsWith('https://')", StringComparison.Ordinal);

        foreach ((string method, string idPrefix, string subject) in new[]
        {
            ("BMustShowSupportAlertDialog", "P0.JS.SUPPORT_POPUP", "官方客服弹窗条件"),
            ("BHasActiveSupportAlerts", "P0.JS.SUPPORT_ALERT", "官方客服告警状态")
        })
        {
            foreach (int index in AllIndexesOf(text, method).Take(20))
            {
                string window = Slice(text, index, 420);
                Match constantReturn = ConstantReturnRegex().Match(window);
                if (!constantReturn.Success || constantReturn.Index > 260) continue;
                string expression = Regex.Replace(constantReturn.Groups["expr"].Value, @"\s+", string.Empty);
                if (!TryEvaluateJavaScriptBoolean(expression, out bool value)) continue;
                string valueLabel = value ? "真值" : "假值";
                string stateLabel = value ? "开启" : "关闭";
                signals.Add(new ScriptSignal(
                    $"{idPrefix}_FORCED_{(value ? "TRUE" : "FALSE")}",
                    AuditLevel.ConfirmedTampering,
                    $"{subject} 被强制设为{stateLabel}",
                    $"{method} 在局部函数体内返回固定{valueLabel}（return {expression}）。",
                    index + constantReturn.Index));
                break;
            }
        }

        foreach (int index in AllIndexesOf(text, "OnGameActionUserRequest").Take(40))
        {
            string window = Slice(text, index, 1200);
            Match call = SupportAlertCallRegex().Match(window);
            if (!call.Success) continue;
            int returnIndex = window.IndexOf("return", call.Index + call.Length, StringComparison.Ordinal);
            int switchIndex = window.IndexOf("switch", StringComparison.Ordinal);
            if (returnIndex >= 0 && returnIndex - (call.Index + call.Length) < 90 && (switchIndex < 0 || call.Index < switchIndex))
            {
                signals.Add(new ScriptSignal(
                    "P0.JS.GAME_REDIRECT",
                    AuditLevel.ConfirmedTampering,
                    "游戏启动处理被改成强制打开客服红信",
                    "OnGameActionUserRequest 在正常分支处理前调用 steam://open/supportalert 并紧接 return。",
                    index + call.Index));
                break;
            }
        }

        foreach (string marker in new[] { "bSecure", "bIsSecure", "isSecure" })
        {
            foreach (int index in AllIndexesOf(text, marker).Take(40))
            {
                string window = Slice(text, index, 260);
                if (!Regex.IsMatch(window, $@"{Regex.Escape(marker)}\s*[:=]\s*(?:!0|true)\b", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100))) continue;
                if (!window.Contains("http", StringComparison.OrdinalIgnoreCase) && !window.Contains("url", StringComparison.OrdinalIgnoreCase)) continue;
                signals.Add(new ScriptSignal(
                    "P0.JS.SECURE_LOCK_FORCED",
                    AuditLevel.HighlySuspicious,
                    "地址安全状态可能被固定为真",
                    "URL/HTTP 相关代码附近将安全状态写成常量 true，需要结合当前 Steam 版本人工复核。",
                    index));
                break;
            }
        }

        foreach (Match hidden in HiddenDisplayRegex().Matches(text).Cast<Match>().Take(80))
        {
            string window = SliceCentered(text, hidden.Index, 1000);
            bool isUrlBar = window.Contains("URLBar", StringComparison.OrdinalIgnoreCase);
            bool hasTrustUi = window.Contains("bIsSecure", StringComparison.Ordinal) ||
                              window.Contains("Browser_NotSecure", StringComparison.Ordinal) ||
                              window.Contains("Browser_Secure", StringComparison.Ordinal);
            if (!isUrlBar || !hasTrustUi) continue;
            signals.Add(new ScriptSignal(
                "P0.JS.URLBAR_HIDDEN",
                AuditLevel.ConfirmedTampering,
                "Steam 内置浏览器地址栏被隐藏",
                "URLBar 与 HTTPS/证书状态绘制逻辑附近被设置为 display:none，用户无法核对实际域名。",
                hidden.Index));
            break;
        }

        HashSet<string> routeKeys = new(StringComparer.Ordinal);
        List<(string Key, string Url)> routeUrls = [];
        foreach (string key in RouteKeyNames)
        {
            foreach (int index in AllIndexesOf(text, key).Take(80))
            {
                routeKeys.Add(key);
            }
        }

        foreach (Match match in RouteAssignmentRegex().Matches(text))
        {
            routeUrls.Add((match.Groups["key"].Value, match.Groups["url"].Value.TrimEnd('.', ',', ';', ')', ']', '}')));
        }

        foreach (Match map in RouteVariableMapRegex().Matches(text))
        {
            string variable = map.Groups["var"].Value;
            int start = Math.Max(0, map.Index - 8000);
            string prefix = text.Substring(start, map.Index - start);
            Match? assignment = UrlVariableAssignmentRegex().Matches(prefix)
                .Cast<Match>()
                .LastOrDefault(item => item.Groups["var"].Value.Equals(variable, StringComparison.Ordinal));
            if (assignment is null) continue;
            routeUrls.Add((map.Groups["key"].Value, assignment.Groups["url"].Value.TrimEnd('.', ',', ';', ')', ']', '}')));
        }

        return new ScriptAnalysis(
            signals.GroupBy(item => item.Id, StringComparer.Ordinal).Select(group => group.First()).ToList(),
            popup,
            active,
            gameAction,
            httpsCheck,
            routeKeys,
            routeUrls.Distinct().ToList());
    }

    private static IEnumerable<string> EnumerateScripts(string steamRoot)
    {
        foreach (string relative in new[] { "steamui", "clientui", Path.Combine("millennium", "plugins") })
        {
            string root = Path.Combine(steamRoot, relative);
            if (!Directory.Exists(root)) continue;
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*.js", SearchOption.AllDirectories); }
            catch { continue; }
            foreach (string file in files) yield return file;
        }
    }

    private static IEnumerable<int> AllIndexesOf(string text, string value)
    {
        int start = 0;
        while (start < text.Length)
        {
            int index = text.IndexOf(value, start, StringComparison.Ordinal);
            if (index < 0) yield break;
            yield return index;
            start = index + value.Length;
        }
    }

    private static string Slice(string text, int index, int length) => text.Substring(index, Math.Min(length, text.Length - index));

    private static string SliceCentered(string text, int index, int radius)
    {
        int start = Math.Max(0, index - radius);
        return text.Substring(start, Math.Min(text.Length - start, radius * 2));
    }

    private static bool TryEvaluateJavaScriptBoolean(string expression, out bool value)
    {
        switch (expression.ToLowerInvariant())
        {
            case "true":
            case "1":
            case "!0":
            case "!!1":
                value = true;
                return true;
            case "false":
            case "0":
            case "!1":
            case "!!0":
                value = false;
                return true;
            default:
                value = false;
                return false;
        }
    }
}
