using System.Security.Cryptography;
using System.Text.Json;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Reporting;
using IsMySteamSafe.Core.Steam;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.SelfTest;

internal static partial class Program
{
    private static async Task TestExpandedContentAsync()
    {
        string root = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-Coverage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            SteamLayout layout = new();
            foreach (string name in new[] { "one", "two" }) { string lib = Path.Combine(root, name); Directory.CreateDirectory(lib); layout.LibraryRoots.Add(lib); }
            layout.SteamRoots.Add(layout.LibraryRoots[0]);
            foreach (var (lib, app) in new[] { (0, "431960"), (0, "3167020"), (1, "4000") })
            {
                string folder = Path.Combine(layout.LibraryRoots[lib], "steamapps", "workshop", "content", app, "123456"); Directory.CreateDirectory(folder);
                await File.WriteAllTextAsync(Path.Combine(folder, "normal.dll"), "not executable, test fixture");
            }
            ContentDiscovery.Populate(layout);
            Assert(layout.WorkshopRoots.Count == 3, "all app IDs not discovered");
            string target = Path.Combine(layout.WorkshopRoots.First(r => r.EndsWith("3167020")), "123456", "normal.dll");
            Assert(!SteamPathClassifier.IsWallpaperContentPath(layout, target) && SteamPathClassifier.IsSteamContentPath(layout, target), "ordinary game classified as Wallpaper");
            AuditReport normal = new();
            normal.Checks.Add(await LightContentAuditor.AuditAsync(layout, normal, default)); normal.RecalculateConclusion();
            Assert(normal.Findings.Count == 0 && normal.Conclusion == AuditConclusion.NoTamperingFound, "normal MOD executable name triggered a threat");
            Assert(normal.ContentSources.Count == 3, "source roots missing");
            AuditReport metadata = new(); WorkshopSourceObserver.Observe(layout, metadata, default);
            Assert(metadata.Metrics.WorkshopItemsObserved == 3 && metadata.Findings.Single().WhatFound.Contains("1 个属于 Wallpaper"), "source counts mislabeled");
            string hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(target)));
            Dictionary<string, KnownContentRule> fixture = new() { [hash] = new("fixture", hash, "无害测试匹配项", true) };
            AuditReport found = new();
            found.Checks.Add(await LightContentAuditor.AuditAsync(layout, found, default, knownRules: fixture)); found.RecalculateConclusion();
            Assert(found.Conclusion == AuditConclusion.ContentRiskFound && found.Findings.All(f => f.EvidenceState == "file-present"), "file presence confused with execution or tampering");
            AuditReport limited = new(); limited.Checks.Add(await LightContentAuditor.AuditAsync(layout, limited, default, maximumBytes: 1)); limited.RecalculateConclusion();
            Assert(limited.Conclusion == AuditConclusion.NoTamperingFound && limited.ContentLimitations.Any(n => n.Kind.Contains("预算")), "scope limit confused with execution failure or hidden");
            AuditComparison comparison = AuditComparison.Compare(found, normal);
            Assert(comparison.NotObservedAgain == 3 && comparison.Summary.Contains("不等于"), "comparison overclaims cleanup");
            Assert(LightContentAuditor.MatchHash("FA00800B88631999E53071FA299932DD38865DD1D2F0B30FF66BD4260D338B59")?.Malware == true, "MOD loading entry missing");
            Assert(LightContentAuditor.MatchHash("0BE00202A0427A85A772B95092FCE44F4E653023092E7A3BC7FBAC7FC7624604")?.Malware == true, "Lua component missing");
            Assert(LightContentAuditor.MatchHash("5126F4C04C21F04F97515155875D6F8B409632BD9FF6B07F59EE4401FA8B654C")?.Malware == false, "uncertain MSI upgraded to malware");
        }
        finally
        {
            if (ContentDiscovery.IsWithin(root, Path.GetTempPath()) && ContentDiscovery.IsLocalSafePath(root)) Directory.Delete(root, true);
        }
    }

    private static void TestExpandedPrivacy()
    {
        string text = FileUtilities.RedactSensitiveText("token=secret-value password='two words' https://example.invalid/?sessionid=private&x=private");
        Assert(!text.Contains("secret-value") && !text.Contains("two words") && !text.Contains("private"), "secret text leaked");
        string json = JsonRedaction.Redact("{\"password\":\"two words\",\"detail\":\"token=secret\",\"array\":[\"https://example.invalid/?x=private\"]}");
        using JsonDocument document = JsonDocument.Parse(json);
        Assert(document.RootElement.GetProperty("password").GetString() == "[REDACTED]" && !json.Contains("private") && !json.Contains("two words"), "JSON redaction broke structure or leaked");
        Assert(!EvidenceBundleOptions.Default.IncludeRunHistory, "run history must be opt-in");
        Assert(ScriptSignals.Analyze("normal millennium plugin https://example.invalid/docs").Count == 0, "normal plugin false positive");
    }
}
