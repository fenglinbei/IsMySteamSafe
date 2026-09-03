using System.Text.Json;
using System.IO.Compression;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Reporting;
using IsMySteamSafe.Core.Steam;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.SelfTest;

internal static class Program
{
    private static int _passed;
    private static int _failed;

    private static async Task<int> Main(string[] args)
    {
        if (args is ["--analyze-script", string path])
        {
            string text = await FileUtilities.ReadTextBoundedAsync(Path.GetFullPath(path));
            ScriptAnalysis analysis = JavaScriptAuditor.AnalyzeText(text);
            foreach (ScriptSignal signal in analysis.Signals)
                Console.WriteLine($"SIGNAL|{signal.Id}|{signal.Level}|{signal.Title}|{signal.Detail}");
            foreach ((string key, string url) in analysis.RouteUrls)
                Console.WriteLine($"ROUTE|{key}|{FileUtilities.RedactSensitiveText(url)}");
            return analysis.Signals.Count > 0 && analysis.RouteUrls.Count > 0 ? 0 : 1;
        }
        if (args.Length is 2 or 3 && args[0].Equals("--export-evidence", StringComparison.Ordinal))
        {
            IReadOnlyList<string> roots = args.Length == 3 ? [Path.GetFullPath(args[2])] : Array.Empty<string>();
            AuditReport report = await new SteamAuditCoordinator().RunAsync(new SteamAuditOptions(IncludeExtendedChecks: true));
            EvidenceExportResult result = await EvidenceBundleExporter.ExportAsync(report, new EvidenceBundleOptions(roots), Path.GetFullPath(args[1]));
            Console.WriteLine($"PATH={result.Path}");
            Console.WriteLine($"SHA256={result.Sha256}");
            Console.WriteLine($"SIZE={result.Size}");
            Console.WriteLine($"BUNDLE={result.BundleId:N}");
            return 0;
        }

        List<(string Name, Func<Task> Test)> tests =
        [
            ("official support URL", () => Sync(() => AssertTrust("https://help.steampowered.com/zh-cn/", UrlTrustLevel.OfficialSupport))),
            ("official host is case insensitive", () => Sync(() => AssertTrust("https://HELP.STEAMPOWERED.COM/", UrlTrustLevel.OfficialSupport))),
            ("bare official host", () => Sync(() => AssertTrust("help.steampowered.com/help", UrlTrustLevel.OfficialSupport))),
            ("HTTP support link needs review", () => Sync(() => AssertTrust("http://help.steampowered.com/", UrlTrustLevel.SteamOwnedDomain))),
            ("other steampowered host", () => Sync(() => AssertTrust("https://store.steampowered.com/about/", UrlTrustLevel.SteamOwnedDomain))),
            ("lookalike suffix rejected", () => Sync(() => AssertTrust("https://help.steampowered.com.evil.example/pay", UrlTrustLevel.NotSteamOwned))),
            ("userinfo deception rejected", () => Sync(() => AssertTrust("https://help.steampowered.com@evil.example/pay", UrlTrustLevel.NotSteamOwned))),
            ("non Steam host rejected", () => Sync(() => AssertTrust("https://steam-support.example/pay", UrlTrustLevel.NotSteamOwned))),
            ("HTML entity decoding", () => Sync(() => Assert(SupportUrlInspector.Inspect("<a href=&quot;https://help.steampowered.com/&quot;>客服</a>").OverallTrust == UrlTrustLevel.OfficialSupport, "HTML URL not decoded"))),
            ("multiple URL risk wins", () => Sync(() => Assert(SupportUrlInspector.Inspect("https://help.steampowered.com/ https://evil.example/").OverallTrust == UrlTrustLevel.NotSteamOwned, "external URL should win"))),
            ("invalid input", () => Sync(() => Assert(SupportUrlInspector.Inspect("联系客服").OverallTrust == UrlTrustLevel.Invalid, "invalid text accepted"))),
            ("domain boundary", () => Sync(TestDomainBoundary)),
            ("normal JS semantics", () => Sync(TestNormalScript)),
            ("forced true support popup detected", () => Sync(TestForcedTruePopup)),
            ("forced false support popup detected", () => Sync(TestForcedFalsePopup)),
            ("game redirect detected", () => Sync(TestGameRedirect)),
            ("third-party support route extracted", () => Sync(TestThirdPartyRoute)),
            ("indirect variable support route extracted", () => Sync(TestIndirectThirdPartyRoute)),
            ("unrelated nearby URL is not a route", () => Sync(TestUnrelatedUrlNotMapped)),
            ("quoted route map extracted", () => Sync(TestQuotedRouteMap)),
            ("hidden Steam URL bar detected", () => Sync(TestHiddenUrlBar)),
            ("evidence redaction", () => Sync(TestEvidenceRedaction)),
            ("path containment boundary", () => Sync(TestPathContainment)),
            ("multi-library Wallpaper path correlation", () => Sync(TestWallpaperPathCorrelation)),
            ("steam cfg update suppression detected", TestSteamCfgAsync),
            ("version forwarder pair is decisive", TestVersionForwarderPairAsync),
            ("acknowledged Millennium loader is review", TestAcknowledgedMillenniumAsync),
            ("installed Steam has Valve signature", () => Sync(TestInstalledSteamSignature)),
            ("report exporters", TestReportExportAsync),
            ("read-only evidence bundle exporter", TestEvidenceBundleExportAsync),
            ("live audit completes", TestLiveAuditAsync)
        ];

        foreach ((string name, Func<Task> test) in tests)
        {
            try
            {
                await test();
                _passed++;
                Console.WriteLine($"PASS  {name}");
            }
            catch (Exception ex)
            {
                _failed++;
                Console.WriteLine($"FAIL  {name}: {ex.Message}");
            }
        }

        Console.WriteLine();
        Console.WriteLine($"RESULT {_passed}/{tests.Count} passed, {_failed} failed");
        return _failed == 0 ? 0 : 1;
    }

    private static Task Sync(Action action)
    {
        action();
        return Task.CompletedTask;
    }

    private static void AssertTrust(string input, UrlTrustLevel expected)
    {
        UrlInspectionResult result = SupportUrlInspector.Inspect(input);
        Assert(result.OverallTrust == expected, $"expected {expected}, got {result.OverallTrust}");
    }

    private static void TestDomainBoundary()
    {
        Assert(SupportUrlInspector.IsSteamPoweredHost("help.steampowered.com"), "official subdomain rejected");
        Assert(SupportUrlInspector.IsSteamPoweredHost("steampowered.com"), "root domain rejected");
        Assert(!SupportUrlInspector.IsSteamPoweredHost("steampowered.com.evil.example"), "lookalike accepted");
        Assert(!SupportUrlInspector.IsSteamPoweredHost("notsteampowered.com"), "substring accepted");
    }

    private static void TestNormalScript()
    {
        const string script = "class X{BMustShowSupportAlertDialog(){return!!this.m_CurrentUser?.bSupportPopupMessage}BHasActiveSupportAlerts(){return!!this.m_CurrentUser?.bSupportAlertActive}OnGameActionUserRequest(e){switch(e){case 1:return}}}const secure=a.startsWith(\"https://\");const routes=['SupportMessages','HelpAppPage','HelpFrontPage'];";
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText(script);
        Assert(result.Signals.Count == 0, "normal script raised a signal");
        Assert(result.HasSupportPopupReference && result.HasSupportActiveReference && result.HasGameActionHandler, "normal invariants missing");
        Assert(result.RouteKeys.Count == 3, "route keys missing");
    }

    private static void TestForcedTruePopup()
    {
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText("BMustShowSupportAlertDialog(){return!0;} bSupportPopupMessage");
        ScriptSignal signal = result.Signals.Single(item => item.Id == "P0.JS.SUPPORT_POPUP_FORCED_TRUE");
        Assert(signal.Title.Contains("开启", StringComparison.Ordinal), "return !0 was not described as true");
    }

    private static void TestForcedFalsePopup()
    {
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText("BMustShowSupportAlertDialog(){return!!0;} bSupportPopupMessage");
        ScriptSignal signal = result.Signals.Single(item => item.Id == "P0.JS.SUPPORT_POPUP_FORCED_FALSE");
        Assert(signal.Title.Contains("关闭", StringComparison.Ordinal), "return !!0 was not described as false");
    }

    private static void TestGameRedirect()
    {
        const string script = "async OnGameActionUserRequest(e,t){SteamClient.URL.ExecuteSteamURL(\"steam://open/supportalert\");return;switch(t){case 1:break;}}";
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText(script);
        Assert(result.Signals.Any(item => item.Id == "P0.JS.GAME_REDIRECT"), "game redirect not detected");
    }

    private static void TestThirdPartyRoute()
    {
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText("const SupportMessages='https://evil.example/support';");
        Assert(result.RouteUrls.Any(item => item.Key == "SupportMessages" && item.Url.Contains("evil.example", StringComparison.Ordinal)), "route URL not extracted");
    }

    private static void TestIndirectThirdPartyRoute()
    {
        const string script = "let i=r.url,_h=\"https://luminovastella.top/steamhelper?d=76561198700358719&a=\",_s=\"https://luminovastella.top/steamhelper.html?u=account&d=76561198700358719&a=\";return ({SupportMessages:_s,HelpAppPage:_h,HelpFrontPage:_h})[e]??i";
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText(script);
        Assert(result.RouteUrls.Count(item => item.Url.Contains("luminovastella.top", StringComparison.Ordinal)) == 3, "indirect route map was not resolved");
    }

    private static void TestUnrelatedUrlNotMapped()
    {
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText("const keys=['SupportMessages'];const unrelated='https://analytics.example/pixel';");
        Assert(result.RouteUrls.Count == 0, "unrelated nearby URL was treated as route mapping");
    }

    private static void TestQuotedRouteMap()
    {
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText("const routes={\"HelpFrontPage\":\"https://fake-support.example/\"};");
        Assert(result.RouteUrls.Any(item => item.Key == "HelpFrontPage" && item.Url.Contains("fake-support.example", StringComparison.Ordinal)), "quoted map not extracted");
    }

    private static void TestHiddenUrlBar()
    {
        const string script = "return jsx(\"div\",{style:{display:\"none\"},className:styles.URLBar,children:[m?.bIsSecure,loc(\"#Browser_NotSecure\")]});";
        ScriptAnalysis result = JavaScriptAuditor.AnalyzeText(script);
        Assert(result.Signals.Any(item => item.Id == "P0.JS.URLBAR_HIDDEN"), "hidden URL bar not detected");
    }

    private static void TestEvidenceRedaction()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string input = $"{profile}\\Desktop\\x C:\\Users\\AnotherUser\\sample https://example.test/?u=name&d=76561198700358719&a=ok 76561198700358719";
        string output = FileUtilities.RedactSensitiveText(input);
        Assert(!output.Contains(profile, StringComparison.OrdinalIgnoreCase), "user profile was not redacted");
        Assert(!output.Contains("AnotherUser", StringComparison.OrdinalIgnoreCase), "foreign user profile was not redacted");
        Assert(!output.Contains("76561198700358719", StringComparison.Ordinal), "SteamID was not redacted");
        Assert(output.Contains("u=[REDACTED]", StringComparison.Ordinal) && output.Contains("d=[REDACTED]", StringComparison.Ordinal), "URL parameters were not redacted");
    }

    private static async Task TestSteamCfgAsync()
    {
        string root = CreateTempSteam();
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "steam.cfg"), "BootStrapperInhibitAll=enable\nBootStrapperForceSelfUpdate=disable\n");
            AuditReport report = new();
            AuditCheckResult check = await SteamConfigurationAuditor.AuditAsync(root, report, CancellationToken.None);
            Assert(check.Level == AuditLevel.HighlySuspicious, $"unexpected steam.cfg level {check.Level}");
            Assert(report.Findings.Any(item => item.Id == "P1.CONFIG.STEAM_UPDATE_SUPPRESSED"), "steam.cfg pair finding absent");
        }
        finally
        {
            DeleteOwnTemp(root);
        }
    }

    private static void TestPathContainment()
    {
        string root = Path.Combine(Path.GetTempPath(), "safe-root");
        Assert(FileUtilities.IsWithin(Path.Combine(root, "child", "file.dll"), root), "child rejected");
        Assert(!FileUtilities.IsWithin(root + "-lookalike" + Path.DirectorySeparatorChar + "file.dll", root), "prefix lookalike accepted");
    }

    private static void TestWallpaperPathCorrelation()
    {
        SteamLayout layout = new();
        layout.SteamRoots.Add(@"C:\Program Files (x86)\Steam");
        layout.WorkshopRoots.Add(@"L:\SteamLibrary\steamapps\workshop\content\431960");
        layout.WallpaperProjectRoots.Add(@"M:\Games\wallpaper_engine\projects");

        string workshopExecutable = @"L:\SteamLibrary\steamapps\workshop\content\431960\3437694514\vid_720p\ServiceApp.exe";
        Assert(SteamPathClassifier.IsWallpaperContentPath(layout, workshopExecutable), "non-primary Workshop process path was not correlated");
        Assert(SteamPathClassifier.CommandReferencesWallpaperContent(layout, $"\"{workshopExecutable}\""), "Workshop Run command was not correlated");
        Assert(SteamPathClassifier.CommandReferencesWallpaperContent(layout, @"M:\Games\wallpaper_engine\projects\custom\helper.exe"), "local Wallpaper project command was not correlated");
        Assert(!SteamPathClassifier.CommandReferencesWallpaperContent(layout, @"L:\SteamLibrary-copy\steamapps\workshop\content\431960\ServiceApp.exe"), "lookalike library prefix was accepted");
        Assert(SteamPathClassifier.CommandReferencesSteamInstallation(layout, "\"C:\\Program Files (x86)\\Steam\\steam.exe\" -silent"), "Steam installation command was not correlated");
    }

    private static void TestInstalledSteamSignature()
    {
        string? root = SteamLocator.Discover().PrimarySteamRoot;
        if (root is null) return;
        string executable = Path.Combine(root, "steam.exe");
        if (!File.Exists(executable)) return;
        SignatureResult signature = AuthenticodeVerifier.Verify(executable);
        Assert(signature.Status == SignatureStatus.Valid, $"unexpected Steam signature status {signature.Status}: {signature.Detail}");
        Assert(signature.IsValveSigner, $"unexpected Steam signer: {signature.Subject ?? "none"}");
    }

    private static async Task TestVersionForwarderPairAsync()
    {
        string root = CreateTempSteam();
        try
        {
            string cef = Path.Combine(root, "bin", "cef", "cef.win7x64");
            Directory.CreateDirectory(cef);
            await File.WriteAllTextAsync(Path.Combine(cef, "version.dll"), "proxy");
            await File.WriteAllTextAsync(Path.Combine(cef, "versionOrg.dll"), "original");
            AuditReport report = new();
            AuditCheckResult check = await SteamClientFileAuditor.AuditAsync(root, new SteamAuditOptions(), report, CancellationToken.None);
            Assert(check.Level == AuditLevel.ConfirmedTampering, $"unexpected level {check.Level}");
            Assert(report.Findings.Any(item => item.Id == "P0.DLL.VERSION_FORWARDER"), "pair finding absent");
        }
        finally
        {
            DeleteOwnTemp(root);
        }
    }

    private static async Task TestAcknowledgedMillenniumAsync()
    {
        string root = CreateTempSteam();
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "millennium", "plugins"));
            await File.WriteAllTextAsync(Path.Combine(root, "wsock32.dll"), "loader");
            AuditReport report = new();
            AuditCheckResult check = await SteamClientFileAuditor.AuditAsync(root, new SteamAuditOptions(UserAcknowledgesClientMods: true), report, CancellationToken.None);
            Assert(check.Level == AuditLevel.NeedsReview, $"expected review, got {check.Level}");
        }
        finally
        {
            DeleteOwnTemp(root);
        }
    }

    private static async Task TestReportExportAsync()
    {
        string directory = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            AuditReport report = new() { CompletedAt = DateTimeOffset.Now, Conclusion = AuditConclusion.NoTamperingFound };
            report.Checks.Add(new AuditCheckResult { Id = "test", Priority = AuditPriority.P0, Area = AuditArea.ClientFiles, Name = "测试", Level = AuditLevel.Passed, Summary = "通过", EvidenceCount = 0 });
            string markdown = Path.Combine(directory, "report.md");
            string json = Path.Combine(directory, "report.json");
            await ReportExporter.ExportMarkdownAsync(report, markdown);
            await ReportExporter.ExportJsonAsync(report, json);
            Assert((await File.ReadAllTextAsync(markdown)).Contains("未发现 Steam 客户端篡改迹象", StringComparison.Ordinal), "markdown content missing");
            using JsonDocument document = JsonDocument.Parse(await File.ReadAllTextAsync(json));
            Assert(document.RootElement.GetProperty("conclusion").GetString() == "NoTamperingFound", "json enum mismatch");
        }
        finally
        {
            DeleteOwnTemp(directory);
        }
    }

    private static async Task TestLiveAuditAsync()
    {
        SteamAuditCoordinator coordinator = new();
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(45));
        AuditReport report = await coordinator.RunAsync(new SteamAuditOptions(IncludeExtendedChecks: true), cancellationToken: timeout.Token);
        Assert(report.CompletedAt is not null, "audit did not complete");
        Assert(report.Checks.Count >= 6, "expected checks missing");
        Console.WriteLine($"      live conclusion: {report.Conclusion}, checks={report.Checks.Count}, findings={report.Findings.Count}");
    }

    private static async Task TestEvidenceBundleExportAsync()
    {
        string directory = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "evidence.zip");
        try
        {
            EvidenceExportResult result = await EvidenceBundleExporter.ExportAsync(null, EvidenceBundleOptions.Default, path);
            Assert(File.Exists(path) && result.Size > 0, "evidence ZIP was not created");
            using ZipArchive archive = ZipFile.OpenRead(path);
            string[] required = ["README.txt", "manifest.json", "coverage.csv", "processes.csv", "tcp-ipv4.csv", "files.csv"];
            foreach (string name in required) Assert(archive.GetEntry(name) is not null, $"evidence entry missing: {name}");
            Assert(archive.Entries.All(item => !item.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !item.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)), "binary sample copied into evidence ZIP");
            using Stream manifestStream = archive.GetEntry("manifest.json")!.Open();
            using JsonDocument manifest = await JsonDocument.ParseAsync(manifestStream);
            Assert(manifest.RootElement.GetProperty("schemaVersion").GetString() == "1.1", "unexpected evidence schema version");
            JsonElement environment = manifest.RootElement.GetProperty("environment");
            Assert(environment.TryGetProperty("libraryRoots", out _) && environment.TryGetProperty("workshopRoots", out _), "multi-library roots missing from evidence manifest");
        }
        finally
        {
            DeleteOwnTemp(directory);
        }
    }

    private static string CreateTempSteam()
    {
        string root = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "steam.exe"), "fixture");
        return root;
    }

    private static void DeleteOwnTemp(string path)
    {
        string full = Path.GetFullPath(path);
        string temp = Path.GetFullPath(Path.GetTempPath());
        if (!full.StartsWith(temp, StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(full).StartsWith("IsMySteamSafe-selftest-", StringComparison.Ordinal))
            throw new InvalidOperationException("Refusing to delete a non-self-test directory.");
        if (Directory.Exists(full)) Directory.Delete(full, recursive: true);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
