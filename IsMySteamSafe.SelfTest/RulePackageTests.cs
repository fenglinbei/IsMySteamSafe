using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Reporting;

namespace IsMySteamSafe.SelfTest;

internal static partial class Program
{
    private static async Task<int> VerifyPublishedRulePackageAsync(string packagePath, string resultPath)
    {
        string directory = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-PublishedRules-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var snapshot = KnownContentCatalog.Import(Path.GetFullPath(packagePath), directory);
            Assert(snapshot.Metadata.Notice is null && snapshot.Metadata.Source == "已验证的本地签名包" && snapshot.Metadata.Version == KnownContentCatalog.BuiltInVersion,
                "published rule package identity differs");
            byte[] input = await File.ReadAllBytesAsync(packagePath);
            byte[] active = await File.ReadAllBytesAsync(Path.Combine(directory, "active.rules.json"));
            Assert(input.SequenceEqual(active), "rule import changed signed bytes");
            Assert(KnownContentCatalog.LoadSnapshot(directory).Rules.Count == 48, "published rule count differs");
            string bad = Path.Combine(directory, "tampered.json");
            await File.WriteAllTextAsync(bad, "{}");
            RejectRule(() => KnownContentCatalog.Import(bad, directory), "tampered update over valid package");
            byte[] afterRejected = await File.ReadAllBytesAsync(Path.Combine(directory, "active.rules.json"));
            Assert(active.SequenceEqual(afterRejected), "rejected update changed active rule package");
            var repeated = KnownContentCatalog.Import(packagePath, directory);
            Assert(repeated.Metadata.Version == snapshot.Metadata.Version, "same-version import was not idempotent");
            using (var lease = new FileStream(Path.Combine(directory, "import.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                RejectRule(() => KnownContentCatalog.Import(packagePath, directory), "simultaneous importer");
            byte[] afterBusy = await File.ReadAllBytesAsync(Path.Combine(directory, "active.rules.json"));
            Assert(active.SequenceEqual(afterBusy), "busy import changed active rule package");
            await File.WriteAllTextAsync(resultPath, JsonSerializer.Serialize(new
            {
                schema = "IsMySteamSafe.RulePackageVerification/1", passed = true, version = snapshot.Metadata.Version,
                ruleCount = snapshot.Metadata.RuleCount, keyId = KnownContentCatalog.SigningKeyId,
                packageSha256 = Convert.ToHexString(SHA256.HashData(input)), buildIdentity = IsMySteamSafe.Core.Utilities.StartupCompatibility.BuildIdentity,
                checks = new[] { "pinned-publisher-signature", "schema-version-expiry", "production-import-and-reload", "signed-bytes-preserved", "failed-import-keeps-active", "same-version-idempotent", "concurrent-import-refused" }
            }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("PASS signed rule package: publisher identity, import, reload and rejection preservation");
            return 0;
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static readonly JsonSerializerOptions RuleJson = new(JsonSerializerDefaults.Web);

    private static byte[] TestRuleEnvelope(RulePackagePayload payload, RSA key)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(payload, RuleJson);
        return JsonSerializer.SerializeToUtf8Bytes(new RulePackageEnvelope(1, KnownContentCatalog.SigningKeyId,
            Convert.ToBase64String(bytes), Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))), RuleJson);
    }

    private static void RejectRule(Action action, string detail)
    {
        try { action(); }
        catch (Exception ex) when (ex is InvalidDataException or IOException or CryptographicException or JsonException or ArgumentException or FormatException) { return; }
        throw new InvalidOperationException("Invalid rule package accepted: " + detail);
    }

    private static Task TestRulePackageTrustAsync()
    {
        using RSA key = RSA.Create(2048);
        using RSA otherKey = RSA.Create(2048);
        var now = new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
        var payload = new RulePackagePayload(1, "IsMySteamSafe", KnownContentCatalog.BuiltInVersion + 1,
            "2026-10-02T00:00:00Z", "2027-03-01T00:00:00Z", "0.2.8",
            [new("TEST-ONLY", new string('A', 64), "Inert fixture fingerprint", false)]);
        byte[] package = TestRuleEnvelope(payload, key);
        Assert(KnownContentCatalog.VerifyPackage(package, key, now).Rules.Count == 1, "signed package not verified");
        RejectRule(() => KnownContentCatalog.VerifyPackage(package, otherKey, now), "untrusted key");
        string text = Encoding.UTF8.GetString(package);
        var envelope = JsonSerializer.Deserialize<RulePackageEnvelope>(package, RuleJson)!;
        byte[] tampered = JsonSerializer.SerializeToUtf8Bytes(envelope with { PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("{}")) }, RuleJson);
        RejectRule(() => KnownContentCatalog.VerifyPackage(tampered, key, now), "tampered payload");
        RejectRule(() => KnownContentCatalog.VerifyPackage(Encoding.UTF8.GetBytes(text.Insert(1, "\"schemaVersion\":1,")), key, now), "duplicate JSON properties");
        RejectRule(() => KnownContentCatalog.VerifyPackage(TestRuleEnvelope(payload with { Product = "OtherProduct" }, key), key, now), "wrong product");
        RejectRule(() => KnownContentCatalog.VerifyPackage(TestRuleEnvelope(payload with { Version = KnownContentCatalog.BuiltInVersion - 1 }, key), key, now), "rollback below engine baseline");
        RejectRule(() => KnownContentCatalog.VerifyPackage(TestRuleEnvelope(payload with { MinimumEngineVersion = "99.0.0" }, key), key, now), "future engine");
        RejectRule(() => KnownContentCatalog.VerifyPackage(package, key, now.AddYears(1)), "expired update");
        RejectRule(() => KnownContentCatalog.VerifyPackage(TestRuleEnvelope(payload with { ExpiresAt = "2030-01-01T00:00:00Z" }, key), key, now), "unbounded validity");
        return Task.CompletedTask;
    }

    private static Task TestRulePackageSchemaAsync()
    {
        using RSA key = RSA.Create(2048);
        var good = new KnownContentRule("VALID", new string('A', 64), "Inert test", false, "https://example.invalid/research");
        Assert(KnownContentCatalog.ValidateRules([good]).Count == 1, "rule schema rejects valid record");
        RejectRule(() => KnownContentCatalog.ValidateRules([good, good]), "duplicate hash and id");
        RejectRule(() => KnownContentCatalog.ValidateRules([good with { Sha256 = "not-a-digest" }]), "malformed hash");
        RejectRule(() => KnownContentCatalog.ValidateRules([good with { SourceUrl = "file:///c:/fixture" }]), "unsafe provenance URL");
        RejectRule(() => KnownContentCatalog.ValidateRules([good with { Label = "new\nline" }]), "control characters");
        RejectRule(() => KnownContentCatalog.ValidateRules([]), "empty rule set");
        RejectRule(() => KnownContentCatalog.VerifyPackage(new byte[KnownContentCatalog.MaximumPackageBytes + 1], key, DateTimeOffset.UtcNow), "oversized package");
        var builtinRule = KnownContentCatalog.LoadSnapshot(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))).Rules.Values.First(r => r.Malware);
        RejectRule(() => KnownContentCatalog.MergeRules([builtinRule with { Malware = false }]), "weakening builtin rule");
        RejectRule(() => KnownContentCatalog.MergeRules([builtinRule with { Sha256 = new string('B', 64) }]), "reusing builtin id");
        Assert(KnownContentCatalog.MergeRules([good]).Count == 49, "additive update discarded builtin catalog");
        var current = new KnownContentSnapshot(KnownContentCatalog.MergeRules([good]), new(KnownContentCatalog.BuiltInVersion + 2, "2026-10-02", "test", 49));
        RejectRule(() => KnownContentCatalog.ValidateTransition(current, KnownContentCatalog.BuiltInVersion + 1, current.Rules), "rollback from an imported version");
        RejectRule(() => KnownContentCatalog.ValidateTransition(current, KnownContentCatalog.BuiltInVersion + 3, KnownContentCatalog.MergeRules([builtinRule])), "removal of a previous external rule");
        KnownContentCatalog.ValidateTransition(current, KnownContentCatalog.BuiltInVersion + 3, current.Rules);
        return Task.CompletedTask;
    }

    private static async Task TestRulePackageFallbackAsync()
    {
        string directory = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-RuleTest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var builtin = KnownContentCatalog.LoadSnapshot(directory);
            Assert(builtin.Rules.Count == 48 && builtin.Metadata.Notice is null, "builtin catalog baseline mismatch");
            string active = Path.Combine(directory, "active.rules.json");
            await File.WriteAllTextAsync(active, "{invalid");
            var fallback = KnownContentCatalog.LoadSnapshot(directory);
            Assert(fallback.Rules.Count == 48 && fallback.Metadata.Notice is not null && fallback.Metadata.Version == KnownContentCatalog.BuiltInVersion,
                "invalid local update hid coverage or disabled builtin rules");
            byte[] before = await File.ReadAllBytesAsync(active);
            RejectRule(() => KnownContentCatalog.Import(active, directory), "invalid local import");
            byte[] after = await File.ReadAllBytesAsync(active);
            Assert(before.SequenceEqual(after), "failed import modified previous bytes");
            await File.WriteAllTextAsync(active, "{}");
            Assert(KnownContentCatalog.LoadSnapshot(directory).Metadata.Notice is not null, "invalid schema did not fall back visibly");
            var report = new AuditReport { RuleSet = fallback.Metadata };
            Assert(ReportExporter.BuildJson(report).Contains("ruleSet") && ReportExporter.BuildMarkdown(report).Contains(KnownContentCatalog.BuiltInVersion.ToString()),
                "rule provenance missing from exports");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }
}
