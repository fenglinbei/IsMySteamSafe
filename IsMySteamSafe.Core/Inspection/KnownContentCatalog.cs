using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.Core.Inspection;

public sealed record KnownContentRule(string Id, string Sha256, string Label, bool Malware, string? SourceUrl = null);
public sealed record KnownContentSnapshot(IReadOnlyDictionary<string, KnownContentRule> Rules, RuleSetInfo Metadata);
public sealed record RulePackagePayload(int SchemaVersion, string Product, long Version, string PublishedAt,
    string ExpiresAt, string MinimumEngineVersion, List<KnownContentRule> Rules);
public sealed record RulePackageEnvelope(int SchemaVersion, string KeyId, string PayloadBase64, string SignatureBase64);

/// <summary>Local, data-only updates. Trust comes from the embedded publisher key, never from an imported certificate.</summary>
public static class KnownContentCatalog
{
    public const long BuiltInVersion = 2026100201;
    public const string BuiltInPublishedAt = "2026-10-02T00:00:00Z";
    public const string SigningKeyId = "3395882D18D66EFA1545C1FE6DD867EB004176D1";
    public const int MaximumPackageBytes = 3 * 1024 * 1024;
    private static readonly object ImportLock = new();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false, MaxDepth = 12,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private static readonly Lazy<IReadOnlyDictionary<string, KnownContentRule>> BuiltIn = new(() =>
    {
        using Stream stream = typeof(KnownContentCatalog).Assembly.GetManifestResourceStream("IsMySteamSafe.Core.Inspection.known-content.json")!;
        var rules = JsonSerializer.Deserialize<List<KnownContentRule>>(stream, JsonOptions) ?? throw new InvalidDataException("内置规则为空。");
        return ValidateRules(rules);
    });
    public static string DefaultDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IsMySteamSafe", "Rules");

    public static KnownContentSnapshot LoadSnapshot(string? directory = null)
    {
        var snapshot = new KnownContentSnapshot(BuiltIn.Value, new(BuiltInVersion, BuiltInPublishedAt, "内置", BuiltIn.Value.Count));
        string path = Path.Combine(directory ?? DefaultDirectory, "active.rules.json");
        try
        {
            // GetAttributes distinguishes an absent file from a present but unreadable/re-directed update.
            try { _ = File.GetAttributes(path); }
            catch (FileNotFoundException) { return snapshot; }
            catch (DirectoryNotFoundException) { return snapshot; }
            using RSA key = PublisherKey();
            RulePackagePayload payload = VerifyPackage(ReadLocalBytes(path), key, DateTimeOffset.UtcNow);
            var merged = MergeRules(payload.Rules);
            return new(merged, new(payload.Version, payload.PublishedAt, "已验证的本地签名包", merged.Count));
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException or CryptographicException or JsonException or ArgumentException or FormatException)
        {
            return snapshot with { Metadata = snapshot.Metadata with { Notice = "本地规则更新未通过读取、签名、版本或有效期验证；本次仅使用内置规则，请重新导入官方规则包。" } };
        }
    }

    public static KnownContentSnapshot Import(string packagePath, string? directory = null)
    {
        byte[] bytes = ReadLocalBytes(packagePath);
        using RSA key = PublisherKey();
        RulePackagePayload payload = VerifyPackage(bytes, key, DateTimeOffset.UtcNow);
        var incoming = MergeRules(payload.Rules);
        string targetDirectory = Path.GetFullPath(directory ?? DefaultDirectory);
        lock (ImportLock)
        {
            EnsureLocal(targetDirectory);
            Directory.CreateDirectory(targetDirectory);
            EnsureLocal(targetDirectory);
            string lockPath = Path.Combine(targetDirectory, "import.lock");
            EnsureLocal(lockPath);
            // The application may have multiple instances. Keep the version check and
            // replacement in one cross-process transaction; a busy importer fails safely.
            using var importLease = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            KnownContentSnapshot current = LoadSnapshot(targetDirectory);
            ValidateTransition(current, payload.Version, incoming);
            if (payload.Version == current.Metadata.Version)
            {
                if (!SameRules(incoming, current.Rules)) throw new InvalidDataException("同版本规则内容冲突，请获取新版规则包。");
                if (current.Metadata.Notice is null && current.Metadata.Source != "内置") return current;
            }
            string active = Path.Combine(targetDirectory, "active.rules.json");
            EnsureLocal(active);
            string temporary = Path.Combine(targetDirectory, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { stream.Write(bytes); stream.Flush(true); }
                EnsureLocal(active);
                File.Move(temporary, active, overwrite: true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            return LoadSnapshot(targetDirectory);
        }
    }

    // Public only to make the cryptographic contract independently testable with an ephemeral test key.
    // Production load/import always supply PublisherKey() above; callers cannot persist an arbitrary key.
    public static RulePackagePayload VerifyPackage(byte[] bytes, RSA publicKey, DateTimeOffset now)
    {
        if (bytes.Length is 0 or > MaximumPackageBytes) throw new InvalidDataException("规则包大小不符合限制。");
        RejectDuplicateProperties(bytes);
        var envelope = JsonSerializer.Deserialize<RulePackageEnvelope>(bytes, JsonOptions) ?? throw new InvalidDataException("规则包为空。");
        if (envelope.SchemaVersion != 1 || envelope.KeyId != SigningKeyId || envelope.PayloadBase64 is null || envelope.SignatureBase64 is null)
            throw new InvalidDataException("不支持的规则包格式或签名身份。");
        byte[] payloadBytes = Convert.FromBase64String(envelope.PayloadBase64);
        byte[] signature = Convert.FromBase64String(envelope.SignatureBase64);
        if (payloadBytes.Length is 0 or > 2 * 1024 * 1024 || signature.Length != publicKey.KeySize / 8 ||
            !publicKey.VerifyData(payloadBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("规则包签名校验失败。");
        RejectDuplicateProperties(payloadBytes);
        var payload = JsonSerializer.Deserialize<RulePackagePayload>(payloadBytes, JsonOptions) ?? throw new InvalidDataException("规则数据为空。");
        if (payload.SchemaVersion != 1 || payload.Product != "IsMySteamSafe" || payload.Version < BuiltInVersion ||
            !Version.TryParse(payload.MinimumEngineVersion, out Version? minimum) || minimum > Version.Parse(ProductInfo.Version) ||
            !DateTimeOffset.TryParse(payload.PublishedAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var published) ||
            !DateTimeOffset.TryParse(payload.ExpiresAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var expires) ||
            published > now.AddDays(2) || expires <= now || expires <= published || expires - published > TimeSpan.FromDays(366))
            throw new InvalidDataException("规则包产品、版本、日期或引擎要求不符合要求。");
        _ = ValidateRules(payload.Rules);
        return payload;
    }

    public static IReadOnlyDictionary<string, KnownContentRule> ValidateRules(IReadOnlyList<KnownContentRule>? rules)
    {
        if (rules is null || rules.Count is 0 or > 4096) throw new InvalidDataException("规则数量不符合限制。");
        var result = new Dictionary<string, KnownContentRule>(StringComparer.OrdinalIgnoreCase);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in rules)
        {
            if (rule is null || string.IsNullOrWhiteSpace(rule.Id) || rule.Id.Length > 96 || !rule.Id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') ||
                rule.Sha256 is null || rule.Sha256.Length != 64 || !rule.Sha256.All(char.IsAsciiHexDigit) ||
                string.IsNullOrWhiteSpace(rule.Label) || rule.Label.Length > 240 || rule.Label.Any(char.IsControl) || !ids.Add(rule.Id) ||
                !result.TryAdd(rule.Sha256, rule)) throw new InvalidDataException("规则标识、指纹、标签或重复项无效。");
            if (rule.SourceUrl is not null && (rule.SourceUrl.Length > 1024 || !Uri.TryCreate(rule.SourceUrl, UriKind.Absolute, out var url) || url.Scheme != "https" || !string.IsNullOrEmpty(url.UserInfo)))
                throw new InvalidDataException("规则来源链接无效。");
        }
        return new ReadOnlyDictionary<string, KnownContentRule>(result);
    }

    internal static IReadOnlyDictionary<string, KnownContentRule> MergeRules(IReadOnlyList<KnownContentRule> rules)
    {
        var merged = new Dictionary<string, KnownContentRule>(BuiltIn.Value, StringComparer.OrdinalIgnoreCase);
        foreach (var rule in ValidateRules(rules).Values)
        {
            if (merged.TryGetValue(rule.Sha256, out var original) && original != rule) throw new InvalidDataException("更新包不能改写内置规则。");
            if (merged.Values.Any(r => r.Id == rule.Id && !r.Sha256.Equals(rule.Sha256, StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("更新包规则标识冲突。");
            merged[rule.Sha256] = rule;
        }
        return new ReadOnlyDictionary<string, KnownContentRule>(merged);
    }

    private static bool SameRules(IReadOnlyDictionary<string, KnownContentRule> first, IReadOnlyDictionary<string, KnownContentRule> second) =>
        first.Count == second.Count && first.All(pair => second.TryGetValue(pair.Key, out var other) && pair.Value == other);
    internal static void ValidateTransition(KnownContentSnapshot current, long nextVersion, IReadOnlyDictionary<string, KnownContentRule> next)
    {
        if (nextVersion < current.Metadata.Version) throw new InvalidDataException("拒绝导入比当前规则更旧的规则包。");
        if (current.Rules.Any(pair => !next.TryGetValue(pair.Key, out var rule) || rule != pair.Value))
            throw new InvalidDataException("更新包不能移除或改写当前有效规则。");
    }
    private static RSA PublisherKey()
    {
        using Stream source = typeof(KnownContentCatalog).Assembly.GetManifestResourceStream("IsMySteamSafe.Core.Inspection.rule-signing.cer")!;
        using MemoryStream buffer = new(); source.CopyTo(buffer);
        using var certificate = X509CertificateLoader.LoadCertificate(buffer.ToArray());
        if (certificate.Thumbprint != SigningKeyId) throw new CryptographicException("内置信任身份不一致。");
        return certificate.GetRSAPublicKey() ?? throw new CryptographicException("内置信任密钥不可用。");
    }
    private static byte[] ReadLocalBytes(string path)
    {
        EnsureLocal(path);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is 0 or > MaximumPackageBytes) throw new InvalidDataException("规则包大小不符合限制。");
        byte[] bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return bytes;
    }
    private static void EnsureLocal(string path)
    {
        if (!ContentDiscovery.IsLocalSafePath(Path.GetFullPath(path))) throw new IOException("规则文件必须位于可读取的本地目录，不支持网络路径或重解析点。");
    }
    private static void RejectDuplicateProperties(byte[] bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 });
        Walk(document.RootElement);
        static void Walk(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject()) { if (!names.Add(property.Name)) throw new InvalidDataException("规则包包含重复字段。"); Walk(property.Value); }
            }
            else if (value.ValueKind == JsonValueKind.Array) foreach (var child in value.EnumerateArray()) Walk(child);
        }
    }
}
