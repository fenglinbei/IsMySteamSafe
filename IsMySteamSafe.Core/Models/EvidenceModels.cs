namespace IsMySteamSafe.Core.Models;

public sealed record EvidenceProgress(int Percent, string Stage, string Detail);

public sealed record EvidenceExportResult(string Path, string Sha256, long Size, Guid BundleId);

public sealed record EvidenceBundleOptions(IReadOnlyList<string> AdditionalRoots)
{
    public bool IncludeRunHistory { get; init; }
    public static EvidenceBundleOptions Default { get; } = new(Array.Empty<string>());
}

public sealed class EvidenceBundle
{
    public string SchemaVersion { get; init; } = "1.1";
    public string ProductVersion { get; init; } = ProductInfo.Version;
    public Guid BundleId { get; init; } = Guid.NewGuid();
    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.Now;
    public bool RedactionEnabled { get; init; } = true;
    public required EvidenceEnvironment Environment { get; init; }
    public AuditReport? Audit { get; init; }
    public List<EvidenceProcess> Processes { get; init; } = [];
    public List<EvidenceModule> Modules { get; init; } = [];
    public List<EvidenceConnection> Connections { get; init; } = [];
    public List<EvidenceRegistryValue> RegistryValues { get; init; } = [];
    public List<EvidenceService> Services { get; init; } = [];
    public List<EvidenceTask> ScheduledTasks { get; init; } = [];
    public List<EvidenceCertificate> Certificates { get; init; } = [];
    public List<EvidenceFile> Files { get; init; } = [];
    public List<EvidenceTextSnapshot> TextSnapshots { get; init; } = [];
    public List<EvidenceNetworkSetting> NetworkSettings { get; init; } = [];
    public List<EvidenceCoverage> Coverage { get; init; } = [];
}

public sealed record EvidenceEnvironment(
    string MachineFingerprint,
    string OperatingSystem,
    string OsArchitecture,
    string ProcessArchitecture,
    string Framework,
    bool IsAdministrator,
    string CurrentCulture,
    string TimeZone,
    IReadOnlyList<string> SteamRoots,
    IReadOnlyList<string> LibraryRoots,
    IReadOnlyList<string> WorkshopRoots,
    IReadOnlyList<string> WallpaperProjectRoots);

public sealed record EvidenceProcess(
    int ProcessId,
    int? ParentProcessId,
    string Name,
    string? Path,
    DateTimeOffset? StartTime,
    string? Sha256,
    string Signature,
    string? Signer,
    string? ReadError);

public sealed record EvidenceModule(
    int ProcessId,
    string ProcessName,
    string Path,
    string? Sha256,
    string Signature,
    string? Signer);

public sealed record EvidenceConnection(
    int ProcessId,
    string ProcessName,
    string State,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort);

public sealed record EvidenceRegistryValue(
    string Hive,
    string View,
    string Key,
    string Name,
    string Kind,
    string Value);

public sealed record EvidenceService(
    string Name,
    string DisplayName,
    string ImagePath,
    string ServiceDll,
    string Start,
    string Type);

public sealed record EvidenceTask(
    string RelativePath,
    long Size,
    DateTimeOffset LastWriteTime,
    string? Sha256,
    string? Command,
    string? Arguments,
    string? ReadError);

public sealed record EvidenceCertificate(
    string Location,
    string Store,
    string Thumbprint,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string SerialNumber,
    string SignatureAlgorithm);

public sealed record EvidenceFile(
    string Source,
    string Path,
    long Size,
    DateTimeOffset CreationTime,
    DateTimeOffset LastWriteTime,
    string? Sha256,
    string Signature,
    string? Signer,
    string? ReadError);

public sealed record EvidenceTextSnapshot(string Kind, string Path, string Content, bool Truncated);

public sealed record EvidenceNetworkSetting(string Area, string Name, string Value);

public sealed record EvidenceCoverage(string Area, string Status, string Detail);
