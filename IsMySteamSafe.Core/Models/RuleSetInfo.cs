namespace IsMySteamSafe.Core.Models;

public sealed record RuleSetInfo(long Version, string PublishedAt, string Source, int RuleCount, string? Notice = null);
