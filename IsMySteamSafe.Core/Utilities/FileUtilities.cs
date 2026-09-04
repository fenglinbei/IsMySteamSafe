using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace IsMySteamSafe.Core.Utilities;

public static class FileUtilities
{
    private static readonly Regex SteamIdRegex = new(@"(?<!\d)7656119\d{10}(?!\d)", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex SensitiveQueryRegex = new(@"(?<prefix>[?&](?:u|d)=)[^&#\s""'<>]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex UserProfilePathRegex = new(@"\b[A-Z]:\\Users\\[^\\/:*?""<>|\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static async Task<string> Sha256Async(string path, CancellationToken cancellationToken = default)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 1024 * 128, FileOptions.Asynchronous | FileOptions.SequentialScan);
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static async Task<string> ReadTextBoundedAsync(
        string path,
        long maximumBytes = 32L * 1024 * 1024,
        CancellationToken cancellationToken = default)
    {
        FileInfo info = new(path);
        if (info.Length > maximumBytes)
        {
            throw new IOException($"文件超过只读检查上限（{maximumBytes / 1024 / 1024} MiB）。");
        }

        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 1024 * 64, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using StreamReader reader = new(stream, new UTF8Encoding(false, false), detectEncodingFromByteOrderMarks: true);
        return await reader.ReadToEndAsync(cancellationToken);
    }

    public static string CompactSnippet(string text, int index, int radius = 150)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        int start = Math.Max(0, index - radius);
        int length = Math.Min(text.Length - start, radius * 2);
        string snippet = text.Substring(start, length)
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ');
        while (snippet.Contains("  ", StringComparison.Ordinal)) snippet = snippet.Replace("  ", " ", StringComparison.Ordinal);
        return snippet.Length == 0 ? snippet : $"…{RedactSensitiveText(snippet.Trim())}…";
    }

    public static string RedactSensitiveText(string? value)
    {
        if (string.IsNullOrEmpty(value)) return value ?? string.Empty;
        string redacted = UserProfilePathRegex.Replace(value, "%USERPROFILE%");
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd(Path.DirectorySeparatorChar);
        if (!string.IsNullOrWhiteSpace(profile))
        {
            redacted = redacted.Replace(profile, "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
            redacted = redacted.Replace(profile.Replace("\\", "\\\\", StringComparison.Ordinal), "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
        }
        string userName = Environment.UserName;
        if (!string.IsNullOrWhiteSpace(userName))
        {
            redacted = redacted.Replace($"C:\\Users\\{userName}", "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
            redacted = redacted.Replace($"C:\\\\Users\\\\{userName}", "%USERPROFILE%", StringComparison.OrdinalIgnoreCase);
        }
        redacted = SteamIdRegex.Replace(redacted, "[STEAM_ID_REDACTED]");
        redacted = SensitiveQueryRegex.Replace(redacted, match => match.Groups["prefix"].Value + "[REDACTED]");
        return Inspection.ScriptSignals.RedactSecrets(redacted);
    }

    public static bool IsWithin(string candidate, string root)
    {
        try
        {
            string fullCandidate = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return fullCandidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
                   fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static string SafeFileName(string value)
    {
        HashSet<char> invalid = [.. Path.GetInvalidFileNameChars()];
        string safe = new(value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
        return string.IsNullOrWhiteSpace(safe) ? "report" : safe;
    }
}
