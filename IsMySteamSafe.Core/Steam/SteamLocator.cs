using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace IsMySteamSafe.Core.Steam;

public sealed class SteamLayout
{
    public List<string> SteamRoots { get; } = [];
    public List<string> LibraryRoots { get; } = [];
    public List<string> WorkshopRoots { get; } = [];
    public List<string> WallpaperProjectRoots { get; } = [];
    public List<ContentRoot> ContentRoots { get; } = [];
    public List<InstalledGame> Games { get; } = [];
    public List<string> DiscoveryNotes { get; } = [];
    public string? PrimarySteamRoot => SteamRoots.FirstOrDefault(path => File.Exists(Path.Combine(path, "steam.exe"))) ?? SteamRoots.FirstOrDefault();
}

public sealed record WallpaperProject(
    string Directory,
    string WorkshopId,
    string? Title,
    string? Type,
    string? EntryFile,
    DateTimeOffset LastWriteTime,
    string? ParseError);

public static partial class SteamLocator
{
    [GeneratedRegex("\\\"path\\\"\\s*\\\"(?<path>(?:\\\\.|[^\\\"])*)\\\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LibraryPathRegex();

    public static SteamLayout Discover()
    {
        SteamLayout layout = new();
        HashSet<string> steamRoots = new(StringComparer.OrdinalIgnoreCase);

        AddRegistryPath(RegistryHive.CurrentUser, RegistryView.Default, @"Software\Valve\Steam", "SteamPath", steamRoots);
        AddRegistryPath(RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Valve\Steam", "InstallPath", steamRoots);
        AddRegistryPath(RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Valve\Steam", "InstallPath", steamRoots);

        foreach (Process process in Process.GetProcessesByName("steam"))
        {
            try
            {
                string? directory = Path.GetDirectoryName(process.MainModule?.FileName);
                if (directory is not null) AddExisting(directory, steamRoots);
            }
            catch
            {
                // Standard-user audit may not be able to query every process.
            }
            finally
            {
                process.Dispose();
            }
        }

        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam"), steamRoots);
        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Steam"), steamRoots);

        HashSet<string> libraries = new(StringComparer.OrdinalIgnoreCase);
        foreach (string steamRoot in steamRoots)
        {
            AddExisting(steamRoot, libraries);
            string vdf = Path.Combine(steamRoot, "steamapps", "libraryfolders.vdf");
            if (!File.Exists(vdf)) continue;
            try
            {
                if (!ContentDiscovery.IsLocalSafePath(vdf) || new FileInfo(vdf).Length > 2 * 1024 * 1024)
                { layout.DiscoveryNotes.Add("Steam 库清单过大或路径不安全，未完整发现库。"); continue; }
                string text = File.ReadAllText(vdf);
                foreach (Match match in LibraryPathRegex().Matches(text))
                {
                    string path = Regex.Unescape(match.Groups["path"].Value);
                    AddExisting(path, libraries);
                }
            }
            catch
            {
                // A malformed or locked VDF should not abort discovery.
            }
        }

        layout.SteamRoots.AddRange(steamRoots.Order(StringComparer.OrdinalIgnoreCase));
        layout.LibraryRoots.AddRange(libraries.Order(StringComparer.OrdinalIgnoreCase));
        ContentDiscovery.Populate(layout);

        return layout;
    }

    public static WallpaperProject ReadWallpaperProject(string directory)
    {
        DirectoryInfo info = new(directory);
        string id = info.Name;
        string projectJson = Path.Combine(directory, "project.json");
        if (!File.Exists(projectJson))
        {
            return new WallpaperProject(directory, id, null, null, null, info.LastWriteTime, "缺少 project.json");
        }

        try
        {
            if (!ContentDiscovery.IsLocalSafePath(projectJson) || new FileInfo(projectJson).Length > 1024 * 1024)
                throw new IOException("项目清单过大或路径不安全。");
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(projectJson));
            JsonElement root = document.RootElement;
            return new WallpaperProject(
                directory,
                id,
                GetString(root, "title"),
                GetString(root, "type"),
                GetString(root, "file"),
                info.LastWriteTime,
                null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new WallpaperProject(directory, id, null, null, null, info.LastWriteTime, ex.Message);
        }
    }

    private static string? GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static void AddRegistryPath(RegistryHive hive, RegistryView view, string keyPath, string valueName, ISet<string> paths)
    {
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? key = baseKey.OpenSubKey(keyPath, writable: false);
            if (key?.GetValue(valueName) is string value) AddExisting(value, paths);
        }
        catch
        {
            // Registry view may not be accessible.
        }
    }

    private static void AddExisting(string path, ISet<string> paths)
    {
        try
        {
            string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path.Replace('/', Path.DirectorySeparatorChar)));
            if (Directory.Exists(full) && ContentDiscovery.IsLocalSafePath(full)) paths.Add(full);
        }
        catch
        {
            // Ignore malformed paths from external configuration.
        }
    }

    private static void AddExisting(string path, ICollection<string> paths)
    {
        try
        {
            string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            if (Directory.Exists(full) && ContentDiscovery.IsLocalSafePath(full) && !paths.Contains(full, StringComparer.OrdinalIgnoreCase)) paths.Add(full);
        }
        catch
        {
            // Ignore malformed paths from external configuration.
        }
    }
}
