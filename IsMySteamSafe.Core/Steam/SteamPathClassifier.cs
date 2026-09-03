using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.Core.Steam;

public static class SteamPathClassifier
{
    public static bool IsWallpaperContentPath(SteamLayout layout, string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        return layout.WorkshopRoots.Any(root => FileUtilities.IsWithin(path, root)) ||
               layout.WallpaperProjectRoots.Any(root => FileUtilities.IsWithin(path, root));
    }

    public static bool CommandReferencesWallpaperContent(SteamLayout layout, string command) =>
        CommandReferencesAnyRoot(command, layout.WorkshopRoots) ||
        CommandReferencesAnyRoot(command, layout.WallpaperProjectRoots);

    public static bool CommandReferencesSteamInstallation(SteamLayout layout, string command) =>
        CommandReferencesAnyRoot(command, layout.SteamRoots);

    private static bool CommandReferencesAnyRoot(string command, IEnumerable<string> roots)
    {
        if (string.IsNullOrWhiteSpace(command)) return false;
        string normalizedCommand = Environment.ExpandEnvironmentVariables(command).Replace('/', '\\');
        foreach (string root in roots)
        {
            try
            {
                string normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)).Replace('/', '\\');
                if (normalizedCommand.Contains(normalizedRoot + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch
            {
                // Ignore a malformed discovered path and continue with the remaining roots.
            }
        }
        return false;
    }
}
