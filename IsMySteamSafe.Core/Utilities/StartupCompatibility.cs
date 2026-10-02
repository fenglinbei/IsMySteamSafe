using System.Reflection;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("IsMySteamSafe.SelfTest")]

namespace IsMySteamSafe.Core.Utilities;

public enum StartupMode { Standard, Compat }

/// <summary>Fixed apphost identity and a side-effect-free startup protocol.</summary>
public static class StartupCompatibility
{
    public const string ProbeArgument = "--startup-probe";
    public const string ReadyPrefix = "ISMYSTEAMSAFE_STARTUP_READY/1";
    public const int InvalidProbeExitCode = 2;
    public static string BuildIdentity => typeof(StartupCompatibility).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
    public static string Version => BuildIdentity.Split('+')[0];

    public static string ModeName(StartupMode mode) => mode switch
    {
        StartupMode.Standard => "standard",
        StartupMode.Compat => "compat",
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };

    public static string HostFileName(StartupMode mode) => mode switch
    {
        StartupMode.Standard => "IsMySteamSafe.Standard.exe",
        StartupMode.Compat => "IsMySteamSafe.Compat.exe",
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };

    public static bool TryIdentifyHost(string? processPath, out StartupMode mode, out bool unified)
    {
        mode = StartupMode.Standard;
        unified = false;
        if (string.IsNullOrEmpty(processPath)) return false;
        string name = Path.GetFileName(processPath);
        if (name.Equals(HostFileName(StartupMode.Standard), StringComparison.OrdinalIgnoreCase)) unified = true;
        else if (name.Equals(HostFileName(StartupMode.Compat), StringComparison.OrdinalIgnoreCase))
        {
            mode = StartupMode.Compat;
            unified = true;
        }
        else if (!name.Equals("IsMySteamSafe.exe", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    public static bool TryRunProbe(string[] args, out int exitCode) =>
        TryRunProbe(args, Environment.ProcessPath, Console.Out, out exitCode);

    internal static bool TryRunProbe(string[] args, string? processPath, TextWriter output, out int exitCode)
    {
        exitCode = InvalidProbeExitCode;
        // Malformed reserved switches must never fall through into WPF or Steam discovery.
        if (!args.Any(arg => arg.StartsWith("--startup-", StringComparison.OrdinalIgnoreCase))) return false;
        if (args.Length != 2 || args[0] != ProbeArgument || args[1].Length != 32 || !args[1].All(char.IsAsciiHexDigit) ||
            !TryIdentifyHost(processPath, out StartupMode mode, out _)) return true;
        output.WriteLine($"{ReadyPrefix}|app|{ModeName(mode)}|{args[1]}");
        output.Flush();
        exitCode = 0;
        return true;
    }
}
