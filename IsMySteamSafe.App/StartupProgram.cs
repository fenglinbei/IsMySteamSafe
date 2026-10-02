using System.Runtime.CompilerServices;
using IsMySteamSafe.App.Services;
using IsMySteamSafe.Core.Utilities;

[assembly: InternalsVisibleTo("IsMySteamSafe.SelfTest")]

namespace IsMySteamSafe.App;

internal static class StartupProgram
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (StartupCompatibility.TryRunProbe(args, out int exitCode)) return exitCode;
        return RunApplication();
    }

    // No WPF JIT, window creation, Steam discovery or report writes in the probe branch.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int RunApplication()
    {
        try
        {
            App application = new();
            application.InitializeComponent();
            return application.Run();
        }
        catch (Exception error)
        {
            App.ShowError(error, AppErrorLog.Write("ManagedStartup", error), "程序未能启动");
            return 1;
        }
    }
}
