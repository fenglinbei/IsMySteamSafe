using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace IsMySteamSafe.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        base.OnStartup(e);
    }
}
