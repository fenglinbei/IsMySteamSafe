using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Diagnostics;
using IsMySteamSafe.App.Services;

namespace IsMySteamSafe.App;

public partial class App : Application
{
    private bool _handlingUnhandledError;

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            string? reportPath = AppErrorLog.Write("DispatcherUnhandledException", args.Exception);
            if (_handlingUnhandledError) return;
            _handlingUnhandledError = true;
            try
            {
                ShowError(args.Exception, reportPath, "程序遇到未处理错误，请保存已有报告后重新启动");
                // A failed StartupUri/window constructor must not leave a windowless process
                // running after its dispatcher exception has been marked as handled.
                if (MainWindow is null || !MainWindow.IsLoaded) Shutdown(1);
            }
            finally { _handlingUnhandledError = false; }
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception error) AppErrorLog.Write("FatalUnhandledException", error);
        };
        TaskScheduler.UnobservedTaskException += (_, args) => AppErrorLog.Write("UnobservedTaskException", args.Exception);
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        base.OnStartup(e);
    }

    internal static void ReportError(string stage, Exception error, string title) =>
        ShowError(error, AppErrorLog.Write(stage, error), title);

    internal static string ErrorMessage(Exception error, string? reportPath)
    {
        string detail;
        try { detail = AppErrorLog.Redact(error.Message, 2048); }
        catch { detail = "无法读取异常详情。"; }
        return detail + "\n\n" + (reportPath is null
            ? "未能保存本地错误报告，日志目录可能无法写入。没有上传任何内容。"
            : $"已保存本地错误报告（未上传）：\n{reportPath}\n\n是否现在打开报告？请检查内容后再发送给协助排查的人员。");
    }

    internal static void ShowError(Exception error, string? reportPath, string title)
    {
        try
        {
            MessageBoxResult choice = MessageBox.Show(ErrorMessage(error, reportPath), title,
                reportPath is null ? MessageBoxButton.OK : MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (reportPath is not null && choice == MessageBoxResult.Yes)
                Process.Start(new ProcessStartInfo(reportPath) { UseShellExecute = true });
        }
        catch (Exception dialogError) { AppErrorLog.Write("ErrorReportDialog", dialogError); }
    }
}
