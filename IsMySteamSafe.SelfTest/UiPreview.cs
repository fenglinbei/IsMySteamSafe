using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using IsMySteamSafe.Core.Models;

namespace IsMySteamSafe.SelfTest;

internal static class UiPreview
{
    public static int Render(string output)
    {
        Exception? error = null;
        Thread thread = new(() =>
        {
            IsMySteamSafe.App.App? app = null;
            IsMySteamSafe.App.MainWindow? window = null;
            try
            {
                Directory.CreateDirectory(output);
                RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                app = new();
                // Load the real application resources without InitializeComponent's
                // StartupUri assignment; pumping the dispatcher must not create a second UI.
                Application.LoadComponent(app, new Uri("/IsMySteamSafe;component/app.xaml", UriKind.Relative));
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                window = new()
                {
                    Width = 1180, Height = 940, WindowStartupLocation = WindowStartupLocation.Manual,
                    Left = -32000, Top = -32000, ShowInTaskbar = false, ShowActivated = false,
                    WindowStyle = WindowStyle.None, ResizeMode = ResizeMode.NoResize
                };
                window.Show();
                AuditReport scope = new() { Conclusion = AuditConclusion.NoTamperingFound, CompletedAt = DateTimeOffset.Now };
                scope.Checks.Add(new() { Id = "client-files", Name = "客户端文件", Area = AuditArea.ClientFiles, Priority = AuditPriority.P0,
                    Level = AuditLevel.Passed, Summary = "无害预览，核心检查完成。" });
                scope.Checks.Add(new() { Id = "content-risk", Name = "工坊、MOD 与插件", Area = AuditArea.ContentSources, Priority = AuditPriority.P1,
                    Level = AuditLevel.Information, Summary = "视频已做结构检查，压缩内容未展开。" });
                scope.ContentLimitations.Add(new("视频已做结构检查，未做完整比对", @"C:\示例内容\壁纸.mp4", "已完成快速结构检查。"));
                scope.ContentLimitations.Add(new("压缩内容未展开", @"C:\示例内容\安装包.rar", "未解压或执行内容。"));
                typeof(IsMySteamSafe.App.MainWindow).GetMethod("PopulateReport", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [scope]);
                Capture(window, Path.Combine(output, "quick-scope-complete.png"));
                ((Expander)window.FindName("CoverageExpander")).IsExpanded = true;
                Capture(window, Path.Combine(output, "quick-coverage-next-step.png"));
                ((Expander)window.FindName("CoverageExpander")).IsExpanded = false;
                ((FrameworkElement)window.FindName("RuleStatusText")).BringIntoView();
                Capture(window, Path.Combine(output, "detection-rules.png"));
                foreach (var (name, conclusion) in new[] { ("content-risk", AuditConclusion.ContentRiskFound), ("active-risk", AuditConclusion.ActiveThreatFound), ("persistence-risk", AuditConclusion.PersistenceRiskFound) })
                {
                    AuditReport report = new() { Conclusion = conclusion };
                    report.Checks.Add(new() { Id = "content-risk", Name = "工坊、MOD 与插件", Priority = AuditPriority.P1,
                        Area = AuditArea.ContentSources, Level = AuditLevel.HighlySuspicious, Summary = "这是无害界面预览，不是本机扫描结果。" });
                    typeof(IsMySteamSafe.App.MainWindow).GetMethod("PopulateReport", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, [report]);
                    Capture(window, Path.Combine(output, name + ".png"));
                }
                TabControl? tabs = Descendants((DependencyObject)window.Content).OfType<TabControl>().FirstOrDefault();
                if (tabs is not null) { tabs.SelectedIndex = 3; Capture(window, Path.Combine(output, "evidence.png")); }
            }
            catch (Exception ex) { error = ex; }
            finally { window?.Close(); app?.Shutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); thread.Join();
        if (error is not null) { Console.Error.WriteLine("UI_PREVIEW_FAILED: " + error); return 1; }
        Console.WriteLine("UI_PREVIEW_OK"); return 0;
    }
    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        { DependencyObject child = VisualTreeHelper.GetChild(parent, i); yield return child; foreach (var nested in Descendants(child)) yield return nested; }
    }
    private static void Capture(Window window, string output)
    {
        FrameworkElement content = (FrameworkElement)window.Content;
        const int width = 1180, height = 940;
        window.UpdateLayout();
        DispatcherFrame frame = new();
        window.Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
        window.UpdateLayout();
        DrawingVisual background = new();
        using (DrawingContext context = background.RenderOpen())
            context.DrawRectangle(window.Background ?? Brushes.White, null, new Rect(0, 0, width, height));
        RenderTargetBitmap bitmap = new(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(background);
        bitmap.Render(content);
        byte[] pixels = new byte[width * height * 4]; bitmap.CopyPixels(pixels, width * 4, 0);
        HashSet<uint> colors = [];
        int nontransparent = 0;
        for (int i = 0; i < pixels.Length; i += 4)
        {
            if (pixels[i + 3] > 0) nontransparent++;
            if ((i & 63) == 0) colors.Add(BitConverter.ToUInt32(pixels, i));
        }
        if (nontransparent < width * height / 2 || colors.Count < 16)
            throw new InvalidOperationException($"UI preview rendered an empty/flat image: pixels={nontransparent}, colors={colors.Count}, visible={content.IsVisible}, size={content.ActualWidth}x{content.ActualHeight}, bounds={VisualTreeHelper.GetDescendantBounds(content)}, offset={VisualTreeHelper.GetOffset(content)}, tier={RenderCapability.Tier}. No successful visual check can be claimed.");
        PngBitmapEncoder encoder = new(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream stream = File.Create(output); encoder.Save(stream);
    }
}
