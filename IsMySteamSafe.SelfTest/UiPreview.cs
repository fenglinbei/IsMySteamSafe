using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using IsMySteamSafe.Core.Models;

namespace IsMySteamSafe.SelfTest;

internal static class UiPreview
{
    public static int Render(string output)
    {
        Exception? error = null;
        Thread thread = new(() =>
        {
            try
            {
                Directory.CreateDirectory(output);
                IsMySteamSafe.App.App app = new(); app.InitializeComponent();
                IsMySteamSafe.App.MainWindow window = new();
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
                app.Shutdown();
            }
            catch (Exception ex) { error = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); thread.Join();
        if (error is not null) throw new InvalidOperationException("UI preview failed", error);
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
        content.DataContext = window.DataContext; window.Content = null;
        Border host = new() { Width = 1180, Height = 840, Background = window.Background ?? Brushes.White, Child = content };
        host.Measure(new Size(1180, 840)); host.Arrange(new Rect(0, 0, 1180, 840)); host.UpdateLayout();
        RenderTargetBitmap bitmap = new(1180, 840, 96, 96, PixelFormats.Pbgra32); bitmap.Render(host);
        PngBitmapEncoder encoder = new(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream stream = File.Create(output); encoder.Save(stream);
        host.Child = null; window.Content = content;
    }
}
