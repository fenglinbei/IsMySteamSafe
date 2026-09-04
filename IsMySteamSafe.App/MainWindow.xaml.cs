using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using IsMySteamSafe.App.ViewModels;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Reporting;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.App;

public partial class MainWindow : Window
{
    private readonly SteamAuditCoordinator _coordinator = new();
    private CancellationTokenSource? _auditCancellation;
    private AuditReport? _lastReport;
    private bool _busy;
    private string? _additionalEvidenceRoot;

    public MainWindow()
    {
        InitializeComponent();
        ScopeDescriptionText.Text = AuditCoverage.Scope;
        ScopeLimitsText.Text = AuditCoverage.Limits;
        CheckCards = [];
        Findings = [];
        UrlResults = [];
        DataContext = this;
        Loaded += MainWindow_Loaded;
        Closing += (_, _) => _auditCancellation?.Cancel();
    }

    public ObservableCollection<CheckCardViewModel> CheckCards { get; }
    public ObservableCollection<FindingViewModel> Findings { get; }
    public ObservableCollection<UrlViewModel> UrlResults { get; }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            SteamLayout layout = await Task.Run(SteamLocator.Discover);
            SteamPathText.Text = layout.PrimarySteamRoot is null ? "未找到 Steam 安装目录" : $"Steam：{layout.PrimarySteamRoot}";
        }
        catch
        {
            SteamPathText.Text = "Steam 位置将在体检时重新确认";
        }
    }

    private async void StartAudit_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true);
        _lastReport = null;
        CheckCards.Clear();
        Findings.Clear();
        ResultsPanel.Visibility = Visibility.Collapsed;
        EmptyResultsPanel.Visibility = Visibility.Visible;
        EmptyResultsTitleText.Text = "正在逐项核对";
        EmptyResultsDescriptionText.Text = "仅收集证据，不会尝试清除或修复任何内容。";
        ApplyHero("体检进行中", "正在确认 Steam 客户端有没有被动过", "扫描只在本机进行，请保持窗口打开。", Palette.BlueTint, Palette.Blue, "…");
        _auditCancellation = new CancellationTokenSource();
        CancellationToken token = _auditCancellation.Token;
        Progress<AuditProgress> progress = new(UpdateProgress);
        SteamAuditOptions options = new(ClientModsCheckBox.IsChecked == true, IncludeExtendedChecks: true);

        try
        {
            AuditReport report = await Task.Run(() => _coordinator.RunAsync(options, progress, token), token);
            _lastReport = report;
            PopulateReport(report);
        }
        catch (OperationCanceledException)
        {
            ApplyHero("已取消", "体检没有完整完成", "没有形成可用于判断的完整结果，你可以随时重新开始。", Palette.GrayTint, Palette.Gray, "—");
            FooterStatusText.Text = "体检已取消 · 没有修改任何系统状态";
            ProgressStageText.Text = "已取消";
            ProgressDetailText.Text = "本次结果未保存";
        }
        catch (Exception ex)
        {
            ApplyHero("未完成", "体检遇到错误", "检查出现错误，请保留信息后重试。", Palette.RedTint, Palette.Red, "!");
            FooterStatusText.Text = "体检失败";
            MessageBox.Show(this, ex.Message, "体检未完成", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            SetBusy(false);
            _auditCancellation?.Dispose();
            _auditCancellation = null;
        }
    }

    private void CancelAudit_Click(object sender, RoutedEventArgs e) => _auditCancellation?.Cancel();

    private void ChooseEvidenceFolder_Click(object sender, RoutedEventArgs e)
    {
        OpenFolderDialog dialog = new()
        {
            Title = "选择补充取证目录（不会执行或解压其中的文件）",
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true) return;
        _additionalEvidenceRoot = Path.GetFullPath(dialog.FolderName);
        EvidenceFolderTextBox.Text = _additionalEvidenceRoot;
    }

    private void ClearEvidenceFolder_Click(object sender, RoutedEventArgs e)
    {
        _additionalEvidenceRoot = null;
        EvidenceFolderTextBox.Text = "未选择";
    }

    private async void ExportEvidence_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SaveFileDialog dialog = new()
        {
            Title = "导出证据包",
            Filter = "ZIP 证据包 (*.zip)|*.zip",
            FileName = $"Steam安全证据-{DateTime.Now:yyyyMMdd-HHmmss}.zip",
            AddExtension = true
        };
        if (dialog.ShowDialog(this) != true) return;

        SetBusy(true);
        _auditCancellation = new CancellationTokenSource();
        CancellationToken token = _auditCancellation.Token;
        try
        {
            AuditReport? report = _lastReport;
            if (report is null)
            {
                UpdateEvidenceProgress(new EvidenceProgress(2, "先完成 Steam 体检", "没有可复用的体检结果，正在重新检查"));
                SteamAuditOptions auditOptions = new(ClientModsCheckBox.IsChecked == true, IncludeExtendedChecks: true);
                report = await Task.Run(() => _coordinator.RunAsync(auditOptions, cancellationToken: token), token);
                _lastReport = report;
                PopulateReport(report);
            }

            IReadOnlyList<string> roots = _additionalEvidenceRoot is null ? Array.Empty<string>() : [_additionalEvidenceRoot];
            EvidenceBundleOptions evidenceOptions = new(roots) { IncludeRunHistory = EvidenceHistoryCheckBox.IsChecked == true };
            Progress<EvidenceProgress> progress = new(UpdateEvidenceProgress);
            EvidenceExportResult result = await Task.Run(
                () => EvidenceBundleExporter.ExportAsync(report, evidenceOptions, dialog.FileName, progress, token),
                token);
            EvidenceProgressBar.Value = 100;
            EvidencePercentText.Text = "100%";
            EvidenceStageText.Text = "证据包已生成";
            EvidenceDetailText.Text = $"{result.Size / 1024.0 / 1024.0:N1} MiB · SHA-256：{result.Sha256}";
            FooterStatusText.Text = $"证据包已导出 · {result.Path}";
            MessageBox.Show(this,
                $"证据包已生成。\n\n编号：{result.BundleId:N}\nSHA-256：{result.Sha256}\n\n分享前请检查其中的文本和注册表清单。",
                "证据提取完成",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            EvidenceStageText.Text = "已取消";
            EvidenceDetailText.Text = "证据提取已安全停止";
            FooterStatusText.Text = "证据提取已安全停止";
        }
        catch (Exception ex)
        {
            EvidenceStageText.Text = "取证未完成";
            EvidenceDetailText.Text = ex.Message;
            FooterStatusText.Text = "证据提取失败";
            MessageBox.Show(this, ex.Message, "证据包导出失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            SetBusy(false);
            _auditCancellation?.Dispose();
            _auditCancellation = null;
        }
    }

    private void UpdateEvidenceProgress(EvidenceProgress progress)
    {
        EvidenceProgressBar.Value = progress.Percent;
        EvidencePercentText.Text = $"{progress.Percent}%";
        EvidenceStageText.Text = progress.Stage;
        EvidenceDetailText.Text = progress.Detail;
        FooterStatusText.Text = $"{progress.Stage} · 证据提取";
    }

    private void UpdateProgress(AuditProgress progress)
    {
        AuditProgressBar.Value = progress.Percent;
        ProgressPercentText.Text = $"{progress.Percent}%";
        ProgressStageText.Text = progress.Stage;
        ProgressDetailText.Text = string.IsNullOrWhiteSpace(progress.CurrentItem)
            ? progress.Message
            : $"{progress.Message} · {progress.CurrentItem}";
        FooterStatusText.Text = $"{progress.Stage} · 只读检查";
    }

    private void PopulateReport(AuditReport report)
    {
        CoverageSummaryText.Text = report.CoverageSummary;
        ScopeDescriptionText.Text = AuditCoverage.Scope;
        ScopeLimitsText.Text = AuditCoverage.Limits;
        CoverageGroupsControl.ItemsSource = AuditCoverage.Groups(report);
        CheckCards.Clear();
        foreach (AuditCheckResult check in report.Checks) CheckCards.Add(new CheckCardViewModel { Check = check });

        Findings.Clear();
        foreach (AuditFinding finding in report.Findings
                     .OrderByDescending(item => AuditLabels.RiskRank(item.Level))
                     .ThenBy(item => item.Priority))
        {
            Findings.Add(new FindingViewModel { Finding = finding });
        }

        ExportButton.IsEnabled = true;
        CompareButton.IsEnabled = true;
        AuditProgressBar.Value = 100;
        ProgressPercentText.Text = "100%";
        ProgressStageText.Text = "体检完成";
        ProgressDetailText.Text = $"{report.Checks.Count} 项检查 · {report.Findings.Count} 条证据或提示 · 未检查内容另列";
        FooterStatusText.Text = $"体检完成 · {AuditLabels.Conclusion(report.Conclusion)}";
        SteamPathText.Text = report.SteamRoots.Count == 0 ? "未找到 Steam" : $"Steam：{string.Join("，", report.SteamRoots)}";

        switch (report.Conclusion)
        {
            case AuditConclusion.NoTamperingFound:
                ApplyHero("快速体检已完成", "未发现 Steam 客户端篡改迹象", "结论仅适用于已完成的检查。工坊、MOD 与压缩内容可能尚未深查，请查看下方检查范围。", Palette.GreenTint, Palette.Green, "✓");
                break;
            case AuditConclusion.ReviewNeeded:
                ApplyHero("本次结论", "有几项需要你核对", "先确认是否来自你主动安装的客户端插件，若为不认识的项目请交给专业杀毒软件辨别。", Palette.AmberTint, Palette.Amber, "!");
                break;
            case AuditConclusion.StrongTamperingSignal:
                ApplyHero("请先停止操作", "发现强篡改信号", "不要付款、扫码或立刻改密码。先断网并交给专业杀毒软件全盘查杀。", Palette.RedTint, Palette.Red, "!");
                break;
            case AuditConclusion.ContentRiskFound:
                ApplyHero("请先不要打开可疑内容", "发现有风险的内容文件", "文件存在不等于已经运行，也不等于 Steam 已被篡改。请核对来源并隔离，未展开内容仍需进一步检查。", Palette.RedTint, Palette.Red, "!");
                break;
            case AuditConclusion.PersistenceRiskFound:
                ApplyHero("请先停止操作", "发现关联恶意文件的启动链", "启动入口指向已知恶意文件，不等于当前正在运行。请处理入口和文件，再重启复查。", Palette.RedTint, Palette.Red, "!");
                break;
            case AuditConclusion.ActiveThreatFound:
                ApplyHero("请先停止操作", "发现正在运行的恶意组件", "先处理本机威胁，再从可信设备更换凭据并撤销其他会话。正常游戏可能只是加载了恶意 MOD。", Palette.RedTint, Palette.Red, "!");
                break;
            default:
                ApplyHero("快速体检已结束", "部分检查缺失，暂不能充分判断", "有检查未能完成，请展开“检查范围与未检查内容”查看具体原因。未检查部分不能视为安全。", Palette.GrayTint, Palette.Gray, "…");
                break;
        }

        if (Findings.Count == 0)
        {
            ResultsPanel.Visibility = Visibility.Collapsed;
            EmptyResultsPanel.Visibility = Visibility.Visible;
            EmptyResultsTitleText.Text = "没有异常证据需要展开";
            EmptyResultsDescriptionText.Text = "请同时查看上方检查卡与覆盖限制，如果你看到可疑红信，仍建议使用“红信判真伪”交叉核对。";
        }
        else
        {
            EmptyResultsPanel.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Visible;
            FindingsList.SelectedIndex = 0;
        }
    }

    private async void Compare_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _lastReport is null) return;
        OpenFileDialog dialog = new() { Title = "选择上一次导出的 JSON 体检报告", Filter = "JSON 体检报告 (*.json)|*.json", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            SetBusy(true);
            if (!ContentDiscovery.IsLocalSafePath(dialog.FileName)) throw new IOException("仅支持安全的本地报告路径。");
            string json = await IsMySteamSafe.Core.Utilities.FileUtilities.ReadTextBoundedAsync(dialog.FileName, 16 * 1024 * 1024);
            AuditReport before = System.Text.Json.JsonSerializer.Deserialize<AuditReport>(json,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? throw new IOException("报告内容无效。");
            AuditComparison comparison = AuditComparison.Compare(before, _lastReport);
            MessageBox.Show(this, comparison.Summary, "两次体检对比", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        { MessageBox.Show(this, ex.Message, "无法对比报告", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { SetBusy(false); }
    }

    private void ApplyHero(string eyebrow, string title, string description, Brush tint, Brush accent, string glyph)
    {
        HeroEyebrowText.Text = eyebrow;
        HeroTitleText.Text = title;
        HeroDescriptionText.Text = description;
        HeroBorder.Background = tint;
        HeroBorder.BorderBrush = accent;
        HeroGlyphText.Text = glyph;
        HeroGlyphText.Foreground = accent;
        HeroIconBorder.Background = Brushes.White;
    }

    private void FindingsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsList.SelectedItem is not FindingViewModel item) return;
        DetailLevelText.Text = $"{item.Level} · {item.Priority}";
        DetailLevelText.Foreground = item.Accent;
        DetailLevelBorder.Background = item.Tint;
        DetailTitleText.Text = item.Title;
        DetailWhatText.Text = item.WhatFound;
        DetailMeaningText.Text = item.Meaning;
        DetailRecommendationText.Text = item.Recommendation;
        DetailTargetText.Text = item.Target;
        DetailEvidenceText.Text = item.EvidenceText;
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_lastReport is null) return;
        SaveFileDialog dialog = new()
        {
            Title = "导出本地体检报告",
            Filter = "Markdown 报告 (*.md)|*.md|JSON 证据 (*.json)|*.json",
            FileName = $"Steam安全体检-{DateTime.Now:yyyyMMdd-HHmmss}.md",
            AddExtension = true
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            if (Path.GetExtension(dialog.FileName).Equals(".json", StringComparison.OrdinalIgnoreCase))
                await ReportExporter.ExportJsonAsync(_lastReport, dialog.FileName);
            else
                await ReportExporter.ExportMarkdownAsync(_lastReport, dialog.FileName);
            FooterStatusText.Text = $"报告已导出 · {dialog.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "报告导出失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void InspectUrl_Click(object sender, RoutedEventArgs e)
    {
        UrlInspectionResult result = SupportUrlInspector.Inspect(UrlInputTextBox.Text);
        UrlResults.Clear();
        foreach (InspectedUrl url in result.Urls) UrlResults.Add(new UrlViewModel { Url = url });

        UrlSummaryText.Text = result.Summary;
        UrlSummaryNoteText.Text = string.Join(" ", result.Notes);
        switch (result.OverallTrust)
        {
            case UrlTrustLevel.OfficialSupport:
                UrlSummaryEyebrow.Text = "本地解析结果";
                UrlSummaryBorder.Background = Palette.GreenTint;
                UrlSummaryBorder.BorderBrush = Palette.Green;
                UrlSummaryEyebrow.Foreground = Palette.Green;
                break;
            case UrlTrustLevel.SteamOwnedDomain:
                UrlSummaryEyebrow.Text = "需要确认用途";
                UrlSummaryBorder.Background = Palette.AmberTint;
                UrlSummaryBorder.BorderBrush = Palette.Amber;
                UrlSummaryEyebrow.Foreground = Palette.Amber;
                break;
            case UrlTrustLevel.NotSteamOwned:
                UrlSummaryEyebrow.Text = "不要付款或输入凭据";
                UrlSummaryBorder.Background = Palette.RedTint;
                UrlSummaryBorder.BorderBrush = Palette.Red;
                UrlSummaryEyebrow.Foreground = Palette.Red;
                break;
            default:
                UrlSummaryEyebrow.Text = "没有可判断的链接";
                UrlSummaryBorder.Background = Palette.GrayTint;
                UrlSummaryBorder.BorderBrush = Palette.Gray;
                UrlSummaryEyebrow.Foreground = Palette.Gray;
                break;
        }
        FooterStatusText.Text = "链接仅在本地完成解析";
    }

    private void ClearUrl_Click(object sender, RoutedEventArgs e)
    {
        UrlInputTextBox.Clear();
        UrlResults.Clear();
        UrlSummaryEyebrow.Text = "等待检查";
        UrlSummaryText.Text = "实际主机";
        UrlSummaryNoteText.Text = "Steam 官方客服主机应为 help.steampowered.com，任何多余字符都可能意味着风险。本工具的信息可能随 Steam 更新而过时，请以 Steam 官方信息为准。";
        UrlSummaryBorder.Background = Palette.GrayTint;
        UrlSummaryBorder.BorderBrush = Palette.Gray;
    }

    private void CloudSync_Changed(object sender, RoutedEventArgs e)
    {
        if (CloudSyncGuidanceText is null) return;
        if (SyncPcOnlyRadio.IsChecked == true)
        {
            CloudSyncGuidanceText.Text = "只有这台电脑显示，是很强的本地异常信号，但仍不能单独证明具体木马。请停止付款，运行体检并交给专业杀毒软件复核。";
            CloudSyncGuidanceText.Background = Palette.RedTint;
        }
        else if (SyncYesRadio.IsChecked == true)
        {
            CloudSyncGuidanceText.Text = "跨设备可见更符合云端通知，但仍需核对“联系客服”链接的实际主机。Steam 客服不会要求通过二维码小额付款进行验证。";
            CloudSyncGuidanceText.Background = Palette.GreenTint;
        }
        else
        {
            CloudSyncGuidanceText.Text = "建议在手机 Steam App 或浏览器手动进入官方客服页交叉核对。不要从当前红信页面跳转。";
            CloudSyncGuidanceText.Background = Palette.GrayTint;
        }
    }

    private void CopyOfficialSupport_Click(object sender, RoutedEventArgs e) => CopyText(ProductInfo.OfficialSupportUrl, "官方客服地址已复制");

    private void OpenWindowsSecurity_Click(object sender, RoutedEventArgs e) => OpenTrustedTarget("windowsdefender:", "无法打开 Windows 安全中心");
    private void OpenOfficialSupport_Click(object sender, RoutedEventArgs e) => OpenTrustedTarget(ProductInfo.OfficialSupportUrl, "无法打开 Steam 官方客服");
    private void OpenOfficialInstaller_Click(object sender, RoutedEventArgs e) => OpenTrustedTarget(ProductInfo.OfficialInstallerUrl, "无法打开 Steam 官方安装页");

    private void CopyText(string text, string successMessage)
    {
        try
        {
            Clipboard.SetText(text);
            FooterStatusText.Text = successMessage;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "复制失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OpenTrustedTarget(string target, string errorTitle)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, errorTitle, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        StartAuditButton.IsEnabled = !busy;
        CancelAuditButton.IsEnabled = busy;
        ExportButton.IsEnabled = !busy && _lastReport is not null;
        CompareButton.IsEnabled = !busy && _lastReport is not null;
        EvidenceHistoryCheckBox.IsEnabled = !busy;
        ClientModsCheckBox.IsEnabled = !busy;
        EvidenceExportButton.IsEnabled = !busy;
        EvidenceCancelButton.IsEnabled = busy;
        ChooseEvidenceFolderButton.IsEnabled = !busy;
        ClearEvidenceFolderButton.IsEnabled = !busy;
    }
}
