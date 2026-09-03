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
        EmptyResultsDescriptionText.Text = "这里只读取证据，不会尝试清除或修复任何内容。";
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
            ApplyHero("未完成", "体检遇到错误", "错误不会触发自动修复，请保留信息后重试。", Palette.RedTint, Palette.Red, "!");
            FooterStatusText.Text = "体检失败 · 没有修改任何系统状态";
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
        EvidenceFolderTextBox.Text = "未选择（仅收集 Steam 与系统证据）";
    }

    private async void ExportEvidence_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SaveFileDialog dialog = new()
        {
            Title = "导出只读取证包",
            Filter = "ZIP 证据包 (*.zip)|*.zip",
            FileName = $"Steam只读取证-{DateTime.Now:yyyyMMdd-HHmmss}.zip",
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
                UpdateEvidenceProgress(new EvidenceProgress(2, "先完成 Steam 体检", "没有可复用的本次结果，正在执行同一套只读审计"));
                SteamAuditOptions auditOptions = new(ClientModsCheckBox.IsChecked == true, IncludeExtendedChecks: true);
                report = await Task.Run(() => _coordinator.RunAsync(auditOptions, cancellationToken: token), token);
                _lastReport = report;
                PopulateReport(report);
            }

            IReadOnlyList<string> roots = _additionalEvidenceRoot is null ? Array.Empty<string>() : [_additionalEvidenceRoot];
            Progress<EvidenceProgress> progress = new(UpdateEvidenceProgress);
            EvidenceExportResult result = await Task.Run(
                () => EvidenceBundleExporter.ExportAsync(report, new EvidenceBundleOptions(roots), dialog.FileName, progress, token),
                token);
            EvidenceProgressBar.Value = 100;
            EvidencePercentText.Text = "100%";
            EvidenceStageText.Text = "证据包已生成";
            EvidenceDetailText.Text = $"{result.Size / 1024.0 / 1024.0:N1} MiB · SHA-256：{result.Sha256}";
            FooterStatusText.Text = $"只读取证包已导出 · {result.Path}";
            MessageBox.Show(this,
                $"证据包已生成。\n\n编号：{result.BundleId:N}\nSHA-256：{result.Sha256}\n\n分享前请检查其中的文本和注册表清单。",
                "只读取证完成",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            EvidenceStageText.Text = "已取消";
            EvidenceDetailText.Text = "未留下半成品证据包，也没有修改系统状态。";
            FooterStatusText.Text = "取证已取消 · 没有修改任何系统状态";
        }
        catch (Exception ex)
        {
            EvidenceStageText.Text = "取证未完成";
            EvidenceDetailText.Text = ex.Message;
            FooterStatusText.Text = "取证失败 · 没有修改任何系统状态";
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
        FooterStatusText.Text = $"{progress.Stage} · 只读取证";
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
        AuditProgressBar.Value = 100;
        ProgressPercentText.Text = "100%";
        ProgressStageText.Text = "体检完成";
        ProgressDetailText.Text = $"{report.Checks.Count} 项检查 · {report.Findings.Count} 条证据/提示 · {report.CoverageNotes.Count} 条覆盖说明";
        FooterStatusText.Text = $"体检完成 · {AuditLabels.Conclusion(report.Conclusion)} · 没有修改系统状态";
        SteamPathText.Text = report.SteamRoots.Count == 0 ? "未找到 Steam" : $"Steam：{string.Join("；", report.SteamRoots)}";

        switch (report.Conclusion)
        {
            case AuditConclusion.NoTamperingFound:
                ApplyHero("本次结论", "未发现 Steam 客户端篡改迹象", "这是“未命中已支持证据”，不是对整台电脑的绝对安全保证。", Palette.GreenTint, Palette.Green, "✓");
                break;
            case AuditConclusion.ReviewNeeded:
                ApplyHero("本次结论", "有几项需要你核对", "先确认是否来自你主动安装的客户端插件，不认识的项目交给专业杀毒软件。", Palette.AmberTint, Palette.Amber, "!");
                break;
            case AuditConclusion.StrongTamperingSignal:
                ApplyHero("请先停止操作", "发现强篡改信号", "不要付款、扫码或立刻改密码。先断网并交给专业杀毒软件全盘查杀。", Palette.RedTint, Palette.Red, "!");
                break;
            default:
                ApplyHero("覆盖不足", "体检没有完整覆盖所有项目", "请查看灰色检查卡与覆盖说明，不要把未检查部分理解成安全。", Palette.GrayTint, Palette.Gray, "…");
                break;
        }

        if (Findings.Count == 0)
        {
            ResultsPanel.Visibility = Visibility.Collapsed;
            EmptyResultsPanel.Visibility = Visibility.Visible;
            EmptyResultsTitleText.Text = "没有异常证据需要展开";
            EmptyResultsDescriptionText.Text = "请同时查看上方检查卡与覆盖限制。如果你看到可疑红信，仍建议使用“红信判真伪”交叉核对。";
        }
        else
        {
            EmptyResultsPanel.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Visible;
            FindingsList.SelectedIndex = 0;
        }
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
        FooterStatusText.Text = "链接仅在本地完成解析 · 未联网、未打开";
    }

    private void ClearUrl_Click(object sender, RoutedEventArgs e)
    {
        UrlInputTextBox.Clear();
        UrlResults.Clear();
        UrlSummaryEyebrow.Text = "等待检查";
        UrlSummaryText.Text = "实际主机会在这里显示";
        UrlSummaryNoteText.Text = "官方客服主机应为 help.steampowered.com，看起来相似的前缀、@ 符号或多一级后缀都不算。";
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
            CloudSyncGuidanceText.Text = "跨设备可见更符合云端通知，但仍必须核对“联系客服”链接的实际主机，且 Steam 客服不会要求二维码小额付款验证。";
            CloudSyncGuidanceText.Background = Palette.GreenTint;
        }
        else
        {
            CloudSyncGuidanceText.Text = "建议在手机 Steam App 或浏览器手动进入官方客服页交叉核对。不要从当前红信页面跳转。";
            CloudSyncGuidanceText.Background = Palette.GrayTint;
        }
    }

    private void CopyOfficialSupport_Click(object sender, RoutedEventArgs e) => CopyText(ProductInfo.OfficialSupportUrl, "官方客服地址已复制");

    private void CopyHandoff_Click(object sender, RoutedEventArgs e) =>
        CopyText(ProfessionalHandoff.BuildChecklist(_lastReport), "交接清单已复制，可粘贴给安全人员或保存到记事本");

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
        ClientModsCheckBox.IsEnabled = !busy;
        EvidenceExportButton.IsEnabled = !busy;
        EvidenceCancelButton.IsEnabled = busy;
        ChooseEvidenceFolderButton.IsEnabled = !busy;
        ClearEvidenceFolderButton.IsEnabled = !busy;
    }
}
