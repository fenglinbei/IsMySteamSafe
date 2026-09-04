using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.Core.Inspection;

public sealed class SteamAuditCoordinator
{
    public async Task<AuditReport> RunAsync(
        SteamAuditOptions options,
        IProgress<AuditProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        AuditReport report = new();
        progress?.Report(new AuditProgress(4, "定位 Steam", "仅检查注册表和常见安装位置"));
        SteamLayout layout = SteamLocator.Discover();
        report.SteamRoots.AddRange(layout.SteamRoots);
        report.CoverageNotes.AddRange(layout.DiscoveryNotes);

        if (layout.SteamRoots.Count == 0)
        {
            report.CoverageNotes.Add("没有找到 Steam 安装目录，请确认 Steam 已安装并至少启动过一次，然后重试。");
            report.Checks.AddRange(MissingSteamChecks());
        }
        else
        {
            List<AuditCheckResult> fileChecks = [];
            List<AuditCheckResult> configurationChecks = [];
            List<AuditCheckResult> interfaceChecks = [];
            List<AuditCheckResult> routeChecks = [];
            int rootIndex = 0;
            foreach (string root in layout.SteamRoots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                rootIndex++;
                progress?.Report(new AuditProgress(10 + rootIndex * 8, "检查客户端文件", $"检查 DLL 侧载与签名（{rootIndex}/{layout.SteamRoots.Count}）", root));
                try
                {
                    fileChecks.Add(await SteamClientFileAuditor.AuditAsync(root, options, report, cancellationToken));
                    configurationChecks.Add(await SteamConfigurationAuditor.AuditAsync(root, report, cancellationToken));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    report.CoverageNotes.Add($"客户端文件检查未完成：{root}，{ex.Message}");
                    fileChecks.Add(Incomplete("client-files", AuditPriority.P0, AuditArea.ClientFiles, "客户端 DLL 侧载", "目录无法完整读取。"));
                    configurationChecks.Add(Incomplete("client-configuration", AuditPriority.P1, AuditArea.ClientConfiguration, "Steam 更新配置", "目录无法完整读取。"));
                }

                progress?.Report(new AuditProgress(32 + rootIndex * 8, "检查 Steam 界面", "检查客服告警、游戏启动和路由逻辑", root));
                try
                {
                    (AuditCheckResult interfaceCheck, AuditCheckResult routeCheck) = await JavaScriptAuditor.AuditAsync(root, report, cancellationToken);
                    interfaceChecks.Add(interfaceCheck);
                    routeChecks.Add(routeCheck);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    report.CoverageNotes.Add($"steamui 脚本检查未完成：{root}，{ex.Message}");
                    interfaceChecks.Add(Incomplete("interface-code", AuditPriority.P0, AuditArea.InterfaceCode, "steamui 关键逻辑", "脚本无法完整读取。"));
                    routeChecks.Add(Incomplete("support-routes", AuditPriority.P0, AuditArea.SupportRoutes, "客服路由域名", "脚本无法完整读取。"));
                }
            }

            report.Checks.Add(Merge(fileChecks));
            report.Checks.Add(Merge(configurationChecks));
            report.Checks.Add(Merge(interfaceChecks));
            report.Checks.Add(Merge(routeChecks));
        }

        if (options.IncludeExtendedChecks)
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new AuditProgress(65, "检查运行状态", "仅检查 Steam 进程模块"));
            report.Checks.Add(ProcessModuleAuditor.Audit(layout, report, cancellationToken));

            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new AuditProgress(76, "检查启动链", "仅检查 Steam 相关 Run、IFEO 和退出触发器"));
            report.Checks.Add(RegistryPersistenceAuditor.Audit(layout, report));
            report.Checks.Add(NetworkConfigurationAuditor.Audit(report));

            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new AuditProgress(88, "检查内容来源", "检查所有本地工坊 AppID、MOD 与插件，不解压或执行内容"));
            report.Checks.Add(WorkshopSourceObserver.Observe(layout, report, cancellationToken));
            report.Checks.Add(await LightContentAuditor.AuditAsync(layout, report, cancellationToken));
            foreach (string path in WallpaperUiInspector.CandidateFiles(layout))
            {
                try
                {
                    if (!ContentDiscovery.IsLocalSafePath(path)) throw new IOException("路径不安全");
                    string text = await Utilities.FileUtilities.ReadTextBoundedAsync(path, cancellationToken: cancellationToken);
                    if (!WallpaperUiInspector.HasCombinedSuppression(text)) continue;
                    report.Findings.Add(new AuditFinding { Id = "CONTENT.WALLPAPER.REPORT", Priority = AuditPriority.P1,
                        Level = AuditLevel.NeedsReview, Area = AuditArea.ContentSources, Title = "Wallpaper 举报入口存在组合隐藏信号", Target = path,
                        WhatFound = "举报能力被强制关闭，同时出现举报界面隐藏逻辑。", Meaning = "这是界面修改线索，需核对主动安装的插件，不单凭此项判定 Steam 感染。",
                        Recommendation = "先处理活动威胁，再在 Steam 中验证 Wallpaper Engine 文件完整性，必要时从官方渠道重新安装。" });
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { report.CoverageNotes.Add("Wallpaper 界面未能完整检查：" + path); }
            }
        }

        progress?.Report(new AuditProgress(96, "生成结论", "整理证据与覆盖限制"));
        report.CompletedAt = DateTimeOffset.Now;
        report.RecalculateConclusion();
        progress?.Report(new AuditProgress(100, "体检完成", AuditLabels.Conclusion(report.Conclusion)));
        return report;
    }

    private static AuditCheckResult Merge(IReadOnlyList<AuditCheckResult> checks)
    {
        if (checks.Count == 0) throw new ArgumentException("未生成检查结果。", nameof(checks));
        AuditCheckResult strongest = checks.OrderByDescending(item => AuditLabels.RiskRank(item.Level)).First();
        return new AuditCheckResult
        {
            Id = strongest.Id,
            Priority = strongest.Priority,
            Area = strongest.Area,
            Name = strongest.Name,
            Level = strongest.Level,
            Summary = checks.Count == 1 ? strongest.Summary : $"检查了 {checks.Count} 个 Steam 安装：{string.Join("，", checks.Select(item => item.Summary))}",
            EvidenceCount = checks.Sum(item => item.EvidenceCount)
        };
    }

    private static AuditCheckResult Incomplete(string id, AuditPriority priority, AuditArea area, string name, string summary) => new()
    {
        Id = id,
        Priority = priority,
        Area = area,
        Name = name,
        Level = AuditLevel.Incomplete,
        Summary = summary,
        EvidenceCount = 0
    };

    private static IEnumerable<AuditCheckResult> MissingSteamChecks()
    {
        yield return Incomplete("client-files", AuditPriority.P0, AuditArea.ClientFiles, "客户端 DLL 侧载", "未找到 Steam，无法检查。");
        yield return Incomplete("client-configuration", AuditPriority.P1, AuditArea.ClientConfiguration, "Steam 更新配置", "未找到 Steam，无法检查。");
        yield return Incomplete("interface-code", AuditPriority.P0, AuditArea.InterfaceCode, "steamui 关键逻辑", "未找到 Steam，无法检查。");
        yield return Incomplete("support-routes", AuditPriority.P0, AuditArea.SupportRoutes, "客服路由域名", "未找到 Steam，无法检查。");
    }
}
