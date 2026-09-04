using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using IsMySteamSafe.Core.Models;

namespace IsMySteamSafe.Core.Reporting;

public static class ReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task ExportJsonAsync(AuditReport report, string path, CancellationToken cancellationToken = default)
    {
        string fullPath = PreparePath(path);
        await File.WriteAllTextAsync(fullPath, BuildJson(report), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken);
    }

    public static async Task ExportMarkdownAsync(AuditReport report, string path, CancellationToken cancellationToken = default)
    {
        string fullPath = PreparePath(path);
        await File.WriteAllTextAsync(fullPath, BuildMarkdown(report), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancellationToken);
    }

    public static string BuildJson(AuditReport report) => JsonRedaction.Redact(JsonSerializer.Serialize(report, JsonOptions));

    public static string BuildMarkdown(AuditReport report)
    {
        StringBuilder text = new();
        text.AppendLine($"# {ProductInfo.Name} · 体检报告");
        text.AppendLine();
        text.AppendLine($"- 工具版本：`{report.ProductVersion}`");
        text.AppendLine($"- 体检编号：`{report.AuditId:N}`");
        text.AppendLine($"- 开始时间：{report.StartedAt:yyyy-MM-dd HH:mm:ss zzz}");
        text.AppendLine($"- 完成时间：{report.CompletedAt:yyyy-MM-dd HH:mm:ss zzz}");
        text.AppendLine($"- 结论：**{AuditLabels.Conclusion(report.Conclusion)}**");
        text.AppendLine($"- 执行状态：{report.ExecutionStatus}");
        text.AppendLine($"- 覆盖说明：{report.CoverageSummary}");
        text.AppendLine($"- 检查范围：{AuditCoverage.Scope}");
        text.AppendLine($"- 内容阶段边界：{AuditCoverage.Limits}");
        text.AppendLine();
        text.AppendLine("> 本工具仅检查 Steam 是否出现已支持的篡改状态，不提供杀毒功能，“未发现异常”不代表系统绝对安全。");
        text.AppendLine();
        text.AppendLine("## 检查概览");
        text.AppendLine();
        text.AppendLine("| 优先级 | 检查项 | 状态 | 摘要 |");
        text.AppendLine("|---|---|---|---|");
        foreach (AuditCheckResult check in report.Checks)
        {
            text.AppendLine($"| {AuditLabels.Priority(check.Priority)} | {Escape(check.Name)} | {AuditLabels.Level(check.Level)} | {Escape(check.Summary)} |");
        }

        text.AppendLine();
        text.AppendLine("## 证据");
        text.AppendLine();
        foreach (string source in report.ContentSources.Distinct()) text.AppendLine("- 内容来源：" + Escape(source));
        text.AppendLine();
        if (report.Findings.Count == 0)
        {
            text.AppendLine("未生成异常或提示类证据。");
        }
        else
        {
            foreach (AuditFinding finding in report.Findings.OrderByDescending(item => AuditLabels.RiskRank(item.Level)).ThenBy(item => item.Priority))
            {
                text.AppendLine($"### {AuditLabels.Level(finding.Level)} · {finding.Title}");
                text.AppendLine();
                text.AppendLine($"- 分级：{AuditLabels.Priority(finding.Priority)}");
                if (!string.IsNullOrWhiteSpace(finding.Target)) text.AppendLine($"- 目标：`{Escape(finding.Target)}`");
                text.AppendLine($"- 检查结果：{Escape(finding.WhatFound)}");
                text.AppendLine($"- 说明：{Escape(finding.Meaning)}");
                text.AppendLine($"- 建议处理：{Escape(finding.Recommendation)}");
                foreach (EvidenceItem evidence in finding.Evidence) text.AppendLine($"- {Escape(evidence.Name)}：`{Escape(evidence.Value)}`");
                text.AppendLine();
            }
        }

        if (report.ContentLimitations.Count > 0)
        {
            text.AppendLine("## 未深查内容与补查方式");
            text.AppendLine();
            foreach (var group in report.ContentLimitations.GroupBy(i => (i.Kind, i.NextStep)))
            {
                text.AppendLine($"### {Escape(group.Key.Kind)} · {group.Count()} 条记录");
                text.AppendLine();
                text.AppendLine(Escape(group.Key.NextStep));
                text.AppendLine();
                foreach (var item in group) text.AppendLine($"- {Escape(item.Target)}：{Escape(item.Detail)}");
                text.AppendLine();
            }
        }
        if (report.CoverageNotes.Count > 0)
        {
            text.AppendLine("## 覆盖限制");
            text.AppendLine();
            foreach (string note in report.CoverageNotes.Distinct()) text.AppendLine($"- {Escape(note)}");
            text.AppendLine();
        }

        text.AppendLine("## 发现明显篡改时");
        text.AppendLine();
        text.AppendLine("1. 停止付款、扫码和输入凭据，断开网络。");
        text.AppendLine("2. 使用已更新的专业杀毒软件执行全盘扫描。");
        text.AppendLine("3. 确认查杀完成后，在可信设备上修改 Steam 密码并重新绑定手机令牌。");
        text.AppendLine("4. 卸载 Steam，并从官网重新安装，不要只修补单个文件。");
        text.AppendLine("5. 撤销其他设备授权，检查 Web API 密钥与购买记录。");
        text.AppendLine();
        text.AppendLine($"Steam 官方客服：{ProductInfo.OfficialSupportUrl}");
        text.AppendLine($"Steam 官方安装页：{ProductInfo.OfficialInstallerUrl}");

        return Utilities.FileUtilities.RedactSensitiveText(text.ToString());
    }

    private static string PreparePath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string? directory = Path.GetDirectoryName(fullPath);
        if (directory is not null) Directory.CreateDirectory(directory);
        return fullPath;
    }

    private static string Escape(string? value) => (value ?? string.Empty).Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");
}

public static class ProfessionalHandoff
{
    public static string BuildChecklist(AuditReport? report)
    {
        StringBuilder text = new();
        text.AppendLine("《我的 Steam 安全吗？》专业杀毒软件交接清单");
        text.AppendLine();
        text.AppendLine("重要顺序：先断网并完成全盘查杀，确认查杀完成后，再修改密码。请勿颠倒。");
        text.AppendLine();
        if (report is not null)
        {
            text.AppendLine($"体检结论：{AuditLabels.Conclusion(report.Conclusion)}");
            text.AppendLine($"体检编号：{report.AuditId:N}");
            foreach (string root in report.SteamRoots) text.AppendLine($"Steam 目录：{root}");
            foreach (AuditFinding finding in report.Findings.Where(item => item.Level is AuditLevel.ConfirmedTampering or AuditLevel.HighlySuspicious or AuditLevel.NeedsReview))
            {
                text.AppendLine($"重点核对：[{AuditLabels.Level(finding.Level)}] {finding.Title}");
                if (!string.IsNullOrWhiteSpace(finding.Target)) text.AppendLine($"  路径/位置：{finding.Target}");
                foreach (EvidenceItem hash in finding.Evidence.Where(item => item.Name.Contains("SHA-256", StringComparison.OrdinalIgnoreCase)))
                    text.AppendLine($"  {hash.Name}：{hash.Value}");
            }
        }
        else
        {
            text.AppendLine("尚无本次体检报告，请先运行安全体检，再复制此清单。");
        }

        text.AppendLine();
        text.AppendLine("建议处理步骤：");
        text.AppendLine("1. 断开网络，退出 Steam。 ");
        text.AppendLine("2. 更新并运行可信的专业杀毒软件（例如你已安装的 360、卡巴斯基或 Windows 安全中心），执行全盘扫描。 ");
        text.AppendLine("3. 查杀后重启并再次全盘扫描，确认没有检出。");
        text.AppendLine("4. 在干净设备上修改 Steam 密码并重新绑定手机令牌。 ");
        text.AppendLine("5. 卸载 Steam，从 https://store.steampowered.com/about/ 重新安装。 ");
        text.AppendLine("6. 在 Steam 客服中撤销其他设备授权，检查 Web API 密钥和购买记录。 ");
        text.AppendLine();
        text.AppendLine("本工具不会删除、隔离或修复文件，实际查杀请交给专业安全软件。");
        return text.ToString();
    }
}
