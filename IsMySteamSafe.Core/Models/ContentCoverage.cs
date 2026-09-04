namespace IsMySteamSafe.Core.Models;

public sealed record ContentCoverageItem(string Kind, string Target, string Detail, bool ReadFailed = false)
{
    public string NextStep => ReadFailed
        ? "请先核对文件是否存在、能否读取。完整内容扫描不能自动解决权限、损坏或不支持的格式，可导出报告进一步核对。"
        : "使用完整内容扫描以覆盖此项：打开 SteamSentinel，选择“完整内容扫描”，或单独扫描下列文件或目录。加密内容需要正确密码，仍受格式与安全上限限制。";
}

public sealed record ContentCoverageGroup(string Kind, int Count, string NextStep, string Details);

public static class AuditCoverage
{
    public const string Scope = "快速体检检查 Steam 客户端文件、界面逻辑、客服链接、相关进程与启动项，同时轻量检查已发现的本地工坊、MOD 与插件。不全盘扫描，不展开压缩包，不运行文件，正常视频只做格式与结构检查。";
    public const string Limits = "内容阶段最多检查 5,000 个文件，各根目录也有 5,000 个文件系统条目的枚举上限，文件哈希最多读取 256 MiB，单文件最多 64 MiB，内容阶段约 12 秒。达到边界不代表发现病毒，未检查内容不会视为安全。";
    public static IReadOnlyList<ContentCoverageGroup> Groups(AuditReport report)
    {
        List<ContentCoverageGroup> groups = report.ContentLimitations.GroupBy(i => (i.Kind, i.NextStep))
            .Select(g => new ContentCoverageGroup(g.Key.Kind, g.Count(), g.Key.NextStep,
                string.Join(Environment.NewLine + Environment.NewLine, g.Select(i => $"{i.Target}\n{i.Detail}")))).ToList();
        if (report.CoverageNotes.Count > 0) groups.Add(new("其他检查说明", report.CoverageNotes.Distinct().Count(),
            "请按具体原因处理，客户端或运行状态的读取失败应重新体检，不能只靠完整内容扫描替代。",
            string.Join(Environment.NewLine + Environment.NewLine, report.CoverageNotes.Distinct())));
        return groups;
    }
}
