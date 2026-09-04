using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.Core.Models;

public sealed record AuditComparison(int Added, int NotObservedAgain, int StillObserved, string Summary)
{
    public static AuditComparison Compare(AuditReport before, AuditReport after)
    {
        static string Key(AuditFinding item) => item.Id + "|" + item.Area + "|" + FileUtilities.RedactSensitiveText(item.Target ?? "").ToUpperInvariant();
        HashSet<string> previous = before.Findings.Where(f => AuditLabels.RiskRank(f.Level) >= 30).Select(Key).ToHashSet(StringComparer.Ordinal);
        HashSet<string> current = after.Findings.Where(f => AuditLabels.RiskRank(f.Level) >= 30).Select(Key).ToHashSet(StringComparer.Ordinal);
        int added = current.Except(previous).Count(), missing = previous.Except(current).Count(), remaining = current.Intersect(previous).Count();
        return new(added, missing, remaining,
            $"与 {before.StartedAt:yyyy-MM-dd HH:mm} 的报告相比，新增 {added} 条，仍观察到 {remaining} 条，本次未再观察到 {missing} 条。\n\n" +
            "未再观察到不等于已彻底清除，请同时核对两次检查范围、权限与覆盖限制，进程退出也会让运行证据消失。");
    }
}
