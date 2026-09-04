using System.Buffers.Binary;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Reporting;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.SelfTest;

internal static partial class Program
{
    private static async Task TestQuickCoverageAsync()
    {
        string root = Path.Combine(Path.GetTempPath(), "IsMySteamSafe-Quick-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        try
        {
            SteamLayout layout = new(); layout.ContentRoots.Add(new(root, "431960", "workshop", "fixture"));
            string media = Path.Combine(root, "large.mp4");
            using (FileStream stream = File.Create(media))
            {
                byte[] header = new byte[24]; BinaryPrimitives.WriteUInt32BigEndian(header, 16); "ftyp"u8.CopyTo(header.AsSpan(4));
                BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(16), 100 * 1024 * 1024 - 16); "mdat"u8.CopyTo(header.AsSpan(20));
                stream.Write(header); stream.SetLength(100 * 1024 * 1024);
            }
            AuditReport report = new() { CompletedAt = DateTimeOffset.Now };
            report.Checks.Add(await LightContentAuditor.AuditAsync(layout, report, default, maximumBytes: 1)); report.RecalculateConclusion();
            Assert(report.Conclusion == AuditConclusion.NoTamperingFound && report.ContentLimitations.Single().Kind.Contains("结构检查"), "normal large media blamed on permissions or marked scan failed");
            Assert(report.ExecutionStatus == "快速体检已完成" && !AuditLabels.Conclusion(report.Conclusion).Contains("未完成"), "contradictory completion status");
            Assert(report.ContentLimitations.Single().NextStep.Contains("使用完整内容扫描以覆盖此项"), "missing concrete follow-up");
            Assert(ReportExporter.BuildMarkdown(report).Contains("未深查内容与补查方式") && ReportExporter.BuildJson(report).Contains("contentLimitations"), "export lost coverage details");
            await using (FileStream tail = new(media, FileMode.Append)) await tail.WriteAsync("MZ harmless static fixture"u8.ToArray());
            AuditReport overlay = new(); overlay.Checks.Add(await LightContentAuditor.AuditAsync(layout, overlay, default)); overlay.RecalculateConclusion();
            Assert(overlay.Findings.Any(f => f.Title.Contains("额外内容")) && overlay.Conclusion == AuditConclusion.ReviewNeeded, "overlay skipped with large normal video");

            string fake = Path.Combine(root, "fake.mp4"); await File.WriteAllTextAsync(fake, "MZ harmless fixture");
            AuditReport forged = new(); forged.Checks.Add(await LightContentAuditor.AuditAsync(layout, forged, default, maximumBytes: 1));
            Assert(forged.Findings.Any(f => f.Title.Contains("真实格式")), "oversized or over-budget fake media not sniffed");
            string container = Path.Combine(root, "fixture.zip"); await File.WriteAllBytesAsync(container, [0x50, 0x4b, 3, 4, 0, 0]);
            AuditReport archive = new(); archive.Checks.Add(await LightContentAuditor.AuditAsync(layout, archive, default));
            Assert(archive.ContentLimitations.Any(i => i.Kind.Contains("压缩") && i.NextStep.Contains("正确密码")), "encrypted or container boundary unexplained");

            string lockedDir = Path.Combine(root, "locked"); Directory.CreateDirectory(lockedDir);
            string locked = Path.Combine(lockedDir, "file.dll"); await File.WriteAllTextAsync(locked, "harmless fixture");
            SteamLayout onlyLocked = new(); onlyLocked.ContentRoots.Add(new(lockedDir, "4000", "mod", "fixture"));
            using (FileStream lease = new(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                AuditReport denied = new(); denied.Checks.Add(await LightContentAuditor.AuditAsync(onlyLocked, denied, default)); denied.RecalculateConclusion();
                Assert(denied.Conclusion == AuditConclusion.Incomplete && denied.ContentLimitations.Any(i => i.ReadFailed), "real read failure hidden as normal scope limit");
                Assert(denied.CoverageSummary.Contains("未能完成"), "read failure lost from top coverage summary");
            }
            AuditReport critical = new() { CompletedAt = DateTimeOffset.Now };
            critical.Checks.Add(new() { Id = "client-files", Name = "客户端文件", Area = AuditArea.ClientFiles, Priority = AuditPriority.P0,
                Level = AuditLevel.Incomplete, Summary = "读取失败" }); critical.RecalculateConclusion();
            Assert(critical.Conclusion == AuditConclusion.Incomplete, "critical Steam failure masked");
            AuditReport time = new(); time.Checks.Add(await LightContentAuditor.AuditAsync(layout, time, default, maximumTime: TimeSpan.Zero)); time.RecalculateConclusion();
            Assert(time.Conclusion == AuditConclusion.NoTamperingFound && time.ContentLimitations.Any(i => i.Kind.Contains("时间")), "normal time bound promoted to infection or failure");
            Assert(AuditCoverage.Groups(archive).Count < archive.ContentLimitations.Count + 1, "coverage groups not generated");
        }
        finally
        {
            if (ContentDiscovery.IsWithin(root, Path.GetTempPath()) && ContentDiscovery.IsLocalSafePath(root)) Directory.Delete(root, true);
        }
    }
}
