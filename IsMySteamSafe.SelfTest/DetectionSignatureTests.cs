using System.Text;
using Microsoft.Win32;
using IsMySteamSafe.Core.Inspection;
using IsMySteamSafe.Core.Models;
using IsMySteamSafe.Core.Steam;

namespace IsMySteamSafe.SelfTest;

internal static partial class Program
{
    private const string HealthyInterfaceFixture = "class X{BMustShowSupportAlertDialog(){return!!this.m_CurrentUser?.bSupportPopupMessage}BHasActiveSupportAlerts(){return!!this.m_CurrentUser?.bSupportAlertActive}OnGameActionUserRequest(e){switch(e){case 1:return}}}";
    private const string OfficialRouteFixture = "const routes={SupportMessages:'https://help.steampowered.com/messages',HelpAppPage:'https://help.steampowered.com/app',HelpFrontPage:'https://help.steampowered.com/'};";

    private static void TestTrustedValveIdentity()
    {
        const string valve = "CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US";
        Assert(AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, valve), "Observed legitimate Valve identity was rejected.");
        Assert(AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, "CN=Valve Corporation, O=Valve Corporation, C=US"), "Exact Valve Corporation identity was rejected.");
        foreach (SignatureStatus status in new[] { SignatureStatus.Invalid, SignatureStatus.Unsigned, SignatureStatus.Error })
            Assert(!AuthenticodeVerifier.IsTrustedValveSigner(status, valve), $"Untrusted signature {status} received Valve identity.");
        foreach (string subject in new[]
        {
            "CN=Fake Valve Corp. Installer, O=Example", "CN=Valve Corp. Evil, O=Example", "CN=Example, OU=Valve Corp.",
            "CN=Example, O=Valve Corp.", "CN=Valve Corp., O=Example", "CN=Valve Corp. + OU=Example",
            "CN=\"Example, O=Valve Corp.\"", "CN=Valve Corp.\u200b", "invalid-subject", ""
        })
            Assert(!AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, subject), "Spoofed or ambiguous subject accepted: " + subject);
        Assert(!AuthenticodeVerifier.IsTrustedValveSigner(SignatureStatus.Valid, null), "Missing subject accepted.");
    }

    private static void TestClientSignatureClassification()
    {
        const string valve = "CN=Valve Corp., O=Valve Corp., C=US";
        SignatureResult trusted = new(SignatureStatus.Valid, "fixture", valve, true);
        Assert(SteamClientFileAuditor.ClassifyCandidate("version.dll", true, false, false, trusted).Level == AuditLevel.NeedsReview,
            "An additional genuine Valve file should still be reviewed.");
        foreach (SignatureResult invalid in new[]
        {
            new SignatureResult(SignatureStatus.Invalid, "broken signature", valve, true),
            new SignatureResult(SignatureStatus.Error, "read failed", valve, true),
            new SignatureResult(SignatureStatus.Valid, "other publisher", "CN=Example, O=Example", false),
            new SignatureResult(SignatureStatus.Valid, "spoofed subject", "CN=Valve Corp. Evil, O=Example", true)
        })
        {
            Assert(SteamClientFileAuditor.ClassifyCandidate("version.dll", true, true, true, invalid).Level == AuditLevel.HighlySuspicious,
                "Invalid/spoofed/non-Valve CEF candidate was downgraded.");
            if (invalid.Status is SignatureStatus.Invalid or SignatureStatus.Error)
                Assert(SteamClientFileAuditor.ClassifyCandidate("wsock32.dll", false, true, true, invalid).Level == AuditLevel.HighlySuspicious,
                    "Opt-in excused a broken or unreadable signature.");
        }
        SignatureResult unsigned = new(SignatureStatus.Unsigned, "unsigned fixture", null, false);
        ClientFileClassification acknowledged = SteamClientFileAuditor.ClassifyCandidate("wsock32.dll", false, true, true, unsigned);
        Assert(acknowledged.Level == AuditLevel.NeedsReview && acknowledged.AcknowledgedModContext, "Acknowledged unsigned Millennium loader policy changed.");
        Assert(SteamClientFileAuditor.ClassifyCandidate("wsock32.dll", false, true, false, unsigned).Level == AuditLevel.HighlySuspicious,
            "Unacknowledged loader was downgraded.");
        Assert(SteamClientFileAuditor.ClassifyCandidate("wsock32.dll", false, false, true, unsigned).Level == AuditLevel.HighlySuspicious,
            "Opt-in without Millennium context was downgraded.");
        Assert(SteamClientFileAuditor.ClassifyCandidate("version.dll", false, true, true, unsigned).Level == AuditLevel.HighlySuspicious,
            "Opt-in incorrectly covered other candidate names.");
    }

    private static async Task TestStaticRouteCoverageAsync()
    {
        string root = CreateTempSteam();
        string scripts = Path.Combine(root, "steamui");
        Directory.CreateDirectory(scripts);
        string script = Path.Combine(scripts, "fixture.js");
        try
        {
            await File.WriteAllTextAsync(script, HealthyInterfaceFixture + OfficialRouteFixture);
            var healthy = await JavaScriptAuditor.AuditAsync(root, new AuditReport(), CancellationToken.None);
            Assert(healthy.InterfaceCheck.Level == AuditLevel.Passed && healthy.RouteCheck.Level == AuditLevel.Passed,
                "Complete ordinary static fixtures failed.");
            await File.WriteAllTextAsync(script, HealthyInterfaceFixture + "const keys=['SupportMessages','HelpAppPage','HelpFrontPage'];");
            var keysOnly = await JavaScriptAuditor.AuditAsync(root, new AuditReport(), CancellationToken.None);
            Assert(keysOnly.InterfaceCheck.Level == AuditLevel.Passed && keysOnly.RouteCheck.Level == AuditLevel.Incomplete,
                "Merely seeing route keys was incorrectly counted as verified URL mappings.");
            await File.WriteAllTextAsync(script, HealthyInterfaceFixture + OfficialRouteFixture + "const dynamic=SteamClient.URL.GetSteamURLList(); const overrides={SupportMessages:dynamic};");
            var dynamicMapping = await JavaScriptAuditor.AuditAsync(root, new AuditReport(), CancellationToken.None);
            Assert(dynamicMapping.RouteCheck.Level == AuditLevel.Incomplete, "Unresolved dynamic routes were concealed by static routes.");
            await File.WriteAllTextAsync(script, HealthyInterfaceFixture + OfficialRouteFixture + "const bad={SupportMessages:'https://help.steampowered.com.evil.example/'};");
            var thirdParty = await JavaScriptAuditor.AuditAsync(root, new AuditReport(), CancellationToken.None);
            Assert(thirdParty.RouteCheck.Level == AuditLevel.ConfirmedTampering, "Coverage changes lost third-party route findings.");
        }
        finally { DeleteOwnTemp(root); }
    }

    private static async Task TestJavaScriptReadCoverageAsync()
    {
        string root = CreateTempSteam();
        string scripts = Path.Combine(root, "steamui");
        Directory.CreateDirectory(scripts);
        Directory.CreateDirectory(Path.Combine(root, "clientui"));
        string first = Path.Combine(scripts, "first.js");
        string second = Path.Combine(scripts, "second.js");
        string healthy = HealthyInterfaceFixture + OfficialRouteFixture;
        int bytes = Encoding.UTF8.GetByteCount(healthy);
        try
        {
            await File.WriteAllTextAsync(first, healthy);
            await File.WriteAllTextAsync(second, healthy);
            foreach (JavaScriptAuditLimits limits in new[]
            {
                new JavaScriptAuditLimits(MaximumFiles: 1),
                new JavaScriptAuditLimits(MaximumScriptBytes: bytes - 1),
                new JavaScriptAuditLimits(MaximumTotalBytes: bytes),
                new JavaScriptAuditLimits(MaximumDirectories: 1)
            })
            {
                AuditReport report = new();
                var result = await JavaScriptAuditor.AuditAsync(root, report, CancellationToken.None, limits);
                Assert(result.InterfaceCheck.Level == AuditLevel.Incomplete && result.RouteCheck.Level == AuditLevel.Incomplete,
                    "A file/directory/byte budget limit still returned Passed.");
                Assert(report.CoverageNotes.Count > 1, "The coverage limit had no visible explanation.");
            }
            using (FileStream locked = new(second, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                AuditReport report = new();
                var result = await JavaScriptAuditor.AuditAsync(root, report, CancellationToken.None);
                Assert(result.InterfaceCheck.Level == AuditLevel.Incomplete && result.RouteCheck.Level == AuditLevel.Incomplete &&
                    report.Metrics.JavaScriptFilesChecked == 1, "A real locked script was falsely counted as fully covered.");
            }
            await File.WriteAllTextAsync(first, "class X{BMustShowSupportAlertDialog(){return true;}}");
            using (FileStream locked = new(second, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                var result = await JavaScriptAuditor.AuditAsync(root, new AuditReport(), CancellationToken.None);
                Assert(result.InterfaceCheck.Level == AuditLevel.ConfirmedTampering && result.RouteCheck.Level == AuditLevel.Incomplete,
                    "Read failure hid an independently detected tampering finding.");
            }
        }
        finally { DeleteOwnTemp(root); }
    }

    private static void TestRegistryReadCoverage()
    {
        IReadOnlyDictionary<string, object?> empty = new Dictionary<string, object?>();
        SteamLayout layout = new();
        AuditCheckResult clean = RegistryPersistenceAuditor.Audit(layout, new AuditReport(), (_, _, _) => empty);
        Assert(clean.Level == AuditLevel.Passed, "Fully readable empty registry fixture did not pass.");
        foreach (string denied in new[] { "CurrentVersion\\Run", "Image File Execution Options", "SilentProcessExit" })
        {
            AuditReport report = new();
            AuditCheckResult result = RegistryPersistenceAuditor.Audit(layout, report, (_, _, path) =>
                path.Contains(denied, StringComparison.Ordinal) ? throw new UnauthorizedAccessException("fixture denied") : empty);
            Assert(result.Level == AuditLevel.Incomplete && report.CoverageNotes.Count > 0,
                "A denied registry branch falsely passed: " + denied);
        }
    }

    private static void TestRegistryPartialFindings()
    {
        AuditReport report = new();
        AuditCheckResult result = RegistryPersistenceAuditor.Audit(new SteamLayout(), report, (_, _, path) =>
        {
            if (path.Contains("CurrentVersion\\Run", StringComparison.Ordinal)) throw new IOException("fixture read failed");
            if (path.Contains("Image File Execution Options", StringComparison.Ordinal))
                return new Dictionary<string, object?> { ["Debugger"] = "inert-fixture.exe" };
            return new Dictionary<string, object?>();
        });
        Assert(result.Level == AuditLevel.HighlySuspicious && report.Findings.Any(f => f.Id == "P1.REGISTRY.IFEO"),
            "An unreadable branch hid a separate persistence finding.");
        Assert(result.Summary.Contains("检查不完整", StringComparison.Ordinal) && report.CoverageNotes.Count > 0,
            "Partial registry coverage was not disclosed alongside findings.");
    }
}
