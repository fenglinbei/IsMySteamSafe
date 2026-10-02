using System.Diagnostics;
using System.Text;
using IsMySteamSafe.App.Services;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.SelfTest;

internal static partial class Program
{
    private const string ProbeNonce = "0123456789abcdefABCDEF0123456789";

    private static void TestStartupProtocol()
    {
        foreach (StartupMode mode in Enum.GetValues<StartupMode>())
        {
            string host = Path.Combine(@"C:\fixture", StartupCompatibility.HostFileName(mode));
            Assert(StartupCompatibility.TryIdentifyHost(host, out StartupMode actual, out bool unified) && actual == mode && unified,
                "Actual apphost identity was not preserved.");
            using StringWriter output = new();
            Assert(StartupCompatibility.TryRunProbe(["--startup-probe", ProbeNonce], host, output, out int exit) && exit == 0,
                "Valid startup probe failed.");
            Assert(output.ToString() == $"ISMYSTEAMSAFE_STARTUP_READY/1|app|{StartupCompatibility.ModeName(mode)}|{ProbeNonce}{Environment.NewLine}",
                "The readiness response was not exactly one identity-bound line.");
        }
        Assert(StartupCompatibility.TryIdentifyHost("IsMySteamSafe.exe", out StartupMode legacy, out bool legacyUnified) &&
            legacy == StartupMode.Standard && !legacyUnified, "Development apphost compatibility changed.");
        foreach (string unknown in new[] { "IsMySteamSafe.Compat.exe.backup", "IsMySteamSafe.OtherCompat.exe", "dotnet.exe", "SteamSentinel.Compat.exe", "" })
            Assert(!StartupCompatibility.TryIdentifyHost(unknown, out _, out _), "Unknown executable inferred a startup mode.");
        Assert(!string.IsNullOrWhiteSpace(StartupCompatibility.BuildIdentity) && StartupCompatibility.Version != "unknown",
            "Assembly build identity was unavailable.");
    }

    private static void TestMalformedStartupProtocol()
    {
        foreach (string[] args in new[]
        {
            new[] { "--startup-probe" }, new[] { "--startup-probe", "" }, new[] { "--startup-probe", new string('a', 31) },
            new[] { "--startup-probe", new string('a', 33) }, new[] { "--startup-probe", new string('z', 32) },
            new[] { "--startup-probe", ProbeNonce, "extra" }, new[] { "extra", "--startup-probe", ProbeNonce },
            new[] { "--STARTUP-PROBE", ProbeNonce }, new[] { "--startup-probe=" + ProbeNonce },
            new[] { "--startup-mode", "compat" }, new[] { "--startup-check" },
            new[] { "--startup-probe", ProbeNonce[..31] + "|" }
        })
        {
            using StringWriter output = new();
            Assert(StartupCompatibility.TryRunProbe(args, "IsMySteamSafe.Standard.exe", output, out int exit) && exit == 2 && output.ToString().Length == 0,
                "Malformed reserved command could enter business code or claim readiness.");
        }
        using StringWriter sink = new();
        Assert(!StartupCompatibility.TryRunProbe([], "IsMySteamSafe.Standard.exe", sink, out _), "Ordinary startup was intercepted.");
        Assert(StartupCompatibility.TryRunProbe(["--startup-probe", ProbeNonce], "renamed.exe", sink, out int invalidExit) && invalidExit == 2,
            "Unknown host could forge readiness.");
    }

    private static async Task TestRealManagedStartupProbeAsync()
    {
        string directory = CreateTempSteam();
        try
        {
            string workingDirectory = Path.Combine(directory, "probe-work");
            Directory.CreateDirectory(workingDirectory);
            string assembly = typeof(IsMySteamSafe.App.App).Assembly.Location;
            string host = Path.ChangeExtension(assembly, ".exe");
            Assert(File.Exists(host), "Built native apphost is missing.");
            (int exit, string stdout, string stderr) = await RunProbeChildAsync(host, ["--startup-probe", ProbeNonce], workingDirectory);
            Assert(exit == 0 && string.IsNullOrWhiteSpace(stderr) && stdout.TrimEnd('\r', '\n') ==
                $"ISMYSTEAMSAFE_STARTUP_READY/1|app|standard|{ProbeNonce}", "Actual managed apphost did not return the exact readiness response.");
            foreach (string[] malformed in new[] { new[] { "--startup-probe", "invalid" }, new[] { "--startup-mode", "compat" } })
            {
                (int invalidExit, string invalidOut, _) = await RunProbeChildAsync(host, malformed, workingDirectory);
                Assert(invalidExit == 2 && string.IsNullOrEmpty(invalidOut), "Actual apphost accepted an invalid startup command.");
            }
            Assert(Directory.GetFileSystemEntries(workingDirectory).Length == 0 &&
                await File.ReadAllTextAsync(Path.Combine(directory, "steam.exe")) == "fixture", "Readiness probe created business/report files or changed the inert Steam fixture.");
        }
        finally { DeleteOwnTemp(directory); }
    }

    private static async Task<(int Exit, string Stdout, string Stderr)> RunProbeChildAsync(string path, string[] args, string directory)
    {
        ProcessStartInfo start = new(path) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = directory };
        foreach (string arg in args) start.ArgumentList.Add(arg);
        using Process child = Process.Start(start) ?? throw new InvalidOperationException("Startup probe did not start.");
        Task<string> stdout = child.StandardOutput.ReadToEndAsync();
        Task<string> stderr = child.StandardError.ReadToEndAsync();
        try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
        catch { if (!child.HasExited) child.Kill(entireProcessTree: true); throw; }
        return (child.ExitCode, await stdout, await stderr);
    }

    private static async Task TestLocalErrorReportAsync()
    {
        string directory = CreateTempSteam();
        try
        {
            for (int i = 0; i < 130; i++)
            {
                string startupPath = Path.Combine(directory, $"startup-fixture-{i:D3}.txt");
                await File.WriteAllTextAsync(startupPath, "DO_NOT_READ_STARTUP_CONTENT");
                File.SetLastWriteTimeUtc(startupPath, DateTime.UtcNow.AddSeconds(i));
            }
            Exception inner;
            try { throw new IOException("inner-reason token=private-token"); }
            catch (Exception error) { inner = error; }
            Exception outer = new InvalidOperationException("outer-reason\nAuthorization: Bearer private-header", inner);
            outer.Data["secret"] = "DO_NOT_READ_EXCEPTION_DATA";
            string? path = AppErrorLog.Write("test-stage", outer, directory);
            Assert(path is not null && File.Exists(path), "Local diagnostic report was not created.");
            string report = await File.ReadAllTextAsync(path!);
            Assert(report.Contains("BuildIdentity: " + StartupCompatibility.BuildIdentity) && report.Contains("Version: " + StartupCompatibility.Version) &&
                report.Contains("Runtime:") && report.Contains("OS:") && report.Contains("Architecture:") && report.Contains("Startup:") && report.Contains("UTC:"),
                "Local report omitted required process/runtime identity.");
            Assert(report.Contains("outer-reason") && report.Contains("inner-reason") && report.Contains(nameof(TestLocalErrorReportAsync)) &&
                report.Contains("System.IO.IOException"), "Exception chain or real stack was lost.");
            Assert(!report.Contains("private-token") && !report.Contains("private-header") && !report.Contains("DO_NOT_READ_EXCEPTION_DATA"),
                "Diagnostic report leaked a credential or collected Exception.Data.");
            Assert(report.Contains("startup-fixture-129.txt") && report.Contains("startup-fixture-128.txt") && !report.Contains("startup-fixture-127.txt") &&
                !report.Contains("DO_NOT_READ_STARTUP_CONTENT"), "Startup report index was not the latest two path references only.");
            Assert(report.Contains("local only") && report.Contains("no automatic upload"), "Report did not identify local-only collection.");
        }
        finally { DeleteOwnTemp(directory); }
    }

    private static async Task TestLocalErrorReportBoundariesAsync()
    {
        string directory = CreateTempSteam();
        try
        {
            AggregateException huge = new(Enumerable.Range(0, 100).Select(index => new IOException($"reason-{index}:" + new string('测', 8000))));
            string report = AppErrorLog.FormatReport("large", huge, directory);
            Assert(Encoding.UTF8.GetByteCount(report) <= AppErrorLog.MaximumReportBytes && report.Contains("report truncated"),
                "Report exceeded its UTF-8 byte budget or failed to explain truncation.");
            string? path = AppErrorLog.Write("large", huge, directory);
            Assert(path is not null && new FileInfo(path).Length <= AppErrorLog.MaximumReportBytes, "Saved report exceeded the byte budget.");
            string file = Path.Combine(directory, "not-a-directory");
            await File.WriteAllTextAsync(file, "original inert content");
            Assert(AppErrorLog.Write("write-failure", huge, file) is null && await File.ReadAllTextAsync(file) == "original inert content",
                "Write failure threw or modified the existing file.");
            Assert(AppErrorLog.Write("after-failure", new IOException("later error"), directory) is not null, "Write guard was not reset after failure.");
            string recursiveDirectory = Path.Combine(directory, "recursive");
            CallbackMessageException recursive = new(() => AppErrorLog.Write("inner-recursive", huge, recursiveDirectory));
            Assert(AppErrorLog.Write("outer-recursive", recursive, recursiveDirectory) is not null && recursive.Calls == 1 &&
                Directory.EnumerateFiles(recursiveDirectory, "error-*.log").Count() == 1, "Diagnostic error handler recursively wrote reports.");
            string? getterPath = AppErrorLog.Write("throwing-message", new ThrowingMessageException(), directory);
            Assert(getterPath is not null && (await File.ReadAllTextAsync(getterPath)).Contains("exception field unavailable"),
                "A faulty Exception.Message getter prevented the report.");
            int beforeCancellation = Directory.GetFiles(directory, "error-*.log").Length;
            Assert(AppErrorLog.Write("user-cancelled", new OperationCanceledException(), directory) is null &&
                Directory.GetFiles(directory, "error-*.log").Length == beforeCancellation, "User cancellation was recorded as an unexpected crash.");
            string fullDirectory = Path.Combine(directory, "full");
            Directory.CreateDirectory(fullDirectory);
            string[] unrelated = ["error-user-notes.log", "notes.txt", "error-20269999-000000-0123456789abcdef0123456789abcdef.log"];
            foreach (string name in unrelated) await File.WriteAllTextAsync(Path.Combine(fullDirectory, name), "keep unrelated content");
            string? oldest = AppErrorLog.Write("first-report", new IOException("first"), fullDirectory);
            Assert(oldest is not null, "Initial retention report could not be created.");
            File.SetLastWriteTimeUtc(oldest!, DateTime.UtcNow.AddYears(-1));
            string? newest = null;
            for (int i = 0; i < 50; i++) newest = AppErrorLog.Write("rolling-report", new IOException("report " + i), fullDirectory);
            Assert(newest is not null && File.Exists(newest) && !File.Exists(oldest) &&
                Directory.EnumerateFiles(fullDirectory).Count(item => AppErrorLog.IsOwnReportName(Path.GetFileName(item))) == 50,
                "The 51st report was lost or retention did not remove the oldest report.");
            foreach (string name in unrelated)
                Assert(await File.ReadAllTextAsync(Path.Combine(fullDirectory, name)) == "keep unrelated content", "Retention changed an unrelated file.");
            Assert(AppErrorLog.Write("cancel-with-full-logs", new OperationCanceledException(), fullDirectory) is null && File.Exists(newest),
                "User cancellation rotated or created an error report.");
        }
        finally { DeleteOwnTemp(directory); }
    }

    private static void TestErrorReportMessages()
    {
        string saved = IsMySteamSafe.App.App.ErrorMessage(new IOException("token=private-ui-token"), @"C:\fixture\report.log");
        Assert(saved.Contains(@"C:\fixture\report.log") && saved.Contains("未上传") && !saved.Contains("private-ui-token"),
            "Error UI omitted report path or leaked a known credential.");
        string unavailable = IsMySteamSafe.App.App.ErrorMessage(new ThrowingMessageException(), null);
        Assert(unavailable.Contains("未能保存") && unavailable.Contains("没有上传"), "Error UI failed when reporting itself was unavailable.");
    }

    private sealed class CallbackMessageException(Func<string?> callback) : Exception
    {
        internal int Calls { get; private set; }
        public override string Message { get { Calls++; _ = callback(); return "recursive fixture"; } }
    }

    private sealed class ThrowingMessageException : Exception
    {
        public override string Message => throw new InvalidOperationException("fixture getter failure");
    }
}
