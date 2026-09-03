using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace IsMySteamSafe.Core.Inspection;

public enum SignatureStatus
{
    Valid,
    Unsigned,
    Invalid,
    Error
}

public sealed record SignatureResult(SignatureStatus Status, string Detail, string? Subject, bool IsValveSigner);

public static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static SignatureResult Verify(string filePath)
    {
        IntPtr pathPointer = IntPtr.Zero;
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            pathPointer = Marshal.StringToCoTaskMemUni(filePath);
            WinTrustFileInfo fileInfo = new(pathPointer);
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            WinTrustData data = new(fileInfoPointer);
            int result = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref data);
            SignatureStatus status = result switch
            {
                0 => SignatureStatus.Valid,
                unchecked((int)0x800B0100) => SignatureStatus.Unsigned,
                unchecked((int)0x80092003) => SignatureStatus.Unsigned,
                _ => SignatureStatus.Invalid
            };

            string? subject = TryGetSignerSubject(filePath);
            bool valve = subject?.Contains("Valve Corp", StringComparison.OrdinalIgnoreCase) == true;
            string detail = status switch
            {
                SignatureStatus.Valid when valve => "签名链有效，签名者为 Valve Corp.",
                SignatureStatus.Valid => "签名链有效，但签名者不是 Valve。",
                SignatureStatus.Unsigned => "没有可验证的 Authenticode 签名。",
                _ => $"签名链校验失败（0x{result:X8}）。"
            };
            return new SignatureResult(status, detail, subject, valve);
        }
        catch (Exception ex)
        {
            return new SignatureResult(SignatureStatus.Error, ex.Message, null, false);
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPointer);
            if (pathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    private static string? TryGetSignerSubject(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
            using X509Certificate2 certificate2 = new(certificate);
#pragma warning restore SYSLIB0057
            return certificate2.Subject;
        }
        catch
        {
            return null;
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid actionId, ref WinTrustData data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public int StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;

        public WinTrustFileInfo(IntPtr filePath)
        {
            StructSize = Marshal.SizeOf<WinTrustFileInfo>();
            FilePath = filePath;
            FileHandle = IntPtr.Zero;
            KnownSubject = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public int StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SIPClientData;
        public uint UIChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfoPointer;
        public uint StateAction;
        public IntPtr StateData;
        public string? URLReference;
        public uint ProviderFlags;
        public uint UIContext;

        public WinTrustData(IntPtr fileInfoPointer)
        {
            StructSize = Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SIPClientData = IntPtr.Zero;
            UIChoice = 2;
            RevocationChecks = 0;
            UnionChoice = 1;
            FileInfoPointer = fileInfoPointer;
            StateAction = 0;
            StateData = IntPtr.Zero;
            URLReference = null;
            ProviderFlags = 0x00000010 | 0x00000100;
            UIContext = 0;
        }
    }
}
