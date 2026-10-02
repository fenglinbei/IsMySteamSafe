# Shared preview signing helper. Certificates are selected explicitly; trust is never installed.
function Get-ReleaseSigningProfile([string]$Thumbprint, [string]$SignToolPath) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    if ($Thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid signing certificate thumbprint.' }
    $cert = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $Thumbprint) -ErrorAction Stop
    if (-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date) -or $cert.NotBefore -gt (Get-Date)) { throw 'Signing certificate is missing a private key or outside its validity period.' }
    if (-not ($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' })) { throw 'A Code Signing certificate is required.' }
    if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
        $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        $SignToolPath = Get-ChildItem -LiteralPath $sdk -Directory | Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    }
    if ([string]::IsNullOrWhiteSpace($SignToolPath) -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) { throw 'Windows SDK SignTool was not found.' }
    return [pscustomobject]@{ Certificate = $cert; Thumbprint = $Thumbprint.ToUpperInvariant(); Tool = (Resolve-Path -LiteralPath $SignToolPath).Path; SelfSigned = ($cert.Subject -eq $cert.Issuer) }
}

function Get-ReleaseNativeTrustCode([string]$Path) {
    if ($null -eq ('IsMySteamSafeReleaseTrust' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class IsMySteamSafeReleaseTrust {
    [StructLayout(LayoutKind.Sequential)] struct FileInfo { public uint Size; public IntPtr Path, Handle, Subject; }
    [StructLayout(LayoutKind.Sequential)] struct TrustData {
        public uint Size; public IntPtr Callback, Sip; public uint Ui, Revocation, Choice;
        public IntPtr File; public uint StateAction; public IntPtr State, Url; public uint Flags, Context;
    }
    [DllImport("wintrust.dll", ExactSpelling=true)] static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref TrustData data);
    public static uint Check(string path) {
        IntPtr name=Marshal.StringToCoTaskMemUni(path), memory=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileInfo)));
        var file=new FileInfo { Size=(uint)Marshal.SizeOf(typeof(FileInfo)), Path=name };
        Marshal.StructureToPtr(file,memory,false);
        // No UI/network retrieval. Preview validation does not change system trust.
        var data=new TrustData { Size=(uint)Marshal.SizeOf(typeof(TrustData)), Ui=2, Choice=1, File=memory, StateAction=1, Flags=0x1010 };
        var action=new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
        try { return unchecked((uint)WinVerifyTrust(new IntPtr(-1),action,ref data)); }
        finally { data.StateAction=2; WinVerifyTrust(new IntPtr(-1),action,ref data); Marshal.FreeHGlobal(memory); Marshal.FreeCoTaskMem(name); }
    }
}
'@
    }
    return [IsMySteamSafeReleaseTrust]::Check($Path)
}

function Assert-ReleaseSignature($Profile, [string]$Path, [string]$DisplayName = $Path) {
    if ($null -eq $Profile) { throw 'An explicit signing profile is required for signature validation.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $certificate = $signature.SignerCertificate
    $trust = Get-ReleaseNativeTrustCode $Path
    $allowedUntrustedRoot = $Profile.SelfSigned -and $trust -eq [Convert]::ToUInt32('800B0109', 16)
    if ($null -eq $certificate -or $certificate.Thumbprint -cne $Profile.Thumbprint -or
        $signature.Status.ToString() -eq 'HashMismatch' -or ($trust -ne 0 -and -not $allowedUntrustedRoot) -or
        $certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow -or
        ($Profile.SelfSigned -and $certificate.Subject -ne $certificate.Issuer)) {
        throw "Signature integrity/identity failed: $DisplayName (WinVerifyTrust=0x$($trust.ToString('X8')))."
    }
    return [pscustomobject]@{
        file = $DisplayName; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        thumbprint = $certificate.Thumbprint; status = $signature.Status.ToString(); nativeTrustCode = ('0x{0:X8}' -f $trust)
        trustedByWindows = ($trust -eq 0); timestamp = $(if ($null -eq $signature.TimeStamperCertificate) { 'NONE' } else { 'PRESENT' })
    }
}

function Sign-ReleaseFiles($Profile, [string]$Root, [string[]]$RelativeFiles) {
    if ($null -eq $Profile) { return }
    foreach ($relative in $RelativeFiles) {
        $file = [IO.Path]::GetFullPath((Join-Path $Root $relative))
        if (-not $file.StartsWith([IO.Path]::GetFullPath($Root).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Signing target escaped payload root.' }
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or ((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Signing target missing or redirected: $relative" }
        & $Profile.Tool sign /s My /sha1 $Profile.Thumbprint /fd SHA256 $file | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Code signing failed: $relative" }
        Assert-ReleaseSignature $Profile $file $relative | Out-Null
    }
}

function Write-ReleaseSigningInfo($Profile, [string]$Root, [string]$BuildChannel = 'preview') {
    if ($null -eq $Profile) {
        $status = if ($BuildChannel -eq 'ci') { 'UNSIGNED-CI' } else { 'UNSIGNED-PREVIEW' }
        $lines = @("SignatureStatus=$status", 'Timestamp=NONE', 'Trust=Unsigned validation build; no publisher authentication is claimed.')
    }
    else {
        $status = if ($Profile.SelfSigned) { 'SELF-SIGNED-PREVIEW' } else { 'SIGNED-PREVIEW' }
        $lines = @("SignatureStatus=$status", "Subject=$($Profile.Certificate.Subject)", "CertificateThumbprint=$($Profile.Thumbprint)",
            "CertificateExpires=$($Profile.Certificate.NotAfter.ToUniversalTime().ToString('O'))", 'Timestamp=NONE',
            'Trust=No trust store is modified. Self-signed previews are not publicly trusted.',
            'PrivateKey=Not included. SIGNER.cer contains only the public key.',
            'Verify=Compare release hashes and certificate fingerprints through a trusted independent channel.')
        Export-Certificate -Cert $Profile.Certificate -FilePath (Join-Path $Root 'SIGNER.cer') -Type CERT | Out-Null
    }
    [IO.File]::WriteAllLines((Join-Path $Root 'SIGNING.txt'), $lines, [Text.UTF8Encoding]::new($false))
    return $status
}

function Get-InnoSigningArguments($Profile) {
    if ($null -eq $Profile) { return @() }
    # Inno expands $q and $f. Pass them literally and never accept arbitrary $p commands.
    $command = '$q' + $Profile.Tool + '$q sign /s My /sha1 ' + $Profile.Thumbprint + ' /fd SHA256 $f'
    return @('/DEnableSigning=1', ('/Sfenglinbei=' + $command))
}
