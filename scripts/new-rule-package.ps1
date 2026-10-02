#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$SigningThumbprint,
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$catalogSource = Get-Content -LiteralPath (Join-Path $SourceRoot 'IsMySteamSafe.Core\Inspection\KnownContentCatalog.cs') -Raw -Encoding UTF8
if ($catalogSource -notmatch 'BuiltInVersion = (\d+);') { throw 'Missing rule version' }
$ruleVersion = [long]$Matches[1]
if ($catalogSource -notmatch 'BuiltInPublishedAt = "([^"]+)";') { throw 'Missing rule publication date' }
$publishedAt = $Matches[1]
if ($catalogSource -notmatch 'SigningKeyId = "([A-F0-9]{40})";') { throw 'Missing pinned signing identity' }
if ($SigningThumbprint -cne $Matches[1]) { throw 'Rule signing certificate differs from the embedded key' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Preserve existing signed rule package' }
$certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $SigningThumbprint)
if (-not $certificate.HasPrivateKey -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow -or $certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow) { throw 'Valid publisher private key is required' }
$rules = @(Get-Content -LiteralPath (Join-Path $SourceRoot 'IsMySteamSafe.Core\Inspection\known-content.json') -Raw -Encoding UTF8 | ConvertFrom-Json)
$payload = [ordered]@{schemaVersion=1;product='IsMySteamSafe';version=$ruleVersion;publishedAt=$publishedAt;
    expiresAt=([DateTimeOffset]::Parse($publishedAt).AddDays(180).ToString('yyyy-MM-ddTHH:mm:ssZ'));
    minimumEngineVersion='0.2.8';rules=$rules}
$bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress))
$key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
try {
    $signature = $key.SignData($bytes, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pss)
} finally { $key.Dispose() }
$envelope = [ordered]@{schemaVersion=1;keyId=$SigningThumbprint;payloadBase64=[Convert]::ToBase64String($bytes);signatureBase64=[Convert]::ToBase64String($signature)}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), (($envelope | ConvertTo-Json -Compress) + "`r`n"), [Text.UTF8Encoding]::new($false))
[pscustomobject]@{file=[IO.Path]::GetFileName($OutputPath);version=$ruleVersion;ruleCount=$rules.Count;sha256=(Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash;keyId=$SigningThumbprint;expiresAt=$payload.expiresAt}
