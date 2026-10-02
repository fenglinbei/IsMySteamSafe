#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$SkipInstaller,
    [string]$SigningThumbprint,
    [string]$SignToolPath,
    [ValidateSet('preview', 'ci')][string]$BuildChannel = 'preview'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'code-signing.ps1')

function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Invoke-SourceGit([string[]]$Arguments) {
    $output = & git -C $projectRoot @Arguments
    if ($LASTEXITCODE -ne 0) { throw "git failed: $($Arguments -join ' ')" }
    return ($output -join "`n").Trim()
}
function Invoke-ReleaseDotNet([string[]]$Arguments) {
    & dotnet @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed ($LASTEXITCODE): $($Arguments -join ' ')" }
}
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function Assert-ChildPath([string]$Candidate, [string]$Parent) {
    Require ([IO.Path]::GetFullPath($Candidate).StartsWith([IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) "Path escaped expected parent: $Candidate"
}
function No-Reparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        Require (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "Redirected build path: $($item.FullName)"
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent } else { $item = $item.Directory }
    }
}
function Write-Lines([string]$Path, [string[]]$Lines) { [IO.File]::WriteAllLines($Path, $Lines, [Text.UTF8Encoding]::new($false)) }
function Write-Json([string]$Path, $Value) { [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 16) + "`r`n"), [Text.UTF8Encoding]::new($false)) }
function Payload-Files([string]$Root) {
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force) {
        Require (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "Redirected payload entry: $($item.FullName)"
        if ($item.PSIsContainer) { Payload-Files $item.FullName } else { $item }
    }
}
function Payload-Hashes([string]$Root) {
    @(Payload-Files $Root | Where-Object FullName -INE (Join-Path $Root 'SHA256SUMS.txt') | Sort-Object FullName | ForEach-Object {
        '{0} *{1}' -f (Hash $_.FullName), $_.FullName.Substring($Root.Length + 1)
    })
}
function Assert-Runtime([string]$Root, [string]$Application, [string]$ExpectedVersion) {
    $options = (Get-Content -LiteralPath (Join-Path $Root ($Application + '.runtimeconfig.json')) -Raw -Encoding UTF8 | ConvertFrom-Json).runtimeOptions
    Require ($null -eq $options.PSObject.Properties['framework'] -and $null -eq $options.PSObject.Properties['frameworks']) 'Framework-dependent deployment was produced.'
    $included = @($options.includedFrameworks)
    Require ($included.Count -eq 2) 'Both bundled Core and WindowsDesktop frameworks are required.'
    foreach ($name in @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App')) {
        $matches = @($included | Where-Object name -CEQ $name)
        Require ($matches.Count -eq 1 -and $matches[0].version -ceq $ExpectedVersion) "Unexpected servicing runtime: $name"
    }
    $binaries = @()
    foreach ($name in @('System.Private.CoreLib.dll', 'hostfxr.dll', 'hostpolicy.dll', 'PresentationFramework.dll')) {
        $file = Get-Item -LiteralPath (Join-Path $Root $name)
        No-Reparse $file.FullName
        Require ($file.VersionInfo.ProductVersion -match ('^' + [regex]::Escape($ExpectedVersion) + '($|[ +\-])')) "Unexpected bundled runtime identity: $name"
        $binaries += [ordered]@{ path = $name; fileVersion = $file.VersionInfo.FileVersion; productVersion = $file.VersionInfo.ProductVersion; sha256 = Hash $file.FullName }
    }
    $coreClr = Get-Item -LiteralPath (Join-Path $Root 'coreclr.dll')
    No-Reparse $coreClr.FullName
    $coreLib = Get-Item -LiteralPath (Join-Path $Root 'System.Private.CoreLib.dll')
    Require (($coreClr.VersionInfo.FileVersion -split ' ')[0].Replace(',', '.') -ceq $coreLib.VersionInfo.FileVersion) 'coreclr and CoreLib native build versions differ.'
    $binaries += [ordered]@{ path = 'coreclr.dll'; fileVersion = $coreClr.VersionInfo.FileVersion; productVersion = $coreClr.VersionInfo.ProductVersion; sha256 = Hash $coreClr.FullName }
    return [ordered]@{ expectedVersion = $ExpectedVersion; application = $Application; includedFrameworks = $included; binaries = $binaries }
}
function Assert-Results($Result, [int]$Minimum, [string]$Name) {
    foreach ($key in @('passed', 'failed', 'skipped', 'elapsedMs')) {
        Require ($null -ne $Result.PSObject.Properties[$key] -and ($Result.$key -is [int] -or $Result.$key -is [long]) -and $Result.$key -ge 0) "Missing/invalid $Name.$key"
    }
    Require ($Result.passed -ge $Minimum -and $Result.failed -eq 0 -and $Result.skipped -eq 0) "$Name failed its acceptance baseline."
}

Require ([string]::IsNullOrEmpty((Invoke-SourceGit @('status', '--porcelain=v1', '--untracked-files=all')))) 'Release/CI builds require a clean tracked and untracked worktree. Commit reviewed source before building.'
$commit = Invoke-SourceGit @('rev-parse', 'HEAD^{commit}')
$tree = Invoke-SourceGit @('rev-parse', 'HEAD^{tree}')
$short = Invoke-SourceGit @('rev-parse', '--short=12', 'HEAD')
Require ($commit -cmatch '^[0-9a-f]{40}$' -and $tree -cmatch '^[0-9a-f]{40}$') 'Git identity is incomplete.'
foreach ($entry in ((Invoke-SourceGit @('ls-tree', '-r', 'HEAD')) -split "`n")) {
    Require ($entry -match '^(100644|100755) blob ') 'Source snapshots may contain regular tracked files only.'
    Require ($entry -notmatch '(?i)\.(pfx|p12|key)("?)$') 'Private key material cannot enter a source release.'
}
[xml]$props = Get-Content -LiteralPath (Join-Path $projectRoot 'Directory.Build.props') -Raw -Encoding UTF8
$version = [string]$props.Project.PropertyGroup.VersionPrefix
$runtimeVersion = [string]$props.Project.PropertyGroup.IsMySteamSafeRuntimeFrameworkVersion
$framework = [string]$props.Project.PropertyGroup.TargetFramework
$minimum = [int]$props.Project.PropertyGroup.IsMySteamSafeMinimumSelfTests
Require ($version -match '^\d+\.\d+\.\d+$' -and $runtimeVersion -match '^\d+\.\d+\.\d+$' -and $minimum -ge 34) 'Invalid central version/runtime/self-test contract.'
$sdk = [string]((Get-Content -LiteralPath (Join-Path $projectRoot 'global.json') -Raw -Encoding UTF8 | ConvertFrom-Json).sdk.version)
$buildId = "$commit.$BuildChannel"
$identity = "$version+$buildId"
$bundleName = "IsMySteamSafe-$version-$BuildChannel-$short"
if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $projectRoot)) 'outputs\imss' }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
Require (-not $OutputRoot.StartsWith($projectRoot + '\', [StringComparison]::OrdinalIgnoreCase) -and $OutputRoot -ine $projectRoot) 'Place OutputRoot outside the source repository.'
[IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
No-Reparse $OutputRoot
$completed = Join-Path $OutputRoot $bundleName
Require (-not (Test-Path -LiteralPath $completed)) "Immutable output already exists: $completed"
$stage = Join-Path $OutputRoot ('.stage-' + [Guid]::NewGuid().ToString('N').Substring(0, 10))
Require (-not (Test-Path -LiteralPath $stage)) 'Unexpected staging directory collision.'
[IO.Directory]::CreateDirectory($stage) | Out-Null
$work = Join-Path $stage 'src'
$sourceZip = Join-Path $stage ($bundleName + '-source.zip')
$payload = Join-Path $stage ($bundleName + '-win-x64')
$binaryZip = Join-Path $stage ($bundleName + '-win-x64.zip')
$selfTestPath = Join-Path $stage 'SELFTEST-RESULTS.json'
$startupPath = Join-Path $stage 'UNIFIED-STARTUP-RESULTS.json'
$started = [DateTime]::UtcNow.ToString('o')
$oldLocation = Get-Location
try {
    & git -C $projectRoot archive --format=zip --prefix=IsMySteamSafe/ -o $sourceZip $tree
    Require ($LASTEXITCODE -eq 0) 'Exact Git source archive failed.'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($sourceZip, $work)
    $snapshot = Join-Path $work 'IsMySteamSafe'
    Set-Location -LiteralPath $snapshot
    $actualSdk = (& dotnet --version).Trim()
    Require ($LASTEXITCODE -eq 0 -and $actualSdk -ceq $sdk) "Pinned SDK required: expected $sdk, actual $actualSdk"
    . (Join-Path $snapshot 'scripts\code-signing.ps1')
    Require ($BuildChannel -ne 'ci' -or [string]::IsNullOrWhiteSpace($SigningThumbprint)) 'CI must use unsigned output and never access a signing key.'
    $profile = Get-ReleaseSigningProfile $SigningThumbprint $SignToolPath
    $lockHashes = @{}
    foreach ($project in @('IsMySteamSafe.App', 'IsMySteamSafe.Core', 'IsMySteamSafe.SelfTest')) {
        $lock = Join-Path $snapshot "$project\packages.lock.json"
        Require (Test-Path -LiteralPath $lock -PathType Leaf) "Committed lock file is required: $project/packages.lock.json"
        $lockHashes[$lock] = Hash $lock
    }
    $properties = @('-p:SelfContained=true', '-p:UseAppHost=true', '-p:CetCompat=true', '-p:AppendRuntimeIdentifierToOutputPath=false',
        '-p:ContinuousIntegrationBuild=true', '-p:PublishSingleFile=false', '-p:PublishTrimmed=false', '-p:DebugType=None', '-p:DebugSymbols=false',
        "-p:IsMySteamSafeSourceRevision=$commit", "-p:IsMySteamSafeBuildChannel=$BuildChannel", "-p:IsMySteamSafeBuildId=$buildId")
    Invoke-ReleaseDotNet (@('restore', 'IsMySteamSafe.slnx', '--locked-mode', '-r', 'win-x64', '--source', 'https://api.nuget.org/v3/index.json', '-p:NuGetAudit=true', '-p:NuGetAuditMode=all') + $properties)
    foreach ($lock in $lockHashes.Keys) { Require ((Hash $lock) -ceq $lockHashes[$lock]) 'Locked restore modified its source lock file.' }
    Invoke-ReleaseDotNet (@('build', 'IsMySteamSafe.SelfTest\IsMySteamSafe.SelfTest.csproj', '-c', 'Release', '-r', 'win-x64', '--no-restore') + $properties)
    $testRoot = Join-Path $snapshot "IsMySteamSafe.SelfTest\bin\Release\$framework"
    $testedRuntime = Assert-Runtime $testRoot 'IsMySteamSafe.SelfTest' $runtimeVersion
    $testExe = Join-Path $testRoot 'IsMySteamSafe.SelfTest.exe'
    Require ((Get-Item -LiteralPath $testExe).VersionInfo.ProductVersion -ceq $identity) 'Native SelfTest build identity mismatch.'
    & $testExe '--results' $selfTestPath | Out-Host
    Require ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $selfTestPath -PathType Leaf)) 'Native self-contained SelfTest failed or omitted results.'
    $selfTest = Get-Content -LiteralPath $selfTestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Results $selfTest $minimum 'SelfTest'
    Require ($selfTest.version -ceq $version -and $selfTest.buildIdentity -ceq $identity) 'SelfTest result provenance mismatch.'
    Invoke-ReleaseDotNet (@('publish', 'IsMySteamSafe.App\IsMySteamSafe.App.csproj', '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '--no-build', '--no-restore', '-o', $payload) + $properties)
    $publishedRuntime = Assert-Runtime $payload 'IsMySteamSafe' $runtimeVersion
    $nativeBuild = Join-Path $work 'native'
    $unified = & (Join-Path $snapshot 'scripts\build-unified-startup.ps1') -PublishRoot $payload -BuildRoot $nativeBuild -Version $version -BuildIdentity $identity -SourceRoot $snapshot
    Require ($unified.schema -ceq 'IsMySteamSafe.UnifiedStartup/1' -and $unified.mode -ceq 'unified' -and @($unified.hosts).Count -eq 3) 'Unified startup must verify exactly three hosts.'
    $signedFiles = @('IsMySteamSafe.exe', 'IsMySteamSafe.Standard.exe', 'IsMySteamSafe.Compat.exe', 'IsMySteamSafe.dll', 'IsMySteamSafe.Core.dll')
    foreach ($name in $signedFiles) {
        $info = (Get-Item -LiteralPath (Join-Path $payload $name)).VersionInfo
        Require ($info.FileVersion -ceq "$version.0" -and $info.ProductVersion -ceq $identity) "Product version/build identity mismatch: $name"
    }
    Sign-ReleaseFiles $profile $payload $signedFiles
    $signatureStatus = Write-ReleaseSigningInfo $profile $payload $BuildChannel
    $signatureResults = @()
    if ($null -ne $profile) { foreach ($name in $signedFiles) { $signatureResults += Assert-ReleaseSignature $profile (Join-Path $payload $name) $name } }
    Copy-Item -LiteralPath (Join-Path $snapshot 'IsMySteamSafe.App\Assets') -Destination (Join-Path $payload 'Assets') -Recurse
    foreach ($name in @('README.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE', 'LICENSE-STATUS.md', 'THIRD-PARTY-NOTICES.md')) {
        Copy-Item -LiteralPath (Join-Path $snapshot $name) -Destination $payload
    }
    Copy-Item -LiteralPath (Join-Path $snapshot 'docs') -Destination (Join-Path $payload 'docs') -Recurse
    $dotnetRoot = Split-Path -Parent (Get-Command dotnet).Source
    Copy-Item -LiteralPath (Join-Path $dotnetRoot 'LICENSE.txt') -Destination (Join-Path $payload 'DOTNET-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $dotnetRoot 'ThirdPartyNotices.txt') -Destination (Join-Path $payload 'DOTNET-THIRD-PARTY-NOTICES.txt')
    Copy-Item -LiteralPath (Join-Path $dotnetRoot "sdk\$sdk\Sdks\Microsoft.NET.Sdk.WindowsDesktop\THIRD-PARTY-NOTICES.TXT") -Destination (Join-Path $payload 'WINDOWSDESKTOP-THIRD-PARTY-NOTICES.txt')
    Write-Lines (Join-Path $payload 'VERSION.txt') @('Product=IsMySteamSafe', "Version=$version", "BuildIdentity=$identity", "SourceCommit=$commit", "SourceTree=$tree", "BuildChannel=$BuildChannel", "Runtime=win-x64 self-contained .NET $runtimeVersion", 'StartupMode=unified', 'StandardCetCompat=True', 'CompatCetCompat=False', 'NativeRuntime=MSVC static /MT', "SignatureStatus=$signatureStatus")
    $payloadHashes = @(Payload-Hashes $payload)
    $payloadManifest = Join-Path $payload 'SHA256SUMS.txt'
    Write-Lines $payloadManifest $payloadHashes
    $manifestHash = Hash $payloadManifest
    # Synthetic fixtures contain executables and deliberately long paths. Keep
    # them outside the immutable release bundle, retaining failed-run evidence.
    $startupEvidence = Join-Path $OutputRoot ('test-evidence-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($startupEvidence) | Out-Null
    $startupRun = Join-Path $startupEvidence 'startup-run.json'
    try {
        & (Join-Path $snapshot 'scripts\Test-UnifiedStartup.ps1') -PublishRoot $payload -ResultsPath $startupRun | Out-Host
    }
    finally {
        if (Test-Path -LiteralPath $startupRun -PathType Leaf) { Copy-Item -LiteralPath $startupRun -Destination $startupPath }
    }
    Require (Test-Path -LiteralPath $startupPath -PathType Leaf) 'Startup tests did not write results.'
    $startup = Get-Content -LiteralPath $startupPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Results $startup 24 'UnifiedStartup'
    Require ($startup.schema -ceq 'IsMySteamSafe.UnifiedStartupTests/1') 'Unexpected startup test schema.'
    if ($null -ne $startup.PSObject.Properties['needsElevated']) { Require ($startup.needsElevated -eq $false) 'Read-only application startup must not require elevation.' }
    Require ((Hash $payloadManifest) -ceq $manifestHash -and (($payloadHashes -join "`n") -ceq ((Payload-Hashes $payload) -join "`n"))) 'Startup checks changed the signed immutable payload.'
    [IO.Compression.ZipFile]::CreateFromDirectory($payload, $binaryZip, [IO.Compression.CompressionLevel]::Optimal, $true)
    $setupPath = $null
    if (-not $SkipInstaller) {
        $iscc = Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
        Require (Test-Path -LiteralPath $iscc -PathType Leaf) 'Inno Setup 6 is required unless -SkipInstaller is selected.'
        $signArgs = @(Get-InnoSigningArguments $profile)
        if ($null -ne $profile) { [IO.Directory]::CreateDirectory((Join-Path $stage 'signing-cache\IsMySteamSafe')) | Out-Null }
        & $iscc "/DPayloadDir=$payload" "/DOutputDir=$stage" "/DAppVersion=$version" @signArgs (Join-Path $snapshot 'installer\IsMySteamSafe.iss') | Out-Host
        Require ($LASTEXITCODE -eq 0) 'Installer compilation failed.'
        $generatedSetup = Join-Path $stage "IsMySteamSafe-$version-setup.exe"
        $setupPath = Join-Path $stage ($bundleName + '-setup.exe')
        Require (Test-Path -LiteralPath $generatedSetup -PathType Leaf) 'Installer output is missing.'
        [IO.File]::Move($generatedSetup, $setupPath)
        if ($null -ne $profile) { $signatureResults += Assert-ReleaseSignature $profile $setupPath ([IO.Path]::GetFileName($setupPath)) }
    }
    $metadata = [ordered]@{
        schemaVersion = 1; product = 'IsMySteamSafe'; version = $version; buildIdentity = $identity; buildId = $buildId
        mode = 'Preview'; buildChannel = $BuildChannel; preview = $true; dirty = $false; commit = $commit; sourceTree = $tree
        sdk = $actualSdk; runtime = 'win-x64'; runtimeFrameworkVersion = $runtimeVersion; selfContained = $true
        source = [ordered]@{ method = 'git archive'; includesIgnoredFiles = $false; status = @(); archiveSha256 = Hash $sourceZip }
        runtimeVerification = [ordered]@{ tested = $testedRuntime; published = $publishedRuntime }
        selfTest = $selfTest; selfTestResultsSha256 = Hash $selfTestPath; unifiedStartup = $unified
        unifiedStartupTests = $startup; unifiedStartupResultsSha256 = Hash $startupPath
        signing = [ordered]@{ status = $signatureStatus; certificateThumbprint = $(if ($null -eq $profile) { $null } else { $profile.Thumbprint }); timestamp = 'NONE'; publicTrustClaimed = $false; files = $signatureResults }
        payloadManifestSha256 = $manifestHash; payloadFiles = $payloadHashes.Count
        artifacts = [ordered]@{ binaryZip = [IO.Path]::GetFileName($binaryZip); binaryZipSha256 = Hash $binaryZip; sourceZip = [IO.Path]::GetFileName($sourceZip); installer = $(if ($null -eq $setupPath) { $null } else { [IO.Path]::GetFileName($setupPath) }); installerSha256 = $(if ($null -eq $setupPath) { $null } else { Hash $setupPath }) }
        startedAtUtc = $started; completedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-Json (Join-Path $stage 'RELEASE-METADATA.json') $metadata
    Set-Location -LiteralPath $oldLocation.Path
    Assert-ChildPath $work $stage
    No-Reparse $work
    Remove-Item -LiteralPath $work -Recurse -Force
    $signingCache = Join-Path $stage 'signing-cache'
    if (Test-Path -LiteralPath $signingCache) { Assert-ChildPath $signingCache $stage; No-Reparse $signingCache; Remove-Item -LiteralPath $signingCache -Recurse -Force }
    $outerHashes = @(Get-ChildItem -LiteralPath $stage -File | Sort-Object Name | ForEach-Object { '{0} *{1}' -f (Hash $_.FullName), $_.Name })
    Write-Lines (Join-Path $stage ($bundleName + '-RELEASE-SHA256.txt')) $outerHashes
    Require (-not (Test-Path -LiteralPath $completed)) 'Final output appeared during build; refusing replacement.'
    Assert-ChildPath $stage $OutputRoot
    Assert-ChildPath $completed $OutputRoot
    [IO.Directory]::Move($stage, $completed)
    [pscustomobject]@{ bundle = $completed; buildIdentity = $identity; sourceCommit = $commit; sourceTree = $tree; signingStatus = $signatureStatus; selfTests = $selfTest.passed; startupTests = $startup.passed } | ConvertTo-Json
}
finally { Set-Location -LiteralPath $oldLocation.Path }
