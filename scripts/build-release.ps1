[CmdletBinding()]
param([string]$OutputRoot, [switch]$ReplaceExisting, [switch]$SkipInstaller, [string]$SigningThumbprint, [string]$SignToolPath)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'code-signing.ps1')
$signingProfile = Get-ReleaseSigningProfile $SigningThumbprint $SignToolPath
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $projectRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path $workspaceRoot 'outputs' }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$version = '0.2.6'
$packageName = "IsMySteamSafe-$version-win-x64"
$packageDir = Join-Path $OutputRoot $packageName
$binaryZip = Join-Path $OutputRoot "$packageName.zip"
$sourceZip = Join-Path $OutputRoot "IsMySteamSafe-$version-source.zip"
$setupPath = Join-Path $OutputRoot "IsMySteamSafe-$version-setup.exe"
$checksumPath = Join-Path $OutputRoot "IsMySteamSafe-$version-RELEASE-SHA256.txt"
function Assert-ChildPath([string]$Candidate, [string]$Parent) {
    if (-not [IO.Path]::GetFullPath($Candidate).StartsWith([IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Path escaped output root: $Candidate" }
}
$targets = @($packageDir,$binaryZip,$sourceZip,$checksumPath)
if (-not $SkipInstaller) { $targets += $setupPath }
foreach ($target in $targets) {
    Assert-ChildPath $target $OutputRoot
    if (Test-Path -LiteralPath $target) {
        if (-not $ReplaceExisting) { throw "Output exists, refusing overwrite: $target" }
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}
$stageRoot = Join-Path $workspaceRoot ('work\release-IsMySteamSafe-' + [Guid]::NewGuid().ToString('N'))
$sourceStage = Join-Path $stageRoot 'IsMySteamSafe'
New-Item -ItemType Directory -Force -Path $sourceStage,$OutputRoot | Out-Null
function Invoke-DotNet {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed: $LASTEXITCODE" }
}
Invoke-DotNet restore (Join-Path $projectRoot 'IsMySteamSafe.slnx') --source https://api.nuget.org/v3/index.json
Invoke-DotNet build (Join-Path $projectRoot 'IsMySteamSafe.slnx') -c Release --no-restore
Invoke-DotNet run --project (Join-Path $projectRoot 'IsMySteamSafe.SelfTest\IsMySteamSafe.SelfTest.csproj') -c Release --no-build
Invoke-DotNet publish (Join-Path $projectRoot 'IsMySteamSafe.App\IsMySteamSafe.App.csproj') '-c' 'Release' '-r' 'win-x64' '--self-contained' 'true' '-p:PublishSingleFile=false' '-p:DebugType=None' '-p:DebugSymbols=false' '-o' $packageDir
Sign-ReleaseFiles $signingProfile $packageDir @('IsMySteamSafe.exe','IsMySteamSafe.dll','IsMySteamSafe.Core.dll')
$signatureStatus = Write-ReleaseSigningInfo $signingProfile $packageDir
Copy-Item -LiteralPath (Join-Path $projectRoot 'IsMySteamSafe.App\Assets') -Destination (Join-Path $packageDir 'Assets') -Recurse
foreach ($name in @('README.md','CHANGELOG.md','LICENSE','NOTICE','LICENSE-STATUS.md','THIRD-PARTY-NOTICES.md')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $name) -Destination $packageDir
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs') -Destination (Join-Path $packageDir 'docs') -Recurse
$dotnetRoot = Split-Path -Parent (Get-Command dotnet).Source
$sdkVersion = (& dotnet --version).Trim()
Copy-Item -LiteralPath (Join-Path $dotnetRoot 'LICENSE.txt') -Destination (Join-Path $packageDir 'DOTNET-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $dotnetRoot 'ThirdPartyNotices.txt') -Destination (Join-Path $packageDir 'DOTNET-THIRD-PARTY-NOTICES.txt')
Copy-Item -LiteralPath (Join-Path $dotnetRoot "sdk\$sdkVersion\Sdks\Microsoft.NET.Sdk.WindowsDesktop\THIRD-PARTY-NOTICES.TXT") -Destination (Join-Path $packageDir 'WINDOWSDESKTOP-THIRD-PARTY-NOTICES.txt')
[IO.File]::WriteAllLines((Join-Path $packageDir 'VERSION.txt'), @('Product=IsMySteamSafe',"Version=$version",'Runtime=win-x64 self-contained .NET 10',"SignatureStatus=$signatureStatus"), [Text.UTF8Encoding]::new($false))
$manifest = Get-ChildItem -LiteralPath $packageDir -Recurse -File | Sort-Object FullName | ForEach-Object {
    '{0} *{1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash,$_.FullName.Substring($packageDir.Length).TrimStart('\')
}
[IO.File]::WriteAllLines((Join-Path $packageDir 'SHA256SUMS.txt'),$manifest,[Text.UTF8Encoding]::new($false))
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($packageDir,$binaryZip,[IO.Compression.CompressionLevel]::Optimal,$true)
Get-ChildItem -LiteralPath $projectRoot -Recurse -Force -File | Where-Object {
    $_.FullName -notmatch '[\\/](bin|obj|artifacts|\.git)[\\/]' -and $_.Extension -notin @('.pfx','.p12','.key')
} | ForEach-Object {
    Assert-ChildPath $_.FullName $projectRoot
    $destination = Join-Path $sourceStage $_.FullName.Substring($projectRoot.Length).TrimStart('\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $destination
}
[IO.Compression.ZipFile]::CreateFromDirectory($sourceStage,$sourceZip,[IO.Compression.CompressionLevel]::Optimal,$true)
if (-not $SkipInstaller) {
    $iscc = Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
    if (-not (Test-Path -LiteralPath $iscc)) { throw 'Inno Setup 6 was not found.' }
    $signArgs = @(Get-InnoSigningArguments $signingProfile)
    if ($null -ne $signingProfile) { New-Item -ItemType Directory -Force -Path (Join-Path $OutputRoot 'signing-cache\IsMySteamSafe') | Out-Null }
    & $iscc "/DPayloadDir=$packageDir" "/DOutputDir=$OutputRoot" "/DAppVersion=$version" @signArgs (Join-Path $projectRoot 'installer\IsMySteamSafe.iss')
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $setupPath)) { throw 'Installer compilation failed.' }
}
$archives = @($binaryZip,$sourceZip)
if (-not $SkipInstaller) { $archives += $setupPath }
$checksums = $archives | ForEach-Object { '{0} *{1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash,[IO.Path]::GetFileName($_) }
[IO.File]::WriteAllLines($checksumPath,$checksums,[Text.UTF8Encoding]::new($false))
Assert-ChildPath $stageRoot (Join-Path $workspaceRoot 'work')
Remove-Item -LiteralPath $stageRoot -Recurse -Force
Write-Host "PACKAGE_DIR=$packageDir"
Write-Host "SETUP=$setupPath"
Write-Host "SOURCE_ZIP=$sourceZip"
