[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$workspaceRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot '..\..'))
$outputRoot = [IO.Path]::GetFullPath((Join-Path $workspaceRoot 'outputs'))
$releaseName = 'IsMySteamSafe-0.2.2-evidence-win-x64'
$releaseDirectory = [IO.Path]::GetFullPath((Join-Path $outputRoot $releaseName))
$binaryZip = [IO.Path]::GetFullPath((Join-Path $outputRoot ($releaseName + '.zip')))
$sourceZip = [IO.Path]::GetFullPath((Join-Path $outputRoot 'IsMySteamSafe-0.2.2-evidence-source.zip'))
$sourceStage = [IO.Path]::GetFullPath((Join-Path $workspaceRoot 'work\IsMySteamSafe-0.2.2-evidence-source'))

function Assert-ChildPath([string]$candidate, [string]$parent) {
    $candidateFull = [IO.Path]::GetFullPath($candidate)
    $parentFull = [IO.Path]::GetFullPath($parent).TrimEnd('\')
    if (-not $candidateFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing operation outside expected root: $candidateFull"
    }
}

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $workspaceRoot 'work') | Out-Null
foreach ($target in @($releaseDirectory, $binaryZip, $sourceZip, $sourceStage)) {
    $parent = if ($target -eq $sourceStage) { Join-Path $workspaceRoot 'work' } else { $outputRoot }
    Assert-ChildPath $target $parent
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}

dotnet build (Join-Path $projectRoot 'IsMySteamSafe.slnx') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }

dotnet run --project (Join-Path $projectRoot 'IsMySteamSafe.SelfTest\IsMySteamSafe.SelfTest.csproj') -c Release --no-build
if ($LASTEXITCODE -ne 0) { throw 'Self tests failed.' }

dotnet publish (Join-Path $projectRoot 'IsMySteamSafe.App\IsMySteamSafe.App.csproj') -c Release -r win-x64 --self-contained true -o $releaseDirectory
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

$docsDirectory = Join-Path $releaseDirectory 'docs'
$licensesDirectory = Join-Path $releaseDirectory 'licenses'
New-Item -ItemType Directory -Force -Path $docsDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $licensesDirectory | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination (Join-Path $releaseDirectory 'README.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'CHANGELOG.md') -Destination (Join-Path $releaseDirectory 'CHANGELOG.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination (Join-Path $releaseDirectory 'LICENSE')
Copy-Item -LiteralPath (Join-Path $projectRoot 'NOTICE') -Destination (Join-Path $releaseDirectory 'NOTICE')
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE-STATUS.md') -Destination (Join-Path $releaseDirectory 'LICENSE-STATUS.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'THIRD-PARTY-NOTICES.md') -Destination (Join-Path $releaseDirectory 'THIRD-PARTY-NOTICES.md')
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\THREAT-MODEL.md') -Destination $docsDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\TEST-EVIDENCE.md') -Destination $docsDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\EVIDENCE-CHANGESET.md') -Destination $docsDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\RELEASE-CHECKLIST.md') -Destination $docsDirectory

$dotnetNotices = Join-Path $env:ProgramFiles 'dotnet\ThirdPartyNotices.txt'
if (Test-Path -LiteralPath $dotnetNotices) {
    Copy-Item -LiteralPath $dotnetNotices -Destination (Join-Path $licensesDirectory 'Microsoft.NET-ThirdPartyNotices.txt')
}

Compress-Archive -LiteralPath $releaseDirectory -DestinationPath $binaryZip -CompressionLevel Optimal

New-Item -ItemType Directory -Force -Path $sourceStage | Out-Null
$projectRootPrefix = $projectRoot.TrimEnd('\') + '\'
Get-ChildItem -LiteralPath $projectRoot -Recurse -Force -File | Where-Object {
    $_.FullName -notmatch '[\\/](bin|obj)[\\/]'
} | ForEach-Object {
    $sourceFull = [IO.Path]::GetFullPath($_.FullName)
    if (-not $sourceFull.StartsWith($projectRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to stage source outside project root: $sourceFull"
    }
    $relative = $sourceFull.Substring($projectRootPrefix.Length)
    $destination = Join-Path $sourceStage $relative
    New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($destination)) | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $destination
}
Compress-Archive -LiteralPath $sourceStage -DestinationPath $sourceZip -CompressionLevel Optimal
Assert-ChildPath $sourceStage (Join-Path $workspaceRoot 'work')
Remove-Item -LiteralPath $sourceStage -Recurse -Force

$checksums = @(
    Get-FileHash -Algorithm SHA256 -LiteralPath $binaryZip
    Get-FileHash -Algorithm SHA256 -LiteralPath $sourceZip
) | ForEach-Object { "$($_.Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($_.Path))" }
$checksumPath = Join-Path $outputRoot 'IsMySteamSafe-0.2.2-evidence-SHA256SUMS.txt'
$checksums | Set-Content -LiteralPath $checksumPath -Encoding utf8

Write-Host "Release directory: $releaseDirectory"
Write-Host "Binary archive:   $binaryZip"
Write-Host "Source archive:   $sourceZip"
Write-Host "Checksums:        $checksumPath"
