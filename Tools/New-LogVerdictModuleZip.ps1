#requires -Version 5.1

<##
.SYNOPSIS
Create a self-contained ZIP distribution of the LogVerdict PowerShell module.

.DESCRIPTION
The module ZIP is assembled from the manifest FileList rather than from a broad
directory glob. That keeps tests, local state, build output, and other checkout
only files out of the distribution while making the archive tree identical to
the files PowerShell installs for the module. The archive is unsigned by design.

.EXAMPLE
.\Tools\New-LogVerdictModuleZip.ps1 -OutputPath .\dist\LogVerdict-Module-v0.8.3.zip
#>
[CmdletBinding()]
param(
    [string]$SourceDirectory,

    [string]$OutputPath,

    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not $SourceDirectory) { $SourceDirectory = Split-Path -Parent $PSScriptRoot }
$SourceDirectory = [IO.Path]::GetFullPath($SourceDirectory)

if (-not $Version) {
    $Version = (& (Join-Path $PSScriptRoot 'Get-LogVerdictVersion.ps1')).Trim()
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $SourceDirectory ('dist\LogVerdict-Module-v{0}.zip' -f $Version)
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

function Get-LVModuleZipSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Get-LVModuleZipRelativePath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )

    $rootFull = ([IO.Path]::GetFullPath($Root)).TrimEnd('\') + '\'
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw ("Manifest file '{0}' is outside the module source directory." -f $Path)
    }
    $relative = $pathFull.Substring($rootFull.Length).Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($relative) -or $relative -match '(^|/)\.\.(/|$)' -or $relative.StartsWith('/')) {
        throw ("Manifest file '{0}' has an unsafe relative path." -f $relative)
    }
    return $relative
}

$manifestPath = Join-Path $SourceDirectory 'LogVerdict.psd1'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw ("Module manifest not found: {0}" -f $manifestPath)
}

$manifest = Test-ModuleManifest -Path $manifestPath
if ($manifest.Version.ToString() -ne $Version) {
    throw ("Module manifest declares v{0}, but VERSION declares v{1}." -f $manifest.Version, $Version)
}

$manifestFiles = @($manifest.FileList | Where-Object { $_ })
if ($manifestFiles.Count -lt 1) { throw 'Module manifest FileList is empty.' }

$expectedFiles = @()
foreach ($manifestFile in $manifestFiles) {
    $fullPath = [IO.Path]::GetFullPath([string]$manifestFile)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw ("Module manifest FileList entry is missing: {0}" -f $fullPath)
    }
    $expectedFiles += [pscustomobject]@{
        FullPath = $fullPath
        RelativePath = Get-LVModuleZipRelativePath -Root $SourceDirectory -Path $fullPath
    }
}

$duplicatePaths = @($expectedFiles | Group-Object RelativePath | Where-Object { $_.Count -gt 1 })
if ($duplicatePaths.Count -gt 0) {
    throw ("Module manifest FileList contains duplicate path(s): {0}" -f (($duplicatePaths | Select-Object -ExpandProperty Name) -join ', '))
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $outputDirectory -Force
}

$stagingDirectory = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-module-' + [Guid]::NewGuid().ToString('N'))
$temporaryZip = $OutputPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
try {
    $null = New-Item -ItemType Directory -Path $stagingDirectory -Force
    foreach ($file in ($expectedFiles | Sort-Object RelativePath)) {
        $destination = Join-Path $stagingDirectory ($file.RelativePath -replace '/', '\')
        $destinationParent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $destinationParent -Force
        }
        Copy-Item -LiteralPath $file.FullPath -Destination $destination -Force
    }

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    } catch {
        # The assembly is already loaded on some Windows PowerShell hosts.
        Write-Verbose 'System.IO.Compression.FileSystem is already loaded.'
    }
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $stagingDirectory,
        $temporaryZip,
        [IO.Compression.CompressionLevel]::Optimal,
        $false)

    Move-Item -LiteralPath $temporaryZip -Destination $OutputPath -Force
    [pscustomobject]@{
        Version = $Version
        Path = $OutputPath
        FileCount = $expectedFiles.Count
        Sha256 = Get-LVModuleZipSha256 -Path $OutputPath
        Bytes = [int64](Get-Item -LiteralPath $OutputPath).Length
    }
} finally {
    if (Test-Path -LiteralPath $temporaryZip -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryZip -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $stagingDirectory -PathType Container) {
        Remove-Item -LiteralPath $stagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
