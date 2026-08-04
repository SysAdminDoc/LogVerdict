[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path ([System.IO.Path]::GetTempPath()) 'LogVerdict-WindowsBenchmark'),
    [string]$Revision = 'dd61d0952749ee7963bde24220d1be5ede023033',
    [string]$ExpectedSha256 = 'caa98dd6c1291ba0470d5c171df8514616b35669d724652bd7aa973df0dee881',
    [string]$AnnotationPath,
    [switch]$Force,
    [switch]$RunBenchmark,
    [string]$BenchmarkOutputPath
)

$ErrorActionPreference = 'Stop'
if (-not $AnnotationPath) { $AnnotationPath = Join-Path $PSScriptRoot '..\Data\windows-log-benchmark.json' }

function Get-LVWindowsBenchmarkSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

if ($Revision -notmatch '^[0-9a-f]{40}$') { throw 'Revision must be a 40-character lowercase commit SHA.' }
if ($ExpectedSha256 -notmatch '^(?i:[0-9a-f]{64})$') { throw 'ExpectedSha256 must be a 64-character SHA-256 digest.' }
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\') + '\'
$resolvedOutputDirectory = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\') + '\'
if ($resolvedOutputDirectory.StartsWith($repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Benchmark corpus output must remain outside the repository; use the default temporary directory or choose another external path.'
}
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$fileName = 'Windows_2k.log_structured.csv'
$sourceUrl = 'https://raw.githubusercontent.com/logpai/loghub/{0}/Windows/{1}' -f $Revision, $fileName
$targetPath = Join-Path $OutputDirectory $fileName
$needsDownload = $Force -or -not (Test-Path -LiteralPath $targetPath -PathType Leaf)
if (-not $needsDownload) {
    $needsDownload = (Get-LVWindowsBenchmarkSha256 -Path $targetPath) -ine $ExpectedSha256
}

if ($needsDownload) {
    $downloadPath = Join-Path $OutputDirectory ($fileName + '.download')
    if (Test-Path -LiteralPath $downloadPath) { Remove-Item -LiteralPath $downloadPath -Force }
    Invoke-WebRequest -UseBasicParsing -Uri $sourceUrl -OutFile $downloadPath
    $actualSha256 = Get-LVWindowsBenchmarkSha256 -Path $downloadPath
    if ($actualSha256 -ine $ExpectedSha256) {
        Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
        throw "Downloaded benchmark projection hash $actualSha256 does not match the pinned digest $ExpectedSha256. Refusing to use an unreviewed source revision."
    }
    Move-Item -LiteralPath $downloadPath -Destination $targetPath -Force
}

$actualSha256 = Get-LVWindowsBenchmarkSha256 -Path $targetPath
if ($actualSha256 -ine $ExpectedSha256) { throw "Benchmark projection hash mismatch at $targetPath." }
$headers = @((Get-Content -LiteralPath $targetPath -TotalCount 1) -split ',')
foreach ($required in @('LineId', 'Date', 'Time', 'Level', 'Component', 'Content', 'EventId', 'EventTemplate')) {
    if ($headers -notcontains $required) { throw "Benchmark projection is missing the '$required' column." }
}
$rowCount = @(Import-Csv -LiteralPath $targetPath).Count
if ($rowCount -lt 1) { throw 'Benchmark projection contains no rows.' }
if (-not (Test-Path -LiteralPath $AnnotationPath -PathType Leaf)) { throw "Annotation manifest not found: $AnnotationPath" }
try {
    $annotation = Get-Content -LiteralPath $AnnotationPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Benchmark annotation manifest could not be read: $($_.Exception.Message)"
}
if ([int]$annotation.schemaVersion -ne 1 -or [string]$annotation.annotationLicense -ne 'MIT') {
    throw 'Benchmark annotations must use schema version 1 and declare the MIT license.'
}
if ([string]$annotation.source.file -cnotin @($fileName, ('Windows/' + $fileName)) -or
    [string]$annotation.source.revision -cne $Revision -or
    [string]$annotation.source.sha256 -ine $ExpectedSha256 -or
    [string]$annotation.source.uri -cne $sourceUrl) {
    throw 'Benchmark annotation source metadata does not match the pinned fetch revision, file, URI, or SHA-256.'
}

$result = [pscustomobject][ordered]@{
    CorpusPath = (Resolve-Path -LiteralPath $targetPath).Path
    CorpusSha256 = $actualSha256
    RowCount = $rowCount
    SourceUrl = $sourceUrl
    Revision = $Revision
    AnnotationPath = (Resolve-Path -LiteralPath $AnnotationPath).Path
}

if ($RunBenchmark) {
    $testPath = Join-Path $PSScriptRoot 'Test-LogVerdictWindowsBenchmark.ps1'
    $testArgs = @{ CorpusPath = $targetPath; AnnotationPath = $AnnotationPath }
    if ($BenchmarkOutputPath) { $testArgs.OutputPath = $BenchmarkOutputPath }
    $result | Add-Member -NotePropertyName Benchmark -NotePropertyValue (& $testPath @testArgs) -Force
}

return $result
