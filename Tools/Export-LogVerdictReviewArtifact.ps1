#requires -Version 5.1

<#!
.SYNOPSIS
Export one redacted review queue from unknown findings and candidate rule files.

.DESCRIPTION
Combines unknown signatures from a LogVerdict report with local-model, Sigma, or
other inactive candidate rules. The artifact is a review exchange format: it has
stable ids, redacted evidence, source context, provenance, false-positive fields,
and a fixture scaffold. It never updates the curated verdict database.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [AllowEmptyCollection()][string[]]$CandidatePath,
    [string]$OutputPath,
    [ValidatePattern('^\d{4}-\d{2}-\d{2}T')][string]$GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'LogVerdict.psd1') -Force

function Get-LVReviewFileHash {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Read-LVReviewJson {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    return [pscustomobject][ordered]@{
        Path = $resolved
        Hash = Get-LVReviewFileHash -Path $resolved
        Document = [IO.File]::ReadAllText($resolved, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
    }
}

$resultRecord = Read-LVReviewJson -Path $ResultPath
$candidateRecords = New-Object System.Collections.Generic.List[object]
foreach ($path in @($CandidatePath | Where-Object { $_ })) {
    $record = Read-LVReviewJson -Path $path
    $document = $record.Document
    $rules = if ($document.PSObject.Properties['rules']) { @($document.rules) }
        elseif ($document.PSObject.Properties['candidates']) { @($document.candidates) }
        elseif ($document -is [System.Array]) { @($document) }
        else { @($document) }
    foreach ($rule in $rules) {
        $candidateRecords.Add([pscustomobject][ordered]@{
            id = [string]$rule.id
            sourcePath = $record.Path
            sourceHash = $record.Hash
            candidate = $rule
        }) | Out-Null
    }
}

$module = Get-Module LogVerdict
$rawResult = $resultRecord.Document
$candidatePayload = @($candidateRecords.ToArray()) | ConvertTo-Json -Depth 30 -Compress
$machineName = [string]$rawResult.MachineName
$artifact = & $module {
    param($InputResult, $CandidateJson, $When, $OriginalMachineName)
    $normalized = ConvertFrom-LVReportContract -InputObject $InputResult
    $redacted = ConvertTo-LVRedactedResult -Result $normalized
    $candidates = @()
    if ($CandidateJson) { $candidates = @($CandidateJson | ConvertFrom-Json -ErrorAction Stop) }
    New-LVReviewArtifact -Result $redacted -Candidate $candidates -GeneratedAt $When -MachineName $OriginalMachineName
} $rawResult $candidatePayload $GeneratedAt $machineName

if ($OutputPath) {
    $target = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $safeArtifact = & $module {
        param($Value)
        ConvertTo-LVJsonSafeValue -Value $Value
    } $artifact
    [IO.File]::WriteAllText($target, (($safeArtifact | ConvertTo-Json -Depth 30) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
}
return $artifact
