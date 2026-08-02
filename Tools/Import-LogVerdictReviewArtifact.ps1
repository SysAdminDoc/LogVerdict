#requires -Version 5.1

<#!
.SYNOPSIS
Validate a reviewed artifact and emit an added/changed/removed review diff.

.DESCRIPTION
Reads a redacted LogVerdict review artifact and compares it with an earlier artifact
when -ExistingPath is supplied. The output is a queue/diff only. It never edits the
curated verdict database, local rules, or fixture files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArtifactPath,
    [string]$ExistingPath,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'LogVerdict.psd1') -Force

function Read-LVReviewArtifactFile {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $document = [IO.File]::ReadAllText($resolved, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
    $module = Get-Module LogVerdict
    & $module { param($Artifact) Test-LVReviewArtifactObject -Artifact $Artifact } $document | Out-Null
    return [pscustomobject][ordered]@{ Path = $resolved; Document = $document }
}

$currentRecord = Read-LVReviewArtifactFile -Path $ArtifactPath
$previous = $null
if ($ExistingPath) { $previous = (Read-LVReviewArtifactFile -Path $ExistingPath).Document }
$module = Get-Module LogVerdict
$diff = & $module { param($Old, $Current) Get-LVReviewArtifactDiff -Previous $Old -Current $Current } $previous $currentRecord.Document

$output = [pscustomobject][ordered]@{
    schemaVersion = 1
    name = 'LogVerdict.ReviewImport'
    importedAt = (Get-Date).ToUniversalTime().ToString('o')
    artifact = $currentRecord.Path
    diff = $diff
    reviewed = @($currentRecord.Document.items | Where-Object { $_.review.status -ne 'pending' } | Select-Object -ExpandProperty id)
    curatedDatabaseUpdated = $false
    next = 'Review the diff, then apply accepted rules through the existing reviewed local-database workflow; this command does not promote or write rules.'
}
if ($OutputPath) {
    $target = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($target, (($output | ConvertTo-Json -Depth 20) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
}
return $output
