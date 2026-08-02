#requires -Version 5.1

<#
.SYNOPSIS
Turn a local Eric Zimmerman EvtxECmd Maps checkout into inactive rule drafts.

.DESCRIPTION
EvtxECmd map files identify a channel/provider/event-id and the EventData fields
worth extracting. This importer preserves that signal as review metadata, but it
does not invent a verdict, title, explanation, or remediation. Every emitted record
is therefore an experimental draft with empty prose and an MIT attribution. The
output is a review queue, not a database that can be shipped or activated directly.

The importer is deliberately local-only. It never downloads maps and never edits
Data/verdicts.json. A reviewer must fill the prose, choose a verdict and confidence,
remove the draft-only metadata, and validate the resulting database before merging.

.PARAMETER MapsPath
Root of a checkout's evtx/Maps directory.

.PARAMETER OutputPath
Optional UTF-8 (without BOM) JSON path for the draft rule array.

.PARAMETER Retrieved
ISO date recorded on every attribution record.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MapsPath,
    [string]$OutputPath,
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$Retrieved = (Get-Date -Format 'yyyy-MM-dd')
)

$ErrorActionPreference = 'Stop'

function Get-LVEvtxMapValue {
    param([Parameter(Mandatory = $true)][string]$Text)
    $value = $Text.Trim()
    if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    return $value.Trim()
}

function Get-LVEvtxMapHeader {
    param([Parameter(Mandatory = $true)][string]$Path)

    $header = [ordered]@{
        Author      = $null
        Description = $null
        EventId     = $null
        Channel     = $null
        Provider    = $null
        Properties  = New-Object System.Collections.Generic.List[string]
    }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*Author:\s*(?<v>.+?)\s*$') { $header.Author = Get-LVEvtxMapValue $Matches['v']; continue }
        if ($line -match '^\s*Description:\s*(?<v>.+?)\s*$') { $header.Description = Get-LVEvtxMapValue $Matches['v']; continue }
        if ($line -match '^\s*EventId:\s*(?<v>\d+)\s*$') { $header.EventId = [int]$Matches['v']; continue }
        if ($line -match '^\s*Channel:\s*(?<v>.+?)\s*$') { $header.Channel = Get-LVEvtxMapValue $Matches['v']; continue }
        if ($line -match '^\s*Provider:\s*(?<v>.+?)\s*$') { $header.Provider = Get-LVEvtxMapValue $Matches['v']; continue }
        if ($line -match '^\s*Property:\s*(?<v>.+?)\s*$') {
            $property = Get-LVEvtxMapValue $Matches['v']
            if ($property -and -not $header.Properties.Contains($property)) { $header.Properties.Add($property) | Out-Null }
        }
    }
    return [pscustomobject]$header
}

function Get-LVEvtxMapFilenameFallback {
    param([Parameter(Mandatory = $true)][string]$Name)

    $stem = [IO.Path]::GetFileNameWithoutExtension($Name)
    $parts = @($stem -split '_')
    if ($parts.Count -lt 3 -or $parts[-1] -notmatch '^\d+$') { return $null }
    return [pscustomobject]@{
        Channel  = ($parts[0..($parts.Count - 3)] -join '_')
        Provider = $parts[$parts.Count - 2]
        EventId  = [int]$parts[$parts.Count - 1]
    }
}

function Get-LVEvtxMapDraftId {
    param(
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $true)][int]$EventId
    )
    $text = '{0}|{1}|{2}' -f $Channel, $Provider, $EventId
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try { $digest = ([BitConverter]::ToString($sha1.ComputeHash($bytes))).Replace('-', '').Substring(0, 12) }
    finally { $sha1.Dispose() }
    return 'EVTXMAP-' + $digest.ToLowerInvariant()
}

$root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $MapsPath).Path).TrimEnd('\', '/')
$licensePath = Join-Path (Split-Path -Parent $root) 'LICENSE'
if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
    $licensePath = Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'LICENSE'
}
if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
    throw 'The EvtxECmd checkout has no root LICENSE file; refusing to infer its terms.'
}
$licenseText = [IO.File]::ReadAllText($licensePath)
if ($licenseText -notmatch '(?i)MIT License' -or $licenseText -notmatch '(?i)Permission is hereby granted, free of charge') {
    throw 'The EvtxECmd checkout licence is not recognizably MIT; refusing to import.'
}

$mapFiles = @(Get-ChildItem -LiteralPath $root -File -Filter '*.map' | Where-Object { $_.Name -notlike '!*.map' })
$drafts = New-Object System.Collections.Generic.List[object]
$seen = @{}
foreach ($file in $mapFiles) {
    $header = Get-LVEvtxMapHeader -Path $file.FullName
    $fallback = Get-LVEvtxMapFilenameFallback -Name $file.Name
    $channel = if ($header.Channel) { $header.Channel } elseif ($fallback) { $fallback.Channel } else { $null }
    $provider = if ($header.Provider) { $header.Provider } elseif ($fallback) { $fallback.Provider } else { $null }
    $eventId = if ($null -ne $header.EventId) { [int]$header.EventId } elseif ($fallback) { [int]$fallback.EventId } else { $null }
    if (-not $channel -or -not $provider -or $null -eq $eventId) {
        throw ("Map '{0}' has no complete Channel, Provider, and EventId header or filename fallback." -f $file.Name)
    }

    $key = '{0}|{1}|{2}' -f $channel.ToLowerInvariant(), $provider.ToLowerInvariant(), $eventId
    if ($seen.ContainsKey($key)) {
        throw ("Duplicate EvtxECmd map identity: {0}, {1}, {2}." -f $channel, $provider, $eventId)
    }
    $seen[$key] = $true

    $uriName = [Uri]::EscapeDataString($file.Name)
    $uri = 'https://github.com/EricZimmerman/evtx/blob/master/evtx/Maps/{0}' -f $uriName
    $drafts.Add([pscustomobject][ordered]@{
        id             = Get-LVEvtxMapDraftId -Channel $channel -Provider $provider -EventId $eventId
        status         = 'experimental'
        verified       = $Retrieved
        match          = [pscustomobject][ordered]@{ source = 'event'; channel = $channel; provider = $provider; eventId = $eventId }
        verdict        = 'unknown'
        title          = ''
        plain          = ''
        why            = ''
        action         = ''
        confidence     = 'low'
        references     = @($uri)
        falsepositives = @()
        sources        = @([pscustomobject][ordered]@{
            uri       = $uri
            licence   = 'MIT'
            author    = if ($header.Author) { $header.Author } else { 'Eric Zimmerman EvtxECmd Maps contributors' }
            retrieved = $Retrieved
            modified  = $false
        })
        mapFile        = $file.Name
        mapDescription = $header.Description
        candidateFields = @($header.Properties.ToArray())
    }) | Out-Null
}

$output = @($drafts.ToArray() | Sort-Object { $_.match.channel }, { $_.match.provider }, { $_.match.eventId })
if ($OutputPath) {
    $target = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($target, (($output | ConvertTo-Json -Depth 12) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
}
if ($output.Count -gt 0) { return $output }
