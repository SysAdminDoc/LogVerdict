#requires -Version 5.1

<#
.SYNOPSIS
Turn a local Sigma rules checkout into an attributed, inactive LogVerdict review queue.

.DESCRIPTION
This importer handles the common Sigma YAML shape without adding a YAML dependency.
It maps Windows logsource and simple detection fields into LogVerdict's match contract,
retains the original Sigma metadata, and emits only unsupported draft rules. A reviewer
must inspect the mapping, false positives, fixture, licence and prose before activation.

The importer is local-only. It never downloads rules, contacts a service, or edits the
shipped database. A recognisable repository licence is mandatory and can be restricted
with -LicensePolicy. -ExistingPath and -DiffPath make the review queue auditable across
successive imports.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RulesPath,
    [string]$OutputPath,
    [string]$ExistingPath,
    [string]$DiffPath,
    [string]$RepositoryUri = 'https://github.com/SigmaHQ/sigma/blob/master',
    [ValidateSet('AnyRecognized', 'DRL-1.1', 'MIT', 'Apache-2.0', 'CC-BY-4.0')]
    [string]$LicensePolicy = 'AnyRecognized',
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$Retrieved = (Get-Date -Format 'yyyy-MM-dd'),
    [ValidateRange(1, 10000)][int]$MaxRules = 5000
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-LVSigmaScalar {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) { return $null }
    $value = $Text.Trim()
    if (-not $value) { return $null }
    if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
        return $value.Substring(1, $value.Length - 2).Replace('\\"', '"').Replace("''", "'")
    }
    if ($value -match '^\[(?<items>.*)\]$') {
        return @($Matches['items'] -split ',' | ForEach-Object { ConvertFrom-LVSigmaScalar -Text $_ })
    }
    if ($value -eq 'null' -or $value -eq '~') { return $null }
    if ($value -match '^(?i:true|false)$') { return [bool]::Parse($value) }
    if ($value -match '^-?\d+$') { return [int64]$value }
    return $value
}

function Get-LVSigmaTopValue {
    param([Parameter(Mandatory)][string[]]$Lines, [Parameter(Mandatory)][string]$Key)

    foreach ($line in $Lines) {
        if ($line -match ('^{0}:\s*(?<value>.*)$' -f [regex]::Escape($Key))) {
            return ConvertFrom-LVSigmaScalar -Text $Matches['value']
        }
    }
    return $null
}

function Get-LVSigmaSectionLine {
    param([Parameter(Mandatory)][string[]]$Lines, [Parameter(Mandatory)][string]$Section)

    $start = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match ('^{0}:\s*$' -f [regex]::Escape($Section))) { $start = $i; break }
    }
    if ($start -lt 0) { return @() }
    $sectionLinesBuilder = New-Object -TypeName 'System.Collections.Generic.List[string]'
    for ($i = $start + 1; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\S' -and $Lines[$i].Trim()) { break }
        if ($Lines[$i].Trim()) { $sectionLinesBuilder.Add([string]$Lines[$i]) | Out-Null }
    }
    return @($sectionLinesBuilder.ToArray())
}

function Get-LVSigmaListValue {
    param([Parameter(Mandatory)][string[]]$Lines, [Parameter(Mandatory)][string]$Section)

    $sectionLines = @(Get-LVSigmaSectionLine -Lines $Lines -Section $Section)
    $values = New-Object System.Collections.Generic.List[object]
    foreach ($line in $sectionLines) {
        if ($line -match '^\s*-\s*(?<value>.+?)\s*$') {
            $values.Add((ConvertFrom-LVSigmaScalar -Text $Matches['value'])) | Out-Null
        }
    }
    return @($values.ToArray())
}

function Get-LVSigmaNestedMap {
    param([Parameter(Mandatory)][string[]]$Lines, [Parameter(Mandatory)][string]$Section)

    $sectionLines = @(Get-LVSigmaSectionLine -Lines $Lines -Section $Section)
    $map = [ordered]@{}
    foreach ($line in $sectionLines) {
        if ($line -match '^\s{2,}(?<key>[^:#][^:]*?):\s*(?<value>.*)$') {
            $key = $Matches['key'].Trim()
            $map[$key] = ConvertFrom-LVSigmaScalar -Text $Matches['value']
        }
    }
    return [pscustomobject]$map
}

function Get-LVSigmaDetection {
    param([Parameter(Mandatory)][string[]]$Lines)

    $sectionLines = @(Get-LVSigmaSectionLine -Lines $Lines -Section 'detection')
    $condition = $null
    $selectionName = $null
    $selectionStart = -1
    for ($i = 0; $i -lt $sectionLines.Count; $i++) {
        if ($sectionLines[$i] -match '^\s{2}condition:\s*(?<value>.+)$') { $condition = ConvertFrom-LVSigmaScalar -Text $Matches['value']; continue }
        if ($sectionLines[$i] -match '^\s{2}(?<name>[A-Za-z0-9_*?-]+):\s*$' -and -not $selectionName) {
            $selectionName = $Matches['name']; $selectionStart = $i
        }
    }
    if (-not $selectionName) { throw 'Sigma detection section has no named selection.' }
    $selectionEnd = $sectionLines.Count
    for ($i = $selectionStart + 1; $i -lt $sectionLines.Count; $i++) {
        if ($sectionLines[$i] -match '^\s{2}[A-Za-z0-9_*?-]+:\s*') { $selectionEnd = $i; break }
    }
    $fields = [ordered]@{}
    for ($i = $selectionStart + 1; $i -lt $selectionEnd; $i++) {
        if ($sectionLines[$i] -match '^\s{4}(?<key>[^:#][^:]*?):\s*(?<value>.*)$') {
            $key = $Matches['key'].Trim()
            $value = $Matches['value']
            if ($value.Trim()) {
                $fields[$key] = ConvertFrom-LVSigmaScalar -Text $value
                continue
            }
            $list = New-Object System.Collections.Generic.List[object]
            for ($j = $i + 1; $j -lt $selectionEnd; $j++) {
                if ($sectionLines[$j] -match '^\s{6}-\s*(?<item>.+?)\s*$') { $list.Add((ConvertFrom-LVSigmaScalar -Text $Matches['item'])) | Out-Null; continue }
                if ($sectionLines[$j] -match '^\s{4}[^ ]') { break }
            }
            $fields[$key] = @($list.ToArray())
        }
    }
    return [pscustomobject][ordered]@{ Condition = $condition; Selection = $selectionName; Fields = [pscustomobject]$fields }
}

function Get-LVSigmaLicense {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Policy)

    $roots = @($Root)
    $parent = Split-Path -Parent $Root
    if ($parent -and $parent -ne $Root) { $roots += $parent }
    $grandparent = if ($parent) { Split-Path -Parent $parent } else { $null }
    if ($grandparent -and $grandparent -ne $parent) { $roots += $grandparent }
    $candidates = foreach ($licenseRoot in $roots) {
        @('LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING') | ForEach-Object { Join-Path $licenseRoot $_ }
    }
    $licensePath = @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
    if ($licensePath.Count -eq 0) { throw 'The Sigma checkout has no root LICENSE/COPYING file; refusing to infer its terms.' }
    $text = [IO.File]::ReadAllText($licensePath[0])
    $license = $null
    if ($text -match '(?i)(Detection Rule License|DRL[- ]?1\.1)') { $license = 'DRL-1.1' }
    elseif ($text -match '(?i)Apache License.*2\.0|Apache-2\.0') { $license = 'Apache-2.0' }
    elseif ($text -match '(?is)MIT License.*Permission is hereby granted') { $license = 'MIT' }
    elseif ($text -match '(?i)Creative Commons.*Attribution.*4\.0|CC-BY-4\.0') { $license = 'CC-BY-4.0' }
    if (-not $license) { throw 'The Sigma checkout licence is not recognizably DRL-1.1, Apache-2.0, MIT, or CC-BY-4.0; refusing to import.' }
    if ($Policy -ne 'AnyRecognized' -and $license -ne $Policy) { throw ("The Sigma checkout licence '{0}' does not satisfy -LicensePolicy '{1}'." -f $license, $Policy) }
    return [pscustomobject]@{ Name = $license; Path = $licensePath[0] }
}

function Get-LVSigmaFileHash {
    param([Parameter(Mandatory)][string]$Path)

    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Get-LVSigmaRelativePath {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $pathFull = [IO.Path]::GetFullPath($Path)
    if ($pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { return $pathFull.Substring($rootFull.Length).TrimStart('\', '/') }
    return [IO.Path]::GetFileName($Path)
}

function Get-LVSigmaEventMapping {
    param([Parameter(Mandatory)]$Logsource, [Parameter(Mandatory)]$Detection)

    $warnings = New-Object System.Collections.Generic.List[string]
    $match = [ordered]@{ source = 'event' }
    $service = [string]$Logsource.service
    $category = [string]$Logsource.category
    $providerMap = @{
        security = 'Microsoft-Windows-Security-Auditing'
        sysmon = 'Microsoft-Windows-Sysmon'
        powershell = 'Microsoft-Windows-PowerShell'
        system = 'Microsoft-Windows-Kernel-General'
    }
    $channelMap = @{
        security = 'Security'
        sysmon = 'Microsoft-Windows-Sysmon/Operational'
        powershell = 'Microsoft-Windows-PowerShell/Operational'
        system = 'System'
        application = 'Application'
    }
    if ($channelMap.ContainsKey($service.ToLowerInvariant())) { $match.channel = $channelMap[$service.ToLowerInvariant()] }
    elseif ($service) { $warnings.Add("No built-in channel mapping for logsource.service '$service'.") | Out-Null }
    if ($providerMap.ContainsKey($service.ToLowerInvariant())) { $match.provider = $providerMap[$service.ToLowerInvariant()] }
    $categoryEventId = @{
        process_creation = 1; network_connection = 3; image_load = 7; create_remote_thread = 8
        process_access = 10; file_event = 11; registry_event = 12; dns_query = 22
        process_termination = 5; driver_load = 6; powershell = 4104
    }
    if ($categoryEventId.ContainsKey($category.ToLowerInvariant())) { $match.eventId = $categoryEventId[$category.ToLowerInvariant()] }
    if ($service.ToLowerInvariant() -eq 'powershell' -and $category.ToLowerInvariant() -eq 'ps_script') { $match.eventId = 4104 }

    $eventDataConditions = New-Object System.Collections.Generic.List[object]
    foreach ($property in $Detection.Fields.PSObject.Properties) {
        $parts = @($property.Name -split '\|', 2)
        $field = $parts[0]
        $modifier = if ($parts.Count -gt 1) { $parts[1].ToLowerInvariant() } else { 'equals' }
        $values = @($property.Value)
        if ($field -match '^(?i:eventid|event\.code)$') {
            $ids = @($values | Where-Object { [string]$_ -match '^\d+$' })
            if ($ids.Count -eq 1) { $match.eventId = [int]$ids[0] } else { $warnings.Add("Detection field '$($property.Name)' has multiple/non-numeric values and was retained as review metadata.") | Out-Null }
            continue
        }
        if ($field -match '^(?i:channel|logname)$' -and $values.Count -eq 1) { $match.channel = [string]$values[0]; continue }
        if ($field -match '^(?i:provider|providername|provider_name)$' -and $values.Count -eq 1) { $match.provider = [string]$values[0]; continue }
        $structuredModifier = if ($modifier -eq 're') { 'regex' } else { $modifier }
        if ($values.Count -gt 0 -and $structuredModifier -in @('contains', 'startswith', 'endswith', 'equals', 'regex')) {
            $fieldName = if ($field -match '^(?i:(EventData|UserData)\.)') { $field } else { 'EventData.' + $field }
            $predicates = foreach ($value in $values) {
                $predicate = [ordered]@{ field = $fieldName }
                $predicate[$structuredModifier] = [string]$value
                [pscustomobject]$predicate
            }
            if (@($predicates).Count -eq 1) {
                $eventDataConditions.Add($predicates[0]) | Out-Null
            } else {
                $eventDataConditions.Add([pscustomobject][ordered]@{ any = @($predicates) }) | Out-Null
            }
        } elseif ($values.Count -gt 0) {
            $warnings.Add("Detection field '$($property.Name)' uses unsupported modifier '$modifier'; it remains an inactive review candidate.") | Out-Null
        }
    }
    if ($eventDataConditions.Count -gt 0) {
        $match.eventData = [pscustomobject][ordered]@{ all = @($eventDataConditions.ToArray()) }
    }
    if ($Detection.Condition -and [string]$Detection.Condition -notmatch ('^(?i:{0})(\s+and\s+{0})?$' -f [regex]::Escape([string]$Detection.Selection))) {
        $warnings.Add("Detection condition '$($Detection.Condition)' is broader than the selected mapping and requires review.") | Out-Null
    }
    return [pscustomobject][ordered]@{ Match = [pscustomobject]$match; Warnings = @($warnings.ToArray()); Status = $(if ($warnings.Count -gt 0) { 'partial' } else { 'mapped' }) }
}

function Get-LVSigmaCandidateId {
    param([Parameter(Mandatory)][string]$SigmaId)

    $bytes = [Text.Encoding]::UTF8.GetBytes($SigmaId)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return 'SIGMA-' + (([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').Substring(0, 12).ToLowerInvariant()) }
    finally { $sha.Dispose() }
}

function ConvertTo-LVSigmaCandidate {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$License,
        [Parameter(Mandatory)][string]$Retrieved,
        [Parameter(Mandatory)][string]$RepositoryUri
    )

    $lines = @([IO.File]::ReadAllLines($Path) | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*---\s*$' })
    $sigmaId = [string](Get-LVSigmaTopValue -Lines $lines -Key 'id')
    if (-not $sigmaId) { throw ("Sigma rule '{0}' has no id." -f $Path) }
    $title = [string](Get-LVSigmaTopValue -Lines $lines -Key 'title')
    if (-not $title) { throw ("Sigma rule '{0}' has no title." -f $Path) }
    $logsource = Get-LVSigmaNestedMap -Lines $lines -Section 'logsource'
    $detection = Get-LVSigmaDetection -Lines $lines
    $mapping = Get-LVSigmaEventMapping -Logsource $logsource -Detection $detection
    $relative = Get-LVSigmaRelativePath -Root $Root -Path $Path
    $hash = Get-LVSigmaFileHash -Path $Path
    $uri = $RepositoryUri.TrimEnd('/') + '/' + ((@($relative -split '[\\/]') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/')
    $author = [string](Get-LVSigmaTopValue -Lines $lines -Key 'author')
    if (-not $author) { $author = 'Sigma rule author not declared' }
    $level = [string](Get-LVSigmaTopValue -Lines $lines -Key 'level')
    $status = 'unsupported'
    return [pscustomobject][ordered]@{
        id = Get-LVSigmaCandidateId -SigmaId $sigmaId
        status = $status
        verified = $Retrieved
        match = $mapping.Match
        verdict = 'unknown'
        title = '[Sigma review] ' + $title
        plain = 'Imported Sigma detection candidate. Review its field mapping and evidence before activation.'
        why = 'Third-party detection logic is useful as a review lead, but its assumptions and false positives have not been accepted into the curated rule database.'
        action = 'Review the logsource, detection condition, license, references and a regression fixture; replace draft status and prose only after human review.'
        confidence = 'draft'
        references = @(Get-LVSigmaListValue -Lines $lines -Section 'references')
        falsepositives = @(Get-LVSigmaListValue -Lines $lines -Section 'falsepositives')
        sources = @([pscustomobject][ordered]@{ uri = $uri; licence = $License.Name; author = $author; retrieved = $Retrieved; modified = $false })
        sigma = [pscustomobject][ordered]@{
            id = $sigmaId; title = $title; author = $author; level = $level
            status = Get-LVSigmaTopValue -Lines $lines -Key 'status'
            date = Get-LVSigmaTopValue -Lines $lines -Key 'date'
            tags = @(Get-LVSigmaListValue -Lines $lines -Section 'tags')
            logsource = $logsource
            condition = $detection.Condition
            selection = $detection.Selection
            mappingStatus = $mapping.Status
            mappingWarnings = @($mapping.Warnings)
            sourcePath = $relative
            sourceHash = $hash
            license = $License.Name
            reviewStatus = 'pending'
        }
    }
}

function Get-LVSigmaDiff {
    param([AllowNull()][object[]]$Previous, [Parameter(Mandatory)][object[]]$Current)

    $oldById = @{}
    foreach ($item in @($Previous | Where-Object { $_ -and $_.id })) { $oldById[[string]$item.id] = $item }
    $newById = @{}
    foreach ($item in @($Current | Where-Object { $_ -and $_.id })) { $newById[[string]$item.id] = $item }
    $added = @($Current | Where-Object { $_ -and $_.id -and -not $oldById.ContainsKey([string]$_.id) } | Select-Object -ExpandProperty id)
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($id in $newById.Keys) {
        if ($oldById.ContainsKey($id)) {
            $oldHash = [string]$oldById[$id].sigma.sourceHash
            $newHash = [string]$newById[$id].sigma.sourceHash
            if ($oldHash -ne $newHash) { $changed.Add($id) | Out-Null }
        }
    }
    $removed = @($Previous | Where-Object { $_ -and $_.id -and -not $newById.ContainsKey([string]$_.id) } | Select-Object -ExpandProperty id)
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        added = @($added | Sort-Object)
        changed = @($changed.ToArray() | Sort-Object)
        removed = @($removed | Sort-Object)
        counts = [pscustomobject]@{ added = @($added).Count; changed = $changed.Count; removed = @($removed).Count; current = @($Current).Count }
    }
}

$resolved = (Resolve-Path -LiteralPath $RulesPath -ErrorAction Stop).Path
$root = if (Test-Path -LiteralPath $resolved -PathType Container) { [IO.Path]::GetFullPath($resolved) } else { Split-Path -Parent ([IO.Path]::GetFullPath($resolved)) }
$license = Get-LVSigmaLicense -Root $root -Policy $LicensePolicy
$files = if (Test-Path -LiteralPath $resolved -PathType Container) {
    @(Get-ChildItem -LiteralPath $resolved -Recurse -File | Where-Object { $_.Extension -in @('.yml', '.yaml') } | Sort-Object FullName | Select-Object -First $MaxRules)
} else { @([IO.FileInfo]$resolved) }
if ($files.Count -eq 0) { throw 'No Sigma .yml or .yaml files were found.' }
$candidates = New-Object System.Collections.Generic.List[object]
foreach ($file in $files) {
    $candidates.Add((ConvertTo-LVSigmaCandidate -Path $file.FullName -Root $root -License $license -Retrieved $Retrieved -RepositoryUri $RepositoryUri)) | Out-Null
}
$current = @($candidates.ToArray() | Sort-Object id)
$previous = @()
if ($ExistingPath) {
    $existing = Get-Content -LiteralPath $ExistingPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $previous = if ($existing.PSObject.Properties['rules']) { @($existing.rules) } elseif ($existing -is [System.Array]) { @($existing) } else { @($existing) }
}
$diff = Get-LVSigmaDiff -Previous $previous -Current $current
$queue = [pscustomobject][ordered]@{
    schemaVersion = 1
    generated = $Retrieved
    source = [pscustomobject][ordered]@{ repository = $RepositoryUri; license = $license.Name; licensePath = $license.Path; rulesPath = $root }
    rules = @($current)
    diff = $diff
}
if ($OutputPath) {
    $target = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($target, (($queue | ConvertTo-Json -Depth 20) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
}
if ($DiffPath) {
    $target = [IO.Path]::GetFullPath($DiffPath)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($target, (($diff | ConvertTo-Json -Depth 10) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
}
if ($current.Count -gt 0) { return $current }
