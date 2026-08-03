# Case profiles and deterministic responder handoffs.
# A profile is a small, shareable record of how evidence was collected. It is metadata,
# not a verdict, and it never contains raw event messages.

$script:LVCaseProfileSchemaVersion = 1
$script:LVCaseHandoffSchemaVersion = 1

function Get-LVCaseSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) |
            ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-LVCaseCanonicalJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)

    return ($Value | ConvertTo-Json -Depth 30 -Compress)
}

function ConvertTo-LVCaseUtcText {
    [CmdletBinding()]
    param([AllowNull()]$Value)

    return ConvertTo-LVUtcTimestamp -Value $Value
}

function Get-LVCaseSourceRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [switch]$Redact
    )

    $records = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $machine = if ($Result.MachineName) { [string]$Result.MachineName } else { $null }

    foreach ($source in @($Result.EvidenceManifest | Where-Object { $_ }) + @($Result.Coverage | Where-Object { $_ })) {
        $kind = if ($source.Kind) { [string]$source.Kind } else { 'source' }
        $name = if ($source.Name) { [string]$source.Name } elseif ($source.Channel) { [string]$source.Channel } else { 'unnamed' }
        $nameText = if ($Redact) { ConvertTo-LVRedactedText -Text $name -MachineName $machine } else { $name }
        $sha = if ($source.SHA256 -and [string]$source.SHA256 -match '^[0-9A-Fa-f]{64}$') { ([string]$source.SHA256).ToLowerInvariant() } else { $null }
        $key = '{0}|{1}|{2}|{3}' -f $source.Source, $kind, $nameText, $sha
        if (-not $seen.Add($key)) { continue }
        $records.Add([pscustomobject][ordered]@{
            source = [string]$source.Source
            kind = $kind
            name = $nameText
            status = [string]$source.Status
            sha256 = $sha
            sizeBytes = if ($null -ne $source.SizeBytes) { [long]$source.SizeBytes } else { $null }
        }) | Out-Null
    }

    return @($records.ToArray() | Sort-Object source, kind, name, sha256)
}

function Get-LVCaseScanChoices {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    if ($Result.PSObject.Properties['ScanOptions'] -and $Result.ScanOptions) {
        $options = [ordered]@{}
        $pairs = if ($Result.ScanOptions -is [System.Collections.IDictionary]) {
            @($Result.ScanOptions.GetEnumerator() | Sort-Object Key | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Key; Value = $_.Value }
            })
        } else {
            @($Result.ScanOptions.PSObject.Properties | Sort-Object Name | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; Value = $_.Value }
            })
        }
        foreach ($property in $pairs) {
            $value = $property.Value
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $value = @($value)
            }
            if ($null -ne $value) { $options[$property.Name] = $value }
        }
        return $options
    }

    return [ordered]@{
        channelMode = 'observed'
        channels = @($Result.Channels | Where-Object { $_ } | Sort-Object)
        evidencePath = [bool]($Result.PSObject.Properties['Offline'] -and $Result.Offline)
    }
}

function Get-LVCaseProfileCore {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile)

    $operator = if ($Profile.PSObject.Properties['operator'] -and $Profile.operator) { $Profile.operator } else { [pscustomobject]@{} }
    $bounds = if ($Profile.PSObject.Properties['bounds'] -and $Profile.bounds) { $Profile.bounds } else { [pscustomobject]@{} }
    $redaction = if ($Profile.PSObject.Properties['redaction'] -and $Profile.redaction) { $Profile.redaction } else { [pscustomobject]@{} }
    $hashes = if ($Profile.PSObject.Properties['hashes'] -and $Profile.hashes) { $Profile.hashes } else { [pscustomobject]@{} }
    $attribution = if ($Profile.PSObject.Properties['attribution'] -and $Profile.attribution) { $Profile.attribution } else { [pscustomobject]@{} }

    $sourceRecords = @($Profile.sources | Where-Object { $_ } | ForEach-Object {
        [pscustomobject][ordered]@{
            source = [string]$_.source
            kind = [string]$_.kind
            name = [string]$_.name
            status = [string]$_.status
            sha256 = if ($_.sha256) { ([string]$_.sha256).ToLowerInvariant() } else { $null }
            sizeBytes = if ($null -ne $_.sizeBytes) { [long]$_.sizeBytes } else { $null }
        }
    } | Sort-Object source, kind, name, sha256)
    $notes = @($Profile.notes | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })

    return [ordered]@{
        schemaVersion = [int]$Profile.schemaVersion
        name = [string]$Profile.name
        purpose = [string]$Profile.purpose
        operator = [ordered]@{
            name = [string]$operator.name
            ticket = if ($null -ne $operator.ticket) { [string]$operator.ticket } else { $null }
        }
        notes = $notes
        sources = $sourceRecords
        bounds = [ordered]@{
            daysBack = if ($null -ne $bounds.daysBack) { [int]$bounds.daysBack } else { $null }
            windowStart = ConvertTo-LVCaseUtcText $bounds.windowStart
            windowEnd = ConvertTo-LVCaseUtcText $bounds.windowEnd
            channels = @($bounds.channels | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object)
        }
        redaction = [ordered]@{
            requested = [bool]$redaction.requested
            rawEvidenceAllowed = [bool]$redaction.rawEvidenceAllowed
            fields = @($redaction.fields | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object)
        }
        choices = if ($Profile.PSObject.Properties['choices'] -and $Profile.choices) {
            Get-LVCaseScanChoices -Result ([pscustomobject]@{ ScanOptions = $Profile.choices })
        } else { [ordered]@{} }
        hashes = [ordered]@{
            sourceManifestSha256 = [string]$hashes.sourceManifestSha256
            sourceCount = [int]$hashes.sourceCount
        }
        attribution = [ordered]@{
            tool = [string]$attribution.tool
            version = [string]$attribution.version
            source = [string]$attribution.source
        }
    }
}

function Get-LVCaseProfileProblems {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile)

    $problems = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Profile) { $problems.Add('profile is null') | Out-Null; return @($problems.ToArray()) }
    if ([int]$Profile.schemaVersion -ne $script:LVCaseProfileSchemaVersion) { $problems.Add(('schemaVersion must be {0}' -f $script:LVCaseProfileSchemaVersion)) | Out-Null }
    if ([string]::IsNullOrWhiteSpace([string]$Profile.profileId) -or [string]$Profile.profileId -notmatch '^[0-9a-fA-F]{64}$') { $problems.Add('profileId must be a SHA-256 digest') | Out-Null }
    if ([string]::IsNullOrWhiteSpace([string]$Profile.name)) { $problems.Add('name is required') | Out-Null }
    if (-not ($Profile.PSObject.Properties['operator'] -and $Profile.operator)) { $problems.Add('operator is required') | Out-Null }
    if (-not ($Profile.PSObject.Properties['bounds'] -and $Profile.bounds)) { $problems.Add('bounds is required') | Out-Null }
    if (-not ($Profile.PSObject.Properties['redaction'] -and $Profile.redaction)) { $problems.Add('redaction is required') | Out-Null }
    if (-not ($Profile.PSObject.Properties['hashes'] -and $Profile.hashes)) { $problems.Add('hashes is required') | Out-Null }

    if (@($Profile.sources | Where-Object { $_ }) | ForEach-Object { $_.sha256 } | Where-Object { $_ -and $_ -notmatch '^[0-9a-fA-F]{64}$' }) {
        $problems.Add('every source sha256 must be a SHA-256 digest or null') | Out-Null
    }
    if ($Profile.hashes -and $Profile.hashes.sourceCount -ne @($Profile.sources | Where-Object { $_ }).Count) { $problems.Add('hashes.sourceCount does not match sources') | Out-Null }

    if ($problems.Count -eq 0) {
        $core = Get-LVCaseProfileCore -Profile $Profile
        $expected = Get-LVCaseSha256 -Text (ConvertTo-LVCaseCanonicalJson -Value $core)
        if ([string]$Profile.profileId -ne $expected) { $problems.Add('profileId does not match the canonical profile content') | Out-Null }
    }
    return @($problems.ToArray())
}

function Read-LVCaseProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Case profile not found: $Path" }
    try {
        $profile = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Case profile is not valid JSON: $Path ($($_.Exception.Message))"
    }
    $problems = @(Get-LVCaseProfileProblems -Profile $profile)
    if ($problems.Count -gt 0) { throw ('Case profile validation failed: ' + ($problems -join '; ')) }
    return $profile
}

function New-LVCaseProfileObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [string]$Name = 'LogVerdict case',
        [string]$Purpose,
        [string[]]$Note = @(),
        [string]$OperatorName,
        [string]$Ticket,
        [switch]$Redact,
        [switch]$AllowRawEvidence
    )

    if ($Redact -and $AllowRawEvidence) { throw 'A case profile cannot request both -Redact and -AllowRawEvidence.' }
    $machine = if ($Result.MachineName) { [string]$Result.MachineName } else { $null }
    $operator = if ($OperatorName) { $OperatorName } else { [string]$env:USERNAME }
    $purposeText = if ($Purpose) { $Purpose } else { 'Preserve collection choices, source coverage, and analyst context for repeatable review.' }
    $notes = @($Note | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    if ($Redact) {
        $operator = '<USER>'
        $Ticket = if ($Ticket) { '<TICKET>' } else { $null }
        $purposeText = ConvertTo-LVRedactedText -Text $purposeText -MachineName $machine -UserName $env:USERNAME
        $notes = @($notes | ForEach-Object { ConvertTo-LVRedactedText -Text $_ -MachineName $machine -UserName $env:USERNAME })
    }

    $sources = @(Get-LVCaseSourceRecords -Result $Result -Redact:$Redact)
    $sourceJson = ConvertTo-LVCaseCanonicalJson -Value $sources
    $sourceHash = Get-LVCaseSha256 -Text $sourceJson
    $started = ConvertTo-LVCaseUtcText $Result.ScanTime
    $ended = if ($Result.ScanTime -and $Result.Duration) { ConvertTo-LVCaseUtcText ([datetime]$Result.ScanTime + $Result.Duration) } else { $started }
    $core = [ordered]@{
        schemaVersion = $script:LVCaseProfileSchemaVersion
        name = [string]$Name
        purpose = [string]$purposeText
        operator = [ordered]@{ name = [string]$operator; ticket = if ($Ticket) { [string]$Ticket } else { $null } }
        notes = $notes
        sources = $sources
        bounds = [ordered]@{
            daysBack = if ($null -ne $Result.DaysBack) { [int]$Result.DaysBack } else { $null }
            windowStart = if ($Result.ScanTime -and $Result.DaysBack) { ConvertTo-LVCaseUtcText ([datetime]$Result.ScanTime).AddDays(-1 * [math]::Abs([int]$Result.DaysBack)) } else { $null }
            windowEnd = $ended
            channels = @($Result.Channels | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object)
        }
        redaction = [ordered]@{
            requested = [bool]$Redact
            rawEvidenceAllowed = [bool]($AllowRawEvidence -and -not $Redact)
            fields = @('account', 'machine', 'mail', 'profile-path', 'SID')
        }
        choices = Get-LVCaseScanChoices -Result $Result
        hashes = [ordered]@{ sourceManifestSha256 = $sourceHash; sourceCount = $sources.Count }
        attribution = [ordered]@{ tool = 'LogVerdict'; version = [string]$Result.Version; source = 'normalized scan result' }
    }
    $profileId = Get-LVCaseSha256 -Text (ConvertTo-LVCaseCanonicalJson -Value $core)
    $output = [ordered]@{ profileId = $profileId }
    foreach ($key in $core.Keys) { $output[$key] = $core[$key] }
    return [pscustomobject]$output
}

function ConvertTo-LVCaseRedactedProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile, [AllowNull()][string]$MachineName)

    $core = Get-LVCaseProfileCore -Profile $Profile
    $core.operator.name = '<USER>'
    if ($core.operator.ticket) { $core.operator.ticket = '<TICKET>' }
    $core.purpose = ConvertTo-LVRedactedText -Text $core.purpose -MachineName $MachineName -UserName $env:USERNAME
    $core.notes = @($core.notes | ForEach-Object { ConvertTo-LVRedactedText -Text $_ -MachineName $MachineName -UserName $env:USERNAME })
    $core.sources = @($core.sources | ForEach-Object {
        $_.name = ConvertTo-LVRedactedText -Text $_.name -MachineName $MachineName -UserName $env:USERNAME
        $_
    })
    $core.redaction.requested = $true
    $core.redaction.rawEvidenceAllowed = $false
    $profileId = Get-LVCaseSha256 -Text (ConvertTo-LVCaseCanonicalJson -Value $core)
    $output = [ordered]@{ profileId = $profileId }
    foreach ($key in $core.Keys) { $output[$key] = $core[$key] }
    return [pscustomobject]$output
}

function Add-LVCaseProfileToResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [AllowNull()]$Profile)

    if ($Profile) { $Result | Add-Member -NotePropertyName CaseProfile -NotePropertyValue $Profile -Force }
    return $Result
}

function Get-LVCaseProfileSourceHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile, [Parameter(Mandatory)]$Finding)

    $candidateNames = @($Finding.Channel, $Finding.Provider, $Finding.Source) | Where-Object { $_ }
    foreach ($source in @($Profile.sources | Where-Object { $_ -and $_.sha256 })) {
        if ($candidateNames -contains [string]$source.name) { return [string]$source.sha256 }
    }
    return $null
}

function ConvertTo-LVCaseHandoffRows {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Profile, [switch]$Redact)

    $machine = if ($Redact) { '<MACHINE>' } else { [string]$Result.MachineName }
    $rows = foreach ($finding in @($Result.Findings | Where-Object { $_ })) {
        $when = if ($finding.FirstSeen) { $finding.FirstSeen } else { $Result.ScanTime }
        $datetime = ConvertTo-LVCaseUtcText $when
        if (-not $datetime) { continue }
        $parsed = [DateTimeOffset]::Parse($datetime)
        $message = if ($finding.SampleMessage) { [string]$finding.SampleMessage } else { [string]$finding.Plain }
        if ($Redact) { $message = ConvertTo-LVRedactedText -Text $message -MachineName $Result.MachineName -UserName $env:USERNAME }
        [pscustomobject][ordered]@{
            timestamp = $parsed.ToUnixTimeMilliseconds()
            datetime = $datetime
            timestamp_desc = 'LogVerdict first observed'
            message = $message
            source = [string]$finding.Source
            channel = [string]$finding.Channel
            provider = [string]$finding.Provider
            event_id = $finding.Id
            computer = $machine
            rule_title = [string]$finding.Title
            rule_id = [string]$finding.RuleId
            verdict = [string]$finding.Verdict
            occurrence_count = $finding.Count
            signature_key = [string]$finding.Key
            logverdict_tool = 'LogVerdict'
            logverdict_version = [string]$Result.Version
            logverdict_profile_id = [string]$Profile.profileId
            logverdict_source_sha256 = Get-LVCaseProfileSourceHash -Profile $Profile -Finding $finding
        }
    }
    return @($rows | Sort-Object datetime, source, channel, provider, event_id, signature_key)
}

function Get-LVCaseKapeRecipe {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('Description: LogVerdict collection profile {0}' -f $Profile.profileId)) | Out-Null
    $lines.Add('Category: Windows Event Logs') | Out-Null
    $lines.Add('Path: C:\Windows\System32\winevt\Logs') | Out-Null
    $lines.Add('FileMask: *.evtx') | Out-Null
    $lines.Add('Recursive: false') | Out-Null
    $lines.Add(('Comment: Generated by LogVerdict {0}; verify source scope and destination before collection.' -f $Profile.attribution.version)) | Out-Null
    $textSources = @($Profile.sources | Where-Object { $_.kind -match 'text|log' } | Select-Object -ExpandProperty name -Unique | Sort-Object)
    if ($textSources.Count -gt 0) {
        $lines.Add('') | Out-Null
        $lines.Add('Description: LogVerdict text-log collection') | Out-Null
        $lines.Add('Category: Windows Text Logs') | Out-Null
        $lines.Add('Path: C:\Windows\Logs') | Out-Null
        $lines.Add('FileMask: CBS.log;dism.log;setupapi.dev.log;setupact.log;BlueBox.log') | Out-Null
        $lines.Add('Recursive: true') | Out-Null
        $lines.Add('Comment: Text-log names observed by the profile: ' + ($textSources -join ', ')) | Out-Null
    }
    return ($lines.ToArray() -join [Environment]::NewLine) + [Environment]::NewLine
}

function Get-LVCaseVelociraptorRecipe {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile)

    $name = 'Custom.LogVerdict.' + $Profile.profileId.Substring(0, 16)
    $paths = New-Object System.Collections.Generic.List[string]
    $paths.Add('C:/Windows/System32/winevt/Logs/*.evtx') | Out-Null
    if (@($Profile.sources | Where-Object { $_.kind -match 'text|log' }).Count -gt 0) {
        $paths.Add('C:/Windows/Logs/**/*.log') | Out-Null
    }
    $escapedPaths = @($paths | ForEach-Object { '        - "' + $_ + '"' }) -join [Environment]::NewLine
    return @"
name: $name
description: |
  Deterministic LogVerdict collection recipe for profile $($Profile.profileId).
  Review the scope, destination, and authorization before collecting from an endpoint.
type: CLIENT
parameters:
  - name: DaysBack
    description: Requested look-back window recorded by LogVerdict.
    default: "$($Profile.bounds.daysBack)"
sources:
  - name: EvidenceFiles
    query: |
      LET profile_id = "$($Profile.profileId)"
      SELECT profile_id, OSPath, Size, Mtime
      FROM glob(globs=[
$escapedPaths
      ])
"@
}
