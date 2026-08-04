# Versioned machine-readable report contract. The contract wraps the existing result
# graph without changing the fields consumed by older callers.

$script:LVReportContractVersion = 1
$script:LVEvidenceContractVersion = 1

function ConvertTo-LVScanDateTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Value,
        [Parameter(Mandatory)][string]$Role
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return [datetime]$Value }
    if ($Value -is [datetimeoffset]) { return ([datetimeoffset]$Value).LocalDateTime }

    $text = [string]$Value
    $legacy = [regex]::Match($text, '^/Date\((?<milliseconds>-?\d+)(?:[+-]\d{4})?\)/$')
    if ($legacy.Success) {
        try { return [datetimeoffset]::FromUnixTimeMilliseconds([long]$legacy.Groups['milliseconds'].Value).LocalDateTime }
        catch { throw ("The {0} report has an invalid ScanTime value: {1}" -f $Role, $text) }
    }

    $parsed = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [Globalization.DateTimeStyles]::RoundtripKind
    if ([datetime]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }
    throw ("The {0} report has an invalid ScanTime value: {1}" -f $Role, $text)
}

function ConvertTo-LVScanDuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Value,
        [Parameter(Mandatory)][string]$Role
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [timespan]) { return [timespan]$Value }

    $ticksProperty = $Value.PSObject.Properties['Ticks']
    if ($ticksProperty -and $null -ne $ticksProperty.Value) {
        try { return [timespan]::FromTicks([int64]$ticksProperty.Value) }
        catch { throw ("The {0} report has an invalid Duration.Ticks value: {1}" -f $Role, $ticksProperty.Value) }
    }

    $text = [string]$Value
    $parsed = [timespan]::Zero
    if ([timespan]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
        return $parsed
    }
    if ($text -match '^P') {
        try { return [System.Xml.XmlConvert]::ToTimeSpan($text) }
        catch { Write-Verbose ("Ignoring non-ISO Duration value while parsing {0}: {1}" -f $Role, $_.Exception.Message) }
    }
    throw ("The {0} report has an invalid Duration value: {1}" -f $Role, $text)
}

function Resolve-LVScanInput {
    <#
        Normalize a live result object or a JSON report path for every public
        result consumer. ConvertFrom-Json cannot restore DateTime and TimeSpan
        runtime types, so repair those two fields once at this boundary rather
        than making each consumer know the serialized representation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Role
    )

    $report = $InputObject
    if ($InputObject -is [string] -or $InputObject -is [IO.FileInfo]) {
        $path = [string]$InputObject
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw ("The {0} scan report does not exist: {1}" -f $Role, $path)
        }
        try {
            $report = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw ("The {0} scan report is not readable JSON: {1}" -f $Role, $_.Exception.Message)
        }
    }

    if ($null -eq $report -or $null -eq $report.PSObject.Properties['Findings']) {
        throw ("The {0} input is not a LogVerdict scan result: it has no Findings collection." -f $Role)
    }

    $normalized = [pscustomobject]@{}
    foreach ($property in $report.PSObject.Properties) {
        $normalized | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
    }
    if ($report.PSObject.Properties['ScanTime']) {
        $normalized.ScanTime = ConvertTo-LVScanDateTime -Value $report.ScanTime -Role $Role
    }
    if ($report.PSObject.Properties['Duration']) {
        $normalized.Duration = ConvertTo-LVScanDuration -Value $report.Duration -Role $Role
    }
    return $normalized
}

function New-LVReportContract {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This function constructs an in-memory contract object and changes no external state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [switch]$Redacted
    )

    $mode = 'live'
    if ($Result.PSObject.Properties['Offline'] -and $Result.Offline) { $mode = 'offline' }
    $scanTime = $null
    if ($Result.PSObject.Properties['ScanTime'] -and $Result.ScanTime) {
        $scanTime = ConvertTo-LVUtcTimestamp -Value $Result.ScanTime
    }
    $alreadyRedacted = $false
    if ($Result.PSObject.Properties['Redacted']) { $alreadyRedacted = [bool]$Result.Redacted }

    return [pscustomobject][ordered]@{
        schemaVersion = $script:LVReportContractVersion
        name          = 'LogVerdict.Report'
        mode          = $mode
        generatedAt   = $scanTime
        privacy       = [pscustomobject][ordered]@{
            redacted     = [bool]($Redacted -or $alreadyRedacted)
            rawEvidence  = $false
            statement    = 'Redaction state describes the report fields; raw binary evidence is a separate bundle choice.'
        }
        compatibility = [pscustomobject][ordered]@{
            readerMajor = $script:LVReportContractVersion
            migration   = $null
        }
    }
}

function ConvertTo-LVReportContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [switch]$Redacted
    )

    $copy = [pscustomobject]@{}
    foreach ($property in $Result.PSObject.Properties) {
        $copy | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
    }
    $copy | Add-Member -NotePropertyName 'Contract' -NotePropertyValue (New-LVReportContract -Result $Result -Redacted:$Redacted) -Force
    if ($Redacted) { $copy | Add-Member -NotePropertyName 'Redacted' -NotePropertyValue $true -Force }
    return $copy
}

function ConvertFrom-LVReportContract {
    <#
        Upgrade an older or unversioned report for a current reader. No fields are
        guessed: a legacy object receives only an explicit migration marker.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $copy = ConvertTo-LVReportContract -Result $InputObject
    $existing = $InputObject.PSObject.Properties['Contract']
    if ($existing -and $existing.Value) {
        $version = [int]$existing.Value.schemaVersion
        if ($version -gt $script:LVReportContractVersion) {
            throw ('Report contract schemaVersion {0} is newer than this reader supports ({1}).' -f $version, $script:LVReportContractVersion)
        }
        if ($version -eq $script:LVReportContractVersion) { return $copy }
    }

    $copy.Contract.compatibility.migration = 'legacy-unversioned-to-v1'
    return $copy
}

function Test-LVReportContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [switch]$Quiet
    )

    $problems = New-Object System.Collections.Generic.List[string]
    $required = @('Contract', 'Tool', 'Version', 'ScanTime', 'DaysBack', 'Coverage', 'Findings', 'WorstVerdict', 'ExitCode')
    foreach ($name in $required) {
        if (-not $InputObject.PSObject.Properties[$name]) { $problems.Add("missing required field '$name'") | Out-Null }
    }
    $contractProperty = $InputObject.PSObject.Properties['Contract']
    $contract = if ($contractProperty) { $contractProperty.Value } else { $null }
    if ($contract) {
        if ([int]$contract.schemaVersion -ne $script:LVReportContractVersion) { $problems.Add('Contract.schemaVersion is not supported') | Out-Null }
        if ([string]$contract.name -ne 'LogVerdict.Report') { $problems.Add('Contract.name is not LogVerdict.Report') | Out-Null }
        if (-not $contract.generatedAt) { $problems.Add('Contract.generatedAt is missing') | Out-Null }
        if (-not $contract.privacy -or -not $contract.privacy.PSObject.Properties['redacted']) { $problems.Add('Contract.privacy.redacted is missing') | Out-Null }
    }
    if ($InputObject.Tool -and [string]$InputObject.Tool -ne 'LogVerdict') { $problems.Add('Tool is not LogVerdict') | Out-Null }
    $when = [datetime]::MinValue
    if ($InputObject.ScanTime -and -not [datetime]::TryParse([string]$InputObject.ScanTime, [ref]$when)) { $problems.Add('ScanTime is not parseable') | Out-Null }
    if ($null -ne $InputObject.DaysBack -and ([int]$InputObject.DaysBack -lt 1 -or [int]$InputObject.DaysBack -gt 3650)) { $problems.Add('DaysBack is outside 1-3650') | Out-Null }

    foreach ($coverage in @($InputObject.Coverage | Where-Object { $_ })) {
        foreach ($name in @('Source', 'Kind', 'Name', 'Status', 'ObservedRecords', 'SkippedRecords')) {
            if (-not $coverage.PSObject.Properties[$name]) { $problems.Add("coverage is missing '$name'") | Out-Null }
        }
        if ([string]$coverage.Status -notin @('readable', 'empty', 'artifact-read', 'executed', 'disabled', 'policy-disabled', 'provider-absent', 'not-observed', 'unreadable', 'truncated', 'timeout', 'filtered', 'parsed', 'queued', 'skipped')) {
            $problems.Add(("coverage status '{0}' is unsupported" -f $coverage.Status)) | Out-Null
        }
    }
    foreach ($finding in @($InputObject.Findings | Where-Object { $_ })) {
        foreach ($name in @('Key', 'Verdict', 'Title', 'RuleId', 'Confidence')) {
            if (-not $finding.PSObject.Properties[$name]) { $problems.Add("finding is missing '$name'") | Out-Null }
        }
    }
    foreach ($performance in @($InputObject.Performance | Where-Object { $_ })) {
        foreach ($name in @('Source', 'Kind', 'Name', 'Status', 'ObservedRecords', 'SkippedRecords', 'ElapsedMilliseconds')) {
            if (-not $performance.PSObject.Properties[$name]) { $problems.Add("performance is missing '$name'") | Out-Null }
        }
    }

    if ($Quiet) { return ($problems.Count -eq 0) }
    return ConvertTo-LVArrayOutput -Value @($problems.ToArray() | ForEach-Object { [pscustomobject]@{ Problem = $_ } })
}

function Get-LVContractFileHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [IO.File]::OpenRead($Path)
        return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        if ($stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

function New-LVEvidenceContract {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This function constructs an in-memory contract object and changes no external state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Content,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Omission,
        [switch]$Redacted,
        [switch]$AllowRawEvidence,
        [AllowNull()]$PrivacyAudit
    )

    $reportContract = if ($Result.PSObject.Properties['Contract'] -and $Result.Contract) {
        $Result.Contract
    } else {
        New-LVReportContract -Result $Result -Redacted:$Redacted
    }
    $files = foreach ($path in @($Content | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })) {
        $item = Get-Item -LiteralPath $path
        [pscustomobject][ordered]@{
            name      = $item.Name
            sizeBytes = [int64]$item.Length
            sha256    = Get-LVContractFileHash -Path $path
        }
    }
    $raw = [bool]($AllowRawEvidence -and -not $Redacted)
    return [pscustomobject][ordered]@{
        Contract = [pscustomobject][ordered]@{
            schemaVersion = $script:LVEvidenceContractVersion
            name          = 'LogVerdict.Evidence'
            generatedAt   = ConvertTo-LVUtcTimestamp -Value $Result.ScanTime
            compatibility = [pscustomobject][ordered]@{ readerMajor = $script:LVEvidenceContractVersion; migration = $null }
        }
        ReportContract = $reportContract
        Privacy = [pscustomobject][ordered]@{
            redacted    = [bool]$Redacted
            rawEvidence = $raw
            statement   = if ($raw) { 'Raw evidence was explicitly authorized for forensic use; this bundle is not sanitized.' } else { 'Text and metadata were redacted for sharing; binary raw evidence is omitted.' }
            auditStatus = if ($PrivacyAudit) { [string]$PrivacyAudit.Status } else { $null }
        }
        Coverage = @($Result.Coverage | Where-Object { $_ })
        Performance = @($Result.Performance | Where-Object { $_ })
        Files = @($files)
        Omissions = @($Omission | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
}

function ConvertFrom-LVEvidenceContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)

    $property = $InputObject.PSObject.Properties['Contract']
    if (-not $property -or -not $property.Value) { throw 'Evidence contract is missing its Contract envelope.' }
    $version = [int]$property.Value.schemaVersion
    if ($version -gt $script:LVEvidenceContractVersion) {
        throw ('Evidence contract schemaVersion {0} is newer than this reader supports ({1}).' -f $version, $script:LVEvidenceContractVersion)
    }
    return $InputObject
}

function Test-LVEvidenceContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [switch]$Quiet
    )

    $problems = New-Object System.Collections.Generic.List[string]
    $required = @('Contract', 'ReportContract', 'Privacy', 'Coverage', 'Performance', 'Files', 'Omissions')
    foreach ($name in $required) {
        if (-not $InputObject.PSObject.Properties[$name]) { $problems.Add("missing required field '$name'") | Out-Null }
    }
    $contractProperty = $InputObject.PSObject.Properties['Contract']
    if ($contractProperty -and $contractProperty.Value) {
        $contract = $contractProperty.Value
        if ([int]$contract.schemaVersion -ne $script:LVEvidenceContractVersion) { $problems.Add('Contract.schemaVersion is not supported') | Out-Null }
        if ([string]$contract.name -ne 'LogVerdict.Evidence') { $problems.Add('Contract.name is not LogVerdict.Evidence') | Out-Null }
        if (-not $contract.generatedAt) { $problems.Add('Contract.generatedAt is missing') | Out-Null }
    }
    if ($InputObject.Privacy -and -not $InputObject.Privacy.PSObject.Properties['redacted']) { $problems.Add('Privacy.redacted is missing') | Out-Null }
    foreach ($file in @($InputObject.Files | Where-Object { $_ })) {
        foreach ($name in @('name', 'sizeBytes', 'sha256')) {
            if (-not $file.PSObject.Properties[$name]) { $problems.Add("file is missing '$name'") | Out-Null }
        }
        if ([string]$file.sha256 -notmatch '^[0-9a-fA-F]{64}$') { $problems.Add('file sha256 is not a SHA-256 digest') | Out-Null }
    }
    if ($Quiet) { return ($problems.Count -eq 0) }
    return ConvertTo-LVArrayOutput -Value @($problems.ToArray() | ForEach-Object { [pscustomobject]@{ Problem = $_ } })
}
