# Collection layer: Windows' own Reliability Monitor.
#
# Worth reading for two reasons the event channels cannot supply.
#
# First, it is Microsoft's pre-curated view of what actually failed - a much smaller
# set than "every error-level record", chosen by the people who write the events.
#
# Second, and more useful in practice, it carries the software install, removal,
# reconfigure and update history. An error-only sweep of the event channels never sees
# those, because they are logged at Information level, and "what changed just before
# this started" is the first question in any triage.
#
# It overlaps the event channels heavily for anything that failed, so records already
# collected from a channel are dropped rather than counted twice. The overlap is real:
# on the authoring machine 95 of 355 reliability records duplicated a channel record.
#
# The provider is Group Policy gated and disabled by default on Windows Server. Its
# absence is reported as a source that was skipped, never as evidence of health.

function Get-LVReliabilityPolicyValue {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Reliability Analysis\WMI'
    try {
        $policy = Get-ItemProperty -LiteralPath $path -Name 'WMIEnable' -ErrorAction Stop
        if ($policy -and $policy.PSObject.Properties['WMIEnable']) {
            return [int]$policy.WMIEnable
        }
    } catch {
        # A missing policy key is meaningful: Windows client enables the provider by
        # default, while Windows Server disables it by default. The provider probe and
        # OS product type below resolve that default without changing machine state.
        Write-Verbose 'Reliability WMI policy is not explicitly configured; resolving the operating-system default.'
    }
    return $null
}

function Get-LVReliabilityProviderState {
    [CmdletBinding()]
    param(
        [AllowNull()]$PolicyValue,
        [AllowNull()]$RecordError
    )

    if ($null -eq $PolicyValue) { $PolicyValue = Get-LVReliabilityPolicyValue }
    $recordReason = if ($RecordError) { [string]$RecordError.Exception.Message } else { $null }

    if ($PolicyValue -eq 0) {
        return [pscustomobject]@{
            Status = 'policy-disabled'
            Reason = 'Configure Reliability WMI Providers is disabled (WMIEnable=0); Reliability Monitor data is unavailable.'
        }
    }
    if ($null -ne $PolicyValue -and $PolicyValue -ne 1) {
        return [pscustomobject]@{
            Status = 'unreadable'
            Reason = ('The Reliability WMI policy value was not understood; Reliability Monitor query result: {0}' -f $PolicyValue)
        }
    }

    $provider = @()
    try {
        $provider = @(Get-CimInstance -Namespace 'root\cimv2' -ClassName '__Provider' `
                -Filter "Name = 'ReliabilityMetricsProvider'" -ErrorAction Stop)
    } catch {
        return [pscustomobject]@{
            Status = 'unreadable'
            Reason = ('The ReliabilityMetricsProvider registration could not be inspected: {0}' -f $_.Exception.Message)
        }
    }
    if ($provider.Count -eq 0) {
        return [pscustomobject]@{
            Status = 'provider-absent'
            Reason = 'ReliabilityMetricsProvider is not registered on this system; Reliability Monitor data is unavailable.'
        }
    }
    if ($PolicyValue -eq 1) {
        if ($RecordError) {
            return [pscustomobject]@{
                Status = 'unreadable'
                Reason = ('ReliabilityMetricsProvider is registered, but Win32_ReliabilityRecords could not be read: {0}' -f $recordReason)
            }
        }
        return [pscustomobject]@{ Status = 'available'; Reason = $null }
    }

    try {
        $os = @(Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop | Select-Object -First 1)
        $productType = if ($os.Count -gt 0 -and $os[0].PSObject.Properties['ProductType']) { [int]$os[0].ProductType } else { $null }
    } catch {
        $productType = $null
    }
    if ($productType -in @(2, 3)) {
        return [pscustomobject]@{
            Status = 'policy-disabled'
            Reason = 'Configure Reliability WMI Providers is not configured and Windows Server disables it by default; Reliability Monitor data is unavailable.'
        }
    }
    if ($RecordError) {
        return [pscustomobject]@{
            Status = 'unreadable'
            Reason = ('ReliabilityMetricsProvider is registered, but Win32_ReliabilityRecords could not be read: {0}' -f $recordReason)
        }
    }
    return [pscustomobject]@{ Status = 'available'; Reason = $null }
}

function Get-LVReliabilityRecord {
    <#
        .SYNOPSIS
        Reliability Monitor records, minus anything already collected from a channel.

        .PARAMETER ExistingRecord
        Records already collected this scan. A reliability record whose provider and
        event id already appear here describes the same incident, so it is dropped -
        counting it again would inflate the count and the rate of a signature that is
        used to decide whether something is failing.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 30,
        [AllowEmptyCollection()][object[]]$ExistingRecord = @(),
        [AllowNull()]$CollectionBudget
    )

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $records = New-Object System.Collections.Generic.List[object]
    $script:LVReliabilityBudgetStop = $null
    $script:LVReliabilityStatus = 'available'
    $script:LVReliabilityAvailable = $true
    $script:LVReliabilitySkipReason = $null

    $policyValue = Get-LVReliabilityPolicyValue
    if ($policyValue -eq 0) {
        $state = Get-LVReliabilityProviderState -PolicyValue $policyValue
        $script:LVReliabilityStatus = $state.Status
        $script:LVReliabilityAvailable = $false
        $script:LVReliabilitySkipReason = $state.Reason
        Write-LVLog -Level warn -Message ('Reliability Monitor is unavailable ({0}).' -f $state.Reason)
        return ConvertTo-LVArrayOutput -Value @()
    }

    $seen = @{}
    foreach ($r in $ExistingRecord) {
        if ($r.Source -ne 'event') { continue }
        $seen[('{0}/{1}' -f $r.Provider, $r.Id)] = $true
    }

    $raw = $null
    try {
        $readLimit = 100000
        if ($CollectionBudget) {
            $readLimit = [Math]::Min([int64]$readLimit, [int64]$CollectionBudget.MaxRecords - [int64]$CollectionBudget.RecordsRead)
        }
        if ($readLimit -lt 1) {
            $script:LVReliabilityBudgetStop = 'truncated'
            $script:LVReliabilityStatus = 'truncated'
            return ConvertTo-LVArrayOutput -Value @()
        }
        $raw = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop | Select-Object -First $readLimit)
    } catch {
        # Absence is a coverage gap, not a clean bill of health. Group Policy can
        # disable the provider outright and Server disables it by default.
        $state = Get-LVReliabilityProviderState -PolicyValue $policyValue -RecordError $_
        $script:LVReliabilityStatus = $state.Status
        $script:LVReliabilityAvailable = ($state.Status -eq 'available')
        $script:LVReliabilitySkipReason = $state.Reason
        Write-LVLog -Level warn -Message ('Reliability Monitor is unavailable ({0}); that source was skipped, not cleared.' -f $state.Reason)
        return ConvertTo-LVArrayOutput -Value @()
    }

    $script:LVReliabilityAvailable = $true
    $script:LVReliabilityStatus = 'available'
    $script:LVReliabilitySkipReason = $null

    if ($raw.Count -eq 0 -and $policyValue -ne 1) {
        $state = Get-LVReliabilityProviderState -PolicyValue $policyValue
        if ($state.Status -in @('policy-disabled', 'provider-absent')) {
            $script:LVReliabilityStatus = $state.Status
            $script:LVReliabilityAvailable = $false
            $script:LVReliabilitySkipReason = $state.Reason
            Write-LVLog -Level warn -Message ('Reliability Monitor returned no records because {0}.' -f $state.Reason)
            return ConvertTo-LVArrayOutput -Value @()
        }
    }

    $duplicates = 0
    $tooOld = 0

    foreach ($r in $raw) {
        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        if ($budgetStop) { $script:LVReliabilityBudgetStop = $budgetStop; break }
        $when = $r.TimeGenerated
        if ($null -ne $when -and $when -lt $cutoff) { $tooOld++; continue }

        $provider = $r.SourceName
        if (-not $provider) { $provider = 'Unknown' }
        $id = 0
        if ($null -ne $r.EventIdentifier) { $id = [int]$r.EventIdentifier }

        if ($seen.ContainsKey(('{0}/{1}' -f $provider, $id))) { $duplicates++; continue }

        $estimatedBytes = 256
        if ($r.Message) { $estimatedBytes += [Text.Encoding]::UTF8.GetByteCount([string]$r.Message) }
        if ($CollectionBudget -and (([int64]$CollectionBudget.BytesRead + $estimatedBytes) -gt [int64]$CollectionBudget.MaxBytes)) {
            $script:LVReliabilityBudgetStop = 'truncated'
            break
        }

        $records.Add([pscustomobject]@{
            Source      = 'reliability'
            Channel     = 'Reliability'
            Provider    = $provider
            Id          = $id
            # Reliability Monitor does not expose a severity. Inventing one would put a
            # level on the report that Windows never asserted, so these are recorded as
            # informational and their weight comes from the rule that claims them.
            Level       = 4
            LevelName   = 'Information'
            TimeCreated = $when
            Undated     = ($null -eq $when)
            MachineName = $env:COMPUTERNAME
            RecordId    = $r.RecordNumber
            Area        = 'Reliability Monitor'
            Hint        = "Microsoft's own record of what failed and what was installed."
            Message     = [string]$r.Message
        }) | Out-Null
        if ($CollectionBudget) { Add-LVCollectionBudgetUsage -Budget $CollectionBudget -Bytes $estimatedBytes -Records 1 }
    }

    if (-not $script:LVReliabilityBudgetStop) {
        $script:LVReliabilityBudgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
    }
    if ($script:LVReliabilityBudgetStop) { $script:LVReliabilityStatus = $script:LVReliabilityBudgetStop }

    $detail = ''
    if ($duplicates -gt 0) { $detail += (' ({0} already seen in an event channel)' -f $duplicates) }
    if ($tooOld -gt 0)     { $detail += (' ({0} outside the window)' -f $tooOld) }
    Write-LVLog -Level ok -Message ('Reliability Monitor: {0} record(s){1}' -f $records.Count, $detail)

    return ConvertTo-LVArrayOutput -Value @($records.ToArray())
}

function Get-LVStabilityTrend {
    <#
        .SYNOPSIS
        The system stability index and which way it is moving.

        .DESCRIPTION
        Windows scores stability from 1 to 10 over a rolling window, recalculated hourly.
        Rate escalation answers "is this signature frequent"; this answers the question
        underneath it, "is this machine getting worse", which a single scan otherwise
        cannot see at all.

        Direction compares the most recent reading against the oldest one inside the
        requested window. Returns $null when the provider is unavailable, so callers can
        distinguish "no trend" from "a flat trend".
    #>
    [CmdletBinding()]
    param([int]$DaysBack = 30)

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))

    try {
        $metrics = @(Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction Stop |
            Where-Object { $null -ne $_.TimeGenerated -and $_.TimeGenerated -ge $cutoff } |
            Sort-Object TimeGenerated)
    } catch {
        Write-LVLog -Level info -Message ('Stability metrics unavailable: {0}' -f $_.Exception.Message)
        return $null
    }

    if ($metrics.Count -eq 0) { return $null }

    $newest = $metrics[-1]
    $oldest = $metrics[0]
    $current = [Math]::Round([double]$newest.SystemStabilityIndex, 2)
    $starting = [Math]::Round([double]$oldest.SystemStabilityIndex, 2)
    $lowest = [Math]::Round(($metrics | Measure-Object -Property SystemStabilityIndex -Minimum).Minimum, 2)

    # A tenth of a point either way is noise in an hourly rolling average, not a trend.
    $delta = $current - $starting
    $direction = 'steady'
    if ($delta -ge 0.1) { $direction = 'improving' }
    elseif ($delta -le -0.1) { $direction = 'worsening' }

    return [pscustomobject]@{
        Current     = $current
        Starting    = $starting
        Lowest      = $lowest
        Direction   = $direction
        SampleCount = $metrics.Count
        Since       = $oldest.TimeGenerated
    }
}
