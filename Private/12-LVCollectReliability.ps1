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
        [AllowEmptyCollection()][object[]]$ExistingRecord = @()
    )

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $records = New-Object System.Collections.Generic.List[object]

    $seen = @{}
    foreach ($r in $ExistingRecord) {
        if ($r.Source -ne 'event') { continue }
        $seen[('{0}/{1}' -f $r.Provider, $r.Id)] = $true
    }

    $raw = $null
    try {
        $raw = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction Stop)
    } catch {
        # Absence is a coverage gap, not a clean bill of health. Group Policy can
        # disable the provider outright and Server disables it by default.
        $script:LVReliabilityAvailable = $false
        $script:LVReliabilitySkipReason = $_.Exception.Message
        Write-LVLog -Level warn -Message ('Reliability Monitor is not available on this machine ({0}); that source was skipped, not cleared.' -f $_.Exception.Message)
        return ConvertTo-LVArrayOutput -Value @()
    }

    $script:LVReliabilityAvailable = $true
    $script:LVReliabilitySkipReason = $null

    $duplicates = 0
    $tooOld = 0

    foreach ($r in $raw) {
        $when = $r.TimeGenerated
        if ($null -ne $when -and $when -lt $cutoff) { $tooOld++; continue }

        $provider = $r.SourceName
        if (-not $provider) { $provider = 'Unknown' }
        $id = 0
        if ($null -ne $r.EventIdentifier) { $id = [int]$r.EventIdentifier }

        if ($seen.ContainsKey(('{0}/{1}' -f $provider, $id))) { $duplicates++; continue }

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
    }

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
