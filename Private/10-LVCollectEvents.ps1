# Collection layer: pull raw records out of the Windows event channels.
# Read-only. Nothing in this file interprets anything - that is the reducer's job.

# Channels that are commonly ACL-restricted and therefore invisible to
# Get-WinEvent -ListLog when running unelevated. They are probed explicitly so a
# non-elevated scan can report them as denied rather than pretend they do not exist.
$script:LVAlwaysProbeChannel = @('Security')

function Get-LVDefaultChannel {
    # The two channels that carry almost all client-troubleshooting signal.
    return @('System', 'Application')
}

function Get-LVErrorKind {
    <#
        .SYNOPSIS
        Classify a Get-WinEvent failure without reading its message.

        .DESCRIPTION
        Exception messages are rendered from localized resources, so branching on
        English text ("No events were found", "Access is denied") silently changes
        behaviour on a non-English Windows. FullyQualifiedErrorId is stable across
        locales, so it is the only safe discriminator.

        .OUTPUTS
        'denied' | 'empty' | 'missing' | 'other'
    #>
    param([Parameter(Mandatory)]$ErrorRecord)

    $fqid = [string]$ErrorRecord.FullyQualifiedErrorId
    if ($fqid -like 'System.UnauthorizedAccessException,*') { return 'denied' }
    if ($fqid -like 'NoMatchingEventsFound,*')              { return 'empty' }
    if ($fqid -like 'NoMatchingLogsFound,*')                { return 'missing' }
    if ($fqid -like 'LogInfoUnavailable,*')                 { return 'denied' }
    return 'other'
}

function Get-LVChannelStatus {
    <#
        .SYNOPSIS
        Probe each channel for readability and its oldest surviving record.

        .DESCRIPTION
        Two jobs in one pass because both need the same expensive call.

        Readability matters because Get-WinEvent reports a denied channel through the
        -FilterHashtable path as NoMatchingEventsFound - identical to an empty one. A
        scan that trusts that path reports "nothing wrong here" for channels it was
        never allowed to open. Probing with -LogName instead surfaces the real
        UnauthorizedAccessException, so denial can be reported as denial.

        The oldest record matters because an in-place upgrade or a cleared log resets a
        channel, so "no errors found" can mean "the evidence was destroyed".

        .OUTPUTS
        Hashtable keyed by channel name, values carrying Access and Oldest.
    #>
    [CmdletBinding()]
    param([string[]]$Channel = (Get-LVDefaultChannel))

    $status = @{}
    $total = @($Channel).Count
    $done = 0
    foreach ($ch in $Channel) {
        $done++
        # -AllChannels probes ~128 channels and takes tens of seconds. Without this the
        # tool sits silent long enough to look hung.
        if ($total -gt 8) {
            Write-Progress -Id 1 -Activity 'LogVerdict: probing event channels' `
                -Status ("{0} of {1}: {2}" -f $done, $total, $ch) `
                -PercentComplete ([Math]::Min(100, [int](100 * $done / $total)))
        }
        $entry = [pscustomobject]@{
            Channel = $ch
            Access  = 'readable'
            Oldest  = $null
        }
        try {
            $oldest = Get-WinEvent -LogName $ch -Oldest -MaxEvents 1 -ErrorAction Stop
            if ($oldest) { $entry.Oldest = $oldest.TimeCreated }
        } catch {
            $kind = Get-LVErrorKind -ErrorRecord $_
            if ($kind -eq 'other') {
                Write-LVLog -Level warn -Message ("Channel '{0}' probe failed: {1}" -f $ch, $_.Exception.Message)
                $entry.Access = 'unreadable'
            } else {
                $entry.Access = $kind
            }
        }
        $status[$ch] = $entry
    }
    if ($total -gt 8) { Write-Progress -Id 1 -Activity 'LogVerdict: probing event channels' -Completed }
    return $status
}

function Get-LVPopulatedChannel {
    <#
        .SYNOPSIS
        Every channel on this machine that holds records, plus the restricted ones
        worth reporting on even when their metadata cannot be read.

        .DESCRIPTION
        A stock Windows 11 install defines roughly 1,300 channels but only a few
        hundred are enabled and non-empty. Enumerating first avoids hundreds of
        "no events found" round trips.

        Get-WinEvent -ListLog silently omits channels whose metadata the caller cannot
        stat, which unelevated includes Security. Those omissions are counted and
        surfaced rather than discarded, because a channel missing from the sweep is a
        hole in coverage, not an absence of problems.
    #>
    [CmdletBinding()]
    param([int]$MinimumRecords = 1)

    $listErrors = $null
    $logs = @()
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue -ErrorVariable listErrors |
            Where-Object { $_.RecordCount -ge $MinimumRecords }
    } catch {
        Write-LVLog -Level warn -Message ("Channel enumeration failed: {0}" -f $_.Exception.Message)
        return @()
    }

    $script:LVChannelMetadataErrorCount = @($listErrors).Count
    if ($script:LVChannelMetadataErrorCount -gt 0) {
        Write-LVLog -Level warn -Message ("{0} channel(s) would not report their metadata and were not enumerated; elevation may reveal more." -f $script:LVChannelMetadataErrorCount)
    }

    $names = @($logs | Sort-Object -Property RecordCount -Descending | Select-Object -ExpandProperty LogName)

    # Union in the restricted channels so they get classified rather than vanish.
    foreach ($ch in $script:LVAlwaysProbeChannel) {
        if ($names -notcontains $ch) { $names += $ch }
    }
    return $names
}

function Get-LVEventRecord {
    <#
        .SYNOPSIS
        Normalized event records from the requested channels.

        .PARAMETER ChannelStatus
        Optional access map from Get-LVChannelStatus. Channels already known to be
        denied or missing are skipped rather than re-probed.

        .OUTPUTS
        PSCustomObject with Source='event' plus Channel/Provider/Id/Level/TimeCreated/Message.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Channel = (Get-LVDefaultChannel),
        [int]$DaysBack = 30,
        [int[]]$Level = @(1, 2, 3),
        [int]$MaxPerChannel = 20000,
        [hashtable]$ChannelStatus
    )

    $since = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $records = New-Object System.Collections.Generic.List[object]
    $denied = New-Object System.Collections.Generic.List[string]
    $truncated = New-Object System.Collections.Generic.List[string]

    $total = @($Channel).Count
    $done = 0
    foreach ($ch in $Channel) {
        $done++
        if ($total -gt 8) {
            Write-Progress -Id 2 -Activity 'LogVerdict: reading event channels' `
                -Status ("{0} of {1}: {2} ({3} records so far)" -f $done, $total, $ch, $records.Count) `
                -PercentComplete ([Math]::Min(100, [int](100 * $done / $total)))
        }

        # A denied channel answers the FilterHashtable query with "no events found",
        # so trust the -LogName probe instead of asking and believing the answer.
        if ($ChannelStatus -and $ChannelStatus.ContainsKey($ch)) {
            $access = $ChannelStatus[$ch].Access
            if ($access -eq 'denied')  { $denied.Add($ch) | Out-Null; continue }
            if ($access -eq 'missing') { continue }
        }

        $filter = @{ LogName = $ch; StartTime = $since }
        if ($Level -and $Level.Count -gt 0) { $filter['Level'] = $Level }

        $events = $null
        try {
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxPerChannel -ErrorAction Stop
        } catch {
            $kind = Get-LVErrorKind -ErrorRecord $_
            switch ($kind) {
                'empty'   { continue }
                'missing' { continue }
                'denied'  { $denied.Add($ch) | Out-Null; continue }
                default   {
                    Write-LVLog -Level warn -Message ("Channel '{0}' unreadable: {1}" -f $ch, $_.Exception.Message)
                    continue
                }
            }
        }

        $events = @($events)
        if ($events.Count -ge $MaxPerChannel) { $truncated.Add($ch) | Out-Null }

        foreach ($e in $events) {
            $message = $e.Message
            if ([string]::IsNullOrWhiteSpace($message)) {
                # Provider metadata missing (uninstalled software, or an offline copy).
                # Keep the record - the signature is still valid, the prose just is not.
                $message = '(no message template registered for this provider on this machine)'
            }

            $records.Add([pscustomobject]@{
                Source       = 'event'
                Channel      = $ch
                Provider     = $e.ProviderName
                Id           = [int]$e.Id
                Level        = [int]$e.Level
                LevelName    = $e.LevelDisplayName
                TimeCreated  = $e.TimeCreated
                MachineName  = $e.MachineName
                RecordId     = $e.RecordId
                Message      = $message.Trim()
            }) | Out-Null
        }
    }

    if ($total -gt 8) { Write-Progress -Id 2 -Activity 'LogVerdict: reading event channels' -Completed }

    $script:LVDeniedChannel = @($denied.ToArray())
    $script:LVTruncatedChannel = @($truncated.ToArray())

    if ($denied.Count -gt 0) {
        Write-LVLog -Level warn -Message ("Access denied on {0} channel(s): {1}. Re-run elevated for full coverage." -f $denied.Count, ($denied -join ', '))
    }
    if ($truncated.Count -gt 0) {
        Write-LVLog -Level warn -Message ("Hit the {0}-record cap on: {1}. Those channels are truncated; narrow -DaysBack or raise -MaxPerChannel for full coverage." -f $MaxPerChannel, ($truncated -join ', '))
    }

    return ConvertTo-LVArrayOutput -Value @($records.ToArray())
}
