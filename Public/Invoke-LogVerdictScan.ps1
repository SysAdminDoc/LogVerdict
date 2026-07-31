function Invoke-LogVerdictScan {
    <#
        .SYNOPSIS
        Scan this PC's logs, deduplicate them, and rule on what is left.

        .DESCRIPTION
        Runs the full pipeline: collect -> reduce -> resolve. Read-only; nothing on the
        machine is modified. Returns a result object that Export-LogVerdictReport renders.

        .PARAMETER DaysBack
        How far back to look. Default 30.

        .PARAMETER Channel
        Event channels to read. Defaults to System and Application, which carry almost
        all client-troubleshooting signal.

        .PARAMETER AllChannels
        Sweep every channel on the machine that holds records. Much slower and much
        noisier; use when the default two come back empty but something is clearly wrong.

        .PARAMETER SkipTextLogs
        Skip CBS, DISM, SetupAPI and the other plain-text logs.

        .PARAMETER IncludeBenign
        Keep signatures ruled benign in the result. Off by default - the entire point
        is to remove them.

        .EXAMPLE
        Invoke-LogVerdictScan -DaysBack 7

        .EXAMPLE
        Invoke-LogVerdictScan -AllChannels -IncludeBenign
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 30,
        [string[]]$Channel,
        [switch]$AllChannels,
        [switch]$SkipTextLogs,
        [switch]$IncludeBenign,
        [string]$DatabasePath
    )

    $started = Get-Date
    $elevated = Test-LVElevated

    Write-LVLog -Level step -Message ('LogVerdict {0} starting - window {1} day(s)' -f $script:LVVersion, $DaysBack)
    if (-not $elevated) {
        Write-LVLog -Level warn -Message 'Not elevated. The Security channel and some text logs will be skipped; results are incomplete but honest about it.'
    }

    if ($AllChannels) {
        Write-LVLog -Level info -Message 'Enumerating populated channels...'
        $channels = Get-LVPopulatedChannel
        Write-LVLog -Level ok -Message ('{0} channel(s) hold records' -f $channels.Count)
    } elseif ($Channel) {
        $channels = $Channel
    } else {
        $channels = Get-LVDefaultChannel
    }

    # Probe before reading. The FilterHashtable path cannot tell a denied channel from
    # an empty one, so coverage has to be established with -LogName first or the scan
    # silently reports "nothing wrong" for channels it was never allowed to open.
    $script:LVChannelMetadataErrorCount = 0
    $script:LVDeniedChannel = @()
    $script:LVTruncatedChannel = @()

    Write-LVLog -Level info -Message ('Probing {0} channel(s) for access and history...' -f @($channels).Count)
    $channelStatus = Get-LVChannelStatus -Channel $channels

    $readable = @($channelStatus.Values | Where-Object { $_.Access -eq 'readable' }).Count
    Write-LVLog -Level info -Message ('Reading {0} readable channel(s)...' -f $readable)
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Get-LVEventRecord -Channel $channels -DaysBack $DaysBack -ChannelStatus $channelStatus)) { $records.Add($r) | Out-Null }
    Write-LVLog -Level ok -Message ('{0} event record(s)' -f $records.Count)

    if (-not $SkipTextLogs) {
        Write-LVLog -Level info -Message 'Reading plain-text logs...'
        foreach ($r in (Get-LVTextLogRecord -DaysBack $DaysBack)) { $records.Add($r) | Out-Null }
    }

    $all = @($records.ToArray())
    Write-LVLog -Level info -Message ('Reducing {0} record(s) to signatures...' -f $all.Count)
    $signatures = Group-LVSignature -Record $all -WindowDays $DaysBack
    $stat = Get-LVReductionStat -Record $all -Signature $signatures
    Write-LVLog -Level ok -Message ('{0} signature(s) - reduction {1}:1' -f $stat.SignatureCount, $stat.Ratio)

    $db = Get-LogVerdictDatabase -Path $DatabasePath
    Write-LVLog -Level info -Message ('Applying {0} rule(s) from the verdict database...' -f @($db.rules).Count)
    $findings = Resolve-LVVerdict -Signature $signatures -Database $db

    if (-not $IncludeBenign) {
        $before = @($findings).Count
        $findings = @($findings | Where-Object { $_.Verdict -ne 'benign' })
        $removed = $before - @($findings).Count
        if ($removed -gt 0) {
            Write-LVLog -Level ok -Message ('{0} signature(s) ruled benign and suppressed (use -IncludeBenign to see them)' -f $removed)
        }
    }

    # Coverage honesty: an in-place upgrade or a cleared log resets a channel, which
    # makes a scan look clean for the wrong reason. Say so rather than imply health.
    $horizon = @{}
    foreach ($entry in $channelStatus.Values) {
        if ($entry.Oldest) { $horizon[$entry.Channel] = $entry.Oldest }
    }
    $horizonWarning = $null
    $cutoff = $started.AddDays(-1 * [Math]::Abs($DaysBack))
    foreach ($key in $horizon.Keys) {
        if ($horizon[$key] -gt $cutoff) {
            $horizonWarning = ("The '{0}' channel only goes back to {1:yyyy-MM-dd}, which is inside the requested {2}-day window. An in-place upgrade, a log rollover or a cleared log removed the earlier evidence, so a clean result here does not prove the machine was healthy before that date." -f `
                $key, $horizon[$key], $DaysBack)
            break
        }
    }
    if ($horizonWarning) { Write-LVLog -Level warn -Message $horizonWarning }

    $crash = @()
    if (-not $SkipTextLogs) { $crash = Get-LVCrashArtifact -DaysBack ([Math]::Max($DaysBack, 90)) }
    if (@($crash).Count -gt 0) {
        Write-LVLog -Level warn -Message ('{0} crash artifact(s) on disk (minidumps / WER reports) - collected, not decoded' -f @($crash).Count)
    }

    # Everything the scan could NOT see, stated plainly. A finding list is only as
    # trustworthy as the coverage behind it, so the gaps travel with the results.
    $coverageNotes = New-Object System.Collections.Generic.List[string]
    if (@($script:LVDeniedChannel).Count -gt 0) {
        $coverageNotes.Add(('Access was denied to {0} channel(s) and they were not scanned: {1}. Re-run elevated.' -f @($script:LVDeniedChannel).Count, (@($script:LVDeniedChannel) -join ', '))) | Out-Null
    }
    if ($script:LVChannelMetadataErrorCount -gt 0) {
        $coverageNotes.Add(('{0} channel(s) would not report their metadata and were never enumerated. Elevation may reveal more.' -f $script:LVChannelMetadataErrorCount)) | Out-Null
    }
    $missing = @($channelStatus.Values | Where-Object { $_.Access -eq 'missing' } | Select-Object -ExpandProperty Channel)
    if ($missing.Count -gt 0) {
        $coverageNotes.Add(('{0} requested channel(s) do not exist on this machine and were skipped: {1}. Check the spelling.' -f $missing.Count, ($missing -join ', '))) | Out-Null
        Write-LVLog -Level warn -Message ('Requested channel(s) not present on this machine: {0}' -f ($missing -join ', '))
    }
    if (@($script:LVTruncatedChannel).Count -gt 0) {
        $coverageNotes.Add(('These channel(s) hit the per-channel record cap and are truncated: {0}. Counts and rates for them are lower bounds.' -f (@($script:LVTruncatedChannel) -join ', '))) | Out-Null
    }
    if (-not $elevated) {
        $coverageNotes.Add('Scan ran without elevation. The Security channel and some text logs require administrator rights.') | Out-Null
    }

    # Precomputed here so callers (including the entry script) never need a private helper.
    $worst = 'benign'
    foreach ($f in $findings) {
        if ((Get-LVVerdictRank -Verdict $f.Verdict) -gt (Get-LVVerdictRank -Verdict $worst)) { $worst = $f.Verdict }
    }
    $exitCode = 0
    switch ($worst) {
        'critical'    { $exitCode = 3 }
        'actionable'  { $exitCode = 2 }
        'investigate' { $exitCode = 1 }
        'unknown'     { $exitCode = 1 }
    }

    return [pscustomobject]@{
        Tool           = 'LogVerdict'
        Version        = $script:LVVersion
        MachineName    = $env:COMPUTERNAME
        ScanTime       = $started
        Duration       = ((Get-Date) - $started)
        DaysBack       = $DaysBack
        Elevated       = $elevated
        Channels       = @($channels)
        ChannelStatus  = $channelStatus
        DeniedChannels = @($script:LVDeniedChannel)
        TruncatedChannels = @($script:LVTruncatedChannel)
        MetadataUnreadableCount = [int]$script:LVChannelMetadataErrorCount
        CoverageNotes  = @($coverageNotes)
        Reduction      = $stat
        Findings       = @($findings)
        CrashArtifacts = @($crash)
        Horizon        = $horizon
        HorizonWarning = $horizonWarning
        DatabaseName   = $db.name
        DatabaseDate   = $db.updated
        RuleCount      = @($db.rules).Count
        WorstVerdict   = $worst
        ExitCode       = $exitCode
    }
}
