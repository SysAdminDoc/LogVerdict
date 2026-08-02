function Watch-LogVerdict {
    <#
        .SYNOPSIS
        Tail selected Windows event channels for a bounded period.

        .DESCRIPTION
        Reads only newly arrived events, resumes from a per-channel JSON bookmark,
        and returns normalized records plus coverage and health evidence. The watch
        is local, opt-in, bounded, read-only, and never changes channel retention or
        forwarding configuration. Record-ID gaps are reported as possible drops or
        rollover, not as tampering.

        .PARAMETER Channel
        Event channels to watch. Defaults to System and Application.

        .PARAMETER BookmarkPath
        Optional JSON bookmark path. It is written atomically after observed events
        and again when the watch stops, so a later watch can resume safely.

        .PARAMETER DurationSeconds
        Maximum watch duration, from 1 second through 24 hours. Default 300 seconds.

        .PARAMETER MaxEvents
        Maximum normalized records returned by this watch. Default 1000.

        .PARAMETER IdleTimeoutSeconds
        Stop after this many seconds without a new event. Zero disables the idle stop.

        .PARAMETER IncludeWEFHealth
        Include local Windows Event Forwarding subscription configuration and runtime
        health. WEF intake is advisory and does not require a LogVerdict agent.

        .EXAMPLE
        Watch-LogVerdict -Channel System -BookmarkPath .\system-bookmark.json -DurationSeconds 60
    #>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()][string[]]$Channel = (Get-LVDefaultChannel),
        [string]$BookmarkPath,
        [ValidateRange(1, 86400)][int]$DurationSeconds = 300,
        [ValidateRange(1, 100000)][int]$MaxEvents = 1000,
        [ValidateRange(0, 86400)][int]$IdleTimeoutSeconds = 0,
        [ValidateRange(100, 60000)][int]$PollMilliseconds = 1000,
        [ValidateRange(1, 4096)][int]$PageSize = 256,
        [switch]$IncludeWEFHealth,
        [string[]]$WEFSubscription
    )

    $channels = @($Channel | Where-Object { $_ } | Select-Object -Unique)
    if ($channels.Count -eq 0) { throw 'At least one event channel is required.' }

    $started = Get-Date
    $bookmark = Read-LVWatchBookmark -Path $BookmarkPath
    $records = New-Object System.Collections.Generic.List[object]
    $states = @{}
    foreach ($channelName in $channels) {
        $saved = Get-LVWatchBookmarkEntry -Bookmark $bookmark -Channel $channelName
        $lastId = $null
        if ($saved -and $saved.PSObject.Properties['recordId'] -and [string]$saved.recordId -match '^\d+$') {
            $lastId = [int64]$saved.recordId
        }
        $lastTime = if ($saved -and $saved.PSObject.Properties['timeCreated']) { ConvertTo-LVWatchBookmarkDate -Text ([string]$saved.timeCreated) } else { $null }
        $states[$channelName] = [pscustomobject]@{
            Channel               = $channelName
            LastRecordId          = $lastId
            LastTimeCreated       = $lastTime
            Observed              = [int64]0
            Dropped               = [int64]0
            FirstGap              = $null
            LastGap               = $null
            PollErrors            = 0
            Reconnects            = 0
            HadError              = $false
            LastError             = $null
            Latencies             = New-Object System.Collections.Generic.List[double]
        }
    }

    $lastActivity = $started
    $pollCount = 0
    $stopReason = 'duration'
    $bookmarkDirty = $false
    Write-LVLog -Level step -Message ('LogVerdict live watch starting - {0} channel(s), {1} second limit, {2} record limit' -f $channels.Count, $DurationSeconds, $MaxEvents)
    if ($BookmarkPath) { Write-LVLog -Level info -Message ("Resuming from bookmark '{0}'." -f $BookmarkPath) }

    try {
        while ($true) {
            $pollCount++
            $limitReached = $false
            foreach ($channelName in $channels) {
                $state = $states[$channelName]
                try {
                    $page = @(Get-WinEvent -LogName $channelName -MaxEvents $PageSize -ErrorAction Stop)
                    if ($state.HadError) {
                        $state.Reconnects++
                        Write-LVLog -Level ok -Message ("Live watch reconnected to '{0}'." -f $channelName)
                    }
                    $state.HadError = $false
                } catch {
                    $state.PollErrors++
                    $state.HadError = $true
                    $state.LastError = $_.Exception.Message
                    Write-LVLog -Level warn -Message ("Live watch could not read '{0}': {1}" -f $channelName, $_.Exception.Message)
                    continue
                }

                $ordered = @($page | Sort-Object `
                    @{ Expression = { if ($null -ne $_.RecordId -and [string]$_.RecordId -match '^\d+$') { [int64]$_.RecordId } else { [int64]0 } } }, `
                    @{ Expression = { $_.TimeCreated } })
                foreach ($eventItem in $ordered) {
                    $recordId = $null
                    if ($null -ne $eventItem.RecordId -and [string]$eventItem.RecordId -match '^\d+$') { $recordId = [int64]$eventItem.RecordId }
                    $eventTime = if ($eventItem.TimeCreated) { [datetime]$eventItem.TimeCreated } else { $null }
                    $isNew = if ($null -ne $recordId -and $null -ne $state.LastRecordId) {
                        $recordId -gt $state.LastRecordId
                    } elseif ($null -ne $eventTime -and $null -ne $state.LastTimeCreated) {
                        $eventTime -gt $state.LastTimeCreated
                    } else { $true }
                    if (-not $isNew) { continue }
                    if ($records.Count -ge $MaxEvents) { $limitReached = $true; break }

                    if ($null -ne $recordId -and $null -ne $state.LastRecordId -and $recordId -gt ($state.LastRecordId + 1)) {
                        $gap = $recordId - $state.LastRecordId - 1
                        $state.Dropped += $gap
                        if ($null -eq $state.FirstGap) { $state.FirstGap = $state.LastRecordId }
                        $state.LastGap = $recordId
                    }
                    if ($null -ne $eventTime) {
                        $latency = ((Get-Date) - $eventTime).TotalMilliseconds
                        if ($latency -lt 0) { $latency = 0 }
                        $state.Latencies.Add([double]$latency) | Out-Null
                    }
                    $records.Add((ConvertTo-LVWatchEventRecord -EventObject $eventItem -Channel $channelName)) | Out-Null
                    $state.Observed++
                    if ($null -ne $recordId) { $state.LastRecordId = $recordId }
                    if ($null -ne $eventTime) { $state.LastTimeCreated = $eventTime }
                    $lastActivity = Get-Date
                    $bookmarkDirty = $true
                    Set-LVWatchBookmarkEntry -Bookmark $bookmark -Channel $channelName -Entry ([pscustomobject][ordered]@{
                        recordId = $state.LastRecordId
                        timeCreated = if ($state.LastTimeCreated) { $state.LastTimeCreated.ToUniversalTime().ToString('o') } else { $null }
                        updated = (Get-Date).ToUniversalTime().ToString('o')
                    })
                }
                if (-not $limitReached -and $records.Count -ge $MaxEvents) { $limitReached = $true }
                if ($limitReached) { break }
            }

            if ($BookmarkPath -and $bookmarkDirty) {
                Write-LVWatchBookmark -Path $BookmarkPath -Bookmark $bookmark
                $bookmarkDirty = $false
            }
            if ($limitReached) { $stopReason = 'max-events'; break }
            $now = Get-Date
            if (($now - $started).TotalSeconds -ge $DurationSeconds) { $stopReason = 'duration'; break }
            if ($IdleTimeoutSeconds -gt 0 -and ($now - $lastActivity).TotalSeconds -ge $IdleTimeoutSeconds) { $stopReason = 'idle'; break }
            Start-Sleep -Milliseconds $PollMilliseconds
        }
    } finally {
        if ($BookmarkPath -and $bookmarkDirty) { Write-LVWatchBookmark -Path $BookmarkPath -Bookmark $bookmark }
    }

    $ended = Get-Date
    $coverage = New-Object System.Collections.Generic.List[object]
    $health = New-Object System.Collections.Generic.List[object]
    $coverageNotes = New-Object System.Collections.Generic.List[string]
    foreach ($channelName in $channels) {
        $state = $states[$channelName]
        $latencies = @($state.Latencies.ToArray())
        $status = if ($state.Observed -gt 0) { 'readable' } elseif ($state.PollErrors -gt 0) { 'unreadable' } else { 'empty' }
        $gapText = if ($state.Dropped -gt 0) {
            "RecordId gap after $($state.FirstGap) before $($state.LastGap); $($state.Dropped) record(s) were not observed. Rollover, filtering, or a dropped subscription can cause this."
        } else { $null }
        $reason = if ($state.PollErrors -gt 0) { "The watch encountered $($state.PollErrors) read error(s); the last was: $($state.LastError)" } elseif ($state.Observed -eq 0) { 'No new event was observed during the watch window.' } else { $null }
        $entry = New-LVCoverageRecord -Source 'event-watch' -Kind 'channel' -Name $channelName -Status $status `
            -Reason $reason -WindowStart $started -WindowEnd $ended -Cap $MaxEvents `
            -ObservedRecords $state.Observed -SkippedRecords $state.Dropped -RecordGap $gapText `
            -ParserError $state.LastError -Origin 'live-watch'
        $entry | Add-Member -NotePropertyName PollCount -NotePropertyValue $pollCount
        $entry | Add-Member -NotePropertyName PollErrors -NotePropertyValue $state.PollErrors
        $entry | Add-Member -NotePropertyName ReconnectCount -NotePropertyValue $state.Reconnects
        $entry | Add-Member -NotePropertyName MaxLatencyMilliseconds -NotePropertyValue $(if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Maximum).Maximum, 2) } else { $null })
        $entry | Add-Member -NotePropertyName AverageLatencyMilliseconds -NotePropertyValue $(if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { $null })
        $coverage.Add($entry) | Out-Null
        if ($gapText) { $coverageNotes.Add("${channelName}: $gapText") | Out-Null }
        if ($state.PollErrors -gt 0) { $coverageNotes.Add("${channelName}: $($state.PollErrors) read error(s), $($state.Reconnects) reconnect(s).") | Out-Null }
        $healthEntry = New-LVHealthProfile -Profile 'live-watch' -Source 'event-watch' -Name $channelName -Status $status `
            -ObservedConfiguration ('Observed={0}; Polls={1}; Reconnects={2}; Dropped={3}; AverageLatencyMilliseconds={4}; MaxLatencyMilliseconds={5}' -f `
                $state.Observed, $pollCount, $state.Reconnects, $state.Dropped, `
                $(if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { $null }), `
                $(if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Maximum).Maximum, 2) } else { $null })) `
            -ReadExistingEvents $null -BookmarkState $(if ($BookmarkPath) { 'persisted' } else { 'memory-only' }) `
            -RecordCount $state.Observed -Reason $reason -Advice 'Live-watch reconnect, gap, and latency fields describe collection quality; they are not maliciousness verdicts.' -Origin 'live-watch'
        $healthEntry | Add-Member -NotePropertyName PollErrors -NotePropertyValue $state.PollErrors
        $healthEntry | Add-Member -NotePropertyName ReconnectCount -NotePropertyValue $state.Reconnects
        $healthEntry | Add-Member -NotePropertyName DroppedRecords -NotePropertyValue $state.Dropped
        $healthEntry | Add-Member -NotePropertyName AverageLatencyMilliseconds -NotePropertyValue $(if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { $null })
        $healthEntry | Add-Member -NotePropertyName MaxLatencyMilliseconds -NotePropertyValue $(if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Maximum).Maximum, 2) } else { $null })
        $health.Add($healthEntry) | Out-Null
    }
    $coverageNotes.Add(('Live watch stopped cleanly: {0}; polls={1}; durationSeconds={2}.' -f $stopReason, $pollCount, [math]::Round(($ended - $started).TotalSeconds, 2))) | Out-Null

    if ($IncludeWEFHealth) {
        foreach ($wefHealth in @(Get-LVWEFHealthProfile -Subscription $WEFSubscription)) { $health.Add($wefHealth) | Out-Null }
    }

    return [pscustomobject]@{
        Tool          = 'LogVerdict'
        Version       = $script:LVVersion
        Mode          = 'live-watch'
        MachineName   = $env:COMPUTERNAME
        ScanTime      = $started
        Duration      = $ended - $started
        Channels      = $channels
        BookmarkPath  = $BookmarkPath
        Bookmark      = $bookmark
        StopReason    = $stopReason
        PollCount     = $pollCount
        RecordCount   = $records.Count
        Records       = @($records.ToArray())
        CoverageNotes = @($coverageNotes.ToArray())
        Coverage      = @($coverage.ToArray())
        HealthProfiles = @($health.ToArray())
        Findings      = @()
        Correlations  = @()
        Reduction     = [pscustomobject]@{ RecordCount = $records.Count; SignatureCount = $null; Ratio = $null }
        Elevated      = Test-LVElevated
    }
}
