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

function Get-LVDiagnosticChannel {
    <#
        .SYNOPSIS
        A focused tier between the default scan and a sweep of every populated log.

        .DESCRIPTION
        These channels carry high-value client troubleshooting evidence but are not
        included in the traditional System and Application logs. Keep the defaults
        first so callers get one ordered, duplicate-free list.
    #>
    return @(
        'System'
        'Application'
        'Microsoft-Windows-Ntfs/Operational'
        'Microsoft-Windows-CodeIntegrity/Operational'
        'Microsoft-Windows-Kernel-PnP/Configuration'
        'Microsoft-Windows-AppModel-Runtime/Admin'
        'Microsoft-Windows-Resource-Exhaustion-Detector/Operational'
        'Microsoft-Windows-Kernel-Boot/Operational'
    )
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
    param(
        [string[]]$Channel = (Get-LVDefaultChannel),
        [AllowNull()][hashtable]$Metadata
    )

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
            Channel            = $ch
            Access             = 'readable'
            Oldest             = $null
            RecordCount        = $null
            MaximumSizeInBytes = $null
            LogMode            = $null
            IsEnabled          = $null
            LogFilePath        = $null
            Reason             = $null
        }
        try {
            try {
                if ($Metadata -and $Metadata.ContainsKey($ch)) {
                    $configuration = @($Metadata[$ch])
                } else {
                    $configuration = @(Get-WinEvent -ListLog $ch -ErrorAction Stop | Select-Object -First 1)
                }
                if ($configuration.Count -gt 0) {
                    foreach ($property in @('RecordCount', 'MaximumSizeInBytes', 'LogMode', 'IsEnabled', 'LogFilePath')) {
                        if ($configuration[0].PSObject.Properties[$property]) {
                            $entry.$property = $configuration[0].$property
                        }
                    }
                }
            } catch {
                # A caller may be allowed to read event records while the metadata
                # object itself is unavailable. Preserve the event access result and
                # let the health profile explain the missing retention metadata.
                $entry.Reason = $_.Exception.Message
            }
            if ($entry.IsEnabled -ne $false) {
                $oldest = Get-WinEvent -LogName $ch -Oldest -MaxEvents 1 -ErrorAction Stop
                if ($oldest) { $entry.Oldest = $oldest.TimeCreated }
            }
        } catch {
            $kind = Get-LVErrorKind -ErrorRecord $_
            if ($kind -eq 'other') {
                Write-LVLog -Level warn -Message ("Channel '{0}' probe failed: {1}" -f $ch, $_.Exception.Message)
                $entry.Access = 'unreadable'
            } else {
                $entry.Access = $kind
            }
            $entry.Reason = $_.Exception.Message
        }
        if ($entry.PSObject.Properties['IsEnabled'] -and $entry.IsEnabled -eq $false) {
            $entry.Reason = 'Event logging is disabled for this channel; no events can be observed.'
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
    $script:LVChannelMetadata = @{}
    $script:LVChannelMetadataFailures = @()
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue -ErrorVariable listErrors |
            Where-Object { $_.RecordCount -ge $MinimumRecords }
    } catch {
        Write-LVLog -Level warn -Message ("Channel enumeration failed: {0}" -f $_.Exception.Message)
        $script:LVChannelMetadataFailures = @($_.Exception.Message)
        return @()
    }

    $script:LVChannelMetadataErrorCount = @($listErrors).Count
    $script:LVChannelMetadataFailures = @($listErrors | ForEach-Object { $_.Exception.Message })
    foreach ($log in @($logs | Where-Object { $_ -and $_.LogName })) {
        $script:LVChannelMetadata[[string]$log.LogName] = $log
    }
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
        [hashtable]$ChannelStatus,
        [AllowNull()]$CollectionBudget
    )

    $since = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $records = New-Object System.Collections.Generic.List[object]
    $denied = New-Object System.Collections.Generic.List[string]
    $truncated = New-Object System.Collections.Generic.List[string]
    $coverage = New-Object System.Collections.Generic.List[object]
    $sequenceRecords = New-Object System.Collections.Generic.List[object]
    $sequenceIncomplete = New-Object System.Collections.Generic.List[string]
    $windowStart = $since
    $windowEnd = Get-Date

    # The normal collector intentionally asks Windows for only errors and warnings.
    # RecordId continuity cannot be inferred from that filtered stream: an Information
    # event between two errors is expected, not evidence of a missing record.
    $levelFilterNeedsSequenceRead = $false
    if ($Level -and $Level.Count -gt 0) {
        $levelFilterNeedsSequenceRead = @((0..5 | Where-Object { $Level -notcontains $_ })).Count -gt 0
    }

    $total = @($Channel).Count
    $done = 0
    foreach ($ch in $Channel) {
        $done++
        if ($total -gt 8) {
            Write-Progress -Id 2 -Activity 'LogVerdict: reading event channels' `
                -Status ("{0} of {1}: {2} ({3} records so far)" -f $done, $total, $ch, $records.Count) `
                -PercentComplete ([Math]::Min(100, [int](100 * $done / $total)))
        }

        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        if ($budgetStop) {
            $truncated.Add($ch) | Out-Null
            $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status $budgetStop `
                -Reason ('The shared collection {0} budget stopped this channel before it was read.' -f $budgetStop) `
                -WindowStart $windowStart -WindowEnd (Get-Date) -Cap $MaxPerChannel `
                -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
            break
        }

        # A denied channel answers the FilterHashtable query with "no events found",
        # so trust the -LogName probe instead of asking and believing the answer.
        if ($ChannelStatus -and $ChannelStatus.ContainsKey($ch)) {
            $probe = $ChannelStatus[$ch]
            $access = $probe.Access
            if ($probe.PSObject.Properties['IsEnabled'] -and $probe.IsEnabled -eq $false) {
                $disabledReason = if ($probe.Reason) { [string]$probe.Reason } else { 'Event logging is disabled for this channel; no events can be observed.' }
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'disabled' `
                    -Reason $disabledReason -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel `
                    -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
                continue
            }
            if ($access -eq 'denied') {
                $denied.Add($ch) | Out-Null
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'not-observed' `
                    -Reason 'Access was denied during the channel probe.' -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel -ParserError $probe.Reason -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
                continue
            }
            if ($access -eq 'missing') {
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'not-observed' `
                    -Reason 'The requested channel does not exist on this machine.' -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel -ParserError $probe.Reason -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
                continue
            }
            if ($access -eq 'unreadable') {
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'unreadable' `
                    -Reason 'The channel probe failed, so events were not observed.' -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel -ParserError $probe.Reason -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
                continue
            }
        }

        $filter = @{ LogName = $ch; StartTime = $since }
        if ($Level -and $Level.Count -gt 0) { $filter['Level'] = $Level }

        $events = $null
        try {
            $readLimit = $MaxPerChannel
            if ($CollectionBudget) {
                $remainingRecords = [int64]$CollectionBudget.MaxRecords - [int64]$CollectionBudget.RecordsRead
                $readLimit = [Math]::Min([int64]$readLimit, $remainingRecords)
            }
            if ($readLimit -lt 1) {
                $truncated.Add($ch) | Out-Null
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'truncated' `
                    -Reason 'The shared collection record budget was exhausted before the channel was read.' `
                    -WindowStart $windowStart -WindowEnd (Get-Date) -Cap $MaxPerChannel `
                    -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
                break
            }
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $readLimit -ErrorAction Stop
        } catch {
            # Deliberately if/elseif, not switch: `continue` inside a switch continues
            # the SWITCH rather than this foreach, so the loop body would fall through
            # and emit one phantom record per erroring channel.
            $kind = Get-LVErrorKind -ErrorRecord $_
            if ($kind -eq 'denied') {
                $denied.Add($ch) | Out-Null
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'not-observed' `
                    -Reason 'Access was denied while reading the channel.' -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel -ParserError $_.Exception.Message -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
            } elseif ($kind -eq 'other') {
                Write-LVLog -Level warn -Message ("Channel '{0}' unreadable: {1}" -f $ch, $_.Exception.Message)
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'unreadable' `
                    -Reason 'The channel parser failed before records could be observed.' -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel -ParserError $_.Exception.Message -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
            } else {
                $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status 'empty' `
                    -Reason 'No matching error or warning event was observed in the requested window.' -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
            }
            continue
        }

        $events = @($events)
        $isTruncated = ($events.Count -ge $MaxPerChannel)
        if ($isTruncated) { $truncated.Add($ch) | Out-Null }
        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        $observedThisChannel = 0
        $metadataMissing = 0

        foreach ($e in $events) {
            if ($budgetStop) { break }
            $message = $e.Message
            $fallbackMessage = $null
            if ([string]::IsNullOrWhiteSpace($message)) {
                # Provider metadata missing (uninstalled software, or an offline copy).
                # Keep the record - the signature is still valid, the prose just is not.
                $message = '(no message template registered for this provider on this machine)'
                $fallbackMessage = $message
                $metadataMissing++
            }

            $providerLocale = if ($e.PSObject.Properties['ProviderLocale']) { [string]$e.ProviderLocale } elseif ($e.PSObject.Properties['Locale']) { [string]$e.Locale } else { [string]$script:LVUICulture }
            $errorContext = New-LVErrorContext -InputObject $e -Message ([string]$message) -FallbackMessage $fallbackMessage -ProviderLocale $providerLocale
            $structuredData = Get-LVEventStructuredData -EventObject $e

            $estimatedBytes = 256
            if ($message) { $estimatedBytes += [Text.Encoding]::UTF8.GetByteCount([string]$message) }
            if ($structuredData) { $estimatedBytes += [Text.Encoding]::UTF8.GetByteCount(($structuredData | ConvertTo-Json -Depth 5 -Compress)) }
            if ($CollectionBudget -and (([int64]$CollectionBudget.BytesRead + $estimatedBytes) -gt [int64]$CollectionBudget.MaxBytes)) {
                $budgetStop = 'truncated'
                break
            }

            $records.Add([pscustomobject]@{
                Source       = 'event'
                Channel      = $ch
                Provider     = $e.ProviderName
                ProviderId   = if ($e.PSObject.Properties['ProviderId']) { [string]$e.ProviderId } else { $null }
                Id           = [int]$e.Id
                Version      = if ($e.PSObject.Properties['Version'] -and $null -ne $e.Version) { [int]$e.Version } else { $null }
                Task         = if ($e.PSObject.Properties['Task']) { $e.Task } else { $null }
                Opcode       = if ($e.PSObject.Properties['Opcode']) { $e.Opcode } else { $null }
                Level        = [int]$e.Level
                LevelName    = $e.LevelDisplayName
                TimeCreated  = $e.TimeCreated
                MachineName  = $e.MachineName
                RecordId     = $e.RecordId
                Message      = $message.Trim()
                StructuredData = $structuredData
                ResultCode   = $errorContext.ResultCode
                ExtendCode   = $errorContext.ExtendCode
                Phase        = $errorContext.Phase
                Operation    = $errorContext.Operation
                ProviderLocale = $errorContext.ProviderLocale
                FallbackMessage = $errorContext.FallbackMessage
                ErrorContext = $errorContext
            }) | Out-Null
            if ($CollectionBudget) { Add-LVCollectionBudgetUsage -Budget $CollectionBudget -Bytes $estimatedBytes -Records 1 }
            $observedThisChannel++
            $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        }

        $sequenceEvents = @()
        if (-not $levelFilterNeedsSequenceRead) {
            $sequenceEvents = @($events)
        } elseif (-not $isTruncated -and -not $budgetStop) {
            # A second query is only useful when the filtered stream has a candidate
            # gap or ordering anomaly. Healthy filtered ranges cannot produce a
            # sequence note, so avoid doubling every channel read on a normal scan.
            $filteredSequence = @($events | Where-Object {
                $null -ne $_.RecordId -and [string]$_.RecordId -match '^\d+$'
            })
            $needsSequenceValidation = $false
            if ($filteredSequence.Count -ge 2) {
                $filteredOrdered = @($filteredSequence | Sort-Object { [long]$_.RecordId })
                for ($i = 1; $i -lt $filteredOrdered.Count; $i++) {
                    $previous = $filteredOrdered[$i - 1]
                    $current = $filteredOrdered[$i]
                    if (([long]$current.RecordId - [long]$previous.RecordId) -gt 1 -or
                        ($previous.TimeCreated -and $current.TimeCreated -and $current.TimeCreated -lt $previous.TimeCreated)) {
                        $needsSequenceValidation = $true
                        break
                    }
                }
            }

            if (-not $needsSequenceValidation) {
                $sequenceEvents = @($events)
            } else {
                try {
                    # This is metadata for a coverage check, not a second event stream.
                    # Do not spend the shared record budget on it, but treat a cap-sized
                    # result as incomplete so it can never produce a false warning.
                    $sequenceEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $ch; StartTime = $since } `
                        -MaxEvents $MaxPerChannel -ErrorAction Stop)
                    if ($sequenceEvents.Count -ge $MaxPerChannel) {
                        $sequenceIncomplete.Add($ch) | Out-Null
                    }
                } catch {
                    # The filtered event stream remains useful even when the unfiltered
                    # continuity probe is unavailable. Omitting the probe is safer than
                    # presenting a level-filter artefact as a retention gap.
                    $sequenceEvents = @()
                }
            }
        }
        foreach ($sequenceEvent in $sequenceEvents) {
            if ($null -eq $sequenceEvent.RecordId -or [string]$sequenceEvent.RecordId -notmatch '^\d+$') { continue }
            $sequenceRecords.Add([pscustomobject]@{
                Source = 'event'
                Channel = $ch
                RecordId = $sequenceEvent.RecordId
                TimeCreated = $sequenceEvent.TimeCreated
            }) | Out-Null
        }

        if ($budgetStop) { $isTruncated = $true; $truncated.Add($ch) | Out-Null }
        $coverageStatus = if ($budgetStop) { $budgetStop } elseif ($isTruncated) { 'truncated' } elseif ($observedThisChannel -eq 0) { 'empty' } else { 'readable' }
        $coverageReason = if ($budgetStop) {
            ('The shared collection {0} budget stopped this channel; observed records are a lower bound.' -f $budgetStop)
        } elseif ($isTruncated) {
            ('The per-channel record cap of {0} was reached; observed records are a lower bound.' -f $MaxPerChannel)
        } elseif ($observedThisChannel -eq 0) {
            'No matching error or warning event was observed in the requested window.'
        } elseif ($metadataMissing -gt 0) {
            ('{0} record(s) had no provider message template on this machine.' -f $metadataMissing)
        } else { $null }
        $coverage.Add((New-LVCoverageRecord -Source 'event' -Kind 'channel' -Name $ch -Status $coverageStatus `
            -Reason $coverageReason -WindowStart $windowStart -WindowEnd $windowEnd -Cap $MaxPerChannel `
            -ObservedRecords $observedThisChannel -CollectionBudget $CollectionBudget -Origin 'live')) | Out-Null
    }

    if ($total -gt 8) { Write-Progress -Id 2 -Activity 'LogVerdict: reading event channels' -Completed }

    $script:LVDeniedChannel = @($denied.ToArray())
    $script:LVTruncatedChannel = @($truncated.ToArray())
    $script:LVEventCoverage = @($coverage.ToArray())
    $script:LVEventSequence = @($sequenceRecords.ToArray())
    $script:LVEventSequenceIncompleteChannel = @($sequenceIncomplete.ToArray())

    if ($denied.Count -gt 0) {
        Write-LVLog -Level warn -Message ("Access denied on {0} channel(s): {1}. Re-run elevated for full coverage." -f $denied.Count, ($denied -join ', '))
    }
    if ($truncated.Count -gt 0) {
        Write-LVLog -Level warn -Message ("Hit the {0}-record cap on: {1}. Those channels are truncated; narrow -DaysBack or raise -MaxPerChannel for full coverage." -f $MaxPerChannel, ($truncated -join ', '))
    }

    return ConvertTo-LVArrayOutput -Value @($records.ToArray())
}

function Get-LVEventSequenceGap {
    <#
        .SYNOPSIS
        Identify record-id discontinuities and backwards timestamps in event channels.

        .DESCRIPTION
        A cleared, truncated, or tampered log can look healthy because the missing
        records are indistinguishable from silence. This is a coverage signal, not a
        verdict: level filters, retention and concurrent writers can also create gaps,
        so the note names the channel and the observed range without claiming tampering.
        Truncated channels are excluded because their collector cap already explains why
        the sequence is incomplete.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [AllowEmptyCollection()][object[]]$SequenceRecord
    )

    $notes = New-Object System.Collections.Generic.List[string]
    # Callers that have a level-filtered event stream should provide the separate
    # unfiltered sequence range. Direct fixture callers may omit it and use Record
    # itself, preserving the small pure-function contract used by older integrations.
    $sequenceInput = if ($PSBoundParameters.ContainsKey('SequenceRecord')) { @($SequenceRecord) } else { @($Record) }
    $eventRecords = @($sequenceInput | Where-Object {
        $_ -and $_.Source -eq 'event' -and $null -ne $_.RecordId -and
        [string]$_.RecordId -match '^\d+$' -and $_.Channel
    })
    foreach ($group in @($eventRecords | Group-Object Channel)) {
        if (@($script:LVTruncatedChannel) -contains $group.Name -or
            @($script:LVEventSequenceIncompleteChannel) -contains $group.Name) { continue }
        $ordered = @($group.Group | Sort-Object { [long]$_.RecordId })
        if ($ordered.Count -lt 3) { continue }

        $missing = [long]0
        $firstGap = $null
        $lastGap = $null
        $backwards = New-Object System.Collections.Generic.List[string]
        for ($i = 1; $i -lt $ordered.Count; $i++) {
            $previous = $ordered[$i - 1]
            $current = $ordered[$i]
            $delta = [long]$current.RecordId - [long]$previous.RecordId
            if ($delta -gt 1) {
                $missing += $delta - 1
                if ($null -eq $firstGap) { $firstGap = [long]$previous.RecordId }
                $lastGap = [long]$current.RecordId
            }
            if ($previous.TimeCreated -and $current.TimeCreated -and $current.TimeCreated -lt $previous.TimeCreated) {
                $backwards.Add(('{0:yyyy-MM-dd HH:mm:ss} follows {1:yyyy-MM-dd HH:mm:ss} at RecordId {2}->{3}' -f `
                    $current.TimeCreated, $previous.TimeCreated, $previous.RecordId, $current.RecordId)) | Out-Null
            }
        }
        if ($missing -gt 0) {
            $notes.Add(("Event channel '{0}' has a RecordId discontinuity from {1} to {2} ({3} observed IDs missing). Retention, filtering, or log clearing can cause this; treat it as a coverage warning, not proof of tampering." -f `
                $group.Name, $firstGap, $lastGap, $missing)) | Out-Null
        }
        foreach ($backward in @($backwards | Select-Object -First 3)) {
            $notes.Add(("Event channel '{0}' has a backwards timestamp in RecordId order: {1}. This may indicate an out-of-order writer or reconstructed records; inspect the raw log." -f $group.Name, $backward)) | Out-Null
        }
    }
    return ConvertTo-LVArrayOutput -Value @($notes.ToArray())
}
