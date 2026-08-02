function Invoke-LogVerdictScan {
    <#
        .SYNOPSIS
        Scan this PC's logs, deduplicate them, and rule on what is left.

        .DESCRIPTION
        Runs the full pipeline: collect -> reduce -> resolve. Read-only; nothing on the
        machine is modified. Returns a result object that Export-LogVerdictReport renders.
        Use Export-LogVerdictReport -Format Csv for one stable scalar row per finding.

        .PARAMETER DaysBack
        How far back to look, from 1 through 3650 days. Default 30.

        .PARAMETER Channel
        Event channels to read. Defaults to System and Application, which carry almost
        all client-troubleshooting signal.

        .PARAMETER AllChannels
        Sweep every channel on the machine that holds records. Much slower and much
        noisier; use when the default two come back empty but something is clearly wrong.

        .PARAMETER DiagnosticChannels
        Read System and Application plus six focused operational channels for storage,
        code integrity, device setup, packaged apps, memory pressure, and boot security.
        This is broader than the default scan without the noise and delay of AllChannels.

        .PARAMETER SkipTextLogs
        Skip CBS, DISM, SetupAPI and the other plain-text logs.

        .PARAMETER SkipReliability
        Skip Reliability Monitor. That source supplies the software install and removal
        history, which no error-level channel sweep can see.

        .PARAMETER IncludeBenign
        Keep signatures ruled benign in the result. Off by default - the entire point
        is to remove them.

        .PARAMETER EvidencePath
        Analyze a LogVerdict evidence zip, extracted evidence directory, JSON report,
        one .evtx file, or a directory of .evtx files without reading any source on the
        reviewing PC. Captured report signatures preserve non-event evidence.

        .PARAMETER ExplainUnknown
        Opt in to asking a local Ollama model for a separately labelled, non-remedial
        draft explanation of signatures that have no curated rule. Known verdicts are
        never sent and never changed.

        .PARAMETER PromoteToRule
        Accept each safe model candidate into the local verdict file as an inactive
        review draft. Implies ExplainUnknown. Drafts cannot match until a human replaces
        both status unsupported and confidence draft.

        .PARAMETER LocalRulePath
        Override the local draft-rule destination. The default is Data\verdicts.local.json
        from source and verdicts.local.json beside a compiled executable.

        .PARAMETER HistoryPath
        Opt-in local JSON history for bounded per-signature trend analysis. History is
        never read for offline evidence scans and never changes a curated verdict.

        .PARAMETER HistoryWindowDays
        Number of days of prior local history eligible for comparison. Default 30.

        .PARAMETER AdvisoryPath
        Optional offline advisory-cache JSON. Supplying only this path inventories the
        cache; combine it with AdvisoryPackage and AdvisoryVersion to match a package.

        .PARAMETER AdvisoryPackage
        Package name to match in the optional advisory cache, such as PowerShell.

        .PARAMETER AdvisoryVersion
        Package version to test against the optional advisory cache's affected ranges.

        .PARAMETER CaseProfilePath
        Optional validated case profile to attach to the result. The profile records
        collection scope and operator choices for handoff; explicit scan parameters
        remain authoritative and the profile is not used as a verdict input.

        .EXAMPLE
        Invoke-LogVerdictScan -DaysBack 7

        .EXAMPLE
        Invoke-LogVerdictScan -AllChannels -IncludeBenign

        .EXAMPLE
        Invoke-LogVerdictScan -DiagnosticChannels
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 3650)][int]$DaysBack = 30,
        [string[]]$Channel,
        [switch]$AllChannels,
        [switch]$DiagnosticChannels,
        [switch]$SkipTextLogs,
        [switch]$SkipReliability,
        [switch]$IncludeBenign,
        [string]$DatabasePath,
        [string]$EvidencePath,
        [switch]$ExplainUnknown,
        [string]$OllamaModel = 'llama3.2',
        [string]$OllamaEndpoint = 'http://127.0.0.1:11434',
        [switch]$PromoteToRule,
        [string]$LocalRulePath,
        [string]$HistoryPath,
        [ValidateRange(1, 3650)][int]$HistoryWindowDays = 30,
        [string]$AdvisoryPath,
        [string]$AdvisoryPackage,
        [string]$AdvisoryVersion,
        [string]$CaseProfilePath
    )

    $caseProfile = if ($CaseProfilePath) { Read-LVCaseProfile -Path $CaseProfilePath } else { $null }
    if ($EvidencePath) {
        $offlineArgs = @{
            EvidencePath   = $EvidencePath
            Channel        = $Channel
            SkipTextLogs   = $SkipTextLogs
            SkipReliability = $SkipReliability
            IncludeBenign  = $IncludeBenign
            DatabasePath   = $DatabasePath
            ExplainUnknown = $ExplainUnknown
            OllamaModel    = $OllamaModel
            OllamaEndpoint = $OllamaEndpoint
            PromoteToRule  = $PromoteToRule
            LocalRulePath  = $LocalRulePath
        }
        if ($PSBoundParameters.ContainsKey('DaysBack')) { $offlineArgs['DaysBack'] = $DaysBack }
        $offlineResult = Invoke-LVOfflineScan @offlineArgs
        $offlineResult = Add-LVCaseProfileToResult -Result $offlineResult -Profile $caseProfile
        $offlineAdvisory = Get-LVAdvisoryScanContext -Path $AdvisoryPath -Package $AdvisoryPackage -Version $AdvisoryVersion
        return (Add-LVAdvisoryContextToResult -Result $offlineResult -Context $offlineAdvisory)
    }

    $started = Get-Date
    $elevated = Test-LVElevated
    $advisoryContext = Get-LVAdvisoryScanContext -Path $AdvisoryPath -Package $AdvisoryPackage -Version $AdvisoryVersion
    $script:LVReliabilityAvailable = $true
    $script:LVReliabilitySkipReason = $null

    Write-LVLog -Level step -Message ('LogVerdict {0} starting - window {1} day(s)' -f $script:LVVersion, $DaysBack)
    if (-not $elevated) {
        Write-LVLog -Level warn -Message 'Not elevated. The Security channel and some text logs will be skipped; results are incomplete but honest about it.'
    }

    if ($AllChannels -and $DiagnosticChannels) {
        throw 'Choose only one broad channel mode: -AllChannels or -DiagnosticChannels.'
    }

    # A named channel list is the most specific request. Keep it ahead of broad
    # switches so a wrapper can safely pass its defaults alongside an explicit list.
    if ($Channel) {
        $channels = $Channel
    } elseif ($AllChannels) {
        Write-LVLog -Level info -Message 'Enumerating populated channels...'
        $channels = Get-LVPopulatedChannel
        Write-LVLog -Level ok -Message ('{0} channel(s) hold records' -f $channels.Count)
    } elseif ($DiagnosticChannels) {
        $channels = Get-LVDiagnosticChannel
    } else {
        $channels = Get-LVDefaultChannel
    }
    $channelMode = if ($Channel) { 'named' } elseif ($AllChannels) { 'all' } elseif ($DiagnosticChannels) { 'diagnostic' } else { 'default' }

    # Probe before reading. The FilterHashtable path cannot tell a denied channel from
    # an empty one, so coverage has to be established with -LogName first or the scan
    # silently reports "nothing wrong" for channels it was never allowed to open.
    $script:LVChannelMetadataErrorCount = 0
    $script:LVChannelMetadataFailures = @()
    $script:LVDeniedChannel = @()
    $script:LVTruncatedChannel = @()
    $script:LVEventCoverage = @()
    $script:LVTextLogCoverage = @()

    Write-LVLog -Level info -Message ('Probing {0} channel(s) for access and history...' -f @($channels).Count)
    $channelStatus = Get-LVChannelStatus -Channel $channels

    $readable = @($channelStatus.Values | Where-Object { $_.Access -eq 'readable' }).Count
    Write-LVLog -Level info -Message ('Reading {0} readable channel(s)...' -f $readable)
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Get-LVEventRecord -Channel $channels -DaysBack $DaysBack -ChannelStatus $channelStatus)) { $records.Add($r) | Out-Null }
    Write-LVLog -Level ok -Message ('{0} event record(s)' -f $records.Count)
    $sequenceNotes = @(Get-LVEventSequenceGap -Record @($records.ToArray()))
    foreach ($note in $sequenceNotes) { Write-LVLog -Level warn -Message $note }

    $crash = @()
    $setupDiag = $null
    $setupDiagStatus = $null
    $decodedCrashCount = 0
    if (-not $SkipTextLogs) {
        Write-LVLog -Level info -Message 'Reading plain-text logs...'
        foreach ($r in (Get-LVTextLogRecord -DaysBack $DaysBack)) { $records.Add($r) | Out-Null }

        $setupDiag = Get-LVSetupDiagRecord -DaysBack $DaysBack
        foreach ($r in @($setupDiag.Records | Where-Object { $_ })) { $records.Add($r) | Out-Null }
        # Records are merged into the ordinary pipeline above. Keep only execution
        # status in the public result so raw SetupDiag evidence is not duplicated in
        # JSON (and cannot bypass the finding redaction path on export).
        $setupDiagStatus = [pscustomobject]@{}
        foreach ($property in $setupDiag.PSObject.Properties) {
            if ($property.Name -ne 'Records') {
                $setupDiagStatus | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
            }
        }

        $crash = @(Get-LVCrashArtifact -DaysBack ([Math]::Max($DaysBack, 90)))
        $decodedCrashCount = @($crash | Where-Object { $_.Decoded }).Count
        $scanCutoff = $started.AddDays(-1 * [Math]::Abs($DaysBack))
        foreach ($artifact in $crash) {
            if ($artifact.When -lt $scanCutoff) { continue }
            $record = ConvertTo-LVCrashRecord -Artifact $artifact
            if ($record) { $records.Add($record) | Out-Null }
        }
        if ($crash.Count -gt 0) {
            Write-LVLog -Level warn -Message ('{0} crash artifact(s) on disk; decoded header metadata from {1}' -f $crash.Count, $decodedCrashCount)
        } else {
            Write-LVLog -Level info -Message 'No readable Report.wer or kernel minidump was present; the crash-artifact source was skipped, not treated as clean.'
        }
    }

    $stability = $null
    if (-not $SkipReliability) {
        Write-LVLog -Level info -Message 'Reading Reliability Monitor...'
        # Handed the records collected so far so it can drop anything already seen in a
        # channel. Order matters: this has to run after the channel and text-log reads.
        $reliabilityRecords = @(Get-LVReliabilityRecord -DaysBack $DaysBack -ExistingRecord @($records.ToArray()))
        foreach ($r in $reliabilityRecords) {
            $records.Add($r) | Out-Null
        }
        $stability = Get-LVStabilityTrend -DaysBack $DaysBack
        if ($stability) {
            Write-LVLog -Level info -Message ('System stability index {0}/10, {1} over the window (low {2})' -f $stability.Current, $stability.Direction, $stability.Lowest)
        }
    } else {
        $reliabilityRecords = @()
    }

    $all = @($records.ToArray())
    Write-LVLog -Level info -Message ('Reducing {0} record(s) to signatures...' -f $all.Count)
    $grouped = Get-LVSignatureReduction -Record $all -WindowDays $DaysBack
    $signatures = @($grouped.Signatures)
    $stat = Get-LVReductionStat -Record $all -Signature $signatures `
        -InitialSignatureCount $grouped.InitialSignatureCount -PromotedSlotCount $grouped.PromotedSlotCount
    Write-LVLog -Level ok -Message ('Masked pass: {0} signature(s), {1}:1 reduction; low-cardinality slot pass: {2} signature(s), {3}:1 reduction ({4} slot(s) promoted)' -f `
        $stat.InitialSignatureCount, $stat.InitialRatio, $stat.SignatureCount, $stat.Ratio, $stat.PromotedSlotCount)

    $db = Get-LogVerdictDatabase -Path $DatabasePath
    Write-LVLog -Level info -Message ('Applying {0} rule(s) from the verdict database...' -f @($db.rules).Count)
    $findings = Resolve-LVVerdict -Signature $signatures -Database $db

    # Correlate BEFORE benign suppression. A benign signature is still perfectly good
    # evidence of when something happened, and dropping it here would silently break any
    # pairing that involves one - the correlation would stop firing for a reason nothing
    # in the output could explain.
    $correlations = @(Resolve-LVCorrelation -Finding @($findings) -Database $db)
    if ($correlations.Count -gt 0) {
        Write-LVLog -Level warn -Message ('{0} correlated finding(s): signatures that occurred together and mean more than they do apart' -f $correlations.Count)
    }

    if (-not $IncludeBenign) {
        $before = @($findings).Count
        $findings = @($findings | Where-Object { $_.Verdict -ne 'benign' })
        $removed = $before - @($findings).Count
        if ($removed -gt 0) {
            Write-LVLog -Level ok -Message ('{0} signature(s) ruled benign and suppressed (use -IncludeBenign to see them)' -f $removed)
        }
    }

    $modelRequested = [bool]($ExplainUnknown -or $PromoteToRule)
    $promotedDrafts = @()
    if ($modelRequested) {
        Write-LVLog -Level info -Message ('Requesting non-remedial draft explanations for unknown signatures from local Ollama model {0}...' -f $OllamaModel)
        $findings = @(Add-LVModelExplanation -Finding @($findings) -Model $OllamaModel -Endpoint $OllamaEndpoint)
    }
    if ($PromoteToRule) {
        $accepted = @($findings | Where-Object { $_.PSObject.Properties['ModelExplanation'] -and $_.ModelExplanation })
        if ($accepted.Count -eq 0) {
            Write-LVLog -Level warn -Message 'No safe model candidates were available to promote; the local rule file was not changed.'
        } else {
            $promotedDrafts = @(Write-LVModelDraftRule -Finding $accepted -Path $LocalRulePath -MachineName $env:COMPUTERNAME)
        }
    }

    # Local history is deliberately updated after curated resolution, benign
    # suppression, and optional model annotation. It reports change around the
    # current result; it is never an input to verdicts, correlations, or exit codes.
    $history = Update-LVScanHistory -Path $HistoryPath -Finding @($findings) -ScanTime $started `
        -DaysBack $DaysBack -RecordCount $all.Count -SignatureCount $signatures.Count -WindowDays $HistoryWindowDays
    if ($history.Status -eq 'unreadable') {
        Write-LVLog -Level warn -Message 'Local history was unreadable and was not overwritten; trend status is advisory only.'
    } elseif ($history.Persistence -eq 'write-failed') {
        Write-LVLog -Level warn -Message 'Local history could not be saved; scan findings and verdicts are unchanged.'
    } elseif (@($history.Signals).Count -gt 0) {
        Write-LVLog -Level info -Message ('{0} advisory local trend signal(s); no verdict was escalated.' -f @($history.Signals).Count)
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
    foreach ($note in $sequenceNotes) { $coverageNotes.Add($note) | Out-Null }
    if (-not $elevated) {
        $coverageNotes.Add('Scan ran without elevation. The Security channel and some text logs require administrator rights.') | Out-Null
    }
    if ($setupDiagStatus -and $setupDiagStatus.PSObject.Properties['CoverageNote'] -and $setupDiagStatus.CoverageNote) {
        $coverageNotes.Add([string]$setupDiagStatus.CoverageNote) | Out-Null
    }
    if ($SkipReliability) {
        $coverageNotes.Add('Reliability Monitor was skipped by request, so the software install and removal history was not read.') | Out-Null
    } elseif (-not $script:LVReliabilityAvailable) {
        $coverageNotes.Add(('Reliability Monitor could not be read, so the software install and removal history is missing from this scan. It is Group Policy gated and disabled by default on Windows Server. Reason: {0}' -f $script:LVReliabilitySkipReason)) | Out-Null
    }
    if ($SkipTextLogs) {
        $coverageNotes.Add('Plain-text logs and crash artifacts were skipped by request, so Report.wer and minidump headers were not checked.') | Out-Null
    } elseif ($crash.Count -eq 0) {
        $coverageNotes.Add('No readable Report.wer or kernel minidump was present in the 90-day crash inventory. That source was absent or empty, not a clean-health signal.') | Out-Null
    } elseif ($decodedCrashCount -eq 0) {
        $coverageNotes.Add('Crash artifacts were inventoried, but none contained supported readable header metadata. They remain available by path and were not interpreted as health.') | Out-Null
    }

    $coverageSources = New-Object System.Collections.Generic.List[object]
    foreach ($entry in @($script:LVEventCoverage) + @($script:LVTextLogCoverage)) {
        if ($entry) { $coverageSources.Add($entry) | Out-Null }
    }
    if ($script:LVChannelMetadataErrorCount -gt 0) {
        $coverageSources.Add((New-LVCoverageRecord -Source 'event' -Kind 'metadata' -Name 'channel enumeration' -Status 'not-observed' `
            -Reason 'Channel metadata could not be read, so those channels were not enumerated.' `
            -ParserError (($script:LVChannelMetadataFailures | Where-Object { $_ }) -join ' | ') -Origin 'live')) | Out-Null
    }
    foreach ($note in $sequenceNotes) {
        $match = [regex]::Match([string]$note, "^Event channel '([^']+)' has")
        if ($match.Success) {
            $coverageEntry = @($coverageSources | Where-Object { $_.Source -eq 'event' -and $_.Name -eq $match.Groups[1].Value } | Select-Object -First 1)
            if ($coverageEntry.Count -eq 1) { $coverageEntry[0].RecordGap = [string]$note }
        }
    }
    if ($setupDiagStatus) {
        $setupStatus = if ($setupDiagStatus.Status -in @('absent', 'no-recent-logs', 'untrusted')) { 'not-observed' } elseif ($setupDiagStatus.Status -in @('execution-failed', 'requires-elevation', 'invalid-output', 'no-output')) { 'unreadable' } else { 'readable' }
        $coverageSources.Add((New-LVCoverageRecord -Source 'SetupDiag' -Kind 'tool' -Name 'SetupDiag' -Status $setupStatus `
            -Reason ([string]$setupDiagStatus.Message) -Path $setupDiagStatus.ExecutablePath -WindowStart $cutoff -WindowEnd $started `
            -ObservedRecords @($setupDiag.Records).Count -ParserError $(if ($setupStatus -eq 'unreadable') { [string]$setupDiagStatus.Message } else { $null }) -Origin 'live')) | Out-Null
    }
    $reliabilityStatus = if ($SkipReliability) { 'not-observed' } elseif (-not $script:LVReliabilityAvailable) { 'unreadable' } elseif (@($reliabilityRecords).Count -eq 0) { 'empty' } else { 'readable' }
    $coverageSources.Add((New-LVCoverageRecord -Source 'reliability' -Kind 'provider' -Name 'Reliability Monitor' -Status $reliabilityStatus `
        -Reason $(if ($SkipReliability) { 'Skipped by request.' } elseif (-not $script:LVReliabilityAvailable) { [string]$script:LVReliabilitySkipReason } elseif (@($reliabilityRecords).Count -eq 0) { 'No reliability records were observed in the requested window.' } else { $null }) `
        -WindowStart $cutoff -WindowEnd $started -ObservedRecords @($reliabilityRecords).Count -Origin 'live')) | Out-Null
    $coverageSources.Add((New-LVCoverageRecord -Source 'crash' -Kind 'directory' -Name 'WER and minidump inventory' `
        -Status $(if ($SkipTextLogs) { 'not-observed' } elseif ($crash.Count -eq 0) { 'empty' } else { 'readable' }) `
        -Reason $(if ($SkipTextLogs) { 'Skipped by request.' } elseif ($crash.Count -eq 0) { 'No readable crash artifact was observed in the inventory window.' } else { $null }) `
        -WindowStart $started.AddDays(-1 * [Math]::Max($DaysBack, 90)) -WindowEnd $started -ObservedRecords $crash.Count -Origin 'live')) | Out-Null

    $healthProfiles = @()
    try {
        $healthProfiles = @(Get-LVHealthProfile -EventRecord @($records.ToArray()) -ChannelStatus $channelStatus `
            -WindowStart $cutoff -WindowEnd $started)
    } catch {
        Write-LVLog -Level warn -Message ("Configuration-health profiles could not be collected: {0}" -f $_.Exception.Message)
        $healthProfiles = @((New-LVHealthProfile -Profile 'configuration-health' -Source 'health' -Name 'configuration profiles' `
            -Status 'unreadable' -RequiredConfiguration 'Provider, policy, retention, and forwarding state should be reviewed when diagnostic coverage matters.' `
            -ObservedConfiguration 'The health-profile collector failed before all profiles were available.' `
            -Reason $_.Exception.Message -Advice 'Review configuration health separately; this is not a maliciousness verdict.' -Origin 'live'))
    }

    # Precomputed here so callers (including the entry script) never need a private helper.
    # Correlations count toward the worst verdict: a pairing that is graver than either
    # of its parts is the whole reason it exists, and an exit code that ignored it would
    # under-report the machine.
    $worst = 'benign'
    foreach ($f in @($findings) + @($correlations)) {
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
        Coverage       = @($coverageSources.ToArray())
        HealthProfiles = @($healthProfiles)
        Reduction      = $stat
        Findings       = @($findings)
        Correlations   = @($correlations)
        CrashArtifacts = @($crash)
        SetupDiag      = $setupDiagStatus
        Horizon        = $horizon
        HorizonWarning = $horizonWarning
        Stability      = $stability
        ReliabilityAvailable = [bool]$script:LVReliabilityAvailable
        DatabaseName   = $db.name
        DatabaseDate   = $db.updated
        RuleCount      = @($db.rules).Count
        ScanOptions    = [ordered]@{
            channelMode = $channelMode
            channels = @($channels)
            allChannels = [bool]$AllChannels
            diagnosticChannels = [bool]$DiagnosticChannels
            skipTextLogs = [bool]$SkipTextLogs
            skipReliability = [bool]$SkipReliability
            includeBenign = [bool]$IncludeBenign
            explainUnknown = [bool]$ExplainUnknown
            promoteToRule = [bool]$PromoteToRule
            evidencePath = $false
        }
        CaseProfile    = $caseProfile
        ModelExplanationsEnabled = $modelRequested
        ModelExplanationCount = @($findings | Where-Object { $_.PSObject.Properties['ModelExplanation'] -and $_.ModelExplanation }).Count
        PromotedDraftRules = @($promotedDrafts)
        History        = $history
        AdvisoryStatus = $advisoryContext.Status
        AdvisoryCache  = $advisoryContext.Cache
        Advisories     = @($advisoryContext.Records)
        WorstVerdict   = $worst
        ExitCode       = $exitCode
    }
}
