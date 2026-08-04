# Versioned machine-interchange adapters. The normalized model is deliberately built
# before a standards projection so each adapter preserves the same evidence contract.

$script:LVStandardExportVersion = '1.0.0'

function ConvertTo-LVStandardTimestamp {
    param([AllowNull()]$Value)

    return ConvertTo-LVUtcTimestamp -Value $Value
}

function ConvertTo-LVStandardUnixMillisecond {
    param([AllowNull()]$Value)

    $timestamp = ConvertTo-LVStandardTimestamp -Value $Value
    if (-not $timestamp) { return $null }
    return [DateTimeOffset]::Parse($timestamp).ToUnixTimeMilliseconds()
}

function Get-LVStandardReference {
    param([Parameter(Mandatory)]$Finding)

    $references = New-Object System.Collections.Generic.List[string]
    foreach ($reference in @($Finding.Reference) + @($Finding.References)) {
        if ($reference -and -not $references.Contains([string]$reference)) { $references.Add([string]$reference) | Out-Null }
    }
    foreach ($source in @($Finding.Sources | Where-Object { $_ })) {
        if ($source.uri -and -not $references.Contains([string]$source.uri)) { $references.Add([string]$source.uri) | Out-Null }
    }
    return @($references.ToArray())
}

function ConvertTo-LVStandardCoverage {
    param([AllowNull()][object[]]$Coverage)

    foreach ($source in @($Coverage | Where-Object { $_ })) {
        [pscustomobject][ordered]@{
            source = $source.Source
            kind = $source.Kind
            name = $source.Name
            status = $source.Status
            reason = $source.Reason
            path = $source.Path
            windowStart = ConvertTo-LVStandardTimestamp $source.WindowStart
            windowEnd = ConvertTo-LVStandardTimestamp $source.WindowEnd
            cap = $source.Cap
            observedRecords = $source.ObservedRecords
            skippedRecords = $source.SkippedRecords
            recordGap = $source.RecordGap
            parserError = $source.ParserError
            sizeBytes = $source.SizeBytes
            parseMilliseconds = $source.ParseMilliseconds
            sha256 = $source.SHA256
            origin = $source.Origin
            pollCount = if ($source.PSObject.Properties['PollCount']) { $source.PollCount } else { $null }
            pollErrors = if ($source.PSObject.Properties['PollErrors']) { $source.PollErrors } else { $null }
            reconnectCount = if ($source.PSObject.Properties['ReconnectCount']) { $source.ReconnectCount } else { $null }
            droppedRecords = if ($source.PSObject.Properties['DroppedRecords']) { $source.DroppedRecords } else { $null }
            averageLatencyMilliseconds = if ($source.PSObject.Properties['AverageLatencyMilliseconds']) { $source.AverageLatencyMilliseconds } else { $null }
            maxLatencyMilliseconds = if ($source.PSObject.Properties['MaxLatencyMilliseconds']) { $source.MaxLatencyMilliseconds } else { $null }
        }
    }
}

function ConvertTo-LVStandardHealth {
    param([AllowNull()][object[]]$HealthProfiles)

    foreach ($health in @($HealthProfiles | Where-Object { $_ })) {
        [pscustomobject][ordered]@{
            profile = $health.Profile
            source = $health.Source
            name = $health.Name
            status = $health.Status
            requiredConfiguration = $health.RequiredConfiguration
            observedConfiguration = $health.ObservedConfiguration
            enabledEventIds = @($health.EnabledEventIds)
            filteredEventIds = @($health.FilteredEventIds)
            provider = $health.Provider
            providerId = $health.ProviderId
            channel = $health.Channel
            eventIds = @($health.EventIds)
            eventVersions = @($health.EventVersions)
            metadataStatus = $health.MetadataStatus
            readExistingEvents = $health.ReadExistingEvents
            heartbeatIntervalSeconds = $health.HeartbeatIntervalSeconds
            bookmarkState = $health.BookmarkState
            retentionMode = $health.RetentionMode
            recordCount = $health.RecordCount
            oldestRecord = ConvertTo-LVStandardTimestamp $health.OldestRecord
            maximumSizeBytes = $health.MaximumSizeBytes
            clockOffsetMinutes = $health.ClockOffsetMinutes
            reason = $health.Reason
            advice = $health.Advice
            path = $health.Path
            origin = $health.Origin
            pollErrors = if ($health.PSObject.Properties['PollErrors']) { $health.PollErrors } else { $null }
            reconnectCount = if ($health.PSObject.Properties['ReconnectCount']) { $health.ReconnectCount } else { $null }
            droppedRecords = if ($health.PSObject.Properties['DroppedRecords']) { $health.DroppedRecords } else { $null }
            averageLatencyMilliseconds = if ($health.PSObject.Properties['AverageLatencyMilliseconds']) { $health.AverageLatencyMilliseconds } else { $null }
            maxLatencyMilliseconds = if ($health.PSObject.Properties['MaxLatencyMilliseconds']) { $health.MaxLatencyMilliseconds } else { $null }
        }
    }
}

function ConvertTo-LVStandardPerformance {
    param([AllowNull()][object[]]$Performance)

    foreach ($metric in @($Performance | Where-Object { $_ })) {
        [pscustomobject][ordered]@{
            schemaVersion = $metric.SchemaVersion
            source = $metric.Source
            kind = $metric.Kind
            name = $metric.Name
            status = $metric.Status
            observedRecords = $metric.ObservedRecords
            skippedRecords = $metric.SkippedRecords
            cap = $metric.Cap
            elapsedMilliseconds = $metric.ElapsedMilliseconds
            slow = [bool]$metric.Slow
            slowThresholdMilliseconds = $metric.SlowThresholdMilliseconds
            origin = $metric.Origin
        }
    }
}

function ConvertTo-LVStandardFinding {
    param([Parameter(Mandatory)]$Finding)

    $first = ConvertTo-LVStandardTimestamp $Finding.FirstSeen
    $last = ConvertTo-LVStandardTimestamp $Finding.LastSeen
    $eventRecord = [ordered]@{
        source = $Finding.Source
        channel = $Finding.Channel
        provider = $Finding.Provider
        providerId = if ($Finding.PSObject.Properties['ProviderId']) { $Finding.ProviderId } else { $null }
        eventId = $Finding.Id
        eventVersion = if ($Finding.PSObject.Properties['Version']) { $Finding.Version } else { $null }
        task = if ($Finding.PSObject.Properties['Task']) { $Finding.Task } else { $null }
        opcode = if ($Finding.PSObject.Properties['Opcode']) { $Finding.Opcode } else { $null }
        count = $Finding.Count
        recordId = if ($Finding.PSObject.Properties['RecordId']) { $Finding.RecordId } else { $null }
        recordIds = if ($Finding.PSObject.Properties['RecordIds']) { @($Finding.RecordIds) } else { @() }
        firstObserved = $first
        lastObserved = $last
        messageSamples = @($Finding.Samples)
    }
    return [pscustomobject][ordered]@{
        key = $Finding.Key
        title = $Finding.Title
        verdict = $Finding.Verdict
        confidence = $Finding.Confidence
        ruleId = $Finding.RuleId
        plain = $Finding.Plain
        why = $Finding.Why
        action = $Finding.Action
        errorCode = $Finding.ErrorCode
        errorCatalogKind = $Finding.ErrorCatalogKind
        errorName = $Finding.ErrorName
        errorPhase = $Finding.ErrorPhase
        errorOperation = $Finding.ErrorOperation
        errorContext = [pscustomobject][ordered]@{
            resultCode = $Finding.ResultCode
            extendCode = $Finding.ExtendCode
            phase = $Finding.Phase
            operation = $Finding.Operation
            providerLocale = $Finding.ProviderLocale
            fallbackMessage = $Finding.FallbackMessage
        }
        references = @(Get-LVStandardReference -Finding $Finding)
        event = [pscustomobject]$eventRecord
        burst = if ($Finding.PSObject.Properties['Burst']) { [bool]$Finding.Burst } else { $false }
        burstOnset = if ($Finding.PSObject.Properties['BurstOnset']) { ConvertTo-LVStandardTimestamp $Finding.BurstOnset } else { $null }
        burstCount = if ($Finding.PSObject.Properties['BurstCount']) { $Finding.BurstCount } else { $null }
        burstWindowMinutes = if ($Finding.PSObject.Properties['BurstWindowMinutes']) { $Finding.BurstWindowMinutes } else { $null }
    }
}

function ConvertTo-LVStandardAdvisory {
    param([Parameter(Mandatory)]$Advisory)

    return [pscustomobject][ordered]@{
        recordType    = 'advisory'
        findingType   = 'dependency-advisory'
        matched       = [bool]$Advisory.Matched
        id            = $Advisory.Id
        ecosystem     = $Advisory.Ecosystem
        package       = $Advisory.Package
        version       = $Advisory.Version
        affectedRange = $Advisory.AffectedRange
        fixedVersion  = $Advisory.FixedVersion
        cvss          = $Advisory.CVSS
        cvssVector    = $Advisory.CVSSVector
        kev           = $Advisory.KEV
        kevDate       = $Advisory.KEVDate
        publishedDate = $Advisory.PublishedDate
        modifiedDate  = $Advisory.ModifiedDate
        source        = $Advisory.Source
        sourceUri     = $Advisory.SourceUri
        sourceHash    = $Advisory.SourceHash
        title         = $Advisory.Title
        description   = $Advisory.Description
    }
}

function ConvertTo-LVStandardHistory {
    param([AllowNull()]$History)

    if ($null -eq $History) { return $null }
    return [pscustomobject][ordered]@{
        enabled             = if ($History.PSObject.Properties['Enabled']) { [bool]$History.Enabled } else { $false }
        status              = $History.Status
        persistence         = $History.Persistence
        entriesStored       = $History.EntriesStored
        advisoryOnly        = [bool]$History.AdvisoryOnly
        windowDays          = $History.WindowDays
        baseline            = [pscustomobject][ordered]@{
            method      = $History.Baseline.Method
            sampleCount = $History.Baseline.SampleCount
            scanTimes   = @($History.Baseline.ScanTimes | ForEach-Object { ConvertTo-LVStandardTimestamp $_ })
        }
        threshold           = [pscustomobject][ordered]@{
            relativeIncrease = $History.Threshold.RelativeIncrease
            absolutePerDay   = $History.Threshold.AbsolutePerDay
            description      = $History.Threshold.Description
        }
        signals             = @($History.Signals | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{
                type          = $_.Type
                key           = $_.Key
                beforeRate    = $_.BeforeRate
                afterRate     = $_.AfterRate
                beforeVerdict = $_.BeforeVerdict
                afterVerdict  = $_.AfterVerdict
                reason        = $_.Reason
            }
        })
        falsePositiveCaveat = $History.FalsePositiveCaveat
    }
}

function Get-LVStandardContext {
    param([Parameter(Mandatory)]$Result)

    $redacted = [bool]($Result.PSObject.Properties['Redacted'] -and $Result.Redacted)
    $scanStart = ConvertTo-LVStandardTimestamp $Result.ScanTime
    $scanEnd = if ($Result.ScanTime -and $Result.Duration) { ConvertTo-LVStandardTimestamp ([datetime]$Result.ScanTime + $Result.Duration) } else { $scanStart }
    $windowStart = if ($Result.ScanTime -and $Result.DaysBack) { ConvertTo-LVStandardTimestamp ([datetime]$Result.ScanTime).AddDays(-1 * [Math]::Abs([int]$Result.DaysBack)) } else { $null }
    $machine = if ($redacted) { '<MACHINE>' } else { [string]$Result.MachineName }
    return [pscustomobject][ordered]@{
        schemaVersion = $script:LVStandardExportVersion
        generatedAt = ConvertTo-LVStandardTimestamp (Get-Date)
        privacy = [pscustomobject][ordered]@{
            redacted = $redacted
            rawEvidenceIncluded = (-not $redacted)
            identifiersMasked = $redacted
        }
        scan = [pscustomobject][ordered]@{
            tool = 'LogVerdict'
            version = $Result.Version
            machine = $machine
            started = $scanStart
            completed = $scanEnd
            windowStart = $windowStart
            windowEnd = $scanStart
            daysBack = $Result.DaysBack
            elevated = $Result.Elevated
            channels = @($Result.Channels)
            worstVerdict = $Result.WorstVerdict
            exitCode = $Result.ExitCode
            performanceTelemetry = if ($Result.PSObject.Properties['PerformanceTelemetry']) { [bool]$Result.PerformanceTelemetry } else { $false }
            performance = @(ConvertTo-LVStandardPerformance -Performance $(if ($Result.PSObject.Properties['Performance']) { $Result.Performance } else { @() }))
        }
        coverage = @(ConvertTo-LVStandardCoverage -Coverage @($Result.Coverage))
        healthProfiles = @(ConvertTo-LVStandardHealth -HealthProfiles @($Result.HealthProfiles))
        history = ConvertTo-LVStandardHistory -History $(if ($Result.PSObject.Properties['History']) { $Result.History } else { $null })
        caseProfile = if ($Result.PSObject.Properties['CaseProfile'] -and $Result.CaseProfile) { $Result.CaseProfile } else { $null }
        providerExtensions = @(if ($Result.PSObject.Properties['ProviderExtensions']) { $Result.ProviderExtensions } else { @() })
        providerProjections = @(if ($Result.PSObject.Properties['ProviderProjections']) { $Result.ProviderProjections } else { @() })
        advisories = [pscustomobject][ordered]@{
            status = if ($Result.PSObject.Properties['AdvisoryStatus']) { $Result.AdvisoryStatus } else { 'not-requested' }
            cache = if ($Result.PSObject.Properties['AdvisoryCache']) { $Result.AdvisoryCache } else { $null }
        }
    }
}

function Get-LVStandardModel {
    param([Parameter(Mandatory)]$Result)

    return [pscustomobject][ordered]@{
        context = Get-LVStandardContext -Result $Result
        findings = @($Result.Findings | Where-Object { $_ } | ForEach-Object { ConvertTo-LVStandardFinding -Finding $_ })
        advisories = @($Result.Advisories | Where-Object { $_ } | ForEach-Object { ConvertTo-LVStandardAdvisory -Advisory $_ })
        correlations = @($Result.Correlations | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{
                id = $_.Id; type = $_.Type; verdict = $_.Verdict; title = $_.Title
                plain = $_.Plain; why = $_.Why; action = $_.Action
                references = @($_.References)
                involvedKeys = @($_.InvolvedKeys)
                windows = @($_.Windows | ForEach-Object {
                    [pscustomobject][ordered]@{ start = ConvertTo-LVStandardTimestamp $_.Start; end = ConvertTo-LVStandardTimestamp $_.End; occurrenceCount = @($_.Occurrences).Count }
                })
            }
        })
    }
}

function ConvertTo-LVTimelineLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$RecordType,
        [AllowNull()]$Payload,
        [switch]$Redact
    )

    $redacted = [bool]($Redact -or ($Result.PSObject.Properties['Redacted'] -and $Result.Redacted))
    $scanStart = ConvertTo-LVStandardTimestamp $Result.ScanTime
    $scanEnd = if ($Result.ScanTime -and $Result.Duration) {
        ConvertTo-LVStandardTimestamp ([datetime]$Result.ScanTime + $Result.Duration)
    } else { $scanStart }
    $machine = if ($redacted) { '<MACHINE>' } else { [string]$Result.MachineName }
    $scan = [pscustomobject][ordered]@{
        tool = 'LogVerdict'
        version = [string]$Result.Version
        machine = $machine
        started = $scanStart
        completed = $scanEnd
        windowStart = if ($Result.ScanTime -and $Result.DaysBack) {
            ConvertTo-LVStandardTimestamp ([datetime]$Result.ScanTime).AddDays(-1 * [Math]::Abs([int]$Result.DaysBack))
        } else { $null }
        windowEnd = $scanStart
        daysBack = $Result.DaysBack
        elevated = $Result.Elevated
        worstVerdict = $Result.WorstVerdict
        exitCode = $Result.ExitCode
        caseProfileId = if ($Result.PSObject.Properties['CaseProfile'] -and $Result.CaseProfile) { [string]$Result.CaseProfile.profileId } else { $null }
    }
    $line = [ordered]@{
        schemaVersion = $script:LVStandardExportVersion
        recordType = $RecordType
        privacy = [pscustomobject][ordered]@{
            state = if ($redacted) { 'redacted' } else { 'raw' }
            redacted = $redacted
            rawEvidenceIncluded = (-not $redacted)
        }
        scan = $scan
    }
    if ($Payload) {
        $properties = if ($Payload -is [System.Collections.IDictionary]) {
            @($Payload.GetEnumerator())
        } else {
            @($Payload.PSObject.Properties | ForEach-Object {
                [pscustomobject]@{ Key = $_.Name; Value = $_.Value }
            })
        }
        foreach ($property in $properties) { $line[[string]$property.Key] = $property.Value }
    }
    return [pscustomobject]$line
}

function Get-LVTimelineLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [switch]$Redact
    )

    $started = ConvertTo-LVStandardTimestamp $Result.ScanTime
    $metadata = [ordered]@{
        format = 'LogVerdict.Timeline'
        recordKinds = @('metadata', 'event', 'finding', 'correlation', 'coverage', 'provider')
        timestampUtc = $started
    }
    ConvertTo-LVTimelineLine -Result $Result -RecordType 'metadata' -Payload $metadata -Redact:$Redact

    foreach ($finding in @($Result.Findings | Where-Object { $_ } | Sort-Object FirstSeen, Source, Channel, Provider, Id, Key)) {
        $first = ConvertTo-LVStandardTimestamp $finding.FirstSeen
        $last = ConvertTo-LVStandardTimestamp $finding.LastSeen
        $samples = @($finding.Samples | Where-Object { $null -ne $_ })
        $message = if ($samples.Count -gt 0) { [string]$samples[0] } else { [string]$finding.SampleMessage }
        $eventPayload = [ordered]@{
            timestamp = ConvertTo-LVStandardUnixMillisecond $finding.FirstSeen
            timestampUtc = $first
            source = [string]$finding.Source
            channel = [string]$finding.Channel
            provider = [string]$finding.Provider
            providerId = if ($finding.PSObject.Properties['ProviderId']) { [string]$finding.ProviderId } else { $null }
            eventId = $finding.Id
            recordId = if ($finding.PSObject.Properties['RecordId']) { $finding.RecordId } else { $null }
            recordIds = if ($finding.PSObject.Properties['RecordIds']) { @($finding.RecordIds) } else { @() }
            firstObserved = $first
            lastObserved = $last
            message = $message
            messageSamples = $samples
            structuredData = if ($finding.PSObject.Properties['StructuredData']) { $finding.StructuredData } else { $null }
            findingKey = [string]$finding.Key
        }
        ConvertTo-LVTimelineLine -Result $Result -RecordType 'event' -Payload $eventPayload -Redact:$Redact

        $findingPayload = [ordered]@{
            timestamp = ConvertTo-LVStandardUnixMillisecond $finding.FirstSeen
            timestampUtc = $first
            source = [string]$finding.Source
            channel = [string]$finding.Channel
            provider = [string]$finding.Provider
            providerId = if ($finding.PSObject.Properties['ProviderId']) { [string]$finding.ProviderId } else { $null }
            eventId = $finding.Id
            recordId = if ($finding.PSObject.Properties['RecordId']) { $finding.RecordId } else { $null }
            recordIds = if ($finding.PSObject.Properties['RecordIds']) { @($finding.RecordIds) } else { @() }
            firstObserved = $first
            lastObserved = $last
            findingKey = [string]$finding.Key
            title = [string]$finding.Title
            verdict = [string]$finding.Verdict
            confidence = [string]$finding.Confidence
            count = $finding.Count
            perDay = $finding.PerDay
            ruleId = if ($finding.PSObject.Properties['RuleId']) { $finding.RuleId } else { $null }
            plain = [string]$finding.Plain
            why = [string]$finding.Why
            action = [string]$finding.Action
            references = @(Get-LVStandardReference -Finding $finding)
            provenance = [pscustomobject][ordered]@{
                ruleId = if ($finding.PSObject.Properties['RuleId']) { $finding.RuleId } else { $null }
                confidence = [string]$finding.Confidence
                status = if ($finding.PSObject.Properties['Status']) { $finding.Status } else { $null }
                references = @(Get-LVStandardReference -Finding $finding)
                sources = if ($finding.PSObject.Properties['Sources']) { @($finding.Sources) } else { @() }
                providerExtension = if ($finding.PSObject.Properties['ProviderExtension']) { $finding.ProviderExtension } else { $null }
            }
        }
        ConvertTo-LVTimelineLine -Result $Result -RecordType 'finding' -Payload $findingPayload -Redact:$Redact
    }

    foreach ($correlation in @($Result.Correlations | Where-Object { $_ } | Sort-Object Id)) {
        $windows = @($correlation.Windows | Where-Object { $_ })
        $firstWindow = $windows | Select-Object -First 1
        $lastWindow = $windows | Select-Object -Last 1
        $correlationPayload = [ordered]@{
            timestamp = ConvertTo-LVStandardUnixMillisecond $firstWindow.Start
            timestampUtc = ConvertTo-LVStandardTimestamp $firstWindow.Start
            endTimestampUtc = ConvertTo-LVStandardTimestamp $lastWindow.End
            correlationId = [string]$correlation.Id
            type = [string]$correlation.Type
            timespan = [string]$correlation.Timespan
            verdict = [string]$correlation.Verdict
            title = [string]$correlation.Title
            plain = [string]$correlation.Plain
            why = [string]$correlation.Why
            action = [string]$correlation.Action
            confidence = [string]$correlation.Confidence
            ruleIds = @($correlation.RuleIds)
            involvedKeys = @($correlation.InvolvedKeys)
            occurrenceCount = $correlation.OccurrenceCount
            references = @($correlation.References)
            windows = @($windows | ForEach-Object {
                [pscustomobject][ordered]@{
                    start = ConvertTo-LVStandardTimestamp $_.Start
                    end = ConvertTo-LVStandardTimestamp $_.End
                    occurrenceCount = @($_.Occurrences).Count
                }
            })
            provenance = [pscustomobject][ordered]@{
                ruleIds = @($correlation.RuleIds)
                references = @($correlation.References)
                sources = @($correlation.Sources)
            }
        }
        ConvertTo-LVTimelineLine -Result $Result -RecordType 'correlation' -Payload $correlationPayload -Redact:$Redact
    }

    foreach ($source in @($Result.Coverage | Where-Object { $_ } | Sort-Object Source, Kind, Name)) {
        $coveragePayload = [ordered]@{
            source = [string]$source.Source
            kind = [string]$source.Kind
            name = [string]$source.Name
            status = [string]$source.Status
            reason = $source.Reason
            path = $source.Path
            sha256 = $source.SHA256
            windowStart = ConvertTo-LVStandardTimestamp $source.WindowStart
            windowEnd = ConvertTo-LVStandardTimestamp $source.WindowEnd
            cap = $source.Cap
            observedRecords = $source.ObservedRecords
            skippedRecords = $source.SkippedRecords
            recordGap = $source.RecordGap
            parserError = $source.ParserError
            origin = $source.Origin
        }
        ConvertTo-LVTimelineLine -Result $Result -RecordType 'coverage' -Payload $coveragePayload -Redact:$Redact
    }

    foreach ($provider in @($Result.ProviderExtensions | Where-Object { $_ } | Sort-Object Id)) {
        $providerPayload = [ordered]@{
            providerId = [string]$provider.Id
            name = [string]$provider.Name
            version = [string]$provider.Version
            trust = [string]$provider.Trust
            capabilities = @($provider.Capabilities)
            recordCount = $provider.RecordCount
            rejectedRecords = $provider.RejectedRecords
            budgetStop = $provider.BudgetStop
        }
        ConvertTo-LVTimelineLine -Result $Result -RecordType 'provider' -Payload $providerPayload -Redact:$Redact
    }
}

function Write-LVJsonlTimeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Redact
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $temporary = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N'))
    $writer = $null
    $lineCount = 0
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $writer = New-Object System.IO.StreamWriter($temporary, $false, $utf8NoBom)
        foreach ($line in Get-LVTimelineLine -Result $Result -Redact:$Redact) {
            $safeLine = ConvertTo-LVJsonSafeValue -Value $line
            $writer.WriteLine(($safeLine | ConvertTo-Json -Depth 30 -Compress))
            $lineCount++
        }
        $writer.Flush()
    } catch {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        throw
    } finally {
        if ($writer) { $writer.Dispose() }
    }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try { [IO.File]::Replace($temporary, $Path, $null, $true) }
            catch { Move-Item -LiteralPath $temporary -Destination $Path -Force }
        } else {
            Move-Item -LiteralPath $temporary -Destination $Path -Force
        }
    } catch {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        throw
    }
    return [pscustomobject][ordered]@{ Path = $Path; LineCount = $lineCount; Redacted = [bool]$Redact; Format = 'LogVerdict.Timeline' }
}

function ConvertTo-LVEcsExport {
    param([Parameter(Mandatory)]$Model)

    $findings = foreach ($finding in @($Model.Findings)) {
        $severity = switch ([string]$finding.verdict) {
            'critical' { 100 }
            'actionable' { 80 }
            'investigate' { 60 }
            'unknown' { 40 }
            'informational' { 20 }
            default { 0 }
        }
        [pscustomobject][ordered]@{
            event = [pscustomobject][ordered]@{
                kind = 'alert'
                category = @('host')
                type = @('info')
                dataset = 'logverdict.finding'
                action = $finding.verdict
                outcome = 'unknown'
                severity = $severity
                created = $finding.event.firstObserved
                start = $finding.event.firstObserved
                end = $finding.event.lastObserved
                count = $finding.event.count
                provider = $finding.event.provider
                code = $finding.event.eventId
            }
            host = [pscustomobject]@{ name = $Model.Context.scan.machine }
            log = [pscustomobject][ordered]@{
                level = $finding.verdict
                logger = 'LogVerdict'
                origin = [pscustomobject]@{ file = [pscustomobject]@{ name = $finding.event.channel } }
            }
            rule = [pscustomobject][ordered]@{
                id = $finding.ruleId
                name = $finding.title
                description = $finding.plain
                reference = @($finding.references)
                confidence = $finding.confidence
            }
            message = $finding.plain
            logverdict = $finding
        }
    }
    return [pscustomobject][ordered]@{
        adapter = 'ecs'
        schemaVersion = $Model.Context.schemaVersion
        ecs = [pscustomobject]@{ version = '8.11.0' }
        observer = [pscustomobject][ordered]@{ product = 'LogVerdict'; version = $Model.Context.scan.version }
        event = [pscustomobject][ordered]@{ kind = 'event'; dataset = 'logverdict.scan'; created = $Model.Context.scan.started }
        logverdict = $Model.Context
        findings = @($findings)
        advisories = @($Model.Advisories)
        correlations = @($Model.Correlations)
    }
}

function ConvertTo-LVOcsfExport {
    param([Parameter(Mandatory)]$Model)

    # LogVerdict findings include diagnostics, health signals, and benign context,
    # so they are not OCSF Detection Findings. Keep the envelope intentionally
    # classless and carry the complete normalized evidence in the vendor extension.
    $evidence = foreach ($finding in @($Model.Findings)) {
        $time = ConvertTo-LVStandardUnixMillisecond $finding.event.firstObserved
        [pscustomobject][ordered]@{
            time = $time
            start_time = $time
            end_time = ConvertTo-LVStandardUnixMillisecond $finding.event.lastObserved
            count = $finding.event.count
            metadata = [pscustomobject][ordered]@{ product = [pscustomobject]@{ name = 'LogVerdict'; version = $Model.Context.scan.version }; version = '1.1.0' }
            unmapped = [pscustomobject][ordered]@{
                logverdict = [pscustomobject][ordered]@{
                    recordType = 'normalized-evidence'
                    finding = $finding
                }
            }
        }
    }
    return [pscustomobject][ordered]@{
        adapter = 'ocsf'
        schemaVersion = $Model.Context.schemaVersion
        ocsfVersion = '1.1.0'
        contract = 'normalized-evidence'
        metadata = [pscustomobject][ordered]@{ product = [pscustomobject]@{ name = 'LogVerdict'; version = $Model.Context.scan.version }; profiles = @('logverdict.normalized-evidence') }
        scan = $Model.Context
        evidence = @($evidence)
        unmapped = [pscustomobject][ordered]@{
            logverdict = [pscustomobject][ordered]@{
                advisories = @($Model.Advisories)
                correlations = @($Model.Correlations)
            }
        }
    }
}

function New-LVOtelAttribute {
    param([Parameter(Mandatory)][string]$Key, [AllowNull()]$Value)

    $valueObject = if ($Value -is [bool]) { [pscustomobject]@{ boolValue = [bool]$Value } } elseif ($Value -is [int] -or $Value -is [long]) { [pscustomobject]@{ intValue = [long]$Value } } else { [pscustomobject]@{ stringValue = [string]$Value } }
    return [pscustomobject][ordered]@{ key = $Key; value = $valueObject }
}

function ConvertTo-LVOtelExport {
    param([Parameter(Mandatory)]$Model)

    $severityMap = @{ critical = 21; actionable = 17; investigate = 13; unknown = 9; informational = 5; benign = 1 }
    $logRecords = foreach ($finding in @($Model.Findings)) {
        $attributes = New-Object System.Collections.Generic.List[object]
        foreach ($pair in @(
            @{ Key = 'logverdict.finding.key'; Value = $finding.key }
            @{ Key = 'logverdict.finding.verdict'; Value = $finding.verdict }
            @{ Key = 'logverdict.finding.confidence'; Value = $finding.confidence }
            @{ Key = 'logverdict.finding.rule_id'; Value = $finding.ruleId }
            @{ Key = 'logverdict.event.source'; Value = $finding.event.source }
            @{ Key = 'logverdict.event.channel'; Value = $finding.event.channel }
            @{ Key = 'logverdict.event.provider'; Value = $finding.event.provider }
            @{ Key = 'logverdict.event.id'; Value = $finding.event.eventId }
            @{ Key = 'logverdict.privacy.redacted'; Value = $Model.Context.privacy.redacted }
        )) { $attributes.Add((New-LVOtelAttribute -Key $pair.Key -Value $pair.Value)) | Out-Null }
        [pscustomobject][ordered]@{
            timeUnixNano = [long]((ConvertTo-LVStandardUnixMillisecond $finding.event.firstObserved) * 1000000)
            observedTimeUnixNano = [long]((ConvertTo-LVStandardUnixMillisecond $Model.Context.scan.started) * 1000000)
            severityNumber = $severityMap[[string]$finding.verdict]
            severityText = ([string]$finding.verdict).ToUpperInvariant()
            body = [pscustomobject]@{ stringValue = $finding.plain }
            attributes = @($attributes.ToArray())
            droppedAttributesCount = 0
        }
    }
    return [pscustomobject][ordered]@{
        adapter = 'opentelemetry'
        schemaVersion = $Model.Context.schemaVersion
        schemaUrl = 'https://opentelemetry.io/schemas/1.26.0'
        resourceLogs = @([pscustomobject][ordered]@{
            resource = [pscustomobject]@{ attributes = @(
                (New-LVOtelAttribute -Key 'service.name' -Value 'LogVerdict')
                (New-LVOtelAttribute -Key 'service.version' -Value $Model.Context.scan.version)
                (New-LVOtelAttribute -Key 'host.name' -Value $Model.Context.scan.machine)
                (New-LVOtelAttribute -Key 'logverdict.redacted' -Value $Model.Context.privacy.redacted)
            ) }
            scopeLogs = @([pscustomobject][ordered]@{ scope = [pscustomobject]@{ name = 'LogVerdict'; version = $Model.Context.scan.version }; logRecords = @($logRecords) })
        })
        logverdict = $Model.Context
        advisories = @($Model.Advisories)
    }
}

function ConvertTo-LVStixExport {
    param([Parameter(Mandatory)]$Model)

    $identityId = 'identity--' + [guid]::NewGuid().ToString()
    $reportId = 'report--' + [guid]::NewGuid().ToString()
    $objects = New-Object System.Collections.Generic.List[object]
    $objects.Add([pscustomobject][ordered]@{
        type = 'identity'; spec_version = '2.1'; id = $identityId; created = $Model.Context.generatedAt; modified = $Model.Context.generatedAt
        name = 'LogVerdict'; identity_class = 'tool'; labels = @('diagnostic-tool')
    }) | Out-Null
    $refs = New-Object System.Collections.Generic.List[string]
    foreach ($finding in @($Model.Findings)) {
        $observedId = 'observed-data--' + [guid]::NewGuid().ToString()
        $refs.Add($observedId) | Out-Null
        $objects.Add([pscustomobject][ordered]@{
            type = 'observed-data'; spec_version = '2.1'; id = $observedId
            created_by_ref = $identityId; first_observed = $finding.event.firstObserved; last_observed = $finding.event.lastObserved
            number_observed = $finding.event.count
            objects = [pscustomobject][ordered]@{ '0' = [pscustomobject][ordered]@{
                type = 'x-logverdict-event'; source = $finding.event.source; channel = $finding.event.channel
                provider = $finding.event.provider; event_id = $finding.event.eventId; event_version = $finding.event.eventVersion
                message_samples = @($finding.event.messageSamples)
            } }
            x_logverdict = $finding
        }) | Out-Null
    }
    $objects.Add([pscustomobject][ordered]@{
        type = 'report'; spec_version = '2.1'; id = $reportId; created_by_ref = $identityId
        created = $Model.Context.scan.started; modified = $Model.Context.scan.completed; published = $Model.Context.scan.completed
        name = 'LogVerdict scan'; description = 'Structured diagnostic findings and source coverage from LogVerdict.'
        object_refs = @($refs.ToArray()); x_logverdict = $Model.Context
    }) | Out-Null
    return [pscustomobject][ordered]@{ type = 'bundle'; id = 'bundle--' + [guid]::NewGuid().ToString(); spec_version = '2.1'; adapter = 'stix-2.1'; schemaVersion = $Model.Context.schemaVersion; advisories = @($Model.Advisories); objects = @($objects.ToArray()) }
}

function ConvertTo-LVStandardDocument {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Format)

    $model = Get-LVStandardModel -Result $Result
    switch ($Format) {
        'Ecs' { return ConvertTo-LVEcsExport -Model $model }
        'Ocsf' { return ConvertTo-LVOcsfExport -Model $model }
        'OpenTelemetry' { return ConvertTo-LVOtelExport -Model $model }
        'Stix' { return ConvertTo-LVStixExport -Model $model }
    }
    throw "Unsupported standard export format '$Format'."
}
