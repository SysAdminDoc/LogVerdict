# Versioned machine-interchange adapters. The normalized model is deliberately built
# before a standards projection so each adapter preserves the same evidence contract.

$script:LVStandardExportVersion = '1.0.0'

function ConvertTo-LVStandardTimestamp {
    param([AllowNull()]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('o') } catch { return $null }
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
            scanTimes   = @($History.Baseline.ScanTimes)
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
        }
        coverage = @(ConvertTo-LVStandardCoverage -Coverage @($Result.Coverage))
        healthProfiles = @(ConvertTo-LVStandardHealth -HealthProfiles @($Result.HealthProfiles))
        history = ConvertTo-LVStandardHistory -History $(if ($Result.PSObject.Properties['History']) { $Result.History } else { $null })
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

    $severityMap = @{ critical = 5; actionable = 4; investigate = 3; unknown = 2; informational = 1; benign = 0 }
    $findings = foreach ($finding in @($Model.Findings)) {
        $time = ConvertTo-LVStandardUnixMillisecond $finding.event.firstObserved
        [pscustomobject][ordered]@{
            activity_id = 1
            activity_name = 'Create'
            category_name = 'Findings'
            category_uid = 2
            class_name = 'Detection Finding'
            class_uid = 2004
            type_name = 'Detection Finding: Create'
            type_uid = 200401
            severity_id = $severityMap[[string]$finding.verdict]
            severity = ([string]$finding.verdict).ToUpperInvariant()
            status = 'New'
            time = $time
            start_time = $time
            end_time = ConvertTo-LVStandardUnixMillisecond $finding.event.lastObserved
            count = $finding.event.count
            metadata = [pscustomobject][ordered]@{ product = [pscustomobject]@{ name = 'LogVerdict'; version = $Model.Context.scan.version }; version = '1.1.0' }
            finding_info = [pscustomobject][ordered]@{
                uid = $finding.key
                title = $finding.title
                desc = $finding.plain
                analytic = [pscustomobject][ordered]@{ rule_uid = $finding.ruleId; confidence = $finding.confidence }
                references = @($finding.references)
            }
            unmapped = [pscustomobject]@{ logverdict = $finding }
        }
    }
    return [pscustomobject][ordered]@{
        adapter = 'ocsf'
        schemaVersion = $Model.Context.schemaVersion
        ocsfVersion = '1.1.0'
        metadata = [pscustomobject][ordered]@{ product = [pscustomobject]@{ name = 'LogVerdict'; version = $Model.Context.scan.version }; profiles = @('logverdict.finding') }
        scan = $Model.Context
        findings = @($findings)
        advisories = @($Model.Advisories)
        correlations = @($Model.Correlations)
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
