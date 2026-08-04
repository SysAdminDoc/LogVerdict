# Review artifacts are an exchange format, not another rule database.
# They deliberately carry redacted evidence and review state while keeping curated
# verdicts out of the write path.

function Get-LVReviewProperty {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-LVReviewStableId {
    param([Parameter(Mandatory)][string]$Key)

    return ('UNKNOWN-{0}' -f (Get-LVShortHash -Text $Key)).ToUpperInvariant()
}

function ConvertTo-LVReviewContext {
    param([Parameter(Mandatory)]$Finding)

    $context = [ordered]@{}
    foreach ($pair in @(
        @{ Name = 'source'; Property = 'Source' },
        @{ Name = 'channel'; Property = 'Channel' },
        @{ Name = 'provider'; Property = 'Provider' },
        @{ Name = 'eventId'; Property = 'Id' },
        @{ Name = 'recordId'; Property = 'RecordId' },
        @{ Name = 'area'; Property = 'Area' }
    )) {
        $value = Get-LVReviewProperty -InputObject $Finding -Name $pair.Property
        if ($null -ne $value -and [string]$value) { $context[$pair.Name] = $value }
    }
    return [pscustomobject]$context
}

function ConvertTo-LVReviewFixtureScaffold {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)]$Context,
        [AllowNull()]$Evidence
    )

    $signature = [ordered]@{}
    foreach ($name in @('source', 'channel', 'provider', 'eventId', 'recordId')) {
        $value = Get-LVReviewProperty -InputObject $Context -Name $name
        if ($null -ne $value) {
            $fixtureName = if ($name -eq 'source') { 'Source' } elseif ($name -eq 'channel') { 'Channel' } `
                elseif ($name -eq 'provider') { 'Provider' } elseif ($name -eq 'eventId') { 'Id' } else { 'RecordId' }
            $signature[$fixtureName] = $value
        }
    }
    $sample = Get-LVReviewProperty -InputObject $Evidence -Name 'sampleMessage'
    if ($sample) { $signature['SampleMessage'] = [string]$sample }
    $structured = Get-LVReviewProperty -InputObject $Evidence -Name 'structuredData'
    if ($structured) { $signature['StructuredData'] = $structured }

    return [pscustomobject][ordered]@{
        ruleId = $Id
        origin = 'review-scaffold'
        expect = 'unknown'
        signature = [pscustomobject]$signature
        notes = @('Replace this scaffold with a reviewed fixture only after the source, match and expected verdict are verified.')
    }
}

function Get-LVReviewRetrievedDate {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$GeneratedAt)

    try {
        return ([datetimeoffset]::Parse($GeneratedAt, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime).ToString(
            'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    } catch {
        return [datetime]::UtcNow.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
}

function ConvertTo-LVReviewContribution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Finding,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)][string]$Retrieved
    )

    $provider = [string](Get-LVReviewProperty -InputObject $Context -Name 'provider')
    if (-not $provider) { $provider = '<provider>' }
    $eventId = [string](Get-LVReviewProperty -InputObject $Context -Name 'eventId')
    if (-not $eventId) { $eventId = '<eventId>' }
    $label = 'Rule to write: {0} {1}' -f $provider, $eventId

    $match = [ordered]@{}
    foreach ($name in @('source', 'channel', 'provider', 'eventId')) {
        $value = Get-LVReviewProperty -InputObject $Context -Name $name
        if ($null -eq $value -or -not [string]$value) { continue }
        if ($name -eq 'eventId') {
            $numericId = 0
            if ([int]::TryParse([string]$value, [ref]$numericId)) { $match[$name] = $numericId }
        } else {
            $match[$name] = [string]$value
        }
    }

    $sourceUri = 'https://github.com/SysAdminDoc/LogVerdict/issues/new?template=rule-contribution.yml'
    $rule = [ordered]@{
        id             = ('TEST-{0}' -f (Get-LVShortHash -Text ([string](Get-LVReviewProperty -InputObject $Finding -Name 'Key')))).ToUpperInvariant()
        status         = 'test'
        match          = [pscustomobject]$match
        verdict        = 'unknown'
        title          = $label
        plain          = 'This contribution is a redacted test scaffold for an otherwise unrecognized signature. It is not a diagnosis.'
        why            = 'The signature was not covered by a curated rule. Human review must establish what the provider and event actually mean before any non-unknown verdict is written.'
        action         = 'Review the redacted evidence, add a regression fixture, and replace the test scaffold only after the source and remediation are verified.'
        confidence     = 'low'
        references     = @()
        falsepositives = @()
        sources        = @([pscustomobject][ordered]@{ uri = $sourceUri; retrieved = $Retrieved })
    }

    $body = @(
        $label
        ''
        'Status: test'
        ('Provider: {0}' -f $provider)
        ('Event ID: {0}' -f $eventId)
        ('Source retrieved: {0}' -f $Retrieved)
        ''
        'Redacted evidence:'
        '```json'
        ($Evidence | ConvertTo-Json -Depth 12 -Compress)
        '```'
        ''
        'Do not promote this scaffold without a reviewed meaning, remediation, source, and regression fixture.'
    ) -join [Environment]::NewLine

    return [pscustomobject][ordered]@{
        label      = $label
        status     = 'test'
        rule       = [pscustomobject]$rule
        evidence   = $Evidence
        issue      = [pscustomobject][ordered]@{ title = $label; body = $body }
        instruction = 'This is a redacted contribution scaffold. Keep status=test until a human reviewer has verified the source, meaning, remediation, sources[].retrieved, and a regression fixture.'
    }
}

function ConvertTo-LVReviewRedactedValue {
    param(
        [AllowNull()]$Value,
        [AllowNull()][string]$MachineName,
        [int]$Depth = 0
    )

    if ($null -eq $Value) { return $null }
    if ($Depth -gt 12) { return '[DEPTH-LIMIT]' }
    if ($Value -is [string]) {
        return ConvertTo-LVRedactedText -Text $Value -MachineName $MachineName
    }
    if ($Value -is [datetime] -or $Value -is [timespan] -or $Value -is [bool] -or
        $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or
        $Value -is [int64] -or $Value -is [decimal] -or $Value -is [double]) {
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object)) {
            $out[[string]$key] = ConvertTo-LVReviewRedactedValue -Value $Value[$key] -MachineName $MachineName -Depth ($Depth + 1)
        }
        return [pscustomobject]$out
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in @($Value)) {
            if ($list.Count -ge 100) { break }
            $list.Add((ConvertTo-LVReviewRedactedValue -Value $item -MachineName $MachineName -Depth ($Depth + 1))) | Out-Null
        }
        # Unary comma preserves a one-item array when this helper is used in a
        # property assignment; otherwise PowerShell collapses it to a scalar and
        # JSON consumers see the first character of a string as item zero.
        return ,$list.ToArray()
    }

    $object = [ordered]@{}
    foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) {
        $object[$property.Name] = ConvertTo-LVReviewRedactedValue -Value $property.Value -MachineName $MachineName -Depth ($Depth + 1)
    }
    return [pscustomobject]$object
}

function ConvertTo-LVReviewUnknownItem {
    param(
        [Parameter(Mandatory)]$Finding,
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Retrieved,
        [switch]$IncludeContribution
    )

    $key = [string](Get-LVReviewProperty -InputObject $Finding -Name 'Key')
    if (-not $key) {
        $key = '{0}|{1}|{2}|{3}|{4}' -f (Get-LVReviewProperty $Finding 'Source'),
            (Get-LVReviewProperty $Finding 'Channel'), (Get-LVReviewProperty $Finding 'Provider'),
            (Get-LVReviewProperty $Finding 'Id'), (Get-LVReviewProperty $Finding 'SampleMessage')
    }
    $id = Get-LVReviewStableId -Key $key
    $context = ConvertTo-LVReviewContext -Finding $Finding
    $evidence = [ordered]@{
        sampleMessage = [string](Get-LVReviewProperty -InputObject $Finding -Name 'SampleMessage')
        samples = @((Get-LVReviewProperty -InputObject $Finding -Name 'Samples') | Select-Object -First 10)
        structuredData = Get-LVReviewProperty -InputObject $Finding -Name 'StructuredData'
        count = [int](Get-LVReviewProperty -InputObject $Finding -Name 'Count')
        perDay = Get-LVReviewProperty -InputObject $Finding -Name 'PerDay'
        firstSeen = Get-LVReviewProperty -InputObject $Finding -Name 'FirstSeen'
        lastSeen = Get-LVReviewProperty -InputObject $Finding -Name 'LastSeen'
        burst = Get-LVReviewProperty -InputObject $Finding -Name 'Burst'
        burstOnset = Get-LVReviewProperty -InputObject $Finding -Name 'BurstOnset'
    }
    if ($Finding.PSObject.Properties['ModelExplanation'] -and $Finding.ModelExplanation) {
        $evidence['modelExplanation'] = $Finding.ModelExplanation
    }

    $provenance = [ordered]@{
        origin = 'scan-unknown'
        tool = [string](Get-LVReviewProperty -InputObject $Result -Name 'Tool')
        version = [string](Get-LVReviewProperty -InputObject $Result -Name 'Version')
        scanTime = Get-LVReviewProperty -InputObject $Result -Name 'ScanTime'
        mode = Get-LVReviewProperty -InputObject (Get-LVReviewProperty -InputObject $Result -Name 'Contract') -Name 'mode'
        key = $key
    }

    $item = [ordered]@{
        id = $id
        kind = 'unknown'
        status = 'pending'
        confidence = 'none'
        context = $context
        evidence = [pscustomobject]$evidence
        provenance = [pscustomobject]$provenance
        falsePositives = @()
        fixture = ConvertTo-LVReviewFixtureScaffold -Id $id -Context $context -Evidence ([pscustomobject]$evidence)
        review = [pscustomobject][ordered]@{
            status = 'pending'
            verdict = $null
            confidence = $null
            title = $null
            plain = $null
            why = $null
            action = $null
            notes = @()
        }
    }
    if ($IncludeContribution) {
        $item.contribution = ConvertTo-LVReviewContribution -Finding $Finding -Context $context `
            -Evidence ([pscustomobject]$evidence) -Retrieved $Retrieved
    }
    return [pscustomobject]$item
}

function Test-LVReviewFreshnessReady {
    [CmdletBinding()]
    param([AllowNull()]$Result)

    if ($null -eq $Result -or -not $Result.PSObject.Properties['DatabaseFreshness'] -or -not $Result.DatabaseFreshness) {
        return $false
    }
    $policy = $Result.DatabaseFreshness
    $days = 0
    if (-not $policy.PSObject.Properties['DefaultStaleAfterDays'] -or
        -not [int]::TryParse([string]$policy.DefaultStaleAfterDays, [ref]$days) -or $days -lt 1) {
        return $false
    }
    if ($policy.PSObject.Properties['DateBasis'] -and [string]$policy.DateBasis -ne 'UTC') {
        return $false
    }
    return $true
}

function ConvertTo-LVReviewCandidateItem {
    param(
        [Parameter(Mandatory)]$Candidate,
        [Parameter(Mandatory)][string]$SourcePath,
        [AllowEmptyString()][string]$SourceHash
    )

    $id = [string](Get-LVReviewProperty -InputObject $Candidate -Name 'id')
    if (-not $id) { throw ("Review candidate from '{0}' has no stable id." -f $SourcePath) }
    if (-not $SourceHash) {
        $SourceHash = Get-LVShortHash -Text ($Candidate | ConvertTo-Json -Depth 20 -Compress)
    }
    $match = Get-LVReviewProperty -InputObject $Candidate -Name 'match'
    $context = [ordered]@{}
    foreach ($pair in @(
        @{ Name = 'source'; Property = 'source' },
        @{ Name = 'channel'; Property = 'channel' },
        @{ Name = 'provider'; Property = 'provider' },
        @{ Name = 'eventId'; Property = 'eventId' }
    )) {
        $value = Get-LVReviewProperty -InputObject $match -Name $pair.Property
        if ($null -ne $value -and [string]$value) { $context[$pair.Name] = $value }
    }
    $provenance = [ordered]@{
        origin = 'imported-candidate'
        sourcePath = $SourcePath
        sourceSha256 = $SourceHash
        sourceType = if ($Candidate.PSObject.Properties['sigma']) { 'sigma' } else { 'local-rule' }
        sourceStatus = Get-LVReviewProperty -InputObject $Candidate -Name 'status'
        sourceReviewStatus = Get-LVReviewProperty -InputObject (Get-LVReviewProperty -InputObject $Candidate -Name 'sigma') -Name 'reviewStatus'
    }
    $evidence = [ordered]@{
        candidateTitle = Get-LVReviewProperty -InputObject $Candidate -Name 'title'
        match = $match
        sigma = Get-LVReviewProperty -InputObject $Candidate -Name 'sigma'
    }
    $falsePositives = @(Get-LVReviewProperty -InputObject $Candidate -Name 'falsepositives')
    $confidence = [string](Get-LVReviewProperty -InputObject $Candidate -Name 'confidence')
    if (-not $confidence) { $confidence = 'draft' }

    return [pscustomobject][ordered]@{
        id = $id
        kind = 'candidate'
        status = 'pending'
        confidence = $confidence
        context = [pscustomobject]$context
        evidence = [pscustomobject]$evidence
        provenance = [pscustomobject]$provenance
        falsePositives = $falsePositives
        candidate = $Candidate
        fixture = ConvertTo-LVReviewFixtureScaffold -Id $id -Context ([pscustomobject]$context) -Evidence ([pscustomobject]@{ sampleMessage = $null })
        review = [pscustomobject][ordered]@{
            status = 'pending'
            verdict = $null
            confidence = $null
            title = $null
            plain = $null
            why = $null
            action = $null
            notes = @()
        }
    }
}

function New-LVReviewArtifact {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This function constructs an in-memory review artifact and changes no external state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [AllowEmptyCollection()][object[]]$Candidate,
        [Parameter(Mandatory)][string]$GeneratedAt,
        [AllowNull()][string]$MachineName,
        [int]$MaxCandidates = 1000
    )

    $contributionReady = Test-LVReviewFreshnessReady -Result $Result
    $unknowns = foreach ($finding in @($Result.Findings)) {
        if ($finding.Verdict -eq 'unknown' -and -not $finding.RuleId) {
            ConvertTo-LVReviewUnknownItem -Finding $finding -Result $Result `
                -Retrieved (Get-LVReviewRetrievedDate -GeneratedAt $GeneratedAt) `
                -IncludeContribution:$contributionReady
        }
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($unknowns)) { $items.Add($item) | Out-Null }

    $seen = @{}
    # Explicitly flatten transport arrays. PowerShell 5.1 and 7 differ in how an
    # object[] returned from ConvertFrom-Json is enumerated when it crosses a module
    # invocation; treating both shapes alike keeps duplicate queues deterministic.
    $pendingCandidates = New-Object System.Collections.Generic.List[object]
    foreach ($value in @($Candidate)) { $pendingCandidates.Add($value) | Out-Null }
    $flatCandidates = New-Object System.Collections.Generic.List[object]
    while ($pendingCandidates.Count -gt 0) {
        $value = $pendingCandidates[0]
        $pendingCandidates.RemoveAt(0)
        if ($value -is [Array]) {
            foreach ($child in @($value)) { $pendingCandidates.Add($child) | Out-Null }
        } elseif ($value) {
            $flatCandidates.Add($value) | Out-Null
        }
    }
    $candidateInput = @($flatCandidates.ToArray() | Where-Object { $_ -and $_.id } | Sort-Object id, sourcePath)
    if ($candidateInput.Count -gt $MaxCandidates) {
        throw ("Review candidate count {0} exceeds the safety limit of {1}. Narrow the input queues before exporting." -f $candidateInput.Count, $MaxCandidates)
    }
    foreach ($candidateRecord in $candidateInput) {
        # A caller crossing a module boundary can wrap an object[] one level deeper
        # than the normal pipeline unrolling rules. Flatten that harmless transport
        # wrapper before reading provenance properties.
        while ($candidateRecord -is [Array] -and $candidateRecord.Count -eq 1) {
            $candidateRecord = $candidateRecord[0]
        }
        $candidateValue = $candidateRecord
        $path = [string](Get-LVReviewProperty -InputObject $candidateRecord -Name 'sourcePath')
        if ($candidateRecord.PSObject.Properties['candidate']) {
            $candidateValue = $candidateRecord.candidate
            if (-not $path) { $path = [string]$candidateRecord.sourcePath }
        }
        if (-not $path) { $path = '<in-memory candidate>' }
        $id = [string](Get-LVReviewProperty -InputObject $candidateValue -Name 'id')
        if ($seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $sourceHash = [string](Get-LVReviewProperty -InputObject $candidateRecord -Name 'sourceHash')
        if (-not $sourceHash) { $sourceHash = [string](Get-LVReviewProperty -InputObject $candidateValue -Name 'sourceHash') }
        $items.Add((ConvertTo-LVReviewCandidateItem -Candidate $candidateValue -SourcePath $path -SourceHash $sourceHash)) | Out-Null
    }

    $redactedItems = foreach ($item in @($items.ToArray())) {
        ConvertTo-LVReviewRedactedValue -Value $item -MachineName $MachineName
    }
    $orderedItems = @($redactedItems | Sort-Object kind, id)
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        name = 'LogVerdict.ReviewArtifact'
        generatedAt = $GeneratedAt
        tool = 'LogVerdict'
        version = [string]$Result.Version
        privacy = [pscustomobject][ordered]@{
            redacted = $true
            rawEvidence = $false
            statement = 'Evidence and candidate prose are redacted for review exchange; this is not an anonymity guarantee.'
        }
        run = [pscustomobject][ordered]@{
            mode = Get-LVReviewProperty -InputObject (Get-LVReviewProperty -InputObject $Result -Name 'Contract') -Name 'mode'
            scanTime = ConvertTo-LVCaseUtcText $Result.ScanTime
            daysBack = $Result.DaysBack
            sourceCount = @($Result.Coverage).Count
            unknownCount = @($orderedItems | Where-Object { $_.kind -eq 'unknown' }).Count
            candidateCount = @($orderedItems | Where-Object { $_.kind -eq 'candidate' }).Count
            staleRuleCount = if ($Result.PSObject.Properties['DatabaseFreshness']) { [int]$Result.DatabaseFreshness.StaleRuleCount } else { 0 }
        }
        items = $orderedItems
        import = [pscustomobject][ordered]@{
            curatedDatabaseUpdated = $false
            instruction = 'Review each item, update review.status and review fields, then import the artifact to produce a diff. Curated verdicts are never changed by this format.'
        }
    }
}

function Get-LVReviewArtifactItemHash {
    param([Parameter(Mandatory)]$Item)

    return Get-LVShortHash -Text ($Item | ConvertTo-Json -Depth 30 -Compress)
}

function Test-LVReviewArtifactObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Artifact)

    if ([int]$Artifact.schemaVersion -ne 1 -or [string]$Artifact.name -ne 'LogVerdict.ReviewArtifact') {
        throw 'Unsupported LogVerdict review artifact contract.'
    }
    if (-not $Artifact.privacy.redacted -or $Artifact.privacy.rawEvidence) {
        throw 'Review artifacts must declare redacted=true and rawEvidence=false.'
    }
    $seen = @{}
    foreach ($item in @($Artifact.items)) {
        $id = [string]$item.id
        if (-not $id -or $seen.ContainsKey($id)) { throw 'Review artifact items must have unique stable ids.' }
        $seen[$id] = $true
        if ([string]$item.kind -notin @('unknown', 'candidate')) { throw ("Review item '{0}' has an unsupported kind." -f $id) }
        if ([string]$item.kind -eq 'unknown') {
            $contribution = Get-LVReviewProperty -InputObject $item -Name 'contribution'
            if ($contribution) {
                if ([string]$contribution.status -ne 'test' -or
                    [string]$contribution.rule.status -ne 'test') {
                    throw ("Review item '{0}' contribution scaffold must remain status=test." -f $id)
                }
                if ([string]$contribution.label -notmatch '^Rule to write: .+') {
                    throw ("Review item '{0}' contribution label is not pre-filled." -f $id)
                }
                if ([string]$contribution.rule.verdict -ne 'unknown') {
                    throw ("Review item '{0}' contribution rule must remain verdict=unknown." -f $id)
                }
                $sources = @($contribution.rule.sources | Where-Object { $_ })
                if ($sources.Count -eq 0) { throw ("Review item '{0}' contribution has no source." -f $id) }
                foreach ($source in $sources) {
                    if (-not $source.uri -or [string]$source.uri -notmatch '^https?://') {
                        throw ("Review item '{0}' contribution source URI is not http/https." -f $id)
                    }
                    if ([string]$source.retrieved -notmatch '^\d{4}-\d{2}-\d{2}$') {
                        throw ("Review item '{0}' contribution source must declare sources[].retrieved." -f $id)
                    }
                }
            }
        }
        $reviewStatus = [string]$item.review.status
        if ($reviewStatus -notin @('pending', 'accepted', 'rejected', 'needs-evidence')) {
            throw ("Review item '{0}' has an unsupported review status." -f $id)
        }
    }
    return $true
}

function Get-LVReviewArtifactDiff {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Previous,
        [Parameter(Mandatory)][object]$Current
    )

    $oldItems = if ($Previous -and $Previous.PSObject.Properties['items']) { @($Previous.items) } else { @() }
    $newItems = @($Current.items)
    $oldById = @{}
    foreach ($item in $oldItems) { $oldById[[string]$item.id] = $item }
    $newById = @{}
    foreach ($item in $newItems) { $newById[[string]$item.id] = $item }

    $added = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($item in $newItems) {
        $id = [string]$item.id
        if (-not $oldById.ContainsKey($id)) { $added.Add($id) | Out-Null; continue }
        if ((Get-LVReviewArtifactItemHash -Item $oldById[$id]) -ne (Get-LVReviewArtifactItemHash -Item $item)) {
            $changed.Add($id) | Out-Null
        }
    }
    $removed = New-Object System.Collections.Generic.List[string]
    foreach ($item in $oldItems) {
        $id = [string]$item.id
        if (-not $newById.ContainsKey($id)) { $removed.Add($id) | Out-Null }
    }
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        added = @($added.ToArray() | Sort-Object)
        changed = @($changed.ToArray() | Sort-Object)
        removed = @($removed.ToArray() | Sort-Object)
        counts = [pscustomobject][ordered]@{
            added = $added.Count
            changed = $changed.Count
            removed = $removed.Count
            current = $newItems.Count
            reviewed = @($newItems | Where-Object { $_.review.status -ne 'pending' }).Count
        }
    }
}
