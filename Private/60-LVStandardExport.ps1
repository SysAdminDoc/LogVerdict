# Versioned machine-interchange adapters. The normalized model is deliberately built
# before a standards projection so each adapter preserves the same evidence contract.

$script:LVStandardExportVersion = '1.0.0'
$script:LVStandardTemplateMaxBytes = 1048576
$script:LVStandardTemplateReservedProjections = [ordered]@{
    Ecs            = 'builtin:ecs'
    Ocsf           = 'builtin:ocsf'
    Sarif          = 'builtin:sarif'
    OpenTelemetry  = 'builtin:opentelemetry'
    Stix           = 'builtin:stix'
    Jsonl          = 'builtin:timeline'
}

function New-LVTemplateBudget {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 10000000)][int64]$MaxNodes = 100000,
        [ValidateRange(1, 600000)][int]$MaxMilliseconds = 2000,
        [ValidateRange(1, 256)][int]$MaxDepth = 32
    )

    return [pscustomobject][ordered]@{
        MaxNodes        = [int64]$MaxNodes
        MaxMilliseconds = [int]$MaxMilliseconds
        MaxDepth        = [int]$MaxDepth
        StartedUtc      = [datetime]::UtcNow
        EmittedNodes    = [int64]0
    }
}

function Assert-LVTemplateBudget {
    param(
        [Parameter(Mandatory)]$Budget,
        [int]$Depth = 0
    )

    $Budget.EmittedNodes = [int64]$Budget.EmittedNodes + 1
    if ($Budget.EmittedNodes -gt [int64]$Budget.MaxNodes) {
        throw ("ExportTemplateBudgetExceeded: maximum emitted nodes ({0}) exceeded." -f $Budget.MaxNodes)
    }
    if ($Depth -gt [int]$Budget.MaxDepth) {
        throw ("ExportTemplateBudgetExceeded: maximum recursion depth ({0}) exceeded." -f $Budget.MaxDepth)
    }
    $elapsed = ([datetime]::UtcNow - $Budget.StartedUtc).TotalMilliseconds
    if ($elapsed -ge [int]$Budget.MaxMilliseconds) {
        throw ("ExportTemplateBudgetExceeded: maximum wall clock ({0} ms) exceeded." -f $Budget.MaxMilliseconds)
    }
}

function Assert-LVStandardTemplateRegistry {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Templates)

    if ($Templates.Count -eq 0) {
        throw 'Export template registry must contain at least one template.'
    }
    $seen = @{}
    foreach ($template in $Templates) {
        if ($null -eq $template) { throw 'Export template registry cannot contain a null template.' }
        $id = [string]$template.id
        if ($id -notmatch '^[A-Za-z][A-Za-z0-9._-]{0,63}$') {
            throw ("Export template id '{0}' is invalid." -f $id)
        }
        $idKey = $id.ToLowerInvariant()
        if ($seen.ContainsKey($idKey)) {
            throw ("Export template registry contains duplicate id '{0}'." -f $id)
        }
        $seen[$idKey] = $true
        $reserved = @($script:LVStandardTemplateReservedProjections.Keys | Where-Object { $_ -ieq $id })
        if ($reserved.Count -eq 0) { continue }
        $expectedProjection = [string]$script:LVStandardTemplateReservedProjections[$reserved[0]]
        if ([string]$template.projection -cne $expectedProjection) {
            throw ("Export template id '{0}' is reserved for projection '{1}', not '{2}'." -f $id, $expectedProjection, [string]$template.projection)
        }
        $expectedKind = if ($reserved[0] -ieq 'Jsonl') { 'line' } else { 'single' }
        if ([string]$template.kind -cne $expectedKind) {
            throw ("Export template id '{0}' is reserved for kind '{1}', not '{2}'." -f $id, $expectedKind, [string]$template.kind)
        }
        if ($reserved[0] -ieq 'Jsonl' -and [string]$template.source -cne 'timeline') {
            throw "Export template id 'Jsonl' is reserved for source 'timeline'."
        }
    }
    return $true
}

function Get-LVStandardTemplate {
    <#
        Resolve a built-in or user-supplied export template. Built-in templates are
        data so adding a format name, media type, or projection policy does not
        require changing the public command's validation list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Format,
        [AllowNull()][string]$Path
    )

    $templatePath = $Path
    if (-not $templatePath -and $script:LVDataDir) {
        $candidate = Join-Path $script:LVDataDir 'export-templates.json'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $templatePath = $candidate }
    }

    $document = $null
    if ($templatePath) {
        if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
            throw ("Export template was not found: {0}" -f $templatePath)
        }
        $templateFile = Get-Item -LiteralPath $templatePath -ErrorAction Stop
        if ([int64]$templateFile.Length -gt [int64]$script:LVStandardTemplateMaxBytes) {
            throw ("Export template '{0}' exceeds the {1}-byte size limit." -f $templatePath, $script:LVStandardTemplateMaxBytes)
        }
        try {
            $document = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            throw ("Export template '{0}' is not valid JSON: {1}" -f $templatePath, $_.Exception.Message)
        }
        if ([int]$document.schemaVersion -ne 1) {
            throw 'Export template document must declare schemaVersion 1.'
        }
    } else {
        # A flattened executable may not carry the Data directory. Keep the
        # built-ins available in that shape while the module uses the checked-in
        # JSON registry below.
        $document = [pscustomobject]@{
            schemaVersion = 1
            name = 'LogVerdict.ExportTemplates'
            templates = @(
                [pscustomobject]@{ id = 'Ecs'; kind = 'single'; projection = 'builtin:ecs' }
                [pscustomobject]@{ id = 'Ocsf'; kind = 'single'; projection = 'builtin:ocsf' }
                [pscustomobject]@{ id = 'Sarif'; kind = 'single'; projection = 'builtin:sarif' }
                [pscustomobject]@{ id = 'OpenTelemetry'; kind = 'single'; projection = 'builtin:opentelemetry' }
                [pscustomobject]@{ id = 'Stix'; kind = 'single'; projection = 'builtin:stix' }
                [pscustomobject]@{ id = 'Jsonl'; kind = 'line'; projection = 'builtin:timeline'; source = 'timeline' }
            )
        }
    }

    $templateDocuments = @()
    $isStandalone = $false
    if ($document.PSObject.Properties['templates']) {
        if ([string]$document.name -ne 'LogVerdict.ExportTemplates') {
            throw "Export template registry must declare name 'LogVerdict.ExportTemplates'."
        }
        $templateDocuments = @($document.templates)
    } elseif ($document.PSObject.Properties['id']) {
        # A standalone template is the contribution path: a user can ship one
        # JSON file and select it with -TemplatePath without editing this module.
        $templateDocuments = @($document)
        $isStandalone = $true
    } else {
        throw "Export template document must contain either a 'templates' registry or one standalone 'id' template."
    }
    Assert-LVStandardTemplateRegistry -Templates $templateDocuments | Out-Null

    $template = @($templateDocuments | Where-Object { [string]$_.id -ieq $Format } | Select-Object -First 1)
    if ($template.Count -eq 0 -and $isStandalone) {
        # With a standalone file the file itself is authoritative; the default
        # Ecs format remains convenient for callers that omit -Format.
        $template = @($templateDocuments[0])
    } elseif ($template.Count -eq 0 -and $templateDocuments.Count -eq 1) {
        Write-Warning ("Export template registry does not contain requested format '{0}'; it declares '{1}'. No single-template fallback is applied." -f $Format, [string]$templateDocuments[0].id)
    }
    if ($template.Count -eq 0) {
        throw ("No export template named '{0}' was found." -f $Format)
    }
    $kind = [string]$template[0].kind
    if ($kind -notin @('single', 'line')) { throw ("Export template '{0}' has unsupported kind '{1}'." -f $Format, $kind) }
    if (-not $template[0].PSObject.Properties['projection']) { throw ("Export template '{0}' has no projection." -f $Format) }
    if ($template[0].PSObject.Properties['source'] -and [string]$template[0].source -eq 'timeline' -and [string]$template[0].projection -notlike 'builtin:timeline') {
        throw "Template source 'timeline' is reserved for the built-in Jsonl adapter."
    }
    return $template[0]
}

function Get-LVTemplatePathValue {
    param(
        [AllowNull()]$Scope,
        [Parameter(Mandatory)][string]$Path
    )

    $current = $Scope
    foreach ($segment in @($Path -split '\.' | Where-Object { $_ })) {
        if ($null -eq $current) { return $null }
        if ($segment -eq 'Count' -and $current -is [System.Collections.IEnumerable] -and $current -isnot [string]) {
            $current = @($current).Count
            continue
        }
        $property = $current.PSObject.Properties[$segment]
        if ($property) {
            $current = $property.Value
        } elseif ($current -is [System.Collections.IDictionary] -and $current.Contains($segment)) {
            $current = $current[$segment]
        } else {
            return $null
        }
    }
    return $current
}

function ConvertTo-LVTemplateOutputValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory)]$Budget,
        [int]$Depth = 0
    )

    Assert-LVTemplateBudget -Budget $Budget -Depth $Depth
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($Value.Keys)) {
            $out[[string]$key] = ConvertTo-LVTemplateOutputValue -Value $Value[$key] -Budget $Budget -Depth ($Depth + 1)
        }
        return [pscustomobject]$out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return @($Value | ForEach-Object {
            ConvertTo-LVTemplateOutputValue -Value $_ -Budget $Budget -Depth ($Depth + 1)
        })
    }
    $properties = @($Value.PSObject.Properties)
    if ($properties.Count -gt 0) {
        $out = [ordered]@{}
        foreach ($property in $properties) {
            $out[$property.Name] = ConvertTo-LVTemplateOutputValue -Value $property.Value -Budget $Budget -Depth ($Depth + 1)
        }
        return [pscustomobject]$out
    }
    return $Value
}

function Test-LVTemplateTruthy {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return $false }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return (@($Value).Count -gt 0)
    }
    return [bool]$Value
}

function Get-LVTemplateChildScope {
    param(
        [Parameter(Mandatory)]$Parent,
        [AllowNull()]$Item,
        [int]$Index = 0
    )

    $child = [ordered]@{}
    foreach ($property in @($Parent.PSObject.Properties)) {
        $child[$property.Name] = $property.Value
    }
    $child['item'] = $Item
    $child['record'] = $Item
    $child['index'] = $Index
    if ($Item -and $Item.PSObject.Properties) {
        foreach ($property in @($Item.PSObject.Properties)) {
            if (-not $child.Contains($property.Name)) { $child[$property.Name] = $property.Value }
        }
    }
    return [pscustomobject]$child
}

function Get-LVTemplateRootScope {
    param([Parameter(Mandatory)]$Model)

    return [pscustomobject][ordered]@{
        context = $Model.Context
        findings = @($Model.Findings)
        advisories = @($Model.Advisories)
        correlations = @($Model.Correlations)
    }
}

function ConvertTo-LVTemplateValue {
    <#
        Evaluate the deliberately small, data-only template language. Templates
        can select normalized report-contract paths, map a collection, concatenate
        arrays, select a conditional value, and format a scalar. The scope omits
        the raw result and model objects, so property getters outside the normalized
        projection are never reachable.
    #>
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory)]$Scope,
        [AllowNull()]$Budget,
        [int]$Depth = 0
    )

    if ($null -eq $Budget) { $Budget = New-LVTemplateBudget }
    Assert-LVTemplateBudget -Budget $Budget -Depth $Depth
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($Value.StartsWith('$$', [StringComparison]::Ordinal)) { return $Value.Substring(1) }
        if ($Value -match '^\$([A-Za-z_][A-Za-z0-9_.]*)$') {
            return Get-LVTemplatePathValue -Scope $Scope -Path $Matches[1]
        }
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $dictionaryOperatorKeys = @($Value.Keys | Where-Object { [string]$_ -like '$*' })
        if ($dictionaryOperatorKeys.Count -gt 0) {
            if ($dictionaryOperatorKeys.Count -gt 1) {
                throw 'Export template expression objects may contain only one operator.'
            }
            if (@($Value.Keys).Count -ne 1) {
                throw 'Export template expression objects may contain only one operator and no extra keys.'
            }
            $Value = [pscustomobject][ordered]@{ [string]$dictionaryOperatorKeys[0] = $Value[$dictionaryOperatorKeys[0]] }
        } else {
            $out = [ordered]@{}
            foreach ($key in @($Value.Keys)) {
                $out[[string]$key] = ConvertTo-LVTemplateValue -Value $Value[$key] -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
            }
            return [pscustomobject]$out
        }
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object {
            ConvertTo-LVTemplateValue -Value $_ -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
        })
    }

    $operatorProperties = @($Value.PSObject.Properties | Where-Object { $_.Name -like '$*' })
    if ($operatorProperties.Count -gt 1) {
        throw 'Export template expression objects may contain only one operator.'
    }
    if ($operatorProperties.Count -eq 1 -and @($Value.PSObject.Properties).Count -ne 1) {
        throw 'Export template expression objects may contain only one operator and no extra keys.'
    }
    if ($operatorProperties.Count -eq 1) {
        $operator = $operatorProperties[0].Name
        $spec = $operatorProperties[0].Value
        switch ($operator) {
            '$path' {
                if ($spec -isnot [string]) { throw 'The $path template operator requires a string path.' }
                return ConvertTo-LVTemplateOutputValue -Value (Get-LVTemplatePathValue -Scope $Scope -Path ([string]$spec)) -Budget $Budget -Depth ($Depth + 1)
            }
            '$rootPath' {
                if ($spec -isnot [string]) { throw 'The $rootPath template operator requires a string path.' }
                $root = if ($Scope.PSObject.Properties['root']) { $Scope.root } else { $Scope }
                return ConvertTo-LVTemplateOutputValue -Value (Get-LVTemplatePathValue -Scope $root -Path ([string]$spec)) -Budget $Budget -Depth ($Depth + 1)
            }
            '$map' {
                if (-not $spec.PSObject.Properties['path'] -or -not $spec.PSObject.Properties['projection']) {
                    throw 'The $map template operator requires path and projection.'
                }
                $source = Get-LVTemplatePathValue -Scope $Scope -Path ([string]$spec.path)
                $mapped = New-Object System.Collections.Generic.List[object]
                $index = 0
                foreach ($item in @($source)) {
                    $child = Get-LVTemplateChildScope -Parent $Scope -Item $item -Index $index
                    $mapped.Add((ConvertTo-LVTemplateValue -Value $spec.projection -Scope $child -Budget $Budget -Depth ($Depth + 1))) | Out-Null
                    $index++
                }
                return @($mapped.ToArray())
            }
            '$filter' {
                if (-not $spec.PSObject.Properties['path'] -or -not $spec.PSObject.Properties['where']) {
                    throw 'The $filter template operator requires path and where.'
                }
                $source = Get-LVTemplatePathValue -Scope $Scope -Path ([string]$spec.path)
                $filtered = New-Object System.Collections.Generic.List[object]
                $index = 0
                foreach ($item in @($source)) {
                    $child = Get-LVTemplateChildScope -Parent $Scope -Item $item -Index $index
                    if (Test-LVTemplateTruthy (ConvertTo-LVTemplateValue -Value $spec.where -Scope $child -Budget $Budget -Depth ($Depth + 1))) {
                        $filtered.Add($item) | Out-Null
                    }
                    $index++
                }
                return ConvertTo-LVTemplateOutputValue -Value @($filtered.ToArray()) -Budget $Budget -Depth ($Depth + 1)
            }
            '$concat' {
                $joined = New-Object System.Collections.Generic.List[object]
                foreach ($part in @($spec)) {
                    $evaluated = ConvertTo-LVTemplateValue -Value $part -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
                    foreach ($item in @($evaluated)) { $joined.Add($item) | Out-Null }
                }
                return @($joined.ToArray())
            }
            '$array' {
                return @(ConvertTo-LVTemplateValue -Value $spec -Scope $Scope -Budget $Budget -Depth ($Depth + 1))
            }
            '$if' {
                if (-not $spec.PSObject.Properties['condition'] -or -not $spec.PSObject.Properties['then']) {
                    throw 'The $if template operator requires condition and then.'
                }
                $condition = Test-LVTemplateTruthy (ConvertTo-LVTemplateValue -Value $spec.condition -Scope $Scope -Budget $Budget -Depth ($Depth + 1))
                if ($condition) { return ConvertTo-LVTemplateValue -Value $spec.then -Scope $Scope -Budget $Budget -Depth ($Depth + 1) }
                if ($spec.PSObject.Properties['else']) { return ConvertTo-LVTemplateValue -Value $spec.else -Scope $Scope -Budget $Budget -Depth ($Depth + 1) }
                return $null
            }
            '$equals' {
                $operands = @($spec)
                if ($operands.Count -ne 2) { throw 'The $equals template operator requires exactly two operands.' }
                $left = ConvertTo-LVTemplateValue -Value $operands[0] -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
                $right = ConvertTo-LVTemplateValue -Value $operands[1] -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
                return ($left -eq $right)
            }
            '$contains' {
                $operands = @($spec)
                if ($operands.Count -ne 2) { throw 'The $contains template operator requires exactly two operands.' }
                $haystack = ConvertTo-LVTemplateValue -Value $operands[0] -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
                $needle = ConvertTo-LVTemplateValue -Value $operands[1] -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
                return (@($haystack) -contains $needle)
            }
            '$coalesce' {
                foreach ($candidate in @($spec)) {
                    $evaluated = ConvertTo-LVTemplateValue -Value $candidate -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
                    if ($null -ne $evaluated -and ([string]$evaluated).Length -gt 0) { return $evaluated }
                }
                return $null
            }
            '$count' {
                $evaluated = ConvertTo-LVTemplateValue -Value $spec -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
                return @($evaluated).Count
            }
            '$format' {
                if (-not $spec.PSObject.Properties['format']) { throw 'The $format template operator requires a format string.' }
                if ([string]$spec.format -and ([string]$spec.format).Length -gt 256) {
                    throw 'Export template format strings may not exceed 256 characters.'
                }
                $arguments = @()
                if ($spec.PSObject.Properties['args']) {
                    if (@($spec.args).Count -gt 32) { throw 'Export template format arguments may not exceed 32 values.' }
                    $arguments = @($spec.args | ForEach-Object { ConvertTo-LVTemplateValue -Value $_ -Scope $Scope -Budget $Budget -Depth ($Depth + 1) })
                }
                return [string]::Format([Globalization.CultureInfo]::InvariantCulture, [string]$spec.format, [object[]]$arguments)
            }
            '$literal' {
                return ConvertTo-LVTemplateOutputValue -Value $spec -Budget $Budget -Depth ($Depth + 1)
            }
            default { throw ("Unsupported export template operator '{0}'." -f $operator) }
        }
    }
    if ($Value.PSObject.Properties.Count -gt 0) {
        $out = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties)) {
            $out[$property.Name] = ConvertTo-LVTemplateValue -Value $property.Value -Scope $Scope -Budget $Budget -Depth ($Depth + 1)
        }
        return [pscustomobject]$out
    }
    return $Value
}

function ConvertTo-LVTemplateRecord {
    param(
        [Parameter(Mandatory)]$Model,
        [Parameter(Mandatory)]$Template,
        [AllowNull()]$Budget
    )

    if ($null -eq $Budget) { $Budget = New-LVTemplateBudget }
    $root = Get-LVTemplateRootScope -Model $Model
    $context = [ordered]@{
        context = $Model.Context
        findings = $root.findings
        advisories = $root.advisories
        correlations = $root.correlations
        root = $root
    }
    $sourceName = if ($Template.source) { [string]$Template.source } else { 'findings' }
    $source = Get-LVTemplatePathValue -Scope ([pscustomobject]$context) -Path $sourceName
    if ($sourceName -eq 'timeline') {
        throw "Template source 'timeline' is reserved for the built-in Jsonl adapter."
    }
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($source)) {
        $scope = [ordered]@{
            context = $Model.Context
            record = $item
            item = $item
            root = $root
        }
        if ($item -and $item.PSObject.Properties) {
            foreach ($property in @($item.PSObject.Properties)) {
                if (-not $scope.Contains($property.Name)) { $scope[$property.Name] = $property.Value }
            }
        }
        $value = ConvertTo-LVTemplateValue -Value $Template.projection -Scope ([pscustomobject]$scope) -Budget $Budget
        if ($Template.recordType -and $value -is [pscustomobject] -and -not $value.PSObject.Properties['recordType']) {
            $value | Add-Member -NotePropertyName recordType -NotePropertyValue ([string]$Template.recordType) -Force
        }
        $records.Add($value) | Out-Null
    }
    return @($records.ToArray())
}

function ConvertTo-LVTemplateDocument {
    param(
        [Parameter(Mandatory)]$Model,
        [Parameter(Mandatory)]$Template,
        [AllowNull()]$Budget
    )

    if ($null -eq $Budget) { $Budget = New-LVTemplateBudget }
    if ([string]$Template.projection -like 'builtin:*') {
        switch ([string]$Template.projection) {
            'builtin:ecs' { return ConvertTo-LVEcsExport -Model $Model }
            'builtin:ocsf' { return ConvertTo-LVOcsfExport -Model $Model }
            'builtin:sarif' { return ConvertTo-LVSarifExport -Model $Model }
            'builtin:opentelemetry' { return ConvertTo-LVOtelExport -Model $Model }
            'builtin:stix' { return ConvertTo-LVStixExport -Model $Model }
            'builtin:timeline' { return @(Get-LVTimelineLine -Result $Model.Result -Redact:([bool]$Model.Context.privacy.redacted)) }
            default { throw ("Unsupported built-in export projection '{0}'." -f $Template.projection) }
        }
    }
    $root = Get-LVTemplateRootScope -Model $Model
    $scope = [pscustomobject][ordered]@{
        context = $Model.Context
        findings = $root.findings
        advisories = $root.advisories
        correlations = $root.correlations
        root = $root
    }
    return ConvertTo-LVTemplateValue -Value $Template.projection -Scope $scope -Budget $Budget
}

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
    $suppressed = [bool]($Finding.PSObject.Properties['Suppressed'] -and $Finding.Suppressed)
    $suppression = if ($suppressed) {
        [pscustomobject][ordered]@{
            id = if ($Finding.PSObject.Properties['SuppressionId'] -and $null -ne $Finding.SuppressionId) { [string]$Finding.SuppressionId } else { $null }
            action = if ($Finding.PSObject.Properties['SuppressionAction'] -and $null -ne $Finding.SuppressionAction) { [string]$Finding.SuppressionAction } else { $null }
            statement = if ($Finding.PSObject.Properties['SuppressionStatement'] -and $null -ne $Finding.SuppressionStatement) { [string]$Finding.SuppressionStatement } else { $null }
            created = if ($Finding.PSObject.Properties['SuppressionCreated'] -and $null -ne $Finding.SuppressionCreated) { [string]$Finding.SuppressionCreated } else { $null }
            expiresOn = if ($Finding.PSObject.Properties['SuppressionExpiresOn'] -and $null -ne $Finding.SuppressionExpiresOn) { [string]$Finding.SuppressionExpiresOn } else { $null }
            reviewDueOn = if ($Finding.PSObject.Properties['SuppressionReviewDueOn'] -and $null -ne $Finding.SuppressionReviewDueOn) { [string]$Finding.SuppressionReviewDueOn } else { $null }
            status = if ($Finding.PSObject.Properties['SuppressionStatus'] -and $null -ne $Finding.SuppressionStatus) { [string]$Finding.SuppressionStatus } else { $null }
            signatureHash = if ($Finding.PSObject.Properties['SuppressionSignatureHash'] -and $null -ne $Finding.SuppressionSignatureHash) { [string]$Finding.SuppressionSignatureHash } else { $null }
        }
    } else { $null }
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
        originalVerdict = if ($Finding.PSObject.Properties['OriginalVerdict']) { $Finding.OriginalVerdict } else { $null }
        suppressed = $suppressed
        suppression = $suppression
        signatureCount = if ($Finding.PSObject.Properties['SignatureCount']) { $Finding.SignatureCount } else { 1 }
        signatureKeys = if ($Finding.PSObject.Properties['SignatureKeys']) { @($Finding.SignatureKeys) } else { @($Finding.Key) }
        distinctCodes = if ($Finding.PSObject.Properties['DistinctCodes']) { @($Finding.DistinctCodes) } else { @() }
        burst = if ($Finding.PSObject.Properties['Burst']) { [bool]$Finding.Burst } else { $false }
        burstOnset = if ($Finding.PSObject.Properties['BurstOnset']) { ConvertTo-LVStandardTimestamp $Finding.BurstOnset } else { $null }
        burstCount = if ($Finding.PSObject.Properties['BurstCount']) { $Finding.BurstCount } else { $null }
        burstWindowMinutes = if ($Finding.PSObject.Properties['BurstWindowMinutes']) { $Finding.BurstWindowMinutes } else { $null }
    }
}

function ConvertTo-LVStandardSuppressionStatus {
    param([AllowNull()]$Status)

    if ($null -eq $Status) {
        return [pscustomobject][ordered]@{
            path = $null; status = 'not-requested'; entryCount = 0; activeCount = 0; matchedCount = 0
            unmatchedCount = 0; expiredCount = 0; suppressedFindingCount = 0; asOf = $null
            entries = @(); matched = @(); unmatched = @(); expired = @()
        }
    }
    $projectEntry = {
        param($Entry)
        if ($null -eq $Entry) { return $null }
        [pscustomobject][ordered]@{
            id = $Entry.id
            scope = [pscustomobject][ordered]@{
                signatureHash = $Entry.scope.signatureHash
                machine = $Entry.scope.machine
                windowsBuild = $Entry.scope.windowsBuild
                appVersion = $Entry.scope.appVersion
            }
            action = $Entry.action
            downgradeTo = $Entry.downgradeTo
            statement = $Entry.statement
            created = $Entry.created
            expiresOn = $Entry.expiresOn
            reviewDueOn = $Entry.reviewDueOn
            status = $Entry.status
        }
    }
    return [pscustomobject][ordered]@{
        path = $Status.Path
        status = $Status.Status
        entryCount = [int]$Status.EntryCount
        activeCount = [int]$Status.ActiveCount
        matchedCount = [int]$Status.MatchedCount
        unmatchedCount = [int]$Status.UnmatchedCount
        expiredCount = [int]$Status.ExpiredCount
        suppressedFindingCount = [int]$Status.SuppressedFindingCount
        asOf = ConvertTo-LVStandardTimestamp $Status.AsOf
        entries = @($Status.Entries | Where-Object { $_ } | ForEach-Object { & $projectEntry $_ })
        matched = @($Status.Matched | Where-Object { $_ } | ForEach-Object { & $projectEntry $_ })
        unmatched = @($Status.Unmatched | Where-Object { $_ } | ForEach-Object { & $projectEntry $_ })
        expired = @($Status.Expired | Where-Object { $_ } | ForEach-Object { & $projectEntry $_ })
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
            windowsBuild = if ($Result.PSObject.Properties['WindowsBuild']) { $Result.WindowsBuild } else { $null }
            worstVerdict = $Result.WorstVerdict
            signatureCount = if ($Result.Reduction) { $Result.Reduction.SignatureCount } else { $null }
            incidentSummary = if ($Result.PSObject.Properties['IncidentSummary']) { $Result.IncidentSummary } else { $null }
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
        suppression = ConvertTo-LVStandardSuppressionStatus -Status $(if ($Result.PSObject.Properties['SuppressionStatus']) { $Result.SuppressionStatus } else { $null })
    }
}

function Get-LVStandardModel {
    param([Parameter(Mandatory)]$Result)

    return [pscustomobject][ordered]@{
        result = $Result
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
        windowsBuild = if ($Result.PSObject.Properties['WindowsBuild']) { $Result.WindowsBuild } else { $null }
        suppression = ConvertTo-LVStandardSuppressionStatus -Status $(if ($Result.PSObject.Properties['SuppressionStatus']) { $Result.SuppressionStatus } else { $null })
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
        $standardFinding = ConvertTo-LVStandardFinding -Finding $finding
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
            originalVerdict = $standardFinding.originalVerdict
            suppressed = $standardFinding.suppressed
            suppression = $standardFinding.suppression
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

function ConvertTo-LVTemplateJsonLine {
    param(
        [Parameter(Mandatory)]$Model,
        [Parameter(Mandatory)]$Template,
        [AllowNull()]$Budget
    )

    if ($null -eq $Budget) { $Budget = New-LVTemplateBudget }
    $values = if ([string]$Template.projection -eq 'builtin:timeline') {
        @(Get-LVTimelineLine -Result $Model.Result -Redact:([bool]$Model.Context.privacy.redacted))
    } else {
        @(ConvertTo-LVTemplateRecord -Model $Model -Template $Template -Budget $Budget)
    }
    foreach ($value in $values) {
        $safe = ConvertTo-LVJsonSafeValue -Value $value
        $safe | ConvertTo-Json -Depth 30 -Compress
    }
}

function Write-LVTemplateJsonl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines,
        [switch]$Append
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    if ($Append) {
        $needsSeparator = $false
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $length = (Get-Item -LiteralPath $Path).Length
            if ($length -gt 0) {
                $stream = [System.IO.File]::OpenRead($Path)
                try {
                    $stream.Seek(-1, [System.IO.SeekOrigin]::End) | Out-Null
                    $needsSeparator = ($stream.ReadByte() -ne 10)
                } finally {
                    $stream.Dispose()
                }
            }
        }
        $writer = New-Object System.IO.StreamWriter($Path, $true, $encoding)
        try {
            if ($needsSeparator) { $writer.WriteLine() }
            foreach ($line in $Lines) { $writer.WriteLine($line) }
            $writer.Flush()
        } finally {
            $writer.Dispose()
        }
        return
    }

    $temporary = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N'))
    try {
        $content = if ($Lines.Count -gt 0) { ($Lines -join [Environment]::NewLine) + [Environment]::NewLine } else { '' }
        Write-LVTextFile -Path $temporary -Content $content
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
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

function ConvertTo-LVSarifLevel {
    param([AllowNull()][string]$Verdict)

    $normalized = if ($Verdict) { $Verdict.ToLowerInvariant() } else { '' }
    switch ($normalized) {
        'critical'      { return 'error' }
        'actionable'    { return 'error' }
        'investigate'   { return 'warning' }
        'unknown'       { return 'warning' }
        'informational' { return 'note' }
        'benign'        { return 'none' }
        default         { return 'warning' }
    }
}

function New-LVSarifMessage {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return [pscustomobject][ordered]@{ text = $Text }
}

function ConvertTo-LVSarifRuleDescriptor {
    param([Parameter(Mandatory)]$Rule)

    $descriptor = [ordered]@{ id = [string]$Rule.id }
    $shortDescription = New-LVSarifMessage -Text ([string]$Rule.title)
    $fullDescription = New-LVSarifMessage -Text ([string]$Rule.plain)
    $help = New-LVSarifMessage -Text ([string]$Rule.action)
    if ($shortDescription) { $descriptor.shortDescription = $shortDescription }
    if ($fullDescription) { $descriptor.fullDescription = $fullDescription }
    if ($help) { $descriptor.help = $help }

    $properties = [ordered]@{}
    if ($Rule.verdict) { $properties['logverdict.verdict'] = [string]$Rule.verdict }
    if ($Rule.confidence) { $properties['logverdict.confidence'] = [string]$Rule.confidence }
    $properties['logverdict.status'] = if ($Rule.status) { [string]$Rule.status } else { 'active' }
    if ($Rule.verified) { $properties['logverdict.verified'] = [string]$Rule.verified }
    $references = New-Object System.Collections.Generic.List[string]
    foreach ($reference in @($Rule.references) + @($Rule.reference)) {
        if ($reference -and -not $references.Contains([string]$reference)) { $references.Add([string]$reference) | Out-Null }
    }
    $properties['logverdict.references'] = @($references.ToArray())
    $descriptor.properties = [pscustomobject]$properties
    $descriptor.defaultConfiguration = [pscustomobject][ordered]@{
        enabled = $true
        level = ConvertTo-LVSarifLevel -Verdict ([string]$Rule.verdict)
    }
    return [pscustomobject]$descriptor
}

function ConvertTo-LVSarifLocation {
    param([Parameter(Mandatory)]$Finding)

    $source = [string]$Finding.event.source
    $channel = [string]$Finding.event.channel
    if ($source -eq 'textlog' -and $channel -in @('CBS', 'DISM')) {
        $lineNumber = 1
        $parsedLineNumber = 0
        if ([int]::TryParse([string]$Finding.event.recordId, [ref]$parsedLineNumber) -and $parsedLineNumber -gt 0) {
            $lineNumber = $parsedLineNumber
        }
        $path = if ($channel -eq 'CBS') { 'file:///C:/Windows/Logs/CBS/CBS.log' } else { 'file:///C:/Windows/Logs/DISM/dism.log' }
        return [pscustomobject][ordered]@{
            physicalLocation = [pscustomobject][ordered]@{
                artifactLocation = [pscustomobject][ordered]@{ uri = $path }
                region = [pscustomobject][ordered]@{ startLine = $lineNumber; endLine = $lineNumber }
            }
        }
    }

    $parts = @($source, $channel, [string]$Finding.event.provider, [string]$Finding.event.eventId) | Where-Object { $_ }
    $name = ($parts -join '/')
    if (-not $name) { $name = [string]$Finding.key }
    return [pscustomobject][ordered]@{
        logicalLocations = @([pscustomobject][ordered]@{
            name = $name
            fullyQualifiedName = $name
            kind = 'resource'
        })
    }
}

function ConvertTo-LVSarifResult {
    param(
        [Parameter(Mandatory)]$Finding,
        [Parameter(Mandatory)]$Context,
        [int]$Index
    )

    $verdict = [string]$Finding.verdict
    $kind = if ($verdict -eq 'benign') { 'pass' } elseif ($verdict -eq 'informational') { 'informational' } else { 'fail' }
    $key = [string]$Finding.key
    if (-not $key) { $key = 'finding-{0}' -f $Index }
    $messageText = [string]$Finding.plain
    if (-not $messageText) { $messageText = [string]$Finding.title }
    if (-not $messageText) { $messageText = $key }
    if (-not $messageText) { $messageText = 'LogVerdict finding.' }

    $result = [ordered]@{
        kind = $kind
        level = ConvertTo-LVSarifLevel -Verdict $verdict
        message = [pscustomobject][ordered]@{ text = $messageText }
        locations = @((ConvertTo-LVSarifLocation -Finding $Finding))
        partialFingerprints = [pscustomobject][ordered]@{ 'logverdict.signature' = $key }
    }
    if ($Finding.ruleId) { $result.ruleId = [string]$Finding.ruleId }

    $count = [int]$Finding.event.count
    if ($count -gt 0) { $result.occurrenceCount = $count }
    $provenance = [ordered]@{}
    if ($Finding.event.firstObserved) { $provenance.firstDetectionTimeUtc = [string]$Finding.event.firstObserved }
    if ($Finding.event.lastObserved) { $provenance.lastDetectionTimeUtc = [string]$Finding.event.lastObserved }
    if ($provenance.Count -gt 0) { $result.provenance = [pscustomobject]$provenance }

    $properties = [ordered]@{
        'logverdict.verdict' = $verdict
        'logverdict.signature' = $key
        'logverdict.source' = [string]$Finding.event.source
        'logverdict.channel' = [string]$Finding.event.channel
        'logverdict.provider' = [string]$Finding.event.provider
        'logverdict.eventId' = [string]$Finding.event.eventId
        'logverdict.confidence' = [string]$Finding.confidence
        'logverdict.redacted' = [bool]$Context.privacy.redacted
        'logverdict.references' = @($Finding.references)
        'logverdict.suppressed' = [bool]$Finding.suppressed
    }
    if ($Finding.ruleId) { $properties['logverdict.ruleId'] = [string]$Finding.ruleId }
    if ($Finding.action) { $properties['logverdict.action'] = [string]$Finding.action }
    if ($Finding.originalVerdict) { $properties['logverdict.originalVerdict'] = [string]$Finding.originalVerdict }
    if ($Finding.suppressed -and $Finding.suppression) {
        $result.baselineState = 'unchanged'
        $properties['logverdict.suppressionId'] = [string]$Finding.suppression.id
        $properties['logverdict.suppressionAction'] = [string]$Finding.suppression.action
        $properties['logverdict.suppressionStatement'] = [string]$Finding.suppression.statement
        if ($Finding.suppression.expiresOn) { $properties['logverdict.expiresOn'] = [string]$Finding.suppression.expiresOn }
        if ($Finding.suppression.reviewDueOn) { $properties['logverdict.reviewDueOn'] = [string]$Finding.suppression.reviewDueOn }
        $result.suppressions = @([pscustomobject][ordered]@{
            kind = 'external'
            justification = [string]$Finding.suppression.statement
            properties = [pscustomobject][ordered]@{
                'logverdict.suppressionId' = [string]$Finding.suppression.id
                'logverdict.action' = [string]$Finding.suppression.action
                'logverdict.expiresOn' = if ($Finding.suppression.expiresOn) { [string]$Finding.suppression.expiresOn } else { $null }
                'logverdict.reviewDueOn' = [string]$Finding.suppression.reviewDueOn
            }
        })
    } else {
        $result.baselineState = 'new'
    }
    $result.properties = [pscustomobject]$properties
    return [pscustomobject]$result
}

function ConvertTo-LVSarifExport {
    param([Parameter(Mandatory)]$Model)

    $database = Get-LogVerdictDatabase
    $ruleDescriptors = foreach ($rule in @($database.rules | Where-Object { Test-LVRuleActive -Rule $_ })) {
        ConvertTo-LVSarifRuleDescriptor -Rule $rule
    }
    $results = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($finding in @($Model.Findings)) {
        $results.Add((ConvertTo-LVSarifResult -Finding $finding -Context $Model.Context -Index $index)) | Out-Null
        $index++
    }

    $runProperties = [ordered]@{
        'logverdict.adapter' = 'sarif'
        'logverdict.schemaVersion' = $Model.Context.schemaVersion
        'logverdict.tool' = [string]$Model.Context.scan.tool
        'logverdict.scan' = $Model.Context.scan
        'logverdict.privacy' = $Model.Context.privacy
        'logverdict.coverage' = @($Model.Context.coverage)
        'logverdict.healthProfiles' = @($Model.Context.healthProfiles)
        'logverdict.advisories' = @($Model.Advisories)
        'logverdict.correlations' = @($Model.Correlations)
        'logverdict.suppressions' = $Model.Context.suppression
    }
    $invocation = [ordered]@{ executionSuccessful = $true }
    if ($Model.Context.scan.started) { $invocation.startTimeUtc = [string]$Model.Context.scan.started }
    if ($Model.Context.scan.completed) { $invocation.endTimeUtc = [string]$Model.Context.scan.completed }
    if ($null -ne $Model.Context.scan.exitCode) { $invocation.exitCode = [int]$Model.Context.scan.exitCode }

    $driver = [pscustomobject][ordered]@{
        name = 'LogVerdict'
        version = [string]$Model.Context.scan.version
        informationUri = 'https://github.com/SysAdminDoc/LogVerdict'
        rules = @($ruleDescriptors)
    }
    $run = [pscustomobject][ordered]@{
        tool = [pscustomobject][ordered]@{ driver = $driver }
        language = 'en-US'
        invocations = @([pscustomobject]$invocation)
        results = @($results.ToArray())
        properties = [pscustomobject]$runProperties
    }
    return [pscustomobject][ordered]@{
        '$schema' = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json'
        version = '2.1.0'
        runs = @($run)
        properties = [pscustomobject][ordered]@{
            'logverdict.adapter' = 'sarif'
            'logverdict.schemaVersion' = $Model.Context.schemaVersion
        }
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
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Format,
        [AllowNull()][string]$TemplatePath
    )

    $model = Get-LVStandardModel -Result $Result
    $template = Get-LVStandardTemplate -Format $Format -Path $TemplatePath
    if ([string]$template.kind -ne 'single') {
        throw ("Export template '{0}' is line-oriented; use its JSONL records rather than a single document." -f $Format)
    }
    return ConvertTo-LVTemplateDocument -Model $model -Template $template
}
