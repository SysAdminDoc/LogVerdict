# Versioned, opt-in provider extensions. Providers contribute normalized evidence only;
# they never receive the curated rule database and cannot supply verdicts or rule IDs.

$script:LVProviderSchemaVersion = 1
$script:LVProviderCapabilities = @('collect', 'normalize', 'coverage', 'redaction', 'fixtures', 'reportProjection')

function Get-LVProviderHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-LVProviderProperty {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function ConvertTo-LVProviderStructuredData {
    param([AllowNull()]$StructuredData, [AllowNull()][string]$MachineName)

    if (-not $StructuredData) { return $null }
    $copy = [ordered]@{}
    foreach ($section in @('EventData', 'UserData')) {
        $source = $StructuredData.PSObject.Properties[$section]
        if (-not $source -or -not $source.Value) { continue }
        $values = [ordered]@{}
        foreach ($property in @($source.Value.PSObject.Properties)) {
            $sensitiveName = [string]$property.Name -match '(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)'
            $values[$property.Name] = if ($sensitiveName) {
                @('<SECRET>')
            } else {
                @(@($property.Value) | ForEach-Object {
                    ConvertTo-LVRedactedText -Text ([string]$_) -MachineName $MachineName
                })
            }
        }
        $copy[$section] = [pscustomobject]$values
    }
    return [pscustomobject]$copy
}

function Read-LVProviderPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (Test-Path -LiteralPath $resolved -PathType Container) {
        $resolved = Join-Path $resolved 'manifest.json'
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Provider manifest not found: $Path"
    }

    $manifest = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne $script:LVProviderSchemaVersion) {
        throw ("Provider manifest schemaVersion {0} is unsupported; expected {1}." -f $manifest.schemaVersion, $script:LVProviderSchemaVersion)
    }
    if ([string]$manifest.id -notmatch '^[a-z0-9][a-z0-9.-]{1,62}$') { throw 'Provider id is not a stable lowercase identifier.' }
    if ([string]$manifest.name -notmatch '^.{1,128}$') { throw 'Provider name is required and must be at most 128 characters.' }
    if ([string]$manifest.version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') { throw 'Provider version is not valid SemVer.' }
    if (@($manifest.permissions) -notcontains 'read-only' -or @($manifest.permissions).Count -ne 1) {
        throw 'Provider permissions must contain only read-only.'
    }
    $capabilities = @($manifest.capabilities | ForEach-Object { [string]$_ } | Select-Object -Unique)
    foreach ($capability in @('collect', 'normalize', 'coverage', 'redaction')) {
        if ($capabilities -notcontains $capability) { throw "Provider is missing required capability '$capability'." }
    }
    foreach ($capability in $capabilities) {
        if ($script:LVProviderCapabilities -notcontains $capability) { throw "Provider capability '$capability' is unsupported." }
    }
    $entrypointRelative = [string]$manifest.entrypoint
    if ([string]::IsNullOrWhiteSpace($entrypointRelative) -or [IO.Path]::IsPathRooted($entrypointRelative) -or
        $entrypointRelative -match '(^|[\\/])\.\.([\\/]|$)') {
        throw 'Provider entrypoint must be a relative path inside the provider directory.'
    }
    $entrypoint = Join-Path (Split-Path -Parent $resolved) $entrypointRelative
    if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) { throw "Provider entrypoint not found: $entrypointRelative" }
    $actualHash = Get-LVProviderHash -Path $entrypoint
    if ($actualHash -ine [string]$manifest.entrypointSha256) { throw 'Provider entrypoint SHA-256 does not match its manifest pin.' }

    $projectionFields = @()
    if ($manifest.PSObject.Properties['reportProjection'] -and $manifest.reportProjection) {
        $projectionFields = @($manifest.reportProjection.fields | ForEach-Object { [string]$_ } | Select-Object -Unique)
        if ($projectionFields.Count -gt 32 -or @($projectionFields | Where-Object { $_ -notmatch '^[A-Za-z][A-Za-z0-9_.-]{0,63}$' }).Count -gt 0) {
            throw 'Provider reportProjection fields must be at most 32 stable identifiers.'
        }
        if ($capabilities -notcontains 'reportProjection' -and $projectionFields.Count -gt 0) {
            throw 'Provider reportProjection fields require the reportProjection capability.'
        }
    }

    $fixtures = New-Object System.Collections.Generic.List[object]
    if ($manifest.PSObject.Properties['fixtures'] -and $manifest.fixtures) {
        if ($capabilities -notcontains 'fixtures') { throw 'Provider fixtures require the fixtures capability.' }
        if (@($manifest.fixtures).Count -gt 128) { throw 'Provider fixtures are limited to 128 entries.' }
        foreach ($fixture in @($manifest.fixtures)) {
            $fixtureId = [string](Get-LVProviderProperty -InputObject $fixture -Name 'id')
            $fixtureRelative = [string](Get-LVProviderProperty -InputObject $fixture -Name 'path')
            $fixtureHash = [string](Get-LVProviderProperty -InputObject $fixture -Name 'sha256')
            if ($fixtureId -notmatch '^[a-z0-9][a-z0-9.-]{0,63}$') { throw 'Provider fixture id is not a stable lowercase identifier.' }
            if ([string]::IsNullOrWhiteSpace($fixtureRelative) -or [IO.Path]::IsPathRooted($fixtureRelative) -or
                $fixtureRelative -match '(^|[\\/])\.\.([\\/]|$)') {
                throw "Provider fixture '$fixtureId' path must be relative to the provider directory."
            }
            if ($fixtureHash -notmatch '^[A-Fa-f0-9]{64}$') { throw "Provider fixture '$fixtureId' SHA-256 is invalid." }
            $fixturePath = Join-Path (Split-Path -Parent $resolved) $fixtureRelative
            if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) { throw "Provider fixture not found: $fixtureRelative" }
            if ((Get-LVProviderHash -Path $fixturePath) -ine $fixtureHash) { throw "Provider fixture '$fixtureId' SHA-256 does not match its manifest pin." }
            $fixtures.Add([pscustomobject][ordered]@{
                Id = $fixtureId
                RelativePath = $fixtureRelative
                Path = (Resolve-Path -LiteralPath $fixturePath).Path
                SHA256 = $fixtureHash.ToLowerInvariant()
            }) | Out-Null
        }
    }

    return [pscustomobject][ordered]@{
        ManifestPath = $resolved
        EntrypointPath = (Resolve-Path -LiteralPath $entrypoint).Path
        Manifest = $manifest
        Id = [string]$manifest.id
        Name = [string]$manifest.name
        Version = [string]$manifest.version
        Capabilities = $capabilities
        ProjectionFields = $projectionFields
        Fixtures = @($fixtures.ToArray())
        Trust = 'untrusted'
    }
}

function ConvertTo-LVProviderCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Provider,
        [AllowNull()][object[]]$Coverage,
        [int]$RecordCount,
        [int]$RejectedCount,
        [AllowNull()][string]$BudgetStop,
        [Parameter(Mandatory)]$CollectionBudget
    )

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($Coverage | Where-Object { $_ })) {
        $status = [string](Get-LVProviderProperty -InputObject $item -Name 'status')
        $observed = 0
        [void][int]::TryParse([string](Get-LVProviderProperty -InputObject $item -Name 'observedRecords'), [ref]$observed)
        $status = ConvertTo-LVCoverageStatus -Status $status -ObservedRecords $observed
        $reason = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $item -Name 'reason')) -MachineName $env:COMPUTERNAME
        $rows.Add((New-LVCoverageRecord -Source 'provider' -Kind 'extension' -Name (('{0}/{1}' -f $Provider.Id, [string](Get-LVProviderProperty -InputObject $item -Name 'name'))) `
                -Status $status -Reason $reason -ObservedRecords $observed -CollectionBudget $CollectionBudget -Origin 'provider')) | Out-Null
    }
    if ($rows.Count -eq 0) {
        $status = if ($BudgetStop) { $BudgetStop } elseif ($RecordCount -gt 0) { 'readable' } elseif ($RejectedCount -gt 0) { 'unreadable' } else { 'empty' }
        $reason = if ($BudgetStop) { ('The shared collection budget stopped provider {0}.' -f $Provider.Id) } elseif ($RejectedCount -gt 0) { ('{0} provider record(s) were rejected by the normalized record contract.' -f $RejectedCount) } else { 'The provider returned no records.' }
        $rows.Add((New-LVCoverageRecord -Source 'provider' -Kind 'extension' -Name $Provider.Id -Status $status `
                -Reason $reason -ObservedRecords $RecordCount -CollectionBudget $CollectionBudget -Origin 'provider')) | Out-Null
    }
    if ($BudgetStop -and $rows.Count -gt 0 -and @($rows | Where-Object { $_.Status -eq $BudgetStop }).Count -eq 0) {
        $rows.Add((New-LVCoverageRecord -Source 'provider' -Kind 'extension' -Name $Provider.Id -Status $BudgetStop `
                -Reason ('The shared collection budget stopped provider {0}; records are partial.' -f $Provider.Id) `
                -ObservedRecords $RecordCount -CollectionBudget $CollectionBudget -Origin 'provider')) | Out-Null
    }
    return @($rows.ToArray())
}

function ConvertTo-LVProviderResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Provider,
        [Parameter(Mandatory)]$Payload,
        [Parameter(Mandatory)]$CollectionBudget
    )

    $rawRecords = @(Get-LVProviderProperty -InputObject $Payload -Name 'records' | Where-Object { $_ })
    $normalized = New-Object System.Collections.Generic.List[object]
    $rejected = 0
    $budgetStop = $null
    foreach ($raw in $rawRecords) {
        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        if ($budgetStop) { break }
        $eventId = Get-LVProviderProperty -InputObject $raw -Name 'id'
        if ($null -eq $eventId) { $eventId = Get-LVProviderProperty -InputObject $raw -Name 'eventId' }
        $parsedId = 0
        if (-not [int]::TryParse([string]$eventId, [ref]$parsedId)) { $rejected++; continue }
        $message = [string](Get-LVProviderProperty -InputObject $raw -Name 'message')
        if ($null -eq $message) { $message = '' }
        $channel = [string](Get-LVProviderProperty -InputObject $raw -Name 'channel')
        if ([string]::IsNullOrWhiteSpace($channel)) { $channel = 'records' }
        $channel = ConvertTo-LVRedactedText -Text $channel -MachineName $env:COMPUTERNAME
        $time = $null
        $rawTime = Get-LVProviderProperty -InputObject $raw -Name 'timeCreated'
        if ($rawTime) {
            $parsedTime = [datetime]::MinValue
            if ([datetime]::TryParse(
                    [string]$rawTime,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind,
                    [ref]$parsedTime)) {
                # Event-log, text-log, and Reliability timestamps are local wall-clock
                # values internally. RoundtripKind preserves an explicitly zoned value;
                # only UTC needs projecting into that shared local basis. An unspecified
                # value is already a local wall-clock value and must not be shifted.
                $time = if ($parsedTime.Kind -eq [DateTimeKind]::Utc) {
                    $parsedTime.ToLocalTime()
                } else { $parsedTime }
            }
        }
        $structured = Get-LVProviderProperty -InputObject $raw -Name 'structuredData'
        if ($structured) { $structured = ConvertTo-LVProviderStructuredData -StructuredData (ConvertTo-LVStructuredDataObject -InputObject $structured) -MachineName $env:COMPUTERNAME }
        $level = 0
        [void][int]::TryParse([string](Get-LVProviderProperty -InputObject $raw -Name 'level'), [ref]$level)
        $record = [pscustomobject][ordered]@{
            Source = 'event'
            Channel = ('extension:{0}/{1}' -f $Provider.Id, $channel)
            Provider = ('extension:{0}' -f $Provider.Id)
            ProviderId = $Provider.Id
            Id = $parsedId
            Level = $level
            LevelName = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $raw -Name 'levelName')) -MachineName $env:COMPUTERNAME
            TimeCreated = $time
            RecordId = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $raw -Name 'recordId')) -MachineName $env:COMPUTERNAME
            Message = ConvertTo-LVRedactedText -Text $message -MachineName $env:COMPUTERNAME
            StructuredData = $structured
            ProviderExtension = $Provider.Id
            ResultCode = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $raw -Name 'resultCode')) -MachineName $env:COMPUTERNAME
            ExtendCode = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $raw -Name 'extendCode')) -MachineName $env:COMPUTERNAME
            Phase = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $raw -Name 'phase')) -MachineName $env:COMPUTERNAME
            Operation = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $raw -Name 'operation')) -MachineName $env:COMPUTERNAME
            ProviderLocale = [string](Get-LVProviderProperty -InputObject $raw -Name 'providerLocale')
            FallbackMessage = ConvertTo-LVRedactedText -Text ([string](Get-LVProviderProperty -InputObject $raw -Name 'fallbackMessage')) -MachineName $env:COMPUTERNAME
        }
        $estimatedBytes = 256 + [Text.Encoding]::UTF8.GetByteCount(($record | ConvertTo-Json -Depth 6 -Compress))
        if (([int64]$CollectionBudget.BytesRead + $estimatedBytes) -gt [int64]$CollectionBudget.MaxBytes) {
            $budgetStop = 'truncated'
            break
        }
        $normalized.Add($record) | Out-Null
        Add-LVCollectionBudgetUsage -Budget $CollectionBudget -Bytes $estimatedBytes -Records 1
    }

    $projectionRows = New-Object System.Collections.Generic.List[object]
    $rawProjection = Get-LVProviderProperty -InputObject $Payload -Name 'reportProjection'
    if ($rawProjection -and $Provider.ProjectionFields.Count -gt 0) {
        $fields = [ordered]@{}
        foreach ($name in $Provider.ProjectionFields) {
            $value = Get-LVProviderProperty -InputObject $rawProjection -Name $name
            if ($null -ne $value) {
                $fields[$name] = if ($name -match '(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)') {
                    '<SECRET>'
                } else {
                    ConvertTo-LVRedactedText -Text ([string]$value) -MachineName $env:COMPUTERNAME
                }
            }
        }
        if ($fields.Count -gt 0) {
            $projectionRows.Add([pscustomobject][ordered]@{ ProviderId=$Provider.Id; Fields=[pscustomobject]$fields }) | Out-Null
        }
    }

    return [pscustomobject][ordered]@{
        ProviderId = $Provider.Id
        ProviderVersion = $Provider.Version
        Trust = $Provider.Trust
        Records = @($normalized.ToArray())
        Coverage = ConvertTo-LVProviderCoverage -Provider $Provider -Coverage @(Get-LVProviderProperty -InputObject $Payload -Name 'coverage') `
            -RecordCount $normalized.Count -RejectedCount $rejected -BudgetStop $budgetStop -CollectionBudget $CollectionBudget
        ReportProjection = @($projectionRows.ToArray())
        RejectedRecords = $rejected
        BudgetStop = $budgetStop
    }
}

function Invoke-LVProvider {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Provider,
        [Parameter(Mandatory)][hashtable]$Context,
        [AllowNull()]$CollectionBudget,
        [switch]$AllowUntrustedProvider
    )

    $plan = if ($Provider.PSObject.Properties['EntrypointPath']) { $Provider } else { Read-LVProviderPlan -Path ([string]$Provider) }
    if (-not $AllowUntrustedProvider) {
        throw ("Provider '{0}' is untrusted. Re-run with -AllowUntrustedProvider after reviewing its pinned entrypoint." -f $plan.Id)
    }
    $payloads = @(& $plan.EntrypointPath -Context $Context)
    $payload = @($payloads | Where-Object { $_ -and $_.PSObject.Properties['schemaVersion'] -and $_.PSObject.Properties['records'] } | Select-Object -First 1)
    if ($payload.Count -ne 1) { throw ("Provider '{0}' did not return exactly one schema v1 result object." -f $plan.Id) }
    if ([int]$payload[0].schemaVersion -ne $script:LVProviderSchemaVersion) { throw ("Provider '{0}' returned an unsupported result schema." -f $plan.Id) }
    $budget = if ($CollectionBudget) { $CollectionBudget } else { $Context.CollectionBudget }
    return ConvertTo-LVProviderResult -Provider $plan -Payload $payload[0] -CollectionBudget $budget
}
