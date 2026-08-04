# Bundled Microsoft error-code knowledge. This layer explains a code without
# pretending that a generic status, by itself, proves a root cause.

$script:LVErrorCatalogSchemaVersionMin = 2
$script:LVErrorCatalogSchemaVersionMax = 3
$script:LVErrorCatalogKinds = @('win32', 'hresult', 'bugcheck', 'ntstatus', 'setup', 'windowsupdate')

function Get-LVErrorCatalogSha256 {
    param([Parameter(Mandatory)][string]$Text)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-LVErrorCatalogSourceManifest {
    param([Parameter(Mandatory)]$Sources)

    $items = @($Sources | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) { return '' }
    if ($items[0] -is [string]) { return ($items -join "`n") }
    return (ConvertTo-Json -InputObject $items -Depth 8 -Compress)
}

function Get-LVErrorCatalogEntryCanonicalText {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Hex,
        [Parameter(Mandatory)][int]$SchemaVersion
    )

    if ($SchemaVersion -lt 3) {
        # Preserve the schema-v2 reader contract for old, URL-sourced catalogs.
        return '{0}|{1}|{2}|{3}|{4}' -f $Entry.reference, $Entry.source,
            $Entry.retrieved, $Entry.kind, $Hex
    }

    # Every catalog field rendered as user-facing knowledge is covered here. The
    # normalized object is deliberately omitted because it is re-derived below and
    # compared to the file, rather than trusted as input to the resolver.
    $parts = @(
        [string]$Entry.id
        [string]$Entry.kind
        [string]$Entry.code
        [string]$Hex
        [string]$Entry.name
        [string]$Entry.description
        [string]$Entry.explanation
        [string]$Entry.reference
        [string]$Entry.source
        [string]$Entry.retrieved
        [string]$Entry.applicability
        [string]$Entry.phase
        [string]$Entry.operation
        [string]$Entry.sourceRepository
        [string]$Entry.sourcePath
        [string]$Entry.sourceRevision
        [string]$Entry.licence
        [string]$Entry.sourceDocumentHash
    )
    return ($parts -join '|')
}

function ConvertTo-LVErrorHex {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $text = $Value.Trim()
    if ($text -match '^-[0-9]+$') {
        try {
            $signed = [int64]$text
        } catch {
            return $null
        }
        if ($signed -lt -2147483648) { return $null }
        $number = [uint64]($signed + [int64]4294967296)
        return ('0x{0:X8}' -f [uint32]$number)
    }
    if ($text -notmatch '^(?i:0x)?[0-9a-f]+$') { return $null }
    if ($text -notmatch '^(?i:0x)') { $text = '0x' + $text }
    try {
        $number = [Convert]::ToUInt64($text.Substring(2), 16)
    } catch {
        return $null
    }
    if ($number -gt [uint64]4294967295) { return $null }
    return ('0x{0:X8}' -f [uint32]$number)
}

function Get-LVErrorContextField {
    <#
        Read a typed composite-code field from either the record itself or its
        ErrorContext child. Keeping this accessor tolerant lets old fixtures and
        new collectors travel through the same resolver.
    #>
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $context = $InputObject.PSObject.Properties['ErrorContext']
    if ($context -and $context.Value) {
        $nested = $context.Value.PSObject.Properties[$Name]
        if ($nested) { return $nested.Value }
    }
    return $null
}

function ConvertTo-LVErrorContextText {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    $text = ([string]$Value -replace '\s+', ' ').Trim()
    if ($text) { return $text }
    return $null
}

function New-LVErrorContext {
    <#
        Normalize the invariant fields Windows Update, SetupDiag, and event
        providers expose around a failure. Rendered Message is deliberately only
        a fallback: matching can use these fields when a provider localizes prose
        or has no message resource installed.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$InputObject,
        [AllowNull()][string]$Message,
        [AllowNull()][string]$FallbackMessage,
        [string]$ProviderLocale
    )

    $resultCode = ConvertTo-LVErrorHex -Value ([string](Get-LVErrorContextField -InputObject $InputObject -Name 'ResultCode'))
    if (-not $resultCode) {
        foreach ($name in @('Result', 'FailureCode', 'ErrorCode', 'HResult', 'HRESULT')) {
            $resultCode = ConvertTo-LVErrorHex -Value ([string](Get-LVErrorContextField -InputObject $InputObject -Name $name))
            if ($resultCode) { break }
        }
    }
    $extendCode = ConvertTo-LVErrorHex -Value ([string](Get-LVErrorContextField -InputObject $InputObject -Name 'ExtendCode'))
    if (-not $extendCode) {
        foreach ($name in @('ExtendedErrorCode', 'ExtendedCode', 'ErrorExtendCode', 'Extend')) {
            $extendCode = ConvertTo-LVErrorHex -Value ([string](Get-LVErrorContextField -InputObject $InputObject -Name $name))
            if ($extendCode) { break }
        }
    }

    $rawParts = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($Message, $FallbackMessage)) {
        $line = ConvertTo-LVErrorContextText $value
        if ($line) { $rawParts.Add($line) | Out-Null }
    }
    foreach ($name in @('FailureDetails', 'LogErrorLine', 'FailureData', 'Message')) {
        $value = Get-LVErrorContextField -InputObject $InputObject -Name $name
        foreach ($part in @($value)) {
            $line = ConvertTo-LVErrorContextText $part
            if ($line) { $rawParts.Add($line) | Out-Null }
        }
    }
    $raw = $rawParts -join ' | '
    $codes = New-Object System.Collections.Generic.List[string]
    foreach ($match in [regex]::Matches($raw, '(?i)(?<![0-9a-f])0x[0-9a-f]{1,8}(?![0-9a-f])')) {
        $code = ConvertTo-LVErrorHex -Value $match.Value
        if ($code -and -not $codes.Contains($code)) { $codes.Add($code) | Out-Null }
    }
    if (-not $resultCode -and $codes.Count -gt 0) { $resultCode = $codes[0] }
    if (-not $extendCode -and $codes.Count -gt 1) { $extendCode = $codes[1] }

    $phase = ConvertTo-LVErrorContextText (Get-LVErrorContextField -InputObject $InputObject -Name 'Phase')
    if (-not $phase) {
        foreach ($name in @('LastPhase', 'SetupPhase')) {
            $phase = ConvertTo-LVErrorContextText (Get-LVErrorContextField -InputObject $InputObject -Name $name)
            if ($phase) { break }
        }
    }
    $operation = ConvertTo-LVErrorContextText (Get-LVErrorContextField -InputObject $InputObject -Name 'Operation')
    if (-not $operation) {
        foreach ($name in @('LastOperation', 'SetupOperation')) {
            $operation = ConvertTo-LVErrorContextText (Get-LVErrorContextField -InputObject $InputObject -Name $name)
            if ($operation) { break }
        }
    }
    if (-not $phase) {
        $phaseMatch = [regex]::Match($raw, '(?i)(?:last\s*phase|phase)\s*[:=]\s*([^,;|]+)')
        if ($phaseMatch.Success) { $phase = ConvertTo-LVErrorContextText $phaseMatch.Groups[1].Value }
    }
    if (-not $operation) {
        $operationMatch = [regex]::Match($raw, '(?i)(?:last\s*operation|operation)\s*[:=]\s*([^,;|]+)')
        if ($operationMatch.Success) { $operation = ConvertTo-LVErrorContextText $operationMatch.Groups[1].Value }
    }

    if (-not $ProviderLocale) {
        $ProviderLocale = [string](Get-LVErrorContextField -InputObject $InputObject -Name 'ProviderLocale')
    }
    if (-not $ProviderLocale) {
        foreach ($name in @('Locale', 'Culture', 'Language')) {
            $ProviderLocale = [string](Get-LVErrorContextField -InputObject $InputObject -Name $name)
            if ($ProviderLocale) { break }
        }
    }
    $source = [string](Get-LVErrorContextField -InputObject $InputObject -Name 'Source')
    if (-not $ProviderLocale -and (-not $source -or $source -in @('event', 'reliability'))) {
        $ProviderLocale = [string]$script:LVUICulture
    }

    $fallback = ConvertTo-LVErrorContextText $FallbackMessage
    return [pscustomobject][ordered]@{
        ResultCode      = $resultCode
        ExtendCode      = $extendCode
        Phase           = $phase
        Operation       = $operation
        ProviderLocale  = (ConvertTo-LVErrorContextText $ProviderLocale)
        FallbackMessage = $fallback
    }
}

function Get-LVErrorNormalizedField {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Hex
    )

    $number = [uint64][Convert]::ToUInt32($Hex.Substring(2), 16)
    $signed = [int64]$number
    if ($number -gt 0x7FFFFFFF) { $signed = [int64]$number - 0x100000000 }
    $code = [int]($number -band 0xFFFF)
    $facility = $null
    $severity = 'unknown'
    $customer = $false
    $ntBit = $false
    $win32Code = $null

    if ($Kind -eq 'ntstatus') {
        $facility = [int](($number -shr 16) -band 0x0FFF)
        $severity = @('success', 'informational', 'warning', 'error')[[int](($number -shr 30) -band 0x3)]
        $customer = (($number -band 0x20000000) -ne 0)
        $ntBit = (($number -band 0x10000000) -ne 0)
    } elseif ($Kind -in @('hresult', 'setup', 'windowsupdate')) {
        $facility = [int](($number -shr 16) -band 0x1FFF)
        $severity = if (($number -band 0x80000000) -ne 0) { 'failure' } else { 'success' }
        $customer = (($number -band 0x20000000) -ne 0)
        $ntBit = (($number -band 0x10000000) -ne 0)
        if ($facility -eq 7) { $win32Code = $code }
    } elseif ($Kind -eq 'win32') {
        $code = [int]$number
        $severity = 'status'
        $win32Code = $code
    } elseif ($Kind -eq 'bugcheck') {
        $severity = 'stop-code'
    }

    return [pscustomobject]@{
        family       = $Kind
        hex          = $Hex
        unsigned     = $number
        signed       = $signed
        code         = $code
        facility     = $facility
        severity     = $severity
        customer     = $customer
        ntBit        = $ntBit
        win32Code    = $win32Code
    }
}

function Find-LVErrorCatalogEntry {
    param(
        [Parameter(Mandatory)]$Catalog,
        [Parameter(Mandatory)][string]$Hex,
        [string[]]$PreferredKind
    )

    foreach ($kind in @($PreferredKind)) {
        $key = '{0}|{1}' -f $kind, $Hex.ToUpperInvariant()
        if ($Catalog.LVIndexes.ByKindHex.ContainsKey($key)) { return $Catalog.LVIndexes.ByKindHex[$key] }
    }
    if ($Catalog.LVIndexes.ByHex.ContainsKey($Hex.ToUpperInvariant())) {
        return @($Catalog.LVIndexes.ByHex[$Hex.ToUpperInvariant()])[0]
    }
    return $null
}

function Get-LVErrorCatalog {
    [CmdletBinding()]
    param([string]$Path)

    $cacheKey = if ($Path) { [IO.Path]::GetFullPath($Path) } else { '(default)' }
    if ($script:LVErrorCatalogCache -and $script:LVErrorCatalogCache.ContainsKey($cacheKey)) {
        return $script:LVErrorCatalogCache[$cacheKey]
    }

    $source = $Path
    if (-not $source) {
        $source = Join-Path $script:LVDataDir 'error-codes.json'
    }
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        $raw = Get-Content -LiteralPath $source -Raw -Encoding UTF8
    } elseif (-not $Path -and $script:LVEmbeddedErrorCatalogJson) {
        $raw = $script:LVEmbeddedErrorCatalogJson
        $source = '(embedded)'
    } else {
        throw ("Error catalog not found at '{0}'." -f $source)
    }

    try {
        $catalog = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw ("Error catalog '{0}' is not valid JSON: {1}" -f $source, $_.Exception.Message)
    }
    $version = 0
    try { $version = [int]$catalog.schemaVersion } catch { Write-Verbose 'Error catalog schemaVersion was not an integer.' }
    if ($version -lt $script:LVErrorCatalogSchemaVersionMin -or $version -gt $script:LVErrorCatalogSchemaVersionMax -or -not $catalog.entries) {
        throw ("Error catalog '{0}' has unsupported schemaVersion {1}; expected {2}-{3} with entries." -f $source, $version, $script:LVErrorCatalogSchemaVersionMin, $script:LVErrorCatalogSchemaVersionMax)
    }
    if ([string]$catalog.sourceHash -notmatch '^(?i:[0-9a-f]{64})$') {
        throw ("Error catalog '{0}' has no valid sourceHash." -f $source)
    }
    $sourceManifests = @{}
    if ($version -ge 3) {
        foreach ($manifest in @($catalog.sources)) {
            if ([string]$manifest.repository -notmatch '^MicrosoftDocs/(?:win32|windows-driver-docs|SupportArticles-docs)$' -or
                [string]$manifest.revision -notmatch '^(?i:[0-9a-f]{40})$' -or
                [string]$manifest.licence -ne 'CC-BY-4.0' -or
                [string]$manifest.licenceHash -notmatch '^(?i:[0-9a-f]{64})$') {
                throw ("Error catalog '{0}' contains incomplete licensed source manifest metadata." -f $source)
            }
            if ($sourceManifests.ContainsKey([string]$manifest.repository)) {
                throw ("Error catalog '{0}' contains duplicate source manifest '{1}'." -f $source, $manifest.repository)
            }
            $sourceManifests[[string]$manifest.repository] = $manifest
        }
    } else {
        foreach ($reference in @($catalog.sources)) {
            if ($reference -isnot [string] -or [string]$reference -notmatch '^https?://') {
                throw ("Error catalog '{0}' contains invalid legacy source metadata." -f $source)
            }
        }
    }
    if ([string]$catalog.sourceHash -ine (Get-LVErrorCatalogSha256 -Text (ConvertTo-LVErrorCatalogSourceManifest -Sources $catalog.sources))) {
        throw ("Error catalog '{0}' has a sourceHash that does not match its source manifest." -f $source)
    }

    $ids = @{}
    $kindHex = @{}
    $byHex = @{}
    $byName = @{}
    foreach ($entry in @($catalog.entries)) {
        if (-not $entry.id -or -not $entry.kind -or -not $entry.hex -or -not $entry.name -or -not $entry.description -or -not $entry.explanation -or -not $entry.reference -or -not $entry.retrieved -or -not $entry.sourceHash -or -not $entry.applicability -or -not $entry.normalized) {
            throw ("Error catalog '{0}' contains an incomplete typed entry." -f $source)
        }
        if ($version -ge 3 -and (-not $entry.sourceRepository -or -not $entry.sourcePath -or
            -not $entry.sourceRevision -or -not $entry.licence -or -not $entry.sourceDocumentHash)) {
            throw ("Error catalog '{0}' contains an incomplete licensed typed entry." -f $source)
        }
        $kind = [string]$entry.kind
        if ($script:LVErrorCatalogKinds -notcontains $kind) {
            throw ("Error catalog '{0}' contains unsupported family '{1}'." -f $source, $kind)
        }
        if (-not ([string]$entry.id).StartsWith($kind + ':', [StringComparison]::OrdinalIgnoreCase)) {
            throw ("Error catalog '{0}' entry '{1}' has an id/family mismatch." -f $source, $entry.id)
        }
        if ([string]$entry.sourceHash -notmatch '^(?i:[0-9a-f]{64})$' -or [string]$entry.retrieved -notmatch '^\d{4}-\d{2}-\d{2}$' -or [string]$entry.applicability -notmatch '\S') {
            throw ("Error catalog '{0}' entry '{1}' has invalid provenance metadata." -f $source, $entry.id)
        }
        if ($version -ge 3 -and ([string]$entry.sourceDocumentHash -notmatch '^(?i:[0-9a-f]{64})$' -or
            [string]$entry.licence -ne 'CC-BY-4.0')) {
            throw ("Error catalog '{0}' entry '{1}' has invalid licensed-source provenance metadata." -f $source, $entry.id)
        }
        if ($version -ge 3) {
            $entryRepository = [string]$entry.sourceRepository
            $entryPath = [string]$entry.sourcePath
            if (-not $sourceManifests.ContainsKey($entryRepository) -or
                [string]$entry.sourceRevision -ine [string]$sourceManifests[$entryRepository].revision -or
                $entryPath -notmatch '^(?:desktop-src|windows-driver-docs-pr|support)/' -or
                $entryPath -match '\\' -or $entryPath -match '(?:^|/)\.\.?(?:/|$)') {
                throw ("Error catalog '{0}' entry '{1}' has provenance that does not match its licensed source manifest." -f $source, $entry.id)
            }
        }
        $hex = ConvertTo-LVErrorHex -Value ([string]$entry.hex)
        if (-not $hex) { throw ("Error catalog '{0}' entry '{1}' has an invalid hexadecimal value." -f $source, $entry.id) }
        $sourceHashText = Get-LVErrorCatalogEntryCanonicalText -Entry $entry -Hex $hex -SchemaVersion $version
        $expectedSourceHash = Get-LVErrorCatalogSha256 -Text $sourceHashText
        if ([string]$entry.sourceHash -ine $expectedSourceHash) {
            throw ("Error catalog '{0}' entry '{1}' has a sourceHash that does not match its source metadata." -f $source, $entry.id)
        }
        $normalized = Get-LVErrorNormalizedField -Kind $kind -Hex $hex
        foreach ($field in @('family', 'hex', 'unsigned', 'signed', 'code', 'facility', 'severity', 'customer', 'ntBit', 'win32Code')) {
            if ([string]$entry.normalized.$field -ne [string]$normalized.$field) {
                throw ("Error catalog '{0}' entry '{1}' has inconsistent normalized '{2}'." -f $source, $entry.id, $field)
            }
        }
        $entryHexKey = '{0}|{1}' -f $kind, $hex.ToUpperInvariant()
        if ($ids.ContainsKey([string]$entry.id)) { throw ("Error catalog '{0}' contains duplicate entry '{1}'." -f $source, $entry.id) }
        if ($kindHex.ContainsKey($entryHexKey)) { throw ("Error catalog '{0}' contains duplicate {1} value '{2}'." -f $source, $kind, $hex) }
        $ids[[string]$entry.id] = $true
        $kindHex[$entryHexKey] = $entry
        $hexKey = $hex.ToUpperInvariant()
        if (-not $byHex.ContainsKey($hexKey)) { $byHex[$hexKey] = @() }
        $byHex[$hexKey] += $entry
        $nameKey = ([string]$entry.name).ToUpperInvariant()
        if (-not $byName.ContainsKey($nameKey)) { $byName[$nameKey] = @() }
        $byName[$nameKey] += $entry
        $entry | Add-Member -NotePropertyName 'normalized' -NotePropertyValue $normalized -Force
    }

    $catalog | Add-Member -NotePropertyName 'LVIndexes' -NotePropertyValue ([pscustomobject]@{
        ById       = $ids
        ByKindHex  = $kindHex
        ByHex      = $byHex
        ByName     = $byName
    }) -Force
    if (-not $script:LVErrorCatalogCache) { $script:LVErrorCatalogCache = @{} }
    $script:LVErrorCatalogCache[$cacheKey] = $catalog
    return $catalog
}

function Get-LVErrorCatalogMatch {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Signature)

    try {
        $catalog = Get-LVErrorCatalog
    } catch {
        Write-Verbose ('Error catalog unavailable; leaving the signature unexplained: {0}' -f $_.Exception.Message)
        return $null
    }
    $sample = ''
    foreach ($property in @('SampleMessage', 'Message', 'Key')) {
        if ($Signature.PSObject.Properties[$property] -and $Signature.$property) { $sample += ' ' + [string]$Signature.$property }
    }
    foreach ($property in @('ErrorCode', 'HResult', 'HRESULT', 'Status', 'NtStatus', 'NTSTATUS', 'ResultCode', 'ExtendCode', 'FailureCode', 'Result', 'Code', 'ExitCode', 'Phase', 'Operation')) {
        if ($Signature.PSObject.Properties[$property] -and $null -ne $Signature.$property) { $sample += ' ' + [string]$Signature.$property }
    }
    foreach ($property in @('ResultCode', 'ExtendCode', 'Phase', 'Operation', 'ProviderLocale', 'FallbackMessage')) {
        $value = Get-LVErrorContextField -InputObject $Signature -Name $property
        if ($null -ne $value -and [string]$value) { $sample += ' ' + [string]$value }
    }
    $bugCheckContext = $sample -match '(?i)(?:minidump|bug.?check|stop.?code)'
    $hexMatches = [regex]::Matches($sample, '(?i)(?<![0-9a-f])0x[0-9a-f]{1,8}(?![0-9a-f])')
    foreach ($match in $hexMatches) {
        $hex = ConvertTo-LVErrorHex -Value $match.Value
        if (-not $hex) { continue }
        $preferred = @()
        if ($bugCheckContext) { $preferred += 'bugcheck' }
        $upper = $hex.ToUpperInvariant()
        if ($upper -like '0XC190*' -or $upper -like '0X800F*') { $preferred += 'setup' }
        if ($upper -like '0X8024*') { $preferred += 'windowsupdate' }
        if ($upper -like '0XC*' -or $upper -like '0XE*') { $preferred += 'ntstatus' }
        if ($upper -like '0X8*') { $preferred += 'hresult' }
        if (-not $bugCheckContext -and $hex -notmatch '^0x[0-9A-Fa-f]{8}$') { $preferred += 'win32' }
        $entry = Find-LVErrorCatalogEntry -Catalog $catalog -Hex $hex -PreferredKind $preferred
        if ($entry) {
            $decoded = $null
            if ($entry.kind -eq 'win32' -and $hex -notmatch '^0x000000') { $decoded = $hex }
            return [pscustomobject]@{ Entry=$entry; RawCode=$hex; DecodedFrom=$decoded }
        }
        if ($upper -like '0X8007*') {
            $win32Hex = '0x{0:X8}' -f ([Convert]::ToUInt32($hex.Substring(6), 16))
            $entry = Find-LVErrorCatalogEntry -Catalog $catalog -Hex $win32Hex -PreferredKind @('win32')
            if ($entry) { return [pscustomobject]@{ Entry=$entry; RawCode=$hex; DecodedFrom=$hex } }
        }
    }

    $decimal = [regex]::Matches($sample, '(?i)(?:error|err(?:or)?|code|status|hresult|exception|result)\s*(?:code\s*)?(?:is|was|=|:)\s*(?!0x)(-?\d{1,11})(?!\d)')
    foreach ($match in $decimal) {
        $hex = ConvertTo-LVErrorHex -Value $match.Groups[1].Value
        if (-not $hex) { continue }
        $entry = Find-LVErrorCatalogEntry -Catalog $catalog -Hex $hex -PreferredKind @('win32')
        if ($entry) { return [pscustomobject]@{ Entry=$entry; RawCode=$hex } }
    }
    return $null
}

function Add-LVErrorCatalogContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Signature,
        [AllowNull()]$Match
    )

    if ($null -eq $Match -or $null -eq $Match.Entry) { return }
    $entry = $Match.Entry
    $Signature | Add-Member -NotePropertyName 'ErrorCode' -NotePropertyValue $Match.RawCode -Force
    $Signature | Add-Member -NotePropertyName 'ErrorCatalogKind' -NotePropertyValue $entry.kind -Force
    $Signature | Add-Member -NotePropertyName 'ErrorName' -NotePropertyValue $entry.name -Force
    $Signature | Add-Member -NotePropertyName 'ErrorDescription' -NotePropertyValue $entry.description -Force
    $Signature | Add-Member -NotePropertyName 'ErrorExplanation' -NotePropertyValue $entry.explanation -Force
    $Signature | Add-Member -NotePropertyName 'ErrorReference' -NotePropertyValue $entry.reference -Force
    $Signature | Add-Member -NotePropertyName 'ErrorSource' -NotePropertyValue $entry.source -Force
    $Signature | Add-Member -NotePropertyName 'ErrorApplicability' -NotePropertyValue $entry.applicability -Force
    $Signature | Add-Member -NotePropertyName 'ErrorPhase' -NotePropertyValue $entry.phase -Force
    $Signature | Add-Member -NotePropertyName 'ErrorOperation' -NotePropertyValue $entry.operation -Force
}
