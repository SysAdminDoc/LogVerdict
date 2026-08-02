# Bundled Microsoft error-code knowledge. This layer explains a code without
# pretending that a generic status, by itself, proves a root cause.

$script:LVErrorCatalogSchemaVersionMin = 2
$script:LVErrorCatalogSchemaVersionMax = 2
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

function ConvertTo-LVErrorHex {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $text = $Value.Trim()
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
    if ([string]$catalog.sourceHash -ine (Get-LVErrorCatalogSha256 -Text (@($catalog.sources) -join "`n"))) {
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
        $hex = ConvertTo-LVErrorHex -Value ([string]$entry.hex)
        if (-not $hex) { throw ("Error catalog '{0}' entry '{1}' has an invalid hexadecimal value." -f $source, $entry.id) }
        $expectedSourceHash = Get-LVErrorCatalogSha256 -Text ('{0}|{1}|{2}|{3}|{4}' -f $entry.reference, $entry.source, $entry.retrieved, $entry.kind, $hex)
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
    foreach ($property in @('ErrorCode', 'HResult', 'HRESULT', 'Status', 'NtStatus', 'NTSTATUS', 'ExtendCode', 'FailureCode', 'Result', 'Code', 'ExitCode')) {
        if ($Signature.PSObject.Properties[$property] -and $null -ne $Signature.$property) { $sample += ' ' + [string]$Signature.$property }
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

    $decimal = [regex]::Matches($sample, '(?i)(?:error|err(?:or)?|code|status|hresult|exception|result)\s*(?:code\s*)?(?:is|was|=|:)\s*(?!0x)(\d{1,10})(?!\d)')
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
}
