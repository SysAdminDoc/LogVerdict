# Bundled Microsoft error-code knowledge. This layer explains a code without
# pretending that a generic status, by itself, proves a root cause.

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
    if ([int]$catalog.schemaVersion -ne 1 -or -not $catalog.entries) {
        throw ("Error catalog '{0}' has an unsupported schema or no entries." -f $source)
    }

    $ids = @{}
    foreach ($entry in @($catalog.entries)) {
        if (-not $entry.id -or -not $entry.kind -or -not $entry.hex -or -not $entry.name -or -not $entry.description -or -not $entry.reference) {
            throw ("Error catalog '{0}' contains an incomplete entry." -f $source)
        }
        if ($ids.ContainsKey([string]$entry.id)) {
            throw ("Error catalog '{0}' contains duplicate entry '{1}'." -f $source, $entry.id)
        }
        $ids[[string]$entry.id] = $true
    }

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
    $entries = @($catalog.entries)
    $sample = ''
    foreach ($property in @('SampleMessage', 'Message', 'Key')) {
        if ($Signature.PSObject.Properties[$property] -and $Signature.$property) {
            $sample += ' ' + [string]$Signature.$property
        }
    }

    # Crash signatures have a stable Minidump/0x... identity even after prose is
    # normalized. Match those before considering generic message tokens.
    $bugCheck = [regex]::Match($sample, '(?i)(?:minidump|bug.?check|stop.?code)[^0-9a-f]*(0x[0-9a-f]{2,8})')
    if ($bugCheck.Success) {
        $hex = ('0x{0:X8}' -f [Convert]::ToUInt32($bugCheck.Groups[1].Value.Substring(2), 16))
        $entry = @($entries | Where-Object { $_.kind -eq 'bugcheck' -and $_.hex -eq $hex } | Select-Object -First 1)
        if ($entry.Count -gt 0) { return [pscustomobject]@{ Entry=$entry[0]; RawCode=$hex } }
    }

    # HRESULTs and NTSTATUS values are conventionally eight hexadecimal digits and
    # have a high bit set. Prefer an exact common HRESULT before decoding FACILITY_WIN32.
    foreach ($match in [regex]::Matches($sample, '(?i)(?<![0-9a-f])0x8[0-9a-f]{7}(?![0-9a-f])')) {
        $hex = $match.Value.ToUpperInvariant()
        $entry = @($entries | Where-Object { $_.kind -eq 'hresult' -and $_.hex -eq $hex } | Select-Object -First 1)
        if ($entry.Count -gt 0) { return [pscustomobject]@{ Entry=$entry[0]; RawCode=$hex } }

        # HRESULT_FROM_WIN32 preserves the original Win32 code in the low 16 bits.
        if ($hex.Substring(0, 6) -eq '0X8007') {
            $code = [Convert]::ToInt32($hex.Substring(6), 16)
            $entry = @($entries | Where-Object { $_.kind -eq 'win32' -and [int]$_.code -eq $code } | Select-Object -First 1)
            if ($entry.Count -gt 0) { return [pscustomobject]@{ Entry=$entry[0]; RawCode=$hex; DecodedFrom=$hex } }
        }
    }

    # Text logs commonly write a decimal Win32 status beside Error, Code, Status or
    # HRESULT. Do not use the structured event Id: an EventID is not a Win32 error.
    $decimal = [regex]::Match($sample, '(?i)(?:error|err(?:or)?|code|status|hresult|exception)\s*(?:code\s*)?(?:is|was|=|:)\s*(\d{1,5})(?!\d)')
    if ($decimal.Success) {
        $code = [int]$decimal.Groups[1].Value
        $entry = @($entries | Where-Object { $_.kind -eq 'win32' -and [int]$_.code -eq $code } | Select-Object -First 1)
        if ($entry.Count -gt 0) { return [pscustomobject]@{ Entry=$entry[0]; RawCode=('0x{0:X8}' -f $code) } }
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
