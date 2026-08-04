#requires -Version 5.1

<#!
.SYNOPSIS
Import a licensed provider message-template export into a local LogVerdict cache.

.DESCRIPTION
The normal scan is offline and never downloads provider knowledge. This explicit
tool accepts a normalized JSON or NDJSON export, or downloads one from an operator-
supplied HTTPS URI, validates its source license and bounded event-template shape,
and atomically writes `provider-templates.json` under the per-user LogVerdict data
directory by default. The source corpus is never written to the repository.

The export contract is deliberately small: each entry has a provider, Event ID,
locale, and rendered template. A provider knowledge-base project such as
libyal/winevt-kb can produce this normalized projection without shipping its raw
message-resource corpus in LogVerdict.

.PARAMETER InputPath
Local normalized JSON or NDJSON provider-template export.

.PARAMETER Uri
HTTPS URI for a normalized provider-template export. Network access is explicit;
the normal module scan never calls this tool.

.PARAMETER OutputPath
Cache destination. Defaults to `%LOCALAPPDATA%\LogVerdict\provider-templates.json`.

.PARAMETER SourceName
Human-readable source repository or export name.

.PARAMETER License
License carried by the source repository. Only licenses compatible with the
LogVerdict distribution are accepted.

.PARAMETER SourceRevision
Source commit or immutable export revision.

.PARAMETER ExpectedSha256
Optional SHA-256 pin for the input bytes. This is strongly recommended for URI
imports and is checked before the cache is written.
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [ValidateNotNullOrEmpty()][string]$InputPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Uri')]
    [ValidatePattern('^https://')][uri]$Uri,

    [string]$OutputPath,
    [string]$SourceName,
    [ValidateSet('Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'CC-BY-4.0', 'MIT')]
    [string]$License,
    [string]$SourceRevision,
    [ValidatePattern('^(?i:[0-9a-f]{64})$')][string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
$allowedLicenses = @('Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'CC-BY-4.0', 'MIT')
$maxEntries = 100000
$maxTemplateLength = 32768
$missingMessage = '(no message template registered for this provider on this machine)'

function Get-LVImportProperty {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string[]]$Name)
    if ($null -eq $InputObject) { return $null }
    foreach ($candidate in $Name) {
        $property = $InputObject.PSObject.Properties[$candidate]
        if ($property) { return $property.Value }
    }
    return $null
}

function Get-LVImportSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()) }
    finally { $sha.Dispose() }
}

function ConvertTo-LVImportEventId {
    param([Parameter(Mandatory)][AllowNull()]$Value)
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'Provider template eventId is required.' }
    $number = 0
    try {
        if ($text -match '^(?i:0x)') { $number = [Convert]::ToInt32($text.Substring(2), 16) }
        elseif (-not [int]::TryParse($text, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { throw 'not an integer' }
    } catch { throw ("Provider template eventId '{0}' is not a valid integer." -f $text) }
    if ($number -lt 0 -or $number -gt 65535) { throw ("Provider template eventId '{0}' is outside the Windows Event ID range." -f $text) }
    return [int]$number
}

function Read-LVImportDocument {
    param([Parameter(Mandatory)][string]$Text)

    # Windows PowerShell 5.1's ConvertFrom-Json does not accept a UTF-8 BOM
    # when the input has already been decoded to a .NET string. File exports
    # written by Set-Content -Encoding UTF8 carry that BOM, so remove only the
    # leading marker before trying JSON or NDJSON parsing.
    if ($Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF) {
        $Text = $Text.Substring(1)
    }
    try {
        return [pscustomobject]@{
            Document = ($Text | ConvertFrom-Json -ErrorAction Stop)
            Json = $true
        }
    } catch {
        $lines = New-Object System.Collections.Generic.List[object]
        foreach ($line in ($Text -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $lines.Add(($line | ConvertFrom-Json -ErrorAction Stop)) | Out-Null }
            catch { throw ("Provider template input is neither JSON nor valid NDJSON: {0}" -f $_.Exception.Message) }
        }
        if ($lines.Count -eq 0) { throw 'Provider template input contains no records.' }
        return [pscustomobject]@{
            Document = @($lines.ToArray())
            Json = $false
        }
    }
}

function Get-LVImportEntry {
    param([Parameter(Mandatory)]$Document)
    if ($Document.PSObject.Properties['templates']) { return @($Document.templates | Where-Object { $_ }) }
    if ($Document.PSObject.Properties['entries']) { return @($Document.entries | Where-Object { $_ }) }
    if ($Document -is [Array]) { return @($Document | Where-Object { $_ }) }
    return @($Document)
}

function ConvertTo-LVImportTemplate {
    param([Parameter(Mandatory)]$Document)

    $entries = @(Get-LVImportEntry -Document $Document)
    if ($entries.Count -eq 0) { throw 'Provider template input contains no template entries.' }
    if ($entries.Count -gt $maxEntries) { throw ("Provider template input contains more than the {0} entry limit." -f $maxEntries) }
    $result = New-Object System.Collections.Generic.List[object]
    $keys = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $provider = ([string](Get-LVImportProperty -InputObject $entry -Name @('provider', 'Provider', 'providerName', 'ProviderName'))).Trim()
        if ([string]::IsNullOrWhiteSpace($provider) -or $provider.Length -gt 260) { throw 'Every provider template needs a provider name no longer than 260 characters.' }
        $providerId = ([string](Get-LVImportProperty -InputObject $entry -Name @('providerId', 'ProviderId', 'providerGuid', 'ProviderGuid'))).Trim()
        if ($providerId.Length -gt 128) { throw 'Provider template providerId is too long.' }
        $eventId = ConvertTo-LVImportEventId -Value (Get-LVImportProperty -InputObject $entry -Name @('eventId', 'EventId', 'id', 'Id', 'messageIdentifier', 'MessageIdentifier'))
        $locale = ([string](Get-LVImportProperty -InputObject $entry -Name @('locale', 'Locale', 'language', 'Language'))).Trim()
        if ([string]::IsNullOrWhiteSpace($locale)) { $locale = 'en-US' }
        if ($locale.Length -gt 32) { throw 'Provider template locale is too long.' }
        $template = ([string](Get-LVImportProperty -InputObject $entry -Name @('template', 'Template', 'message', 'Message', 'messageString', 'MessageString'))).Trim()
        if ([string]::IsNullOrWhiteSpace($template) -or $template.Length -gt $maxTemplateLength) { throw ("Provider template for {0}/{1} must contain text no longer than {2} characters." -f $provider, $eventId, $maxTemplateLength) }
        if ($template -like $missingMessage) { throw ("Provider template for {0}/{1} is the local-metadata placeholder, not vendor text." -f $provider, $eventId) }
        $versionValue = Get-LVImportProperty -InputObject $entry -Name @('version', 'Version')
        $version = $null
        if ($null -ne $versionValue -and -not [string]::IsNullOrWhiteSpace([string]$versionValue)) {
            $version = ConvertTo-LVImportEventId -Value $versionValue
        }
        $versionKey = if ($null -eq $version) { '*' } else { [string]$version }
        $key = '{0}|{1}|{2}|{3}|{4}' -f $provider.ToLowerInvariant(), $providerId.ToLowerInvariant(), $eventId, $versionKey, $locale.ToLowerInvariant()
        if (-not $keys.Add($key)) { throw ("Provider template input contains a duplicate entry for {0}/{1}/{2}." -f $provider, $eventId, $locale) }
        $result.Add([ordered]@{
            provider = $provider
            providerId = if ([string]::IsNullOrWhiteSpace($providerId)) { $null } else { $providerId }
            eventId = $eventId
            version = $version
            locale = $locale
            template = $template
        }) | Out-Null
    }
    return @($result.ToArray())
}

$text = $null
$sourceBytes = $null
$inputDocument = $null
if ($PSCmdlet.ParameterSetName -eq 'Uri') {
    if (-not $PSCmdlet.ShouldProcess($Uri.AbsoluteUri, 'download provider-template export')) {
        return [pscustomobject]@{ Action = 'whatif'; OutputPath = $OutputPath; SourceUri = $Uri.AbsoluteUri }
    }
    $response = Invoke-WebRequest -Uri $Uri.AbsoluteUri -UseBasicParsing -ErrorAction Stop
    $text = [string]$response.Content
    $sourceBytes = [Text.Encoding]::UTF8.GetBytes($text)
} else {
    $inputResolved = (Resolve-Path -LiteralPath $InputPath -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $inputResolved -PathType Leaf)) { throw "Provider template input is not a file: $InputPath" }
    $sourceBytes = [IO.File]::ReadAllBytes($inputResolved)
    $text = [Text.Encoding]::UTF8.GetString($sourceBytes)
}

$sourceHash = Get-LVImportSha256 -Bytes $sourceBytes
if ($ExpectedSha256 -and $sourceHash -ine $ExpectedSha256) { throw ("Provider template input SHA-256 mismatch. Expected {0}, got {1}." -f $ExpectedSha256, $sourceHash) }
$parsed = Read-LVImportDocument -Text $text
$inputDocument = $parsed.Document
$templates = @(ConvertTo-LVImportTemplate -Document $inputDocument)
$inputSource = if ($inputDocument -and $inputDocument.PSObject.Properties['source']) { $inputDocument.source } else { $null }
$effectiveName = if ($SourceName) { $SourceName } elseif ($inputSource) { [string](Get-LVImportProperty -InputObject $inputSource -Name @('name', 'repository')) } else { $null }
$effectiveLicense = if ($License) { $License } elseif ($inputSource) { [string](Get-LVImportProperty -InputObject $inputSource -Name @('license', 'licence')) } else { $null }
$effectiveRevision = if ($SourceRevision) { $SourceRevision } elseif ($inputSource) { [string](Get-LVImportProperty -InputObject $inputSource -Name @('revision', 'sourceRevision')) } else { $null }
if (-not $effectiveName) { $effectiveName = 'operator-supplied provider-template export' }
if (-not $effectiveLicense) { $effectiveLicense = 'Apache-2.0' }
if ($allowedLicenses -notcontains $effectiveLicense) { throw ("Provider template source license '{0}' is not permitted." -f $effectiveLicense) }
if (-not $effectiveRevision) { $effectiveRevision = 'operator-export' }
$effectiveUri = if ($Uri) { $Uri.AbsoluteUri } elseif ($inputSource) { [string](Get-LVImportProperty -InputObject $inputSource -Name @('uri', 'url', 'repositoryUri')) } else { $null }

if (-not $OutputPath) {
    $localApplicationData = [string]$env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($localApplicationData)) { $localApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData) }
    if ([string]::IsNullOrWhiteSpace($localApplicationData)) { throw 'LOCALAPPDATA is unavailable; specify -OutputPath.' }
    $OutputPath = Join-Path (Join-Path $localApplicationData 'LogVerdict') 'provider-templates.json'
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $OutputPath
$document = [ordered]@{
    schemaVersion = 1
    name = 'LogVerdict.ProviderTemplates'
    generatedAt = ([DateTimeOffset]::UtcNow).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
    source = [ordered]@{
        name = $effectiveName
        license = $effectiveLicense
        revision = $effectiveRevision
        uri = $effectiveUri
        contentSha256 = $sourceHash
    }
    templates = $templates
}
$json = $document | ConvertTo-Json -Depth 12

if (-not $PSCmdlet.ShouldProcess($OutputPath, 'write provider-template cache')) {
    return [pscustomobject]@{ Action = 'whatif'; OutputPath = $OutputPath; SourceName = $effectiveName; EntryCount = $templates.Count; SourceSha256 = $sourceHash }
}
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) { New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null }
$temporary = Join-Path $outputDirectory ('.provider-templates-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    [IO.File]::WriteAllText($temporary, ($json + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
} finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

[pscustomobject]@{
    Action = 'import'
    OutputPath = $OutputPath
    SourceName = $effectiveName
    License = $effectiveLicense
    Revision = $effectiveRevision
    EntryCount = $templates.Count
    SourceSha256 = $sourceHash
}
