#
# Build the bundled Microsoft Windows error-code catalog from Microsoft Learn.
# The generated catalog is reference knowledge, not a verdict database.
#
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\error-codes.json')
)

$ErrorActionPreference = 'Stop'

function ConvertTo-LVAsciiJson {
    param([Parameter(Mandatory)][string]$Json)

    $builder = New-Object Text.StringBuilder
    foreach ($character in $Json.ToCharArray()) {
        $number = [int][char]$character
        if ($number -le 127) {
            [void]$builder.Append($character)
        } else {
            [void]$builder.Append(('\u{0:X4}' -f $number))
        }
    }
    return $builder.ToString()
}

function ConvertFrom-LVHtmlText {
    param([Parameter(Mandatory)][string]$Html)

    $text = [Net.WebUtility]::HtmlDecode(($Html -replace '(?is)<[^>]+>', ' '))
    return (($text -replace '\s+', ' ').Trim())
}

function Get-LVTextSha256 {
    param([Parameter(Mandatory)][string]$Text)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-LVCanonicalHex {
    param([Parameter(Mandatory)][string]$Value)

    $text = $Value.Trim()
    if ($text -notmatch '^(?i:0x)?[0-9a-f]+$') { throw "Invalid hexadecimal value '$Value'." }
    if ($text -notmatch '^(?i:0x)') { $text = '0x' + $text }
    $number = [Convert]::ToUInt64($text.Substring(2), 16)
    if ($number -gt [uint64]4294967295) { throw "Value '$Value' exceeds 32 bits." }
    return ('0x{0:X8}' -f [uint32]$number)
}

function ConvertTo-LVNormalizedCode {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Hex
    )

    $number = [uint64][Convert]::ToUInt32($Hex.Substring(2), 16)
    $signed = [int64]$number
    if ($number -gt [uint64]2147483647) { $signed = [int64]$number - [int64]4294967296 }
    $code = [int]($number -band 0xFFFF)
    $facility = $null
    $severity = 'unknown'
    $customer = (($number -band 0x20000000) -ne 0)
    $ntBit = (($number -band 0x10000000) -ne 0)
    $win32Code = $null

    if ($Kind -eq 'ntstatus') {
        $facility = [int](($number -shr 16) -band 0x0FFF)
        $severity = @('success', 'informational', 'warning', 'error')[[int](($number -shr 30) -band 3)]
    } elseif ($Kind -in @('hresult', 'setup', 'windowsupdate')) {
        $facility = [int](($number -shr 16) -band 0x1FFF)
        $severity = if (($number -band 0x80000000) -ne 0) { 'failure' } else { 'success' }
        if ($facility -eq 7) { $win32Code = $code }
    } elseif ($Kind -eq 'win32') {
        $code = [int]$number
        $severity = 'status'
        $win32Code = $code
    } elseif ($Kind -eq 'bugcheck') {
        $severity = 'stop-code'
        $customer = $false
        $ntBit = $false
    }

    return [pscustomobject]@{
        family    = $Kind
        hex       = $Hex
        unsigned  = $number
        signed    = $signed
        code      = $code
        facility  = $facility
        severity  = $severity
        customer  = $customer
        ntBit     = $ntBit
        win32Code = $win32Code
    }
}

function ConvertTo-LVTypedSeedEntry {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Hex,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Reference,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Applicability,
        [string]$Phase,
        [string]$Operation
    )

    $canonical = ConvertTo-LVCanonicalHex -Value $Hex
    $entry = [ordered]@{
        id = '{0}:{1}' -f $Kind, $canonical
        kind = $Kind
        code = $canonical
        hex = $canonical
        name = $Name
        description = $Description
        explanation = 'This typed status is context, not a root-cause verdict. Preserve the provider, operation, and surrounding records before choosing remediation.'
        reference = $Reference
        source = $Source
        retrieved = (Get-Date).ToString('yyyy-MM-dd')
        applicability = $Applicability
    }
    if ($Phase) { $entry.phase = $Phase }
    if ($Operation) { $entry.operation = $Operation }
    return [pscustomobject]$entry
}

Set-Alias -Name New-LVTypedSeedEntry -Value ConvertTo-LVTypedSeedEntry -Scope Local

function Get-LVSystemErrorEntry {
    $ranges = @('0-499', '500-999', '1000-1299', '1300-1699', '1700-3999', '4000-5999', '6000-8199', '8200-8999', '9000-11999', '12000-15999')
    $entries = New-Object Collections.Generic.List[object]
    foreach ($range in $ranges) {
        $uri = 'https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--{0}-' -f $range
        $content = (Invoke-WebRequest -UseBasicParsing -Uri $uri -ErrorAction Stop).Content
        $pattern = '(?is)<span id="[^"]+"></span>\s*<span id="[^"]+"></span>\s*<strong>([A-Z][A-Z0-9_]+)</strong>\s*</p>\s*<p>\s*([0-9]+)\s*\((0x[0-9A-Fa-f]+)\)\s*</p>\s*<p>(.*?)</p>'
        foreach ($match in [regex]::Matches($content, $pattern)) {
            $code = [int]$match.Groups[2].Value
            $entries.Add([pscustomobject]@{
                id = 'win32:{0}' -f $code
                kind = 'win32'
                code = $code
                hex = '0x{0:X8}' -f $code
                name = $match.Groups[1].Value
                description = (ConvertFrom-LVHtmlText -Html $match.Groups[4].Value)
                explanation = 'A generic Win32 GetLastError status. Interpret it with the provider, operation and surrounding log message; the numeric code alone is not a root cause.'
                reference = $uri
                source = 'Microsoft Learn WinError.h system error codes'
                retrieved = (Get-Date).ToString('yyyy-MM-dd')
            }) | Out-Null
        }
    }
    return @($entries.ToArray())
}

function Get-LVBugCheckEntry {
    $uri = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2'
    $content = (Invoke-WebRequest -UseBasicParsing -Uri $uri -ErrorAction Stop).Content
    $entries = New-Object Collections.Generic.List[object]
    $pattern = '(?is)<tr>\s*<td>\s*(0x[0-9A-Fa-f]+)\s*</td>\s*<td>\s*<a href="([^"]+)"[^>]*>\s*<strong>([A-Z0-9_]+)</strong>\s*</a>\s*</td>\s*</tr>'
    foreach ($match in [regex]::Matches($content, $pattern)) {
        $hex = ('0x{0:X8}' -f [Convert]::ToUInt32($match.Groups[1].Value.Substring(2), 16))
        $baseUri = [Uri]('https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/')
        $reference = (New-Object System.Uri($baseUri, $match.Groups[2].Value)).AbsoluteUri
        $entries.Add([pscustomobject]@{
            id = 'bugcheck:{0}' -f $hex
            kind = 'bugcheck'
            code = $hex
            hex = $hex
            name = $match.Groups[3].Value
            description = ('Microsoft kernel stop code {0} ({1}).' -f $hex, $match.Groups[3].Value)
            explanation = 'A kernel stop code identifies the class of failure, not necessarily the responsible driver or component. Preserve the dump and inspect its parameters with WinDbg before assigning cause.'
            reference = $reference
            source = 'Microsoft Learn Bug Check Code Reference'
            retrieved = (Get-Date).ToString('yyyy-MM-dd')
        }) | Out-Null
    }
    return @($entries.ToArray())
}

function Get-LVCommonHresultEntry {
    $uri = 'https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values'
    $common = @(
        @{ Name='S_OK'; Hex='0x00000000'; Description='Operation successful' }
        @{ Name='E_ABORT'; Hex='0x80004004'; Description='Operation aborted' }
        @{ Name='E_ACCESSDENIED'; Hex='0x80070005'; Description='General access denied error' }
        @{ Name='E_FAIL'; Hex='0x80004005'; Description='Unspecified failure' }
        @{ Name='E_HANDLE'; Hex='0x80070006'; Description='Handle that is not valid' }
        @{ Name='E_INVALIDARG'; Hex='0x80070057'; Description='One or more arguments are not valid' }
        @{ Name='E_NOINTERFACE'; Hex='0x80004002'; Description='No such interface supported' }
        @{ Name='E_NOTIMPL'; Hex='0x80004001'; Description='Not implemented' }
        @{ Name='E_OUTOFMEMORY'; Hex='0x8007000E'; Description='Failed to allocate necessary memory' }
        @{ Name='E_POINTER'; Hex='0x80004003'; Description='Pointer that is not valid' }
        @{ Name='E_UNEXPECTED'; Hex='0x8000FFFF'; Description='Unexpected failure' }
        @{ Name='E_PENDING'; Hex='0x8000000A'; Description='The data necessary to complete the operation is not yet available' }
        @{ Name='S_FALSE'; Hex='0x00000001'; Description='Operation successful but returned no results' }
    )
    return @($common | ForEach-Object {
        [pscustomobject]@{
            id = 'hresult:{0}' -f $_.Hex.ToUpperInvariant()
            kind = 'hresult'
            code = $_.Hex.ToUpperInvariant()
            hex = $_.Hex.ToUpperInvariant()
            name = $_.Name
            description = $_.Description
            explanation = 'An HRESULT is a 32-bit COM/API result. The high bit indicates failure or success; the facility and code identify the originating API family. Always interpret it with the calling provider.'
            reference = $uri
            source = 'Microsoft Learn Common HRESULT Values'
            retrieved = (Get-Date).ToString('yyyy-MM-dd')
        }
    })
}

$typedReference = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55'
$setupReference = 'https://learn.microsoft.com/en-us/windows/troubleshoot/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes'
$updateReference = 'https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/common-windows-update-errors'
$typedEntries = @(
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000001' -Name 'STATUS_UNSUCCESSFUL' -Description 'The operation failed without a more specific status.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC000000D' -Name 'STATUS_INVALID_PARAMETER' -Description 'A parameter supplied to a system service was invalid.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC000000F' -Name 'STATUS_NO_SUCH_FILE' -Description 'The specified file was not found.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000022' -Name 'STATUS_ACCESS_DENIED' -Description 'Access to the requested object was denied.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000034' -Name 'STATUS_OBJECT_NAME_NOT_FOUND' -Description 'The object name was not found.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000043' -Name 'STATUS_SHARING_VIOLATION' -Description 'A file sharing violation occurred.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC000009A' -Name 'STATUS_INSUFFICIENT_RESOURCES' -Description 'Insufficient system resources existed to complete the operation.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC00000A3' -Name 'STATUS_DEVICE_NOT_READY' -Description 'The device was not ready.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0x80000005' -Name 'STATUS_BUFFER_OVERFLOW' -Description 'The data was too large for the supplied buffer.' -Reference $typedReference -Source 'Microsoft Open Specifications MS-ERREF' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900101' -Name 'MOSETUP_E_PROCESS_CRASH' -Description 'Windows Setup encountered a process failure during upgrade.' -Reference $setupReference -Source 'Microsoft Learn Windows upgrade error codes' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation process)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900200' -Name 'MOSETUP_E_SYSTEM_REQUIREMENT' -Description 'The device does not meet a Windows upgrade system requirement.' -Reference $setupReference -Source 'Microsoft Learn Windows upgrade error codes' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation system-requirement)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900204' -Name 'MOSETUP_E_MIGRATE_DATA_FAILURE' -Description 'Windows Setup could not migrate required data during upgrade.' -Reference $setupReference -Source 'Microsoft Learn Windows upgrade error codes' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation migration)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900208' -Name 'MOSETUP_E_COMPAT_BLOCK' -Description 'An application or device compatibility block prevented the upgrade.' -Reference $setupReference -Source 'Microsoft Learn Windows upgrade error codes' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation compatibility)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC190020E' -Name 'MOSETUP_E_INSTALLDISKSPACE' -Description 'There is not enough disk space to install the upgrade.' -Reference $setupReference -Source 'Microsoft Learn Windows upgrade error codes' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation disk-space)
    (New-LVTypedSeedEntry -Kind setup -Hex '0x800F081F' -Name 'CBS_E_SOURCE_MISSING' -Description 'The servicing stack could not find required source files.' -Reference $setupReference -Source 'Microsoft Learn Windows upgrade error codes' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation servicing)
    (New-LVTypedSeedEntry -Kind setup -Hex '0x800F0922' -Name 'CBS_E_INSTALLERS_FAILED' -Description 'A servicing installer failed while applying the update.' -Reference $setupReference -Source 'Microsoft Learn Windows upgrade error codes' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation servicing)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x80240017' -Name 'WU_E_NOT_APPLICABLE' -Description 'The update is not applicable to the computer.' -Reference $updateReference -Source 'Microsoft Learn common Windows Update errors' -Applicability 'Windows Update client' -Phase update -Operation applicability)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x8024001E' -Name 'WU_E_SERVICE_STOP' -Description 'The Windows Update service stopped during the operation.' -Reference $updateReference -Source 'Microsoft Learn common Windows Update errors' -Applicability 'Windows Update client' -Phase update -Operation service)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x80240022' -Name 'WU_E_ALL_UPDATES_FAILED' -Description 'All updates in the operation failed.' -Reference $updateReference -Source 'Microsoft Learn common Windows Update errors' -Applicability 'Windows Update client' -Phase update -Operation installation)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x8024402C' -Name 'WU_E_PT_WINHTTP_NAME_NOT_RESOLVED' -Description 'The update client could not resolve the proxy or server name.' -Reference $updateReference -Source 'Microsoft Learn common Windows Update errors' -Applicability 'Windows Update client' -Phase update -Operation transport)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x8024A105' -Name 'WU_E_UNKNOWN' -Description 'Windows Update returned an unspecified client error.' -Reference $updateReference -Source 'Microsoft Learn common Windows Update errors' -Applicability 'Windows Update client' -Phase update -Operation client)
)

$entries = @(Get-LVSystemErrorEntry) + @(Get-LVBugCheckEntry) + @(Get-LVCommonHresultEntry) + $typedEntries
$unique = @($entries | Group-Object id | ForEach-Object { $_.Group | Select-Object -First 1 })
if ($unique.Count -lt 3000) {
    throw ('Microsoft catalog scrape returned only {0} unique entries; refusing to publish an incomplete catalog.' -f $unique.Count)
}

$sources = @(
    'https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes'
    'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2'
    'https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values'
    $typedReference
    $setupReference
    $updateReference
)
$minimumByKind = @{ win32 = 2500; bugcheck = 300; hresult = 13; ntstatus = 9; setup = 7; windowsupdate = 5 }
foreach ($family in $minimumByKind.Keys) {
    $count = @($unique | Where-Object { $_.kind -eq $family }).Count
    if ($count -lt $minimumByKind[$family]) {
        throw ("Microsoft catalog family '{0}' returned only {1} entries; expected at least {2}." -f $family, $count, $minimumByKind[$family])
    }
}
$expectedIds = @('win32:5', 'bugcheck:0x00000124', 'hresult:0X80070005', 'ntstatus:0xC0000022', 'setup:0xC1900101', 'windowsupdate:0x80240017')
foreach ($expectedId in $expectedIds) {
    if (@($unique | Where-Object { $_.id -ieq $expectedId }).Count -ne 1) {
        throw ("Microsoft catalog is missing expected typed entry '{0}'." -f $expectedId)
    }
}

$retrieved = (Get-Date).ToString('yyyy-MM-dd')
foreach ($entry in $unique) {
    $entry.hex = ConvertTo-LVCanonicalHex -Value ([string]$entry.hex)
    if (-not $entry.retrieved) { $entry.retrieved = $retrieved }
    if (-not $entry.applicability) {
        $entry.applicability = switch ([string]$entry.kind) {
            'win32' { 'Windows APIs and system components' }
            'bugcheck' { 'Windows kernel and crash dumps' }
            'hresult' { 'Windows COM and API callers' }
            'ntstatus' { 'Windows kernel and native subsystems' }
            'setup' { 'Windows Setup and servicing' }
            'windowsupdate' { 'Windows Update client' }
        }
    }
    $entry.sourceHash = Get-LVTextSha256 -Text ('{0}|{1}|{2}|{3}|{4}' -f $entry.reference, $entry.source, $entry.retrieved, $entry.kind, $entry.hex)
    $entry.normalized = ConvertTo-LVNormalizedCode -Kind $entry.kind -Hex $entry.hex
}
$sourceHash = Get-LVTextSha256 -Text ($sources -join "`n")

$catalog = [pscustomobject]@{
    schemaVersion = 2
    name = 'Microsoft Windows error and stop-code reference catalog'
    updated = (Get-Date).ToString('yyyy-MM-dd')
    notes = 'Reference knowledge from Microsoft Learn. A catalog match explains a code but does not by itself establish root cause or verdict severity.'
    sources = $sources
    sourceHash = $sourceHash
    entries = @($unique | Sort-Object kind,code)
}

$json = $catalog | ConvertTo-Json -Depth 8
$json = ConvertTo-LVAsciiJson -Json $json
$fullPath = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $fullPath
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
[IO.File]::WriteAllText($fullPath, $json, (New-Object Text.UTF8Encoding($false)))
Write-Output ('Wrote {0} catalog entries to {1}' -f $unique.Count, $fullPath)
