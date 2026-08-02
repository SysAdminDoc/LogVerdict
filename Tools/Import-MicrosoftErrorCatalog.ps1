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

$entries = @(Get-LVSystemErrorEntry) + @(Get-LVBugCheckEntry) + @(Get-LVCommonHresultEntry)
$unique = @($entries | Group-Object id | ForEach-Object { $_.Group | Select-Object -First 1 })
if ($unique.Count -lt 3000) {
    throw ('Microsoft catalog scrape returned only {0} unique entries; refusing to publish an incomplete catalog.' -f $unique.Count)
}

$catalog = [pscustomobject]@{
    schemaVersion = 1
    name = 'Microsoft Windows error and stop-code reference catalog'
    updated = (Get-Date).ToString('yyyy-MM-dd')
    notes = 'Reference knowledge from Microsoft Learn. A catalog match explains a code but does not by itself establish root cause or verdict severity.'
    sources = @(
        'https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes'
        'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2'
        'https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values'
    )
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
