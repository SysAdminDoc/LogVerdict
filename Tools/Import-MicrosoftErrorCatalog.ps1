<#
    .SYNOPSIS
    Build the bundled Microsoft Windows error-code catalog from licensed source repositories.

    .DESCRIPTION
    Reads local checkouts of MicrosoftDocs/win32, MicrosoftDocs/windows-driver-docs,
    and MicrosoftDocs/SupportArticles-docs. Each checkout must carry the canonical
    CC-BY-4.0 licence. The importer does not scrape Learn HTML or make network calls.

    Generated entries retain the exact repository path, revision, source-file hash,
    licence, and corresponding Learn URL. The catalog is reference knowledge, not a
    verdict database: a code match never establishes root cause by itself.

    .PARAMETER Win32DocsPath
    Root of a MicrosoftDocs/win32 checkout.

    .PARAMETER WindowsDriverDocsPath
    Root of a MicrosoftDocs/windows-driver-docs checkout.

    .PARAMETER SupportArticlesPath
    Root of a MicrosoftDocs/SupportArticles-docs checkout.

    .PARAMETER Retrieved
    ISO date recorded on generated entries.

    .PARAMETER AllowIncomplete
    Permit small source fixtures when developing the importer. Production regeneration
    omits this switch and fails closed unless every current catalog family is complete.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Win32DocsPath,
    [Parameter(Mandatory = $true)][string]$WindowsDriverDocsPath,
    [Parameter(Mandatory = $true)][string]$SupportArticlesPath,
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data\error-codes.json'),
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$Retrieved = (Get-Date -Format 'yyyy-MM-dd'),
    [switch]$AllowIncomplete
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

function ConvertFrom-LVMarkdownText {
    param([Parameter(Mandatory)][string]$Markdown)

    $text = [Net.WebUtility]::HtmlDecode($Markdown)
    $text = [regex]::Replace($text, '(?i)<(?<uri>https?://[^>]+)>', '${uri}')
    $text = [regex]::Replace($text, '(?is)<[^>]+>', ' ')
    $text = [regex]::Replace($text, '!\[[^\]]*\]\([^)]+\)', ' ')
    $text = [regex]::Replace($text, '\[(?<label>[^\]]+)\]\([^)]+\)', '${label}')
    $text = $text -replace '\\([_*`])', '$1'
    $text = $text -replace '\\([\[\]])', '$1'
    $text = $text -replace '\\\\', '\'
    $text = $text -replace '\*\*', ''
    $text = $text -replace '`', ''
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

function Get-LVFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Get-LVCcByRepository {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Repository
    )

    $root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path).TrimEnd('\', '/')
    $licensePath = Join-Path $root 'LICENSE'
    if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
        throw ("Repository '{0}' has no root LICENSE file; refusing to infer its terms." -f $Repository)
    }
    $licenseText = [IO.File]::ReadAllText($licensePath)
    $hasCanonicalName = $licenseText -match 'Creative Commons Attribution 4\.0 International Public License'
    $hasCanonicalUri = $licenseText -match 'creativecommons\.org/licenses/by/4\.0'
    if ($licenseText -notmatch 'Attribution 4\.0 International' -or
        (-not $hasCanonicalName -and -not $hasCanonicalUri)) {
        throw ("Repository '{0}' is not recognizably CC-BY-4.0; refusing to import." -f $Repository)
    }

    $revision = 'source-archive'
    if (Test-Path -LiteralPath (Join-Path $root '.git')) {
        $gitRevision = (& git -C $root rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $gitRevision -match '^[0-9a-f]{40}$') {
            $revision = [string]$gitRevision
        }
    }
    return [pscustomobject]@{
        Root = $root
        Repository = $Repository
        Revision = $revision
        Licence = 'CC-BY-4.0'
        LicenceHash = Get-LVFileSha256 -Path $licensePath
    }
}

function Get-LVSourceDocument {
    param(
        [Parameter(Mandatory)]$Repository,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Reference
    )

    $relative = ($RelativePath -replace '\\', '/').TrimStart('/')
    $candidate = [IO.Path]::GetFullPath((Join-Path $Repository.Root ($relative -replace '/', '\')))
    $boundary = $Repository.Root.TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) {
        throw ("Source path escapes repository root: {0}" -f $RelativePath)
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw ("Required source document is missing from {0}: {1}" -f $Repository.Repository, $relative)
    }
    return [pscustomobject]@{
        Repository = $Repository.Repository
        Revision = $Repository.Revision
        Licence = $Repository.Licence
        RelativePath = $relative
        Reference = $Reference
        FullPath = $candidate
        Text = [IO.File]::ReadAllText($candidate)
        Hash = Get-LVFileSha256 -Path $candidate
    }
}

function ConvertTo-LVSourceProvenance {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)]$Document
    )

    $Entry | Add-Member -NotePropertyName sourceRepository -NotePropertyValue $Document.Repository -Force
    $Entry | Add-Member -NotePropertyName sourcePath -NotePropertyValue $Document.RelativePath -Force
    $Entry | Add-Member -NotePropertyName sourceRevision -NotePropertyValue $Document.Revision -Force
    $Entry | Add-Member -NotePropertyName licence -NotePropertyValue $Document.Licence -Force
    $Entry | Add-Member -NotePropertyName sourceDocumentHash -NotePropertyValue $Document.Hash -Force
    return $Entry
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
        [Parameter(Mandatory)]$Document,
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
        reference = $Document.Reference
        source = $Source
        retrieved = $Retrieved
        applicability = $Applicability
    }
    if ($Phase) { $entry.phase = $Phase }
    if ($Operation) { $entry.operation = $Operation }
    return ConvertTo-LVSourceProvenance -Entry ([pscustomobject]$entry) -Document $Document
}

Set-Alias -Name New-LVTypedSeedEntry -Value ConvertTo-LVTypedSeedEntry -Scope Local

function Get-LVSystemErrorEntry {
    param([Parameter(Mandatory)]$Repository)

    $ranges = @('0-499', '500-999', '1000-1299', '1300-1699', '1700-3999', '4000-5999', '6000-8199', '8200-8999', '9000-11999', '12000-15999')
    $entries = New-Object Collections.Generic.List[object]
    foreach ($range in $ranges) {
        $reference = 'https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--{0}-' -f $range
        $sourcePath = 'desktop-src/Debug/system-error-codes--{0}-.md' -f $range
        $document = Get-LVSourceDocument -Repository $Repository -RelativePath $sourcePath -Reference $reference
        $pattern = '(?ms)^(?:<span id="[^"]+"></span>)+\*\*(?<name>[^*\r\n]+)\*\*\s*^\s*(?<decimal>\d+)\s+\((?<hex>0x[0-9A-Fa-f]+)\)\s*(?<description>.*?)(?=^(?:<span id="[^"]+"></span>)+\*\*|\z)'
        foreach ($match in [regex]::Matches($document.Text, $pattern)) {
            $code = [int]$match.Groups['decimal'].Value
            $descriptionBlock = [regex]::Split($match.Groups['description'].Value, '(?m)^\s*##\s+')[0]
            $description = ConvertFrom-LVMarkdownText -Markdown $descriptionBlock
            $entry = [pscustomobject]@{
                id = 'win32:{0}' -f $code
                kind = 'win32'
                code = $code
                hex = '0x{0:X8}' -f $code
                name = ($match.Groups['name'].Value -replace '\\', '')
                description = $description
                explanation = 'A generic Win32 GetLastError status. Interpret it with the provider, operation and surrounding log message; the numeric code alone is not a root cause.'
                reference = $document.Reference
                source = 'MicrosoftDocs/win32: {0} (CC-BY-4.0)' -f $document.RelativePath
                retrieved = $Retrieved
            }
            $entries.Add((ConvertTo-LVSourceProvenance -Entry $entry -Document $document)) | Out-Null
        }
    }
    return @($entries.ToArray())
}

function Get-LVBugCheckEntry {
    param([Parameter(Mandatory)]$Repository)

    $indexReference = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2'
    $indexPath = 'windows-driver-docs-pr/debugger/bug-check-code-reference2.md'
    $indexDocument = Get-LVSourceDocument -Repository $Repository -RelativePath $indexPath -Reference $indexReference
    $entries = New-Object Collections.Generic.List[object]
    $pattern = '(?m)^\|\s*(?<hex>0x[0-9A-Fa-f]+)\s*\|\s*\[\*\*(?<name>[A-Z0-9_\\]+)\*\*\]\((?<link>[^)]+)\)'
    foreach ($match in [regex]::Matches($indexDocument.Text, $pattern)) {
        $hex = ('0x{0:X8}' -f [Convert]::ToUInt32($match.Groups['hex'].Value.Substring(2), 16))
        $link = $match.Groups['link'].Value -replace '\?.*$', ''
        $sourcePath = 'windows-driver-docs-pr/debugger/{0}' -f $link
        $referencePath = $link -replace '\.md$', ''
        $reference = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/{0}' -f $referencePath
        $document = Get-LVSourceDocument -Repository $Repository -RelativePath $sourcePath -Reference $reference
        $name = $match.Groups['name'].Value -replace '\\', ''
        $entry = [pscustomobject]@{
            id = 'bugcheck:{0}' -f $hex
            kind = 'bugcheck'
            code = $hex
            hex = $hex
            name = $name
            description = ('Microsoft kernel stop code {0} ({1}).' -f $hex, $name)
            explanation = 'A kernel stop code identifies the class of failure, not necessarily the responsible driver or component. Preserve the dump and inspect its parameters with WinDbg before assigning cause.'
            reference = $document.Reference
            source = 'MicrosoftDocs/windows-driver-docs: {0} (CC-BY-4.0)' -f $document.RelativePath
            retrieved = $Retrieved
        }
        $entries.Add((ConvertTo-LVSourceProvenance -Entry $entry -Document $document)) | Out-Null
    }
    return @($entries.ToArray())
}

function Get-LVCommonHresultEntry {
    param([Parameter(Mandatory)]$Repository)

    $entries = New-Object Collections.Generic.List[object]
    $commonDocument = Get-LVSourceDocument -Repository $Repository `
        -RelativePath 'desktop-src/SecCrypto/common-hresult-values.md' `
        -Reference 'https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values'
    $commonPattern = '(?m)^\|\s*(?<name>[A-Z][A-Z0-9_\\]+)\s*\|\s*(?<description>[^|]+?)\s*\|\s*(?<hex>0x[0-9A-Fa-f]+)\s*\|'
    foreach ($match in [regex]::Matches($commonDocument.Text, $commonPattern)) {
        $hex = $match.Groups['hex'].Value.ToUpperInvariant()
        $entry = [pscustomobject]@{
            id = 'hresult:{0}' -f $hex
            kind = 'hresult'
            code = $hex
            hex = $hex
            name = ($match.Groups['name'].Value -replace '\\', '')
            description = ConvertFrom-LVMarkdownText -Markdown $match.Groups['description'].Value
            explanation = 'An HRESULT is a 32-bit COM/API result. The high bit indicates failure or success; the facility and code identify the originating API family. Always interpret it with the calling provider.'
            reference = $commonDocument.Reference
            source = 'MicrosoftDocs/win32: {0} (CC-BY-4.0)' -f $commonDocument.RelativePath
            retrieved = $Retrieved
        }
        $entries.Add((ConvertTo-LVSourceProvenance -Entry $entry -Document $commonDocument)) | Out-Null
    }

    $pendingDocument = Get-LVSourceDocument -Repository $Repository `
        -RelativePath 'desktop-src/com/com-error-codes-1.md' `
        -Reference 'https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-1'
    $pendingMatch = [regex]::Match($pendingDocument.Text, '(?m)^\|[^|\r\n]*\*\*(?<name>E\\_PENDING)\*\*[^|\r\n]*?<dt>(?<hex>0x[0-9A-Fa-f]+)</dt>[^|\r\n]*\|\s*(?<description>.*?)<br\s*/?>\s*\|')
    if (-not $pendingMatch.Success) { throw 'MicrosoftDocs/win32 no longer exposes E_PENDING in the expected table shape.' }
    $pendingHex = $pendingMatch.Groups['hex'].Value.ToUpperInvariant()
    $pending = [pscustomobject]@{
        id = 'hresult:{0}' -f $pendingHex
        kind = 'hresult'
        code = $pendingHex
        hex = $pendingHex
        name = ($pendingMatch.Groups['name'].Value -replace '\\', '')
        description = ConvertFrom-LVMarkdownText -Markdown $pendingMatch.Groups['description'].Value
        explanation = 'An HRESULT is a 32-bit COM/API result. The high bit indicates failure or success; the facility and code identify the originating API family. Always interpret it with the calling provider.'
        reference = $pendingDocument.Reference
        source = 'MicrosoftDocs/win32: {0} (CC-BY-4.0)' -f $pendingDocument.RelativePath
        retrieved = $Retrieved
    }
    $entries.Add((ConvertTo-LVSourceProvenance -Entry $pending -Document $pendingDocument)) | Out-Null

    $falseDocument = Get-LVSourceDocument -Repository $Repository `
        -RelativePath 'desktop-src/direct3d11/d3d11-graphics-reference-returnvalues.md' `
        -Reference 'https://learn.microsoft.com/en-us/windows/win32/direct3d11/d3d11-graphics-reference-returnvalues'
    $falseMatch = [regex]::Match($falseDocument.Text, '(?m)^\|\s*(?<name>S_FALSE)\s*\(\(HRESULT\)1L\)\s*\|\s*(?<description>.*?)\s*\|')
    if (-not $falseMatch.Success) { throw 'MicrosoftDocs/win32 no longer exposes S_FALSE in the expected table shape.' }
    $falseEntry = [pscustomobject]@{
        id = 'hresult:0X00000001'
        kind = 'hresult'
        code = '0X00000001'
        hex = '0X00000001'
        name = $falseMatch.Groups['name'].Value
        description = ConvertFrom-LVMarkdownText -Markdown $falseMatch.Groups['description'].Value
        explanation = 'An HRESULT is a 32-bit COM/API result. The high bit indicates failure or success; the facility and code identify the originating API family. Always interpret it with the calling provider.'
        reference = $falseDocument.Reference
        source = 'MicrosoftDocs/win32: {0} (CC-BY-4.0)' -f $falseDocument.RelativePath
        retrieved = $Retrieved
    }
    $entries.Add((ConvertTo-LVSourceProvenance -Entry $falseEntry -Document $falseDocument)) | Out-Null
    return @($entries.ToArray())
}

$win32Repository = Get-LVCcByRepository -Path $Win32DocsPath -Repository 'MicrosoftDocs/win32'
$driverRepository = Get-LVCcByRepository -Path $WindowsDriverDocsPath -Repository 'MicrosoftDocs/windows-driver-docs'
$supportRepository = Get-LVCcByRepository -Path $SupportArticlesPath -Repository 'MicrosoftDocs/SupportArticles-docs'

$ntStatusDocument = Get-LVSourceDocument -Repository $driverRepository `
    -RelativePath 'windows-driver-docs-pr/kernel/using-ntstatus-values.md' `
    -Reference 'https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values'
$setupDocument = Get-LVSourceDocument -Repository $supportRepository `
    -RelativePath 'support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md' `
    -Reference 'https://learn.microsoft.com/en-us/windows/troubleshoot/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes'
$updateDocument = Get-LVSourceDocument -Repository $win32Repository `
    -RelativePath 'desktop-src/Wua_Sdk/wua-success-and-error-codes-.md' `
    -Reference 'https://learn.microsoft.com/en-us/windows/win32/wua_sdk/wua-success-and-error-codes-'
$typedEntries = @(
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000001' -Name 'STATUS_UNSUCCESSFUL' -Description 'The operation failed without a more specific status.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC000000D' -Name 'STATUS_INVALID_PARAMETER' -Description 'A parameter supplied to a system service was invalid.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC000000F' -Name 'STATUS_NO_SUCH_FILE' -Description 'The specified file was not found.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000022' -Name 'STATUS_ACCESS_DENIED' -Description 'Access to the requested object was denied.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000034' -Name 'STATUS_OBJECT_NAME_NOT_FOUND' -Description 'The object name was not found.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC0000043' -Name 'STATUS_SHARING_VIOLATION' -Description 'A file sharing violation occurred.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC000009A' -Name 'STATUS_INSUFFICIENT_RESOURCES' -Description 'Insufficient system resources existed to complete the operation.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0xC00000A3' -Name 'STATUS_DEVICE_NOT_READY' -Description 'The device was not ready.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind ntstatus -Hex '0x80000005' -Name 'STATUS_BUFFER_OVERFLOW' -Description 'The data was too large for the supplied buffer.' -Document $ntStatusDocument -Source 'MicrosoftDocs/windows-driver-docs: windows-driver-docs-pr/kernel/using-ntstatus-values.md (CC-BY-4.0)' -Applicability 'Windows kernel and native subsystems')
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900101' -Name 'MOSETUP_E_PROCESS_CRASH' -Description 'Windows Setup encountered a process failure during upgrade.' -Document $setupDocument -Source 'MicrosoftDocs/SupportArticles-docs: support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md (CC-BY-4.0)' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation process)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900200' -Name 'MOSETUP_E_SYSTEM_REQUIREMENT' -Description 'The device does not meet a Windows upgrade system requirement.' -Document $setupDocument -Source 'MicrosoftDocs/SupportArticles-docs: support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md (CC-BY-4.0)' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation system-requirement)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900204' -Name 'MOSETUP_E_MIGRATE_DATA_FAILURE' -Description 'Windows Setup could not migrate required data during upgrade.' -Document $setupDocument -Source 'MicrosoftDocs/SupportArticles-docs: support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md (CC-BY-4.0)' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation migration)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC1900208' -Name 'MOSETUP_E_COMPAT_BLOCK' -Description 'An application or device compatibility block prevented the upgrade.' -Document $setupDocument -Source 'MicrosoftDocs/SupportArticles-docs: support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md (CC-BY-4.0)' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation compatibility)
    (New-LVTypedSeedEntry -Kind setup -Hex '0xC190020E' -Name 'MOSETUP_E_INSTALLDISKSPACE' -Description 'There is not enough disk space to install the upgrade.' -Document $setupDocument -Source 'MicrosoftDocs/SupportArticles-docs: support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md (CC-BY-4.0)' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation disk-space)
    (New-LVTypedSeedEntry -Kind setup -Hex '0x800F081F' -Name 'CBS_E_SOURCE_MISSING' -Description 'The servicing stack could not find required source files.' -Document $setupDocument -Source 'MicrosoftDocs/SupportArticles-docs: support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md (CC-BY-4.0)' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation servicing)
    (New-LVTypedSeedEntry -Kind setup -Hex '0x800F0922' -Name 'CBS_E_INSTALLERS_FAILED' -Description 'A servicing installer failed while applying the update.' -Document $setupDocument -Source 'MicrosoftDocs/SupportArticles-docs: support/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes.md (CC-BY-4.0)' -Applicability 'Windows Setup and servicing' -Phase upgrade -Operation servicing)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x80240017' -Name 'WU_E_NOT_APPLICABLE' -Description 'The update is not applicable to the computer.' -Document $updateDocument -Source 'MicrosoftDocs/win32: desktop-src/Wua_Sdk/wua-success-and-error-codes-.md (CC-BY-4.0)' -Applicability 'Windows Update client' -Phase update -Operation applicability)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x8024001E' -Name 'WU_E_SERVICE_STOP' -Description 'The Windows Update service stopped during the operation.' -Document $updateDocument -Source 'MicrosoftDocs/win32: desktop-src/Wua_Sdk/wua-success-and-error-codes-.md (CC-BY-4.0)' -Applicability 'Windows Update client' -Phase update -Operation service)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x80240022' -Name 'WU_E_ALL_UPDATES_FAILED' -Description 'All updates in the operation failed.' -Document $updateDocument -Source 'MicrosoftDocs/win32: desktop-src/Wua_Sdk/wua-success-and-error-codes-.md (CC-BY-4.0)' -Applicability 'Windows Update client' -Phase update -Operation installation)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x8024402C' -Name 'WU_E_PT_WINHTTP_NAME_NOT_RESOLVED' -Description 'The update client could not resolve the proxy or server name.' -Document $updateDocument -Source 'MicrosoftDocs/win32: desktop-src/Wua_Sdk/wua-success-and-error-codes-.md (CC-BY-4.0)' -Applicability 'Windows Update client' -Phase update -Operation transport)
    (New-LVTypedSeedEntry -Kind windowsupdate -Hex '0x8024A105' -Name 'WU_E_UNKNOWN' -Description 'Windows Update returned an unspecified client error.' -Document $updateDocument -Source 'MicrosoftDocs/win32: desktop-src/Wua_Sdk/wua-success-and-error-codes-.md (CC-BY-4.0 compatibility seed)' -Applicability 'Windows Update client' -Phase update -Operation client)
)

$entries = @(Get-LVSystemErrorEntry -Repository $win32Repository) +
    @(Get-LVBugCheckEntry -Repository $driverRepository) +
    @(Get-LVCommonHresultEntry -Repository $win32Repository) +
    $typedEntries
$unique = @($entries | Group-Object id | ForEach-Object { $_.Group | Select-Object -First 1 })
if (-not $AllowIncomplete -and $unique.Count -lt 3000) {
    throw ('Microsoft source repositories returned only {0} unique entries; refusing to publish an incomplete catalog.' -f $unique.Count)
}

$sources = @(
    [pscustomobject][ordered]@{ repository = $win32Repository.Repository; revision = $win32Repository.Revision; licence = $win32Repository.Licence; licenceHash = $win32Repository.LicenceHash }
    [pscustomobject][ordered]@{ repository = $driverRepository.Repository; revision = $driverRepository.Revision; licence = $driverRepository.Licence; licenceHash = $driverRepository.LicenceHash }
    [pscustomobject][ordered]@{ repository = $supportRepository.Repository; revision = $supportRepository.Revision; licence = $supportRepository.Licence; licenceHash = $supportRepository.LicenceHash }
)
$minimumByKind = @{ win32 = 2500; bugcheck = 300; hresult = 13; ntstatus = 9; setup = 7; windowsupdate = 5 }
if (-not $AllowIncomplete) {
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
}

foreach ($entry in $unique) {
    $entry.hex = ConvertTo-LVCanonicalHex -Value ([string]$entry.hex)
    if (-not $entry.retrieved) { $entry.retrieved = $Retrieved }
    if (-not $entry.applicability) {
        $applicability = switch ([string]$entry.kind) {
            'win32' { 'Windows APIs and system components' }
            'bugcheck' { 'Windows kernel and crash dumps' }
            'hresult' { 'Windows COM and API callers' }
            'ntstatus' { 'Windows kernel and native subsystems' }
            'setup' { 'Windows Setup and servicing' }
            'windowsupdate' { 'Windows Update client' }
        }
        $entry | Add-Member -NotePropertyName applicability -NotePropertyValue $applicability -Force
    }
    $entry | Add-Member -NotePropertyName sourceHash -NotePropertyValue (Get-LVTextSha256 -Text ('{0}|{1}|{2}|{3}|{4}' -f $entry.reference, $entry.source, $entry.retrieved, $entry.kind, $entry.hex)) -Force
    foreach ($field in @('reference', 'sourceRepository', 'sourcePath', 'sourceRevision', 'licence', 'sourceDocumentHash', 'sourceHash')) {
        if ([string]::IsNullOrWhiteSpace([string]$entry.$field)) {
            throw ("Catalog entry '{0}' has no licensed source metadata field '{1}'." -f $entry.id, $field)
        }
    }
    $entry | Add-Member -NotePropertyName normalized -NotePropertyValue (ConvertTo-LVNormalizedCode -Kind $entry.kind -Hex $entry.hex) -Force
}
$sourceHash = Get-LVTextSha256 -Text (ConvertTo-Json -InputObject @($sources) -Depth 8 -Compress)

$catalog = [pscustomobject]@{
    schemaVersion = 3
    name = 'Microsoft Windows error and stop-code reference catalog'
    updated = $Retrieved
    notes = 'Modified reference knowledge from CC-BY-4.0 MicrosoftDocs source repositories. Learn URLs remain human references; a catalog match does not by itself establish root cause or verdict severity.'
    sources = $sources
    sourceHash = $sourceHash
    entries = @($unique | Sort-Object kind,code)
}

$json = $catalog | ConvertTo-Json -Depth 10
$json = ConvertTo-LVAsciiJson -Json $json
$fullPath = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $fullPath
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
[IO.File]::WriteAllText($fullPath, $json, (New-Object Text.UTF8Encoding($false)))
Write-Output ('Wrote {0} catalog entries to {1}' -f $unique.Count, $fullPath)
