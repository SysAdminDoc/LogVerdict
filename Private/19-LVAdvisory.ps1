# Optional dependency and tool advisories. These records are knowledge context,
# never Windows event verdicts.

$script:LVAdvisorySchemaVersion = 1

function Get-LVAdvisoryCanonicalText {
    param([Parameter(Mandatory)]$Advisory)

    $cvss = ([double]$Advisory.CVSS).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture)
    $kev = ([bool]$Advisory.KEV).ToString().ToLowerInvariant()
    return @(
        [string]$Advisory.Id
        [string]$Advisory.Ecosystem
        [string]$Advisory.Package
        [string]$Advisory.AffectedRange
        [string]$Advisory.FixedVersion
        $cvss
        [string]$Advisory.CVSSVector
        $kev
        [string]$Advisory.KEVDate
        [string]$Advisory.PublishedDate
        [string]$Advisory.ModifiedDate
        [string]$Advisory.Source
        [string]$Advisory.SourceUri
    ) -join '|'
}

function Get-LVAdvisorySourceHash {
    param([Parameter(Mandatory)]$Advisory)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes((Get-LVAdvisoryCanonicalText -Advisory $Advisory))
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-LVAdvisoryDocument {
    [CmdletBinding()]
    param([string]$Path)

    $sourceLabel = $Path
    if (-not $sourceLabel) {
        $localCandidates = @(
            (Join-Path $script:LVDataDir 'advisories.local.json'),
            (Join-Path (Get-LVHostDirectory) 'advisories.local.json')
        )
        $sourceLabel = @($localCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
        if (-not $sourceLabel) { $sourceLabel = Join-Path $script:LVDataDir 'advisories.json' }
    }

    if (Test-Path -LiteralPath $sourceLabel -PathType Leaf) {
        return [pscustomobject]@{
            Document    = Get-Content -LiteralPath $sourceLabel -Raw -Encoding UTF8 | ConvertFrom-Json
            SourceLabel = $sourceLabel
        }
    }
    if (-not $Path -and $script:LVEmbeddedAdvisoriesJson) {
        return [pscustomobject]@{
            Document    = $script:LVEmbeddedAdvisoriesJson | ConvertFrom-Json
            SourceLabel = '(embedded)'
        }
    }
    throw ("Advisory cache not found at '{0}'." -f $sourceLabel)
}

function Get-LVAdvisoryDatabaseProblem {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Database)

    $problems = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Database.schemaVersion) {
        $problems.Add('cache declares no schemaVersion') | Out-Null
    } elseif ([int]$Database.schemaVersion -ne $script:LVAdvisorySchemaVersion) {
        $problems.Add(('cache schemaVersion {0} is not supported; expected {1}' -f $Database.schemaVersion, $script:LVAdvisorySchemaVersion)) | Out-Null
    }
    if (-not $Database.name) { $problems.Add('cache has no name') | Out-Null }
    if (-not $Database.updated -or [string]$Database.updated -notmatch '^\d{4}-\d{2}-\d{2}$') {
        $problems.Add('cache updated date is missing or unreadable') | Out-Null
    }
    if ($null -eq $Database.source -or -not $Database.source.name -or -not $Database.source.uri) {
        $problems.Add('cache source metadata requires name and uri') | Out-Null
    }
    if ([string]$Database.sourceHash -notmatch '^(?i:[0-9a-f]{64})$') {
        $problems.Add('cache sourceHash must be a SHA-256 digest') | Out-Null
    }
    if ($null -eq $Database.advisories -or $Database.advisories -is [string]) {
        $problems.Add('cache advisories must be an array') | Out-Null
        return @($problems.ToArray())
    }

    $ids = @{}
    foreach ($advisory in @($Database.advisories | Where-Object { $_ })) {
        $id = [string]$advisory.id
        if (-not $id) { $problems.Add('advisory has no id') | Out-Null; continue }
        if ($ids.ContainsKey($id)) { $problems.Add("duplicate advisory id '$id'") | Out-Null }
        $ids[$id] = $true
        foreach ($field in @('ecosystem', 'package', 'affectedRange', 'fixedVersion', 'source', 'sourceUri')) {
            if (-not $advisory.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace([string]$advisory.$field)) {
                $problems.Add(("advisory '{0}' is missing {1}" -f $id, $field)) | Out-Null
            }
        }
        if (-not $advisory.PSObject.Properties['cvss'] -or [double]$advisory.cvss -lt 0 -or [double]$advisory.cvss -gt 10) {
            $problems.Add(("advisory '{0}' has CVSS outside 0-10" -f $id)) | Out-Null
        }
        if ([string]$advisory.sourceUri -notmatch '^https?://') {
            $problems.Add(("advisory '{0}' sourceUri is not HTTPS/HTTP" -f $id)) | Out-Null
        }
        foreach ($dateField in @('publishedDate', 'modifiedDate')) {
            if ([string]$advisory.$dateField -notmatch '^\d{4}-\d{2}-\d{2}$') {
                $problems.Add(("advisory '{0}' has unreadable {1}" -f $id, $dateField)) | Out-Null
            }
        }
        if ($advisory.KEV -and [string]$advisory.KEVDate -notmatch '^\d{4}-\d{2}-\d{2}$') {
            $problems.Add(("advisory '{0}' is KEV but has no KEV date" -f $id)) | Out-Null
        }
        $expectedHash = Get-LVAdvisorySourceHash -Advisory $advisory
        if ([string]$advisory.sourceHash -notmatch '^(?i:[0-9a-f]{64})$' -or [string]$advisory.sourceHash -ine $expectedHash) {
            $problems.Add(("advisory '{0}' sourceHash does not match its normalized metadata" -f $id)) | Out-Null
        }
    }
    return @($problems.ToArray())
}

function Get-LVAdvisoryDatabase {
    [CmdletBinding()]
    param([string]$Path)

    $loaded = Read-LVAdvisoryDocument -Path $Path
    $problems = @(Get-LVAdvisoryDatabaseProblem -Database $loaded.Document)
    if ($problems.Count -gt 0) {
        throw ("Advisory cache '{0}' failed validation: {1}" -f $loaded.SourceLabel, ($problems -join '; '))
    }
    $result = [pscustomobject]@{
        schemaVersion = [int]$loaded.Document.schemaVersion
        name          = $loaded.Document.name
        updated       = $loaded.Document.updated
        source        = $loaded.Document.source
        sourceHash    = $loaded.Document.sourceHash
        advisories    = @($loaded.Document.advisories)
        sourceLabel   = $loaded.SourceLabel
    }
    return $result
}

function ConvertTo-LVAdvisoryVersionPart {
    param([Parameter(Mandatory)][string]$Version)

    $match = [regex]::Match($Version, '^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?')
    if (-not $match.Success) { return $null }
    return [pscustomobject]@{
        Major = [int]$match.Groups[1].Value
        Minor = if ($match.Groups[2].Success) { [int]$match.Groups[2].Value } else { 0 }
        Build = if ($match.Groups[3].Success) { [int]$match.Groups[3].Value } else { 0 }
        Rev   = if ($match.Groups[4].Success) { [int]$match.Groups[4].Value } else { 0 }
    }
}

function Compare-LVAdvisoryVersion {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)

    $a = ConvertTo-LVAdvisoryVersionPart -Version $Left
    $b = ConvertTo-LVAdvisoryVersionPart -Version $Right
    if ($null -eq $a -or $null -eq $b) { return $null }
    foreach ($field in @('Major', 'Minor', 'Build', 'Rev')) {
        if ($a.$field -lt $b.$field) { return -1 }
        if ($a.$field -gt $b.$field) { return 1 }
    }
    return 0
}

function Test-LVAdvisoryRange {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$Range)

    $alternatives = @($Range -split '\s*;\s*|\s+\|\|\s+' | Where-Object { $_ })
    foreach ($alternative in $alternatives) {
        $clauseMatches = [regex]::Matches($alternative, '(?<op>>=|<=|>|<|=)?\s*v?(?<version>\d+(?:\.\d+){0,3})')
        if ($clauseMatches.Count -eq 0) { continue }
        $matchesAll = $true
        foreach ($clause in $clauseMatches) {
            $comparison = Compare-LVAdvisoryVersion -Left $Version -Right $clause.Groups['version'].Value
            if ($null -eq $comparison) { $matchesAll = $false; break }
            $operator = $clause.Groups['op'].Value
            $matchesClause = switch ($operator) {
                '>=' { $comparison -ge 0 }
                '<=' { $comparison -le 0 }
                '>'  { $comparison -gt 0 }
                '<'  { $comparison -lt 0 }
                default { $comparison -eq 0 }
            }
            if (-not $matchesClause) { $matchesAll = $false; break }
        }
        if ($matchesAll) { return $true }
    }
    return $false
}

function ConvertTo-LVAdvisoryRecord {
    param([Parameter(Mandatory)]$Advisory, [AllowNull()][string]$Version)

    return [pscustomobject][ordered]@{
        RecordType     = 'advisory'
        FindingType    = 'dependency-advisory'
        Matched        = [bool]$Version
        Id             = $Advisory.id
        Ecosystem      = $Advisory.ecosystem
        Package        = $Advisory.package
        Version        = $Version
        AffectedRange  = $Advisory.affectedRange
        FixedVersion   = $Advisory.fixedVersion
        CVSS           = [double]$Advisory.cvss
        CVSSVector     = $Advisory.cvssVector
        KEV            = [bool]$Advisory.kev
        KEVDate        = $Advisory.kevDate
        PublishedDate  = $Advisory.publishedDate
        ModifiedDate   = $Advisory.modifiedDate
        Source         = $Advisory.source
        SourceUri      = $Advisory.sourceUri
        SourceHash     = $Advisory.sourceHash
        Title          = $Advisory.title
        Description    = $Advisory.description
    }
}

function Get-LVAdvisoryFinding {
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Package,
        [string]$Version
    )

    $database = Get-LVAdvisoryDatabase -Path $Path
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($advisory in @($database.advisories | Where-Object { $_ })) {
        if ($Package -and [string]$advisory.package -ne $Package) { continue }
        if ($Version -and -not (Test-LVAdvisoryRange -Version $Version -Range $advisory.affectedRange)) { continue }
        $records.Add((ConvertTo-LVAdvisoryRecord -Advisory $advisory -Version $Version)) | Out-Null
    }
    return [pscustomobject]@{
        Records = @($records.ToArray())
        Cache   = [pscustomobject][ordered]@{
            Status      = 'loaded'
            Name        = $database.name
            Updated     = $database.updated
            Source      = $database.source.name
            SourceUri   = $database.source.uri
            SourceHash  = $database.sourceHash
            EntryCount  = @($database.advisories).Count
            PathName    = Split-Path -Leaf $database.sourceLabel
        }
    }
}

function Get-LVAdvisoryScanContext {
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Package,
        [string]$Version
    )

    if (-not $Path -and -not $Package -and -not $Version) {
        return [pscustomobject]@{
            Status  = 'not-requested'
            Cache   = $null
            Records = @()
            Package = $null
            Version = $null
        }
    }
    if ([bool]$Package -ne [bool]$Version) {
        throw 'AdvisoryPackage and AdvisoryVersion must be supplied together so a cache entry is not mistaken for a local finding.'
    }
    $loaded = Get-LVAdvisoryFinding -Path $Path -Package $Package -Version $Version
    $status = if ($Package) {
        if (@($loaded.Records).Count -gt 0) { 'affected' } else { 'no-match' }
    } else { 'cache-loaded' }
    return [pscustomobject]@{
        Status  = $status
        Cache   = $loaded.Cache
        Records = @($loaded.Records)
        Package = $Package
        Version = $Version
    }
}

function Add-LVAdvisoryContextToResult {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Context)

    $Result | Add-Member -NotePropertyName 'AdvisoryStatus' -NotePropertyValue $Context.Status -Force
    $Result | Add-Member -NotePropertyName 'AdvisoryCache' -NotePropertyValue $Context.Cache -Force
    $Result | Add-Member -NotePropertyName 'Advisories' -NotePropertyValue @($Context.Records) -Force
    return $Result
}
