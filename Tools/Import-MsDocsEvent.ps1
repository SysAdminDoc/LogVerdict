<#
    .SYNOPSIS
    Discover Microsoft support articles about event IDs and turn reviewed prose into rules.

    .DESCRIPTION
    Reads a local checkout of MicrosoftDocs/SupportArticles-docs. The checkout's
    CC-BY-4.0 licence is verified on every run. Discovery mode emits article/event-ID
    candidates only. A review file can then supply the provider, verdict, and prose a
    human has paraphrased; only that reviewed material is converted into rule objects.

    The importer deliberately never copies an article paragraph into a ruling. It
    rejects long verbatim matches, records Microsoft as the source author, marks the
    prose as modified, and stamps the retrieval date so attribution obligations travel
    with the rule.

    .PARAMETER CorpusPath
    Root of a MicrosoftDocs/SupportArticles-docs checkout.

    .PARAMETER ReviewPath
    Optional JSON array of reviewed rule records. Each record must include id,
    sourcePath, match, verdict, title, plain, why, action, and confidence.

    .PARAMETER OutputPath
    Optional path for the discovered candidates or reviewed rule array as JSON.

    .PARAMETER Retrieved
    ISO retrieval date applied to imported sources and rule verification.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CorpusPath,
    [string]$ReviewPath,
    [string]$OutputPath,
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$Retrieved = (Get-Date -Format 'yyyy-MM-dd')
)

$ErrorActionPreference = 'Stop'

function Get-LVMsDocsArticle {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $text = [IO.File]::ReadAllText($Path)
    $title = [IO.Path]::GetFileNameWithoutExtension($Path) -replace '-', ' '
    $titleMatch = [regex]::Match($text, '(?m)^title:\s*["'']?(?<title>.*?)["'']?\s*$')
    if ($titleMatch.Success) { $title = $titleMatch.Groups['title'].Value.Trim() }

    $ids = New-Object System.Collections.Generic.List[int]
    foreach ($match in [regex]::Matches($text, '(?i)\bEvent\s*(?:ID\s*)?[:#]?\s*(?<id>\d{1,5})\b')) {
        $id = [int]$match.Groups['id'].Value
        if (-not $ids.Contains($id)) { $ids.Add($id) }
    }

    $relative = $Path.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
    $uri = $null
    if ($relative -match '^support/(?<family>windows-client|windows-server)/(?<article>.+)\.md$') {
        $uri = 'https://learn.microsoft.com/en-us/troubleshoot/{0}/{1}' -f $Matches['family'], $Matches['article']
    }

    return [pscustomobject]@{
        Path       = $Path
        SourcePath = $relative
        SourceUri  = $uri
        Title      = $title
        EventIds   = [int[]]$ids.ToArray()
        Text       = $text
    }
}

function Test-LVMsDocsParaphrase {
    param(
        [Parameter(Mandatory = $true)][string]$ArticleText,
        [Parameter(Mandatory = $true)][string]$FieldName,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $normalizedArticle = (($ArticleText -replace '[\r\n\t]+', ' ') -replace '\s{2,}', ' ').ToLowerInvariant()
    $normalizedValue = (($Value -replace '[\r\n\t]+', ' ') -replace '\s{2,}', ' ').Trim().ToLowerInvariant()
    if ($normalizedValue.Length -ge 40 -and $normalizedArticle.Contains($normalizedValue)) {
        throw ("Reviewed field '{0}' reproduces source prose verbatim; paraphrase it before importing." -f $FieldName)
    }
}

$root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $CorpusPath).Path).TrimEnd('\', '/')
$licensePath = Join-Path $root 'LICENSE'
if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
    throw 'The corpus has no root LICENSE file; refusing to infer its terms.'
}
$licenseText = [IO.File]::ReadAllText($licensePath)
$hasCanonicalName = $licenseText -match 'Creative Commons Attribution 4\.0 International Public License'
$hasCanonicalUri = $licenseText -match 'creativecommons\.org/licenses/by/4\.0'
if ($licenseText -notmatch 'Attribution 4\.0 International' -or
    (-not $hasCanonicalName -and -not $hasCanonicalUri)) {
    throw 'The corpus licence is not recognizably CC-BY-4.0; refusing to import.'
}

$articles = @{}
foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.md') {
    $article = Get-LVMsDocsArticle -Path $file.FullName -Root $root
    $articles[$article.SourcePath.ToLowerInvariant()] = $article
}

$output = @()
if (-not $ReviewPath) {
    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($article in @($articles.Values | Sort-Object SourcePath)) {
        if (-not $article.SourceUri) { continue }
        foreach ($id in @($article.EventIds)) {
            $candidates.Add([pscustomobject]@{
                EventId    = $id
                SourcePath = $article.SourcePath
                SourceUri  = $article.SourceUri
                SourceTitle = $article.Title
            }) | Out-Null
        }
    }
    $output = @($candidates.ToArray() | Sort-Object EventId, SourcePath)
} else {
    $reviewFile = (Resolve-Path -LiteralPath $ReviewPath).Path
    $review = @([IO.File]::ReadAllText($reviewFile) | ConvertFrom-Json)
    $seen = @{}
    $rules = New-Object System.Collections.Generic.List[object]

    foreach ($item in $review) {
        foreach ($field in @('id', 'sourcePath', 'match', 'verdict', 'title', 'plain', 'why', 'action', 'confidence')) {
            if ($null -eq $item.$field -or [string]::IsNullOrWhiteSpace([string]$item.$field)) {
                throw ("Reviewed record is missing '{0}'." -f $field)
            }
        }
        $id = [string]$item.id
        if ($seen.ContainsKey($id)) { throw ("Duplicate reviewed rule id '{0}'." -f $id) }
        $seen[$id] = $true

        $key = ([string]$item.sourcePath -replace '\\', '/').TrimStart('/').ToLowerInvariant()
        if (-not $articles.ContainsKey($key)) {
            throw ("Reviewed rule {0} names an article outside this corpus or not present in it: {1}" -f $id, $item.sourcePath)
        }
        $article = $articles[$key]
        if (-not $article.SourceUri) {
            throw ("Reviewed rule {0} does not map to a supported Learn article path." -f $id)
        }
        if ($null -eq $item.match.eventId -or @($article.EventIds) -notcontains [int]$item.match.eventId) {
            throw ("Reviewed rule {0} event ID {1} is not stated in its source article." -f $id, $item.match.eventId)
        }

        foreach ($field in @('title', 'plain', 'why', 'action')) {
            Test-LVMsDocsParaphrase -ArticleText $article.Text -FieldName $field -Value ([string]$item.$field)
        }

        $falsepositives = @()
        if ($item.falsepositives) { $falsepositives = @($item.falsepositives | Where-Object { $_ }) }
        $rules.Add([pscustomobject][ordered]@{
            id             = $id
            status         = 'stable'
            verified       = $Retrieved
            match          = $item.match
            verdict        = [string]$item.verdict
            title          = [string]$item.title
            plain          = [string]$item.plain
            why            = [string]$item.why
            action         = [string]$item.action
            confidence     = [string]$item.confidence
            references     = @($article.SourceUri)
            falsepositives = [string[]]$falsepositives
            sources        = @([pscustomobject][ordered]@{
                uri       = $article.SourceUri
                licence   = 'CC-BY-4.0'
                author    = 'Microsoft'
                retrieved = $Retrieved
                modified  = $true
            })
        }) | Out-Null
    }
    $output = @($rules.ToArray())
}

if ($OutputPath) {
    $target = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $json = $output | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($target, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}

if ($output.Count -gt 0) { return $output }
