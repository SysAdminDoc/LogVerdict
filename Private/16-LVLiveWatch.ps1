# Bounded live event-tail helpers. The watch is opt-in and read-only; it never
# changes channel configuration or claims that a missing event is benign.

function New-LVWatchBookmarkDocument {
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        channels     = [pscustomobject][ordered]@{}
    }
}

function Read-LVWatchBookmark {
    [CmdletBinding()]
    param([AllowNull()][string]$Path)

    if (-not $Path) { return New-LVWatchBookmarkDocument }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return New-LVWatchBookmarkDocument }
    try {
        $bookmark = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -eq $bookmark -or [int]$bookmark.schemaVersion -ne 1 -or $null -eq $bookmark.channels) {
            throw 'bookmark schemaVersion is not 1 or channels is missing'
        }
        return $bookmark
    } catch {
        throw ("Live-watch bookmark '{0}' is invalid: {1}" -f $Path, $_.Exception.Message)
    }
}

function Get-LVWatchBookmarkEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Bookmark,
        [Parameter(Mandatory)][string]$Channel
    )

    $property = $Bookmark.channels.PSObject.Properties[$Channel]
    if ($property) { return $property.Value }
    return $null
}

function Set-LVWatchBookmarkEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Bookmark,
        [Parameter(Mandatory)][string]$Channel,
        [Parameter(Mandatory)]$Entry
    )

    $property = $Bookmark.channels.PSObject.Properties[$Channel]
    if ($property) {
        $property.Value = $Entry
    } else {
        $Bookmark.channels | Add-Member -MemberType NoteProperty -Name $Channel -Value $Entry -Force
    }
}

function Write-LVWatchBookmark {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Bookmark
    )

    $target = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temporary = $target + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        $json = ($Bookmark | ConvertTo-Json -Depth 12) + [Environment]::NewLine
        [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $target -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-LVWatchBookmarkDate {
    param([AllowNull()][string]$Text)

    if (-not $Text) { return $null }
    try { return [datetime]::Parse($Text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $null }
}

function ConvertTo-LVWatchEventRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$EventObject,
        [Parameter(Mandatory)][string]$Channel
    )

    $message = if ($EventObject.PSObject.Properties['Message']) { [string]$EventObject.Message } else { $null }
    if ([string]::IsNullOrWhiteSpace($message)) { $message = '(no message template registered for this provider on this machine)' }
    return [pscustomobject]@{
        Source      = 'event'
        Channel     = $Channel
        Provider    = $EventObject.ProviderName
        ProviderId  = if ($EventObject.PSObject.Properties['ProviderId']) { [string]$EventObject.ProviderId } else { $null }
        Id          = [int]$EventObject.Id
        Version     = if ($EventObject.PSObject.Properties['Version'] -and $null -ne $EventObject.Version) { [int]$EventObject.Version } else { $null }
        Task        = if ($EventObject.PSObject.Properties['Task']) { $EventObject.Task } else { $null }
        Opcode      = if ($EventObject.PSObject.Properties['Opcode']) { $EventObject.Opcode } else { $null }
        Level       = if ($EventObject.PSObject.Properties['Level']) { [int]$EventObject.Level } else { $null }
        LevelName   = if ($EventObject.PSObject.Properties['LevelDisplayName']) { $EventObject.LevelDisplayName } else { $null }
        TimeCreated = $EventObject.TimeCreated
        MachineName = if ($EventObject.PSObject.Properties['MachineName']) { $EventObject.MachineName } else { $null }
        RecordId    = if ($EventObject.PSObject.Properties['RecordId']) { $EventObject.RecordId } else { $null }
        Message     = $message.Trim()
        StructuredData = Get-LVEventStructuredData -EventObject $EventObject
    }
}
