# Offline collection: read a LogVerdict evidence bundle without touching the live PC.
#
# A normal evidence bundle contains exported .evtx files, a JSON report, and the
# matching text-log excerpts. Event files are read again so a newer rule database can
# rule on signatures that were benign or unknown during collection. The report's
# captured signatures preserve text-log and Reliability Monitor evidence, because the
# bundle intentionally carries excerpts rather than multi-hundred-megabyte source logs.

function Find-LVProviderTemplateExport {
    param([Parameter(Mandatory)][string]$Root)
    $found = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter 'PROVIDER-TEMPLATES.json' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($found.Count -eq 1) { return $found[0].FullName }
    return $null
}

function Expand-LVEvidencePackage {
    <#
        .SYNOPSIS
        Open an evidence directory, JSON report, or zip in a traversal-safe workspace.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 8589934592)][long]$MaxEntryBytes = 1073741824,
        [ValidateRange(1, 8589934592)][long]$MaxTotalBytes = 2147483648
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (Test-Path -LiteralPath $resolved -PathType Container) {
        return [pscustomobject]@{
            Root       = [IO.Path]::GetFullPath($resolved)
            ReportPath = $null
            Temporary  = $false
            ReportOnly = $false
            EventPath  = $null
            ProviderTemplatePath = Find-LVProviderTemplateExport -Root ([IO.Path]::GetFullPath($resolved))
        }
    }

    if ([IO.Path]::GetExtension($resolved) -eq '.evtx') {
        return [pscustomobject]@{
            Root       = Split-Path -Parent $resolved
            ReportPath = $null
            Temporary  = $false
            ReportOnly = $false
            EventPath  = $resolved
            ProviderTemplatePath = Find-LVProviderTemplateExport -Root (Split-Path -Parent $resolved)
        }
    }

    if ([IO.Path]::GetExtension($resolved) -eq '.json') {
        return [pscustomobject]@{
            Root       = Split-Path -Parent $resolved
            ReportPath = $resolved
            Temporary  = $false
            ReportOnly = $true
            EventPath  = $null
            ProviderTemplatePath = Find-LVProviderTemplateExport -Root (Split-Path -Parent $resolved)
        }
    }

    if ([IO.Path]::GetExtension($resolved) -ne '.zip') {
        throw 'EvidencePath must name a LogVerdict evidence zip, an extracted directory, or LogVerdict-Report.json.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $workspace = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdictOffline-{0}' -f [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($workspace) | Out-Null
    $workspace = [IO.Path]::GetFullPath($workspace)
    $prefix = $workspace.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $zip = $null

    try {
        $zip = [IO.Compression.ZipFile]::OpenRead($resolved)
        if ($zip.Entries.Count -gt 512) {
            throw ('Evidence archive contains {0} entries; the safety limit is 512.' -f $zip.Entries.Count)
        }

        [long]$totalBytes = 0
        foreach ($entry in $zip.Entries) {
            $relative = ([string]$entry.FullName).Replace('/', [IO.Path]::DirectorySeparatorChar)
            if ([IO.Path]::IsPathRooted($relative)) {
                throw ('Evidence member uses an absolute path: {0}' -f $entry.FullName)
            }
            $destination = [IO.Path]::GetFullPath((Join-Path $workspace $relative))
            if (-not $destination.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw ('Evidence member escapes the extraction directory: {0}' -f $entry.FullName)
            }

            # Validate every member before deciding whether it is useful. An ignored
            # traversal entry is still a malformed package and must fail closed.
            if ([string]::IsNullOrWhiteSpace($entry.Name)) { continue }
            $keep = ($entry.Name -eq 'LogVerdict-Report.json' -or
                $entry.Name -eq 'MANIFEST.txt' -or
                $entry.Name -eq 'PROVIDER-TEMPLATES.json' -or
                [IO.Path]::GetExtension($entry.Name) -eq '.evtx')
            if (-not $keep) { continue }
            if (Test-Path -LiteralPath $destination) {
                throw ('Evidence archive contains a duplicate member path: {0}' -f $entry.FullName)
            }

            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Create($destination)
            [long]$entryBytes = 0
            try {
                $buffer = New-Object byte[] 81920
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($read -gt ($MaxEntryBytes - $entryBytes)) {
                        throw ('Evidence member expansion exceeded the {0} byte per-entry cap after {1} bytes: {2}' -f `
                            $MaxEntryBytes, $entryBytes, $entry.FullName)
                    }
                    if ($read -gt ($MaxTotalBytes - $totalBytes)) {
                        throw ('Evidence archive expansion exceeded the {0} byte total cap after {1} bytes while reading: {2}' -f `
                            $MaxTotalBytes, $totalBytes, $entry.FullName)
                    }
                    $outputStream.Write($buffer, 0, $read)
                    $entryBytes += $read
                    $totalBytes += $read
                }
            } finally {
                $outputStream.Dispose()
                $inputStream.Dispose()
            }
        }
    } catch {
        if ($zip) { $zip.Dispose(); $zip = $null }
        if (Test-Path -LiteralPath $workspace) { [IO.Directory]::Delete($workspace, $true) }
        throw
    } finally {
        if ($zip) { $zip.Dispose() }
    }

    $reports = @(Get-ChildItem -LiteralPath $workspace -Recurse -File -Filter 'LogVerdict-Report.json')
    if ($reports.Count -gt 1) {
        [IO.Directory]::Delete($workspace, $true)
        throw 'Evidence archive contains more than one LogVerdict-Report.json.'
    }

    return [pscustomobject]@{
        Root       = $workspace
        ReportPath = $(if ($reports.Count -eq 1) { $reports[0].FullName } else { $null })
        Temporary  = $true
        ReportOnly = $false
        EventPath  = $null
        ProviderTemplatePath = Find-LVProviderTemplateExport -Root $workspace
    }
}

function Close-LVEvidenceWorkspace {
    param([Parameter(Mandatory)]$Package)

    if (-not $Package.Temporary -or -not $Package.Root) { return }
    $root = [IO.Path]::GetFullPath([string]$Package.Root)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $leaf = Split-Path -Leaf $root
    if (-not $root.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch '^LogVerdictOffline-[0-9a-f]{32}$') {
        Write-LVLog -Level warn -Message ('Refused to remove an unexpected offline workspace path: {0}' -f $root)
        return
    }

    # The extractor writes regular files itself and never materializes archive links.
    # Refuse cleanup if a reparse point nevertheless appeared through a race.
    $links = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 })
    if ($links.Count -gt 0) {
        Write-LVLog -Level warn -Message ('Offline workspace contains a reparse point and was left for manual review: {0}' -f $root)
        return
    }
    if (Test-Path -LiteralPath $root) { [IO.Directory]::Delete($root, $true) }
}

function Read-LVEvidenceReport {
    param([Parameter(Mandatory)][string]$Path)

    $report = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ($report.Tool -ne 'LogVerdict' -or $null -eq $report.Findings -or $null -eq $report.Reduction) {
        throw ('Evidence report is not a LogVerdict scan result: {0}' -f $Path)
    }
    return $report
}

function ConvertFrom-LVArchivedDate {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertFrom-LVArchivedSignature {
    param([Parameter(Mandatory)]$Finding)

    $times = New-Object System.Collections.Generic.List[datetime]
    foreach ($value in @($Finding.Times)) {
        $time = ConvertFrom-LVArchivedDate -Value $value
        if ($time) { $times.Add($time) | Out-Null }
    }

    return [pscustomobject]@{
        Key           = [string]$Finding.Key
        Source        = [string]$Finding.Source
        Channel       = [string]$Finding.Channel
        Provider      = [string]$Finding.Provider
        ProviderId    = if ($Finding.PSObject.Properties['ProviderId']) { [string]$Finding.ProviderId } else { $null }
        Id            = [int]$Finding.Id
        Version       = if ($Finding.PSObject.Properties['Version'] -and $null -ne $Finding.Version) { [int]$Finding.Version } else { $null }
        Template      = $Finding.Template
        TemplateTokenCount = $(if ($Finding.PSObject.Properties['TemplateTokenCount']) { [int]$Finding.TemplateTokenCount } else { 0 })
        PromotedSlots = $(if ($Finding.PSObject.Properties['PromotedSlots']) { @($Finding.PromotedSlots) } else { @() })
        Count         = [int]$Finding.Count
        UndatedCount  = [int]$Finding.UndatedCount
        FirstSeen     = ConvertFrom-LVArchivedDate -Value $Finding.FirstSeen
        LastSeen      = ConvertFrom-LVArchivedDate -Value $Finding.LastSeen
        WorstLevel    = [int]$Finding.WorstLevel
        LevelName     = [string]$Finding.LevelName
        SampleMessage = [string]$Finding.SampleMessage
        Samples       = @($Finding.Samples)
        StructuredData = if ($Finding.PSObject.Properties['StructuredData']) { $Finding.StructuredData } else { $null }
        ResultCode    = if ($Finding.PSObject.Properties['ResultCode']) { $Finding.ResultCode } else { $null }
        ExtendCode    = if ($Finding.PSObject.Properties['ExtendCode']) { $Finding.ExtendCode } else { $null }
        Phase         = if ($Finding.PSObject.Properties['Phase']) { $Finding.Phase } else { $null }
        Operation     = if ($Finding.PSObject.Properties['Operation']) { $Finding.Operation } else { $null }
        ProviderLocale = if ($Finding.PSObject.Properties['ProviderLocale']) { $Finding.ProviderLocale } else { $null }
        FallbackMessage = if ($Finding.PSObject.Properties['FallbackMessage']) { $Finding.FallbackMessage } else { $null }
        ProviderTemplateSource = if ($Finding.PSObject.Properties['ProviderTemplateSource']) { [string]$Finding.ProviderTemplateSource } else { $null }
        ErrorContext  = if ($Finding.PSObject.Properties['ErrorContext']) { $Finding.ErrorContext } else { $null }
        Times         = @($times.ToArray() | Sort-Object)
        Area          = $Finding.Area
        PerDay        = [double]$Finding.PerDay
        SpanDays      = [double]$Finding.SpanDays
    }
}

function Resolve-LVArchivedProviderTemplate {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Signature)

    if ($Signature.Source -ne 'event') { return $false }
    $sample = if ($Signature.PSObject.Properties['SampleMessage']) { [string]$Signature.SampleMessage } else { $null }
    $fallback = if ($Signature.PSObject.Properties['FallbackMessage']) { [string]$Signature.FallbackMessage } else { $null }
    if (-not (Test-LVProviderTemplateMissingMessage -Message $sample) -and
        -not (Test-LVProviderTemplateMissingMessage -Message $fallback)) { return $false }

    $missingCount = [Math]::Max([int64]1, [int64]$Signature.Count)
    $script:LVProviderTemplateCoverage.LocalMissing += $missingCount
    if ($null -eq $script:LVProviderTemplateCoverage.Cache) { return $false }

    $template = Resolve-LVProviderTemplate -Cache $script:LVProviderTemplateCoverage.Cache `
        -Provider ([string]$Signature.Provider) -ProviderId ([string]$Signature.ProviderId) `
        -EventId ([int]$Signature.Id) -Version $Signature.Version -Locale ([string]$Signature.ProviderLocale)
    if ($null -eq $template) { return $false }

    $message = ConvertTo-LVProviderTemplateMessage -Template ([string]$template.Template) -EventObject $null
    $Signature.SampleMessage = $message
    $Signature.Samples = @($message)
    $Signature.FallbackMessage = $script:LVProviderTemplateMissingMessage
    $Signature.ProviderTemplateSource = '{0} [{1}]' -f $script:LVProviderTemplateCoverage.Cache.Source.Name, $script:LVProviderTemplateCoverage.Cache.Source.License
    $script:LVProviderTemplateCoverage.CacheResolved += $missingCount
    return $true
}

function Get-LVEvtxSha256 {
    <#
        .SYNOPSIS
        Hash an offline event file without loading it into memory.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $stream = $null
    $sha = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sha = [Security.Cryptography.SHA256]::Create()
        return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('X2') }) -join '')
    } finally {
        if ($sha) { $sha.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Get-LVOfflineEvtxCandidate {
    <#
        .SYNOPSIS
        Enumerate a direct event file or a bounded event-file directory.

        .DESCRIPTION
        Do not materialize an unbounded recursive directory listing. One extra
        candidate is retained so the result can say that the file-count cap was
        reached, while the parser itself only receives the configured maximum.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [AllowNull()][string]$EventPath,
        [ValidateRange(1, 513)][int]$MaxFiles = 64
    )

    $files = New-Object System.Collections.Generic.List[object]
    $discoveryError = $null
    $more = $false
    if ($EventPath) {
        if (Test-Path -LiteralPath $EventPath -PathType Leaf) {
            $files.Add((Get-Item -LiteralPath $EventPath -ErrorAction Stop)) | Out-Null
        } else {
            $discoveryError = 'The requested EVTX file disappeared before collection.'
        }
    } else {
        try {
            foreach ($file in (Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.evtx' -ErrorAction Stop)) {
                if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                $files.Add($file) | Out-Null
                if ($files.Count -gt $MaxFiles) {
                    $more = $true
                    break
                }
            }
        } catch {
            $discoveryError = $_.Exception.Message
        }
    }

    return [pscustomobject]@{
        Files = @($files.ToArray())
        More  = $more
        Error = $discoveryError
    }
}

function Get-LVOfflineEvtxOrigin {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # A snapshot path is evidence from a preserved volume, not a live channel. Do
    # not mount, create, or delete snapshots here; classify only the path supplied
    # by the operator so the report can say where the bytes came from.
    if ($Path -match '(?i)(?:HarddiskVolumeShadowCopy\d+|shadow[ _-]?copy)') {
        return 'shadow-copy'
    }
    return 'offline'
}

function Get-LVOfflineEvtxPlan {
    <#
        .SYNOPSIS
        Apply bounded size/count/total-byte policy and hash selected sources.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$File,
        [ValidateRange(1, 512)][int]$MaxFiles = 64,
        [ValidateRange(1, 4294967296)][long]$MaxFileBytes = 536870912,
        [ValidateRange(1, 8589934592)][long]$MaxTotalBytes = 2147483648,
        [AllowNull()]$CollectionBudget
    )

    $selected = New-Object System.Collections.Generic.List[object]
    $manifest = New-Object System.Collections.Generic.List[object]
    [long]$totalBytes = 0
    $index = 0
    foreach ($item in @($File)) {
        $index++
        $path = [string]$item.FullName
        $size = [long]$item.Length
        $entry = [pscustomobject]@{
            Path = $path; Name = [IO.Path]::GetFileName($path); SizeBytes = $size
            SHA256 = $null; Status = 'skipped'; Reason = $null; ParseMilliseconds = $null
            RecordCount = 0; Channel = $null; Oldest = $null; Truncated = $false
            Origin = Get-LVOfflineEvtxOrigin -Path $path
        }
        if ($index -gt $MaxFiles) {
            $entry.Reason = ('file-count cap of {0} reached' -f $MaxFiles)
            $manifest.Add($entry) | Out-Null
            continue
        }
        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        if ($budgetStop) {
            $entry.Status = $budgetStop
            $entry.Reason = ('The shared collection {0} budget stopped this source before hashing.' -f $budgetStop)
            $manifest.Add($entry) | Out-Null
            continue
        }
        if ($size -gt $MaxFileBytes) {
            $entry.Reason = ('file exceeds the {0} byte per-file cap' -f $MaxFileBytes)
            $manifest.Add($entry) | Out-Null
            continue
        }
        if ($size -gt $MaxTotalBytes -or ($totalBytes -gt 0 -and $size -gt ($MaxTotalBytes - $totalBytes))) {
            $entry.Reason = ('total byte cap of {0} would be exceeded' -f $MaxTotalBytes)
            $manifest.Add($entry) | Out-Null
            continue
        }
        if ($CollectionBudget -and $size -gt ([int64]$CollectionBudget.MaxBytes - [int64]$CollectionBudget.BytesRead)) {
            $entry.Status = 'truncated'
            $entry.Reason = 'The shared collection byte budget would be exceeded by this source.'
            $manifest.Add($entry) | Out-Null
            continue
        }
        try {
            $entry.SHA256 = Get-LVEvtxSha256 -Path $path
        } catch {
            $entry.Reason = ('source hash failed: {0}' -f $_.Exception.Message)
            $manifest.Add($entry) | Out-Null
            continue
        }
        if ($CollectionBudget) { Add-LVCollectionBudgetUsage -Budget $CollectionBudget -Bytes $size }
        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        if ($budgetStop) {
            $entry.Status = $budgetStop
            $entry.Reason = ('The shared collection {0} budget was reached while hashing this source.' -f $budgetStop)
            $manifest.Add($entry) | Out-Null
            continue
        }
        $entry.Status = 'queued'
        $totalBytes += $size
        $selected.Add([pscustomobject]@{ File=$item; Manifest=$entry }) | Out-Null
        $manifest.Add($entry) | Out-Null
    }

    return [pscustomobject]@{
        Files = @($selected.ToArray())
        Manifest = @($manifest.ToArray())
        TotalBytes = $totalBytes
    }
}

function Read-LVArchivedEventFile {
    <#
        .SYNOPSIS
        Normalize error and warning records from one exported .evtx file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$DaysBack = 30,
        [int[]]$Level = @(1, 2, 3),
        [int]$MaxEvents = 20000,
        [AllowNull()]$CollectionBudget
    )

    $fallbackChannel = [IO.Path]::GetFileNameWithoutExtension($Path)
    $channel = $fallbackChannel
    $oldest = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
    if ($budgetStop) {
        return [pscustomobject]@{ Channel=$channel; Oldest=$null; Records=@(); Truncated=($budgetStop -eq 'truncated'); BudgetStop=$budgetStop; Error=$null; ParseMilliseconds=0 }
    }
    try {
        $first = Get-WinEvent -Path $Path -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($first) {
            if ($first.LogName) { $channel = [string]$first.LogName }
            $oldest = $first.TimeCreated
        }
    } catch {
        $timer.Stop()
        return [pscustomobject]@{ Channel=$channel; Oldest=$null; Records=@(); Truncated=$false; BudgetStop=$null; Error=$_.Exception.Message; ParseMilliseconds=[math]::Round($timer.Elapsed.TotalMilliseconds, 0) }
    }

    $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
    if ($budgetStop) {
        $timer.Stop()
        return [pscustomobject]@{ Channel=$channel; Oldest=$oldest; Records=@(); Truncated=($budgetStop -eq 'truncated'); BudgetStop=$budgetStop; Error=$null; ParseMilliseconds=[math]::Round($timer.Elapsed.TotalMilliseconds, 0) }
    }

    $filter = @{ Path = $Path; StartTime = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack)) }
    if ($Level -and $Level.Count -gt 0) { $filter['Level'] = $Level }
    try {
        $readLimit = $MaxEvents
        if ($CollectionBudget) {
            $readLimit = [Math]::Min([int64]$readLimit, [int64]$CollectionBudget.MaxRecords - [int64]$CollectionBudget.RecordsRead)
        }
        if ($readLimit -lt 1) {
            $timer.Stop()
            return [pscustomobject]@{ Channel=$channel; Oldest=$oldest; Records=@(); Truncated=$true; BudgetStop='truncated'; Error=$null; ParseMilliseconds=[math]::Round($timer.Elapsed.TotalMilliseconds, 0) }
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $readLimit -ErrorAction Stop)
    } catch {
        $kind = Get-LVErrorKind -ErrorRecord $_
        if ($kind -eq 'empty') { $events = @() }
        else {
            $timer.Stop()
            return [pscustomobject]@{ Channel=$channel; Oldest=$oldest; Records=@(); Truncated=$false; BudgetStop=$null; Error=$_.Exception.Message; ParseMilliseconds=[math]::Round($timer.Elapsed.TotalMilliseconds, 0) }
        }
    }

    $records = New-Object System.Collections.Generic.List[object]
    $metadataMissing = 0
    $templateRecovered = 0
    foreach ($eventRecord in $events) {
        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        if ($budgetStop) { break }
        $message = $null
        try { $message = $eventRecord.Message } catch { $message = $null }
        $fallbackMessage = $null
        $providerTemplateSource = $null
        $providerLocale = if ($eventRecord.PSObject.Properties['ProviderLocale']) { [string]$eventRecord.ProviderLocale } elseif ($eventRecord.PSObject.Properties['Locale']) { [string]$eventRecord.Locale } else { [string]$script:LVUICulture }
        if ([string]::IsNullOrWhiteSpace([string]$message)) {
            $metadataMissing++
            $template = $null
            $providerVersion = if ($eventRecord.PSObject.Properties['Version'] -and $null -ne $eventRecord.Version) { [int]$eventRecord.Version } else { $null }
            if ($null -ne $eventRecord.Id) {
                $template = Resolve-LVProviderTemplate -Cache $script:LVProviderTemplateCoverage.Cache `
                    -Provider ([string]$eventRecord.ProviderName) `
                    -ProviderId $(if ($eventRecord.PSObject.Properties['ProviderId']) { [string]$eventRecord.ProviderId } else { $null }) `
                    -EventId ([int]$eventRecord.Id) -Version $providerVersion -Locale $providerLocale
            }
            if ($template) {
                $message = ConvertTo-LVProviderTemplateMessage -Template ([string]$template.Template) -EventObject $eventRecord
                $fallbackMessage = $script:LVProviderTemplateMissingMessage
                $providerTemplateSource = '{0} [{1}]' -f $script:LVProviderTemplateCoverage.Cache.Source.Name, $script:LVProviderTemplateCoverage.Cache.Source.License
                $templateRecovered++
                $script:LVProviderTemplateCoverage.CacheResolved++
            } else {
                $message = '(no message template registered for this provider on this machine)'
                $fallbackMessage = $message
            }
            $script:LVProviderTemplateCoverage.LocalMissing++
        }
        $recordChannel = $channel
        if ($eventRecord.LogName) { $recordChannel = [string]$eventRecord.LogName }
        $errorContext = New-LVErrorContext -InputObject $eventRecord -Message ([string]$message) `
            -FallbackMessage $fallbackMessage -ProviderLocale $providerLocale
        $structuredData = Get-LVEventStructuredData -EventObject $eventRecord
        $estimatedBytes = 256
        if ($message) { $estimatedBytes += [Text.Encoding]::UTF8.GetByteCount([string]$message) }
        if ($structuredData) { $estimatedBytes += [Text.Encoding]::UTF8.GetByteCount(($structuredData | ConvertTo-Json -Depth 5 -Compress)) }
        if ($CollectionBudget -and (([int64]$CollectionBudget.BytesRead + $estimatedBytes) -gt [int64]$CollectionBudget.MaxBytes)) {
            $budgetStop = 'truncated'
            break
        }
        $records.Add([pscustomobject]@{
            Source      = 'event'
            Channel     = $recordChannel
            Provider    = [string]$eventRecord.ProviderName
            Id          = [int]$eventRecord.Id
            Level       = [int]$eventRecord.Level
            LevelName   = [string]$eventRecord.LevelDisplayName
            TimeCreated = $eventRecord.TimeCreated
            MachineName = [string]$eventRecord.MachineName
            RecordId    = $eventRecord.RecordId
            Message     = ([string]$message).Trim()
            StructuredData = $structuredData
            ResultCode  = $errorContext.ResultCode
            ExtendCode  = $errorContext.ExtendCode
            Phase       = $errorContext.Phase
            Operation   = $errorContext.Operation
            ProviderLocale = $errorContext.ProviderLocale
            FallbackMessage = $errorContext.FallbackMessage
            ProviderTemplateSource = $providerTemplateSource
            ErrorContext = $errorContext
        }) | Out-Null
        if ($CollectionBudget) { Add-LVCollectionBudgetUsage -Budget $CollectionBudget -Bytes $estimatedBytes -Records 1 }
    }

    $timer.Stop()
    if (-not $budgetStop) { $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget }
    return [pscustomobject]@{
        Channel   = $channel
        Oldest    = $oldest
        Records   = @($records.ToArray())
        MetadataMissing = $metadataMissing
        TemplateRecovered = $templateRecovered
        Truncated = (($events.Count -ge $MaxEvents) -or ($budgetStop -eq 'truncated'))
        BudgetStop = $budgetStop
        Error     = $null
        ParseMilliseconds = [math]::Round($timer.Elapsed.TotalMilliseconds, 0)
    }
}

function Invoke-LVOfflineScan {
    <#
        .SYNOPSIS
        Re-run reduction and ruling against evidence captured on another machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [ValidateRange(1, 3650)][Nullable[int]]$DaysBack,
        [string[]]$Channel,
        [switch]$SkipTextLogs,
        [switch]$SkipReliability,
        [switch]$PerformanceTelemetry,
        [switch]$IncludeBenign,
        [switch]$IncludeLowConfidence,
        [string]$SuppressionPath,
        [string]$DatabasePath,
        [int]$MaxPerChannel = 20000,
        [ValidateRange(1, 512)][int]$MaxEvtxFiles = 64,
        [ValidateRange(1, 4294967296)][long]$MaxEvtxFileBytes = 536870912,
        [ValidateRange(1, 8589934592)][long]$MaxEvtxTotalBytes = 2147483648,
        [ValidateRange(1, 600)][int]$MaxEvtxParseSeconds = 120,
        [switch]$Redact,
        [switch]$ExplainUnknown,
        [string]$OllamaModel = 'llama3.2',
        [string]$OllamaEndpoint = 'http://127.0.0.1:11434',
        [switch]$PromoteToRule,
        [string]$LocalRulePath,
        [string]$ProviderTemplatePath,
        [AllowNull()]$CollectionBudget
    )

    $started = Get-Date
    $performance = New-Object System.Collections.Generic.List[object]
    $performanceEnabled = [bool]$PerformanceTelemetry
    $recordPerformance = {
        param(
            [string]$Source, [string]$Kind, [string]$Name, [string]$Status,
            [int64]$ObservedRecords, [int64]$SkippedRecords, $Cap,
            [int64]$ElapsedMilliseconds, [string]$Origin
        )
        if (-not $performanceEnabled) { return }
        $performance.Add((New-LVPerformanceRecord -Source $Source -Kind $Kind -Name $Name -Status $Status `
                -ObservedRecords $ObservedRecords -SkippedRecords $SkippedRecords -Cap $Cap `
                -ElapsedMilliseconds $ElapsedMilliseconds -Origin $Origin)) | Out-Null
    }
    $scanTimer = [Diagnostics.Stopwatch]::StartNew()
    $package = $null
    try {
        $package = Expand-LVEvidencePackage -Path $EvidencePath
        $cachePath = if ($ProviderTemplatePath) { $ProviderTemplatePath } elseif ($package.ProviderTemplatePath) { [string]$package.ProviderTemplatePath } else { $null }
        Initialize-LVProviderTemplateCache -Path $cachePath | Out-Null
        $reportPath = $package.ReportPath
        if (-not $reportPath) {
            $found = @(Get-ChildItem -LiteralPath $package.Root -Recurse -File -Filter 'LogVerdict-Report.json')
            if ($found.Count -gt 1) { throw 'Evidence directory contains more than one LogVerdict-Report.json.' }
            if ($found.Count -eq 1) { $reportPath = $found[0].FullName }
        }
        $sourceReport = $null
        if ($reportPath) { $sourceReport = Read-LVEvidenceReport -Path $reportPath }

        $effectiveDays = 30
        if ($null -ne $DaysBack) { $effectiveDays = [int]$DaysBack }
        elseif ($sourceReport -and $sourceReport.DaysBack) { $effectiveDays = [int]$sourceReport.DaysBack }
        if ($effectiveDays -lt 1 -or $effectiveDays -gt 3650) {
            throw 'DaysBack must be between 1 and 3650 days.'
        }

        $evtxDiscovery = [pscustomobject]@{ Files=@(); More=$false; Error=$null }
        if (-not $package.ReportOnly) {
            $evtxDiscovery = Get-LVOfflineEvtxCandidate -Root $package.Root -EventPath $package.EventPath -MaxFiles $MaxEvtxFiles
        }
        if ($evtxDiscovery.Error -and -not $sourceReport) {
            throw ('Could not enumerate offline EVTX sources: {0}' -f $evtxDiscovery.Error)
        }
        if (-not $sourceReport -and @($evtxDiscovery.Files).Count -eq 0) {
            throw 'Evidence package contains neither a LogVerdict JSON report nor an .evtx file.'
        }
        $evtxPlan = Get-LVOfflineEvtxPlan -File @($evtxDiscovery.Files) -MaxFiles $MaxEvtxFiles `
            -MaxFileBytes $MaxEvtxFileBytes -MaxTotalBytes $MaxEvtxTotalBytes -CollectionBudget $CollectionBudget
        $evtx = @($evtxPlan.Files)

        Write-LVLog -Level step -Message ('LogVerdict {0} starting offline analysis - window {1} day(s)' -f $script:LVVersion, $effectiveDays)
        Write-LVLog -Level info -Message ('Reading evidence from {0}' -f (Resolve-Path -LiteralPath $EvidencePath).Path)

        $records = New-Object System.Collections.Generic.List[object]
        $channelStatus = @{}
        $parsedChannels = New-Object System.Collections.Generic.List[string]
        $failedChannels = New-Object System.Collections.Generic.List[string]
        $truncatedChannels = New-Object System.Collections.Generic.List[string]

        foreach ($source in $evtx) {
            $file = $source.File
            $manifestEntry = $source.Manifest
            $data = Read-LVArchivedEventFile -Path $file.FullName -DaysBack $effectiveDays -MaxEvents $MaxPerChannel -CollectionBudget $CollectionBudget
            $manifestEntry.ParseMilliseconds = $data.ParseMilliseconds
            $manifestEntry.Channel = $data.Channel
            $manifestEntry.Oldest = $data.Oldest
            $manifestEntry.RecordCount = @($data.Records).Count
            $manifestEntry.Truncated = [bool]$data.Truncated
            if ([string]$manifestEntry.Origin -eq 'shadow-copy') {
                foreach ($record in @($data.Records | Where-Object { $_ })) {
                    $record | Add-Member -NotePropertyName Origin -NotePropertyValue 'shadow-copy' -Force
                }
            }
            if ($data.BudgetStop) {
                $manifestEntry.Status = $data.BudgetStop
                $manifestEntry.Reason = ('The shared collection {0} budget stopped this source; observed records are a lower bound.' -f $data.BudgetStop)
                & $recordPerformance -Source 'offline-evtx' -Kind 'parser' -Name 'archived event channel' -Status $data.BudgetStop `
                    -ObservedRecords @($data.Records).Count -SkippedRecords 0 -Cap $MaxPerChannel -ElapsedMilliseconds $data.ParseMilliseconds -Origin 'offline'
                $failedChannels.Add($data.Channel) | Out-Null
                foreach ($record in @($data.Records)) { $records.Add($record) | Out-Null }
                if ($data.Truncated) { $truncatedChannels.Add($data.Channel) | Out-Null }
                Write-LVLog -Level warn -Message ("Archived channel '{0}' stopped by the shared {1} collection budget." -f $data.Channel, $data.BudgetStop)
                continue
            }
            if ($data.ParseMilliseconds -gt ($MaxEvtxParseSeconds * 1000)) {
                $manifestEntry.Status = 'timeout'
                $manifestEntry.Reason = ('parser exceeded the {0} second cap' -f $MaxEvtxParseSeconds)
                & $recordPerformance -Source 'offline-evtx' -Kind 'parser' -Name 'archived event channel' -Status 'timeout' `
                    -ObservedRecords @($data.Records).Count -SkippedRecords 0 -Cap $MaxPerChannel -ElapsedMilliseconds $data.ParseMilliseconds -Origin 'offline'
                $failedChannels.Add($data.Channel) | Out-Null
                Write-LVLog -Level warn -Message ("Archived channel '{0}' exceeded the {1}-second offline parse cap." -f $data.Channel, $MaxEvtxParseSeconds)
                continue
            }
            if ($Channel -and $Channel -notcontains $data.Channel) {
                $manifestEntry.Status = 'filtered'
                $manifestEntry.Reason = 'channel filter excluded this source'
                & $recordPerformance -Source 'offline-evtx' -Kind 'parser' -Name 'archived event channel' -Status 'filtered' `
                    -ObservedRecords @($data.Records).Count -SkippedRecords 0 -Cap $MaxPerChannel -ElapsedMilliseconds $data.ParseMilliseconds -Origin 'offline'
                continue
            }
            if ($data.Error) {
                $manifestEntry.Status = 'unreadable'
                $manifestEntry.Reason = [string]$data.Error
                & $recordPerformance -Source 'offline-evtx' -Kind 'parser' -Name 'archived event channel' -Status 'unreadable' `
                    -ObservedRecords @($data.Records).Count -SkippedRecords 0 -Cap $MaxPerChannel -ElapsedMilliseconds $data.ParseMilliseconds -Origin 'offline'
                $failedChannels.Add($data.Channel) | Out-Null
                $channelStatus[$data.Channel] = [pscustomobject]@{ Channel=$data.Channel; Access='unreadable'; Oldest=$data.Oldest; Origin='evidence' }
                Write-LVLog -Level warn -Message ("Archived channel '{0}' could not be read: {1}" -f $data.Channel, $data.Error)
                continue
            }
            $manifestEntry.Status = 'parsed'
            & $recordPerformance -Source 'offline-evtx' -Kind 'parser' -Name 'archived event channel' `
                -Status $(if (@($data.Records).Count -eq 0) { 'empty' } else { 'readable' }) -ObservedRecords @($data.Records).Count -SkippedRecords 0 `
                -Cap $MaxPerChannel -ElapsedMilliseconds $data.ParseMilliseconds -Origin 'offline'
            $templateReason = if ([int]$data.MetadataMissing -gt 0 -and $script:LVProviderTemplateCoverage.Cache) {
                ('{0} record(s) had no local provider message template; {1} were resolved from the supplied cache.' -f [int]$data.MetadataMissing, [int]$data.TemplateRecovered)
            } elseif ([int]$data.MetadataMissing -gt 0) {
                ('{0} record(s) had no local provider message template on this machine.' -f [int]$data.MetadataMissing)
            } else { $null }
            if ($templateReason) {
                $manifestEntry.Reason = if ($manifestEntry.Reason) { '{0} {1}' -f $manifestEntry.Reason, $templateReason } else { $templateReason }
            }
            $parsedChannels.Add($data.Channel) | Out-Null
            $channelStatus[$data.Channel] = [pscustomobject]@{ Channel=$data.Channel; Access='readable'; Oldest=$data.Oldest; Origin='evidence' }
            foreach ($record in @($data.Records)) { $records.Add($record) | Out-Null }
            if ($data.Truncated) { $truncatedChannels.Add($data.Channel) | Out-Null }
        }

        $reductionTimer = if ($performanceEnabled) { [Diagnostics.Stopwatch]::StartNew() } else { $null }
        $eventGrouping = Get-LVSignatureReduction -Record @($records.ToArray()) -WindowDays $effectiveDays
        $eventSignatures = @($eventGrouping.Signatures)
        $signatureByKey = @{}
        foreach ($signature in $eventSignatures) { $signatureByKey[$signature.Key] = $signature }
        if ($reductionTimer) {
            $reductionTimer.Stop()
            & $recordPerformance -Source 'reduction' -Kind 'stage' -Name 'signature reduction' `
                -Status $(if ($records.Count -eq 0) { 'empty' } else { 'completed' }) -ObservedRecords $records.Count -SkippedRecords 0 -Cap $null `
                -ElapsedMilliseconds ([int64][Math]::Round($reductionTimer.Elapsed.TotalMilliseconds, 0)) -Origin 'offline'
        }

        [long]$archivedRecordCount = 0
        if ($sourceReport) {
            foreach ($finding in @($sourceReport.Findings)) {
                if ($finding.Source -eq 'textlog' -and $SkipTextLogs) { continue }
                if ($finding.Source -eq 'reliability' -and $SkipReliability) { continue }
                if ($finding.Source -eq 'event' -and $Channel -and $Channel -notcontains $finding.Channel) { continue }

                $archived = ConvertFrom-LVArchivedSignature -Finding $finding
                if ($signatureByKey.ContainsKey($archived.Key)) {
                    # Get-WinEvent can read an offline provider/id even when its message
                    # resource is absent on this PC. Preserve the captured message so
                    # narrow messagePattern rules still have evidence to match against.
                    $current = $signatureByKey[$archived.Key]
                    if ($current.SampleMessage -like '(no message template*' -and $archived.SampleMessage) {
                        $current.SampleMessage = $archived.SampleMessage
                        $current.Samples = @($archived.Samples)
                    }
                    continue
                }

                # Raw .evtx is authoritative for channels it successfully supplied.
                # The report fills sources the bundle cannot carry raw (text logs and
                # Reliability), channels omitted by the export cap, and redacted bundles.
                if ($archived.Source -eq 'event' -and $parsedChannels -contains $archived.Channel) { continue }
                Resolve-LVArchivedProviderTemplate -Signature $archived | Out-Null
                $signatureByKey[$archived.Key] = $archived
                $archivedRecordCount += [long]$archived.Count
                if ($archived.Source -eq 'event' -and -not $channelStatus.ContainsKey($archived.Channel)) {
                    $oldest = $null
                    if ($sourceReport.Horizon -and $sourceReport.Horizon.PSObject.Properties[$archived.Channel]) {
                        $oldest = ConvertFrom-LVArchivedDate -Value $sourceReport.Horizon.$($archived.Channel)
                    }
                    $channelStatus[$archived.Channel] = [pscustomobject]@{ Channel=$archived.Channel; Access='readable'; Oldest=$oldest; Origin='report summary' }
                }
            }
        }

        $signatures = @($signatureByKey.Values | Sort-Object Count -Descending)
        $recordCount = [long]$records.Count + $archivedRecordCount
        $loudest = $signatures | Select-Object -First 1
        $initialSignatureCount = $signatures.Count
        if ($sourceReport -and $evtx.Count -eq 0 -and $sourceReport.Reduction.PSObject.Properties['InitialSignatureCount']) {
            $initialSignatureCount = [int]$sourceReport.Reduction.InitialSignatureCount
        }
        $initialRatio = $(if ($initialSignatureCount -gt 0) { [Math]::Round($recordCount / $initialSignatureCount, 1) } else { 0 })
        $stat = [pscustomobject]@{
            RecordCount    = $recordCount
            InitialSignatureCount = $initialSignatureCount
            InitialRatio   = $initialRatio
            SignatureCount = $signatures.Count
            Ratio          = $(if ($signatures.Count -gt 0) { [Math]::Round($recordCount / $signatures.Count, 1) } else { 0 })
            PromotedSlotCount = [int]$eventGrouping.PromotedSlotCount
            LoudestKey     = $(if ($loudest) { $loudest.Key } else { $null })
            LoudestShare   = $(if ($loudest -and $recordCount -gt 0) { [Math]::Round(100 * $loudest.Count / $recordCount, 1) } else { 0 })
        }
        Write-LVLog -Level ok -Message ('{0} captured record(s), {1} signature(s) available offline' -f $recordCount, $signatures.Count)

        $resolutionTimer = if ($performanceEnabled) { [Diagnostics.Stopwatch]::StartNew() } else { $null }
        $db = Get-LogVerdictDatabase -Path $DatabasePath
        $databaseFreshness = Get-LVDatabaseFreshnessSummary -Database $db -AsOf ([datetime]::UtcNow.Date)
        Write-LVLog -Level info -Message ('Applying {0} rule(s) from the verdict database...' -f @($db.rules).Count)
        $offlineInstalledKbs = @()
        if ($sourceReport -and $sourceReport.PSObject.Properties['InstalledKbs'] -and $sourceReport.InstalledKbs) {
            $offlineInstalledKbs = @(Get-LVSignatureInstalledKbs -Signature ([pscustomobject]@{ InstalledKbs = $sourceReport.InstalledKbs }))
            foreach ($signature in @($signatures)) {
                $signature | Add-Member -NotePropertyName 'InstalledKbs' -NotePropertyValue $offlineInstalledKbs -Force
            }
        }
        $findings = @(Resolve-LVVerdict -Signature $signatures -Database $db)
        $evidenceMachine = '(offline evidence)'
        if ($sourceReport -and $sourceReport.MachineName) { $evidenceMachine = [string]$sourceReport.MachineName }
        elseif ($records.Count -gt 0 -and $records[0].MachineName) { $evidenceMachine = [string]$records[0].MachineName }
        $evidenceWindowsBuild = $null
        if ($sourceReport -and $sourceReport.PSObject.Properties['WindowsBuild']) { $evidenceWindowsBuild = [string]$sourceReport.WindowsBuild }
        $evidenceAppVersion = if ($sourceReport -and $sourceReport.Version) { [string]$sourceReport.Version } else { $script:LVVersion }
        $suppressionSet = Import-LVSuppressionSet -Path $SuppressionPath
        $suppressionApplied = Apply-LVSuppression -Finding @($findings) -SuppressionSet $suppressionSet `
            -MachineName $evidenceMachine -WindowsBuild $evidenceWindowsBuild -AppVersion $evidenceAppVersion
        $findings = @($suppressionApplied.Findings)
        $suppressionSummary = $suppressionApplied.Summary
        if ($suppressionSummary.UnmatchedCount -gt 0) {
            Write-LVLog -Level warn -Message ('{0} active suppression expectation(s) matched nothing in this offline scan.' -f $suppressionSummary.UnmatchedCount)
        }
        if ($suppressionSummary.ExpiredCount -gt 0) {
            Write-LVLog -Level warn -Message ('{0} suppression expectation(s) passed their expiry or 90-day review date and were not applied.' -f $suppressionSummary.ExpiredCount)
        }

        $lowConfidenceSuppressed = 0
        if (-not $IncludeLowConfidence) {
            $beforeLowConfidence = @($findings).Count
            $findings = @($findings | Where-Object { (Test-LVConfidenceIncluded -Finding $_) -or $_.Suppressed })
            $lowConfidenceSuppressed = $beforeLowConfidence - @($findings).Count
            if ($lowConfidenceSuppressed -gt 0) {
                Write-LVLog -Level ok -Message ('{0} low-confidence ruling(s) hidden (use -IncludeLowConfidence to see them)' -f $lowConfidenceSuppressed)
            }
        }
        $correlationFindings = @($findings | Where-Object { -not ($_.Suppressed -and $_.SuppressionAction -eq 'hide') })
        $correlations = @(Resolve-LVCorrelation -Finding $correlationFindings -Database $db)
        if ($resolutionTimer) {
            $resolutionTimer.Stop()
            & $recordPerformance -Source 'resolution' -Kind 'stage' -Name 'rule resolution' `
                -Status $(if ($signatures.Count -eq 0) { 'empty' } else { 'completed' }) -ObservedRecords $signatures.Count -SkippedRecords 0 -Cap $null `
                -ElapsedMilliseconds ([int64][Math]::Round($resolutionTimer.Elapsed.TotalMilliseconds, 0)) -Origin 'offline'
        }
        if (-not $IncludeBenign) { $findings = @($findings | Where-Object { $_.Verdict -ne 'benign' -or $_.Suppressed }) }
        $modelRequested = [bool]($ExplainUnknown -or $PromoteToRule)
        $promotedDrafts = @()
        if ($modelRequested) {
            Write-LVLog -Level info -Message ('Requesting non-remedial draft explanations for unknown signatures from local Ollama model {0}...' -f $OllamaModel)
            $explanationMachine = $evidenceMachine
            $findings = @(Add-LVModelExplanation -Finding @($findings) -Model $OllamaModel -Endpoint $OllamaEndpoint `
                -Redact:$Redact -MachineName $explanationMachine -UserName $env:USERNAME)
        }
        if ($PromoteToRule) {
            $accepted = @($findings | Where-Object { $_.PSObject.Properties['ModelExplanation'] -and $_.ModelExplanation })
            if ($accepted.Count -eq 0) {
                Write-LVLog -Level warn -Message 'No safe model candidates were available to promote; the local rule file was not changed.'
            } else {
                $promotedDrafts = @(Write-LVModelDraftRule -Finding $accepted -Path $LocalRulePath -MachineName $evidenceMachine)
            }
        }

        $incidentReduction = Get-LVIncidentReduction -Finding @($findings)
        $incidents = @($incidentReduction.Incidents)

        $providerTemplateCoverage = New-LVProviderTemplateCoverageRecord -Cache $script:LVProviderTemplateCoverage.Cache `
            -LocalMissing $script:LVProviderTemplateCoverage.LocalMissing `
            -CacheResolved $script:LVProviderTemplateCoverage.CacheResolved `
            -Origin 'offline' -CollectionBudget $CollectionBudget
        $coverageNotes = New-Object System.Collections.Generic.List[string]
        $coverageNotes.Add('This is offline analysis. No event channel, text log, Reliability Monitor provider, or crash directory on the reviewing PC was queried.') | Out-Null
        foreach ($note in @($sourceReport.CoverageNotes | Where-Object { $_ })) { $coverageNotes.Add([string]$note) | Out-Null }
        if ($providerTemplateCoverage -and $providerTemplateCoverage.Reason) {
            $coverageNotes.Add([string]$providerTemplateCoverage.Reason) | Out-Null
        }
        if ($evtxDiscovery.More) {
            $coverageNotes.Add(('The offline EVTX file-count cap of {0} was reached; additional files were not enumerated.' -f $MaxEvtxFiles)) | Out-Null
        }
        if ($evtxDiscovery.Error) {
            $coverageNotes.Add(('Some offline EVTX paths could not be enumerated: {0}' -f $evtxDiscovery.Error)) | Out-Null
        }
        foreach ($source in @($evtxPlan.Manifest)) {
            $hash = if ($source.SHA256) { [string]$source.SHA256 } else { 'unavailable' }
            $timing = if ($null -ne $source.ParseMilliseconds) { ('; parse {0} ms' -f $source.ParseMilliseconds) } else { '' }
            $reason = if ($source.Reason) { ('; {0}' -f $source.Reason) } else { '' }
            $coverageNotes.Add(('EVTX {0}: {1}, {2} bytes, SHA-256 {3}{4}{5}.' -f $source.Name, $source.Status, $source.SizeBytes, $hash, $timing, $reason)) | Out-Null
        }
        $shadowManifest = @($evtxPlan.Manifest | Where-Object { $_.Origin -eq 'shadow-copy' })
        if ($shadowManifest.Count -gt 0) {
            $coverageNotes.Add(('The offline package supplied {0} EVTX file(s) from a preserved shadow-copy path. These records are historical evidence and were not treated as live-channel coverage.' -f $shadowManifest.Count)) | Out-Null
        }
        if ($failedChannels.Count -gt 0) {
            $coverageNotes.Add(('Archived channel file(s) could not be read and only their report summaries were available: {0}.' -f ($failedChannels -join ', '))) | Out-Null
        }
        if ($truncatedChannels.Count -gt 0) {
            $coverageNotes.Add(('Archived channel file(s) hit the {0}-record offline cap: {1}.' -f $MaxPerChannel, ($truncatedChannels -join ', '))) | Out-Null
        }
        $budgetStop = Get-LVCollectionBudgetStopReason -Budget $CollectionBudget
        if ($budgetStop) {
            $coverageNotes.Add(('The shared offline collection {0} budget was reached. Archived findings are partial and incomplete sources are not clean.' -f $budgetStop)) | Out-Null
        }
        if ($sourceReport -and $evtx.Count -eq 0) {
            if (@($evtxPlan.Manifest).Count -eq 0) {
                $coverageNotes.Add('The package contains no raw event channel export. Findings were re-evaluated from the captured report summaries only.') | Out-Null
            } else {
                $coverageNotes.Add('No raw EVTX source passed the offline collection limits. Findings were re-evaluated from the captured report summaries and source coverage manifest.') | Out-Null
            }
        }
        if ($sourceReport -and [int]$sourceReport.Reduction.SignatureCount -gt @($sourceReport.Findings).Count) {
            $missingCount = [int]$sourceReport.Reduction.SignatureCount - @($sourceReport.Findings).Count
            $coverageNotes.Add(('{0} signature(s) suppressed from the source report were unavailable unless represented in an exported event channel.' -f $missingCount)) | Out-Null
        }

        $channels = @($channelStatus.Keys | Sort-Object)
        if ($channels.Count -eq 0 -and $sourceReport) {
            $channels = @($sourceReport.Channels)
            foreach ($name in $channels) {
                $channelStatus[$name] = [pscustomobject]@{ Channel=$name; Access='readable'; Oldest=$null; Origin='report summary' }
            }
        }

        $horizon = @{}
        foreach ($entry in $channelStatus.Values) { if ($entry.Oldest) { $horizon[$entry.Channel] = $entry.Oldest } }
        $horizonWarning = $null
        $cutoff = $started.AddDays(-1 * [Math]::Abs($effectiveDays))
        foreach ($name in $horizon.Keys) {
            if ($horizon[$name] -gt $cutoff) {
                $horizonWarning = ("The '{0}' archived channel only goes back to {1:yyyy-MM-dd}, inside the requested {2}-day window. Earlier evidence was not present in the bundle." -f $name, $horizon[$name], $effectiveDays)
                break
            }
        }

        $worst = 'benign'
        $visibleFindings = @($findings | Where-Object { -not ($_.Suppressed -and $_.SuppressionAction -eq 'hide') })
        foreach ($finding in @($visibleFindings) + @($correlations)) {
            if ((Get-LVVerdictRank -Verdict $finding.Verdict) -gt (Get-LVVerdictRank -Verdict $worst)) { $worst = $finding.Verdict }
        }
        $exitCode = 0
        switch ($worst) {
            'critical'    { $exitCode = 3 }
            'actionable'  { $exitCode = 2 }
            'investigate' { $exitCode = 1 }
            'unknown'     { $exitCode = 1 }
        }

        $scanTimer.Stop()
        & $recordPerformance -Source 'scan' -Kind 'stage' -Name 'scan total' `
            -Status $(if ($recordCount -eq 0) { 'empty' } else { 'completed' }) -ObservedRecords $recordCount -SkippedRecords 0 -Cap $null `
            -ElapsedMilliseconds ([int64][Math]::Round($scanTimer.Elapsed.TotalMilliseconds, 0)) -Origin 'offline'

        $machineName = $evidenceMachine

        $crash = @()
        if ($sourceReport -and -not $SkipTextLogs) { $crash = @($sourceReport.CrashArtifacts) }
        $stability = $null
        $reliabilityAvailable = $false
        if ($sourceReport -and -not $SkipReliability) {
            $stability = $sourceReport.Stability
            $reliabilityAvailable = [bool]$sourceReport.ReliabilityAvailable
        }

        $coverageSources = New-Object System.Collections.Generic.List[object]
        foreach ($source in @($evtxPlan.Manifest)) {
            $coverageStatus = ConvertTo-LVCoverageStatus -Status $source.Status -ObservedRecords $source.RecordCount
            $coverageSources.Add((New-LVCoverageRecord -Source 'offline-evtx' -Kind 'file' -Name $source.Name -Status $coverageStatus `
                -Reason $source.Reason -Path $source.Path -WindowStart ($started.AddDays(-1 * [Math]::Abs($effectiveDays))) -WindowEnd $started `
                -Cap $MaxPerChannel -ObservedRecords $source.RecordCount -RecordGap $null -ParserError $(if ($source.Status -eq 'unreadable') { $source.Reason } else { $null }) `
                -SizeBytes $source.SizeBytes -ParseMilliseconds $source.ParseMilliseconds -SHA256 $source.SHA256 `
                -CollectionBudget $CollectionBudget -Origin ([string]$source.Origin))) | Out-Null
        }
        if ($sourceReport -and $sourceReport.PSObject.Properties['Coverage']) {
            foreach ($source in @($sourceReport.Coverage | Where-Object { $_ })) {
                $normalized = $source | Select-Object *
                $observed = if ($normalized.PSObject.Properties['ObservedRecords']) { [int64]$normalized.ObservedRecords } else { 0 }
                $normalized.Status = ConvertTo-LVCoverageStatus -Status ([string]$normalized.Status) -ObservedRecords $observed
                $coverageSources.Add($normalized) | Out-Null
            }
        }
        if ($providerTemplateCoverage) { $coverageSources.Add($providerTemplateCoverage) | Out-Null }

        $healthProfiles = @()
        if ($sourceReport -and $sourceReport.PSObject.Properties['HealthProfiles']) {
            $healthProfiles = @($sourceReport.HealthProfiles)
        } else {
            $healthProfiles = @((New-LVHealthProfile -Profile 'configuration-health' -Source 'health' -Name 'reviewing machine configuration' `
                -Status 'not-observed' -RequiredConfiguration 'Provider, policy, retention, and forwarding state should be captured on the source machine when diagnostic coverage matters.' `
                -ObservedConfiguration 'Offline analysis does not query the reviewing machine for provider or policy state.' `
                -Reason 'The reviewing machine is intentionally not used as a proxy for the captured machine configuration.' `
                -Advice 'Capture health profiles with the live scan if provider and policy context is needed.' -Origin 'offline'))
        }

        return [pscustomobject]@{
            Tool           = 'LogVerdict'
            Version        = $script:LVVersion
            Contract       = New-LVReportContract -Result ([pscustomobject]@{ ScanTime = $started; Offline = $true })
            MachineName    = $machineName
            WindowsBuild   = $evidenceWindowsBuild
            ScanTime       = $started
            Duration       = ((Get-Date) - $started)
            DaysBack       = $effectiveDays
            Elevated       = $(if ($sourceReport) { [bool]$sourceReport.Elevated } else { $false })
            Channels       = @($channels)
            ChannelStatus  = $channelStatus
            DeniedChannels = $(if ($sourceReport) { @($sourceReport.DeniedChannels) } else { @() })
            TruncatedChannels = @($truncatedChannels.ToArray())
            MetadataUnreadableCount = $(if ($sourceReport) { [int]$sourceReport.MetadataUnreadableCount } else { 0 })
            CoverageNotes  = @($coverageNotes.ToArray())
            Reduction      = $stat
            Findings       = @($findings)
            Incidents      = @($incidents)
            IncidentSummary = $incidentReduction.Summary
            LowConfidenceSuppressedCount = $lowConfidenceSuppressed
            SuppressionStatus = $suppressionSummary
            Correlations   = @($correlations)
            CrashArtifacts = @($crash)
            EvidenceManifest = @($evtxPlan.Manifest)
            Coverage       = @($coverageSources.ToArray())
            CollectionBudget = Get-LVCollectionBudgetSnapshot -Budget $CollectionBudget
            PerformanceTelemetry = [bool]$PerformanceTelemetry
            Performance    = @($performance.ToArray())
            HealthProfiles = @($healthProfiles)
            Horizon        = $horizon
            HorizonWarning = $horizonWarning
            Stability      = $stability
            ReliabilityAvailable = $reliabilityAvailable
            DatabaseName   = $db.name
            DatabaseVersion = $db.schemaVersion
            DatabaseDate   = $db.updated
            DatabaseHash   = if ($db.PSObject.Properties['sourceSha256']) { $db.sourceSha256 } else { $null }
            RuleCount      = @($db.rules).Count
            DatabaseFreshness = $databaseFreshness
            InstalledKbs   = @($offlineInstalledKbs)
            ScanOptions    = [ordered]@{
                channels = @($channels)
                skipTextLogs = [bool]$SkipTextLogs
                skipReliability = [bool]$SkipReliability
                performanceTelemetry = [bool]$PerformanceTelemetry
                includeBenign = [bool]$IncludeBenign
                includeLowConfidence = [bool]$IncludeLowConfidence
                suppressionPath = $suppressionSummary.Path
                explainUnknown = [bool]$ExplainUnknown
                promoteToRule = [bool]$PromoteToRule
                evidencePath = $true
            }
            ModelExplanationsEnabled = $modelRequested
            ModelExplanationCount = @($findings | Where-Object { $_.PSObject.Properties['ModelExplanation'] -and $_.ModelExplanation }).Count
            PromotedDraftRules = @($promotedDrafts)
            WorstVerdict   = $worst
            ExitCode       = $exitCode
            Offline        = $true
            EvidencePath   = (Resolve-Path -LiteralPath $EvidencePath).Path
            EvidenceScanTime = $(if ($sourceReport) { ConvertFrom-LVArchivedDate -Value $sourceReport.ScanTime } else { $null })
        }
    } finally {
        if ($package) { Close-LVEvidenceWorkspace -Package $package }
    }
}
