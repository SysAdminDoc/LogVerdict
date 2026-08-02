# Offline collection: read a LogVerdict evidence bundle without touching the live PC.
#
# A normal evidence bundle contains exported .evtx files, a JSON report, and the
# matching text-log excerpts. Event files are read again so a newer rule database can
# rule on signatures that were benign or unknown during collection. The report's
# captured signatures preserve text-log and Reliability Monitor evidence, because the
# bundle intentionally carries excerpts rather than multi-hundred-megabyte source logs.

function Expand-LVEvidencePackage {
    <#
        .SYNOPSIS
        Open an evidence directory, JSON report, or zip in a traversal-safe workspace.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (Test-Path -LiteralPath $resolved -PathType Container) {
        return [pscustomobject]@{
            Root       = [IO.Path]::GetFullPath($resolved)
            ReportPath = $null
            Temporary  = $false
            ReportOnly = $false
            EventPath  = $null
        }
    }

    if ([IO.Path]::GetExtension($resolved) -eq '.evtx') {
        return [pscustomobject]@{
            Root       = Split-Path -Parent $resolved
            ReportPath = $null
            Temporary  = $false
            ReportOnly = $false
            EventPath  = $resolved
        }
    }

    if ([IO.Path]::GetExtension($resolved) -eq '.json') {
        return [pscustomobject]@{
            Root       = Split-Path -Parent $resolved
            ReportPath = $resolved
            Temporary  = $false
            ReportOnly = $true
            EventPath  = $null
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
            $totalBytes += [long]$entry.Length
            if ($entry.Length -gt 1GB) { throw ('Evidence member is larger than 1 GB: {0}' -f $entry.FullName) }
            if ($totalBytes -gt 2GB) { throw 'Evidence archive expands past the 2 GB safety limit.' }

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
                [IO.Path]::GetExtension($entry.Name) -eq '.evtx')
            if (-not $keep) { continue }
            if (Test-Path -LiteralPath $destination) {
                throw ('Evidence archive contains a duplicate member path: {0}' -f $entry.FullName)
            }

            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Create($destination)
            try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
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
        Id            = [int]$Finding.Id
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
        ResultCode    = if ($Finding.PSObject.Properties['ResultCode']) { $Finding.ResultCode } else { $null }
        ExtendCode    = if ($Finding.PSObject.Properties['ExtendCode']) { $Finding.ExtendCode } else { $null }
        Phase         = if ($Finding.PSObject.Properties['Phase']) { $Finding.Phase } else { $null }
        Operation     = if ($Finding.PSObject.Properties['Operation']) { $Finding.Operation } else { $null }
        ProviderLocale = if ($Finding.PSObject.Properties['ProviderLocale']) { $Finding.ProviderLocale } else { $null }
        FallbackMessage = if ($Finding.PSObject.Properties['FallbackMessage']) { $Finding.FallbackMessage } else { $null }
        ErrorContext  = if ($Finding.PSObject.Properties['ErrorContext']) { $Finding.ErrorContext } else { $null }
        Times         = @($times.ToArray() | Sort-Object)
        Area          = $Finding.Area
        PerDay        = [double]$Finding.PerDay
        SpanDays      = [double]$Finding.SpanDays
    }
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
        [ValidateRange(1, 8589934592)][long]$MaxTotalBytes = 2147483648
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
        }
        if ($index -gt $MaxFiles) {
            $entry.Reason = ('file-count cap of {0} reached' -f $MaxFiles)
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
        try {
            $entry.SHA256 = Get-LVEvtxSha256 -Path $path
        } catch {
            $entry.Reason = ('source hash failed: {0}' -f $_.Exception.Message)
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
        [int]$MaxEvents = 20000
    )

    $fallbackChannel = [IO.Path]::GetFileNameWithoutExtension($Path)
    $channel = $fallbackChannel
    $oldest = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $first = Get-WinEvent -Path $Path -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($first) {
            if ($first.LogName) { $channel = [string]$first.LogName }
            $oldest = $first.TimeCreated
        }
    } catch {
        $timer.Stop()
        return [pscustomobject]@{ Channel=$channel; Oldest=$null; Records=@(); Truncated=$false; Error=$_.Exception.Message; ParseMilliseconds=[math]::Round($timer.Elapsed.TotalMilliseconds, 0) }
    }

    $filter = @{ Path = $Path; StartTime = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack)) }
    if ($Level -and $Level.Count -gt 0) { $filter['Level'] = $Level }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch {
        $kind = Get-LVErrorKind -ErrorRecord $_
        if ($kind -eq 'empty') { $events = @() }
        else {
            $timer.Stop()
            return [pscustomobject]@{ Channel=$channel; Oldest=$oldest; Records=@(); Truncated=$false; Error=$_.Exception.Message; ParseMilliseconds=[math]::Round($timer.Elapsed.TotalMilliseconds, 0) }
        }
    }

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($eventRecord in $events) {
        $message = $null
        try { $message = $eventRecord.Message } catch { $message = $null }
        $fallbackMessage = $null
        if ([string]::IsNullOrWhiteSpace([string]$message)) {
            $message = '(no message template registered for this provider on this machine)'
            $fallbackMessage = $message
        }
        $recordChannel = $channel
        if ($eventRecord.LogName) { $recordChannel = [string]$eventRecord.LogName }
        $errorContext = New-LVErrorContext -InputObject $eventRecord -Message ([string]$message) `
            -FallbackMessage $fallbackMessage
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
            ResultCode  = $errorContext.ResultCode
            ExtendCode  = $errorContext.ExtendCode
            Phase       = $errorContext.Phase
            Operation   = $errorContext.Operation
            ProviderLocale = $errorContext.ProviderLocale
            FallbackMessage = $errorContext.FallbackMessage
            ErrorContext = $errorContext
        }) | Out-Null
    }

    $timer.Stop()
    return [pscustomobject]@{
        Channel   = $channel
        Oldest    = $oldest
        Records   = @($records.ToArray())
        Truncated = ($events.Count -ge $MaxEvents)
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
        [switch]$IncludeBenign,
        [string]$DatabasePath,
        [int]$MaxPerChannel = 20000,
        [ValidateRange(1, 512)][int]$MaxEvtxFiles = 64,
        [ValidateRange(1, 4294967296)][long]$MaxEvtxFileBytes = 536870912,
        [ValidateRange(1, 8589934592)][long]$MaxEvtxTotalBytes = 2147483648,
        [ValidateRange(1, 600)][int]$MaxEvtxParseSeconds = 120,
        [switch]$ExplainUnknown,
        [string]$OllamaModel = 'llama3.2',
        [string]$OllamaEndpoint = 'http://127.0.0.1:11434',
        [switch]$PromoteToRule,
        [string]$LocalRulePath
    )

    $started = Get-Date
    $package = $null
    try {
        $package = Expand-LVEvidencePackage -Path $EvidencePath
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
            -MaxFileBytes $MaxEvtxFileBytes -MaxTotalBytes $MaxEvtxTotalBytes
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
            $data = Read-LVArchivedEventFile -Path $file.FullName -DaysBack $effectiveDays -MaxEvents $MaxPerChannel
            $manifestEntry.ParseMilliseconds = $data.ParseMilliseconds
            $manifestEntry.Channel = $data.Channel
            $manifestEntry.Oldest = $data.Oldest
            $manifestEntry.RecordCount = @($data.Records).Count
            $manifestEntry.Truncated = [bool]$data.Truncated
            if ($data.ParseMilliseconds -gt ($MaxEvtxParseSeconds * 1000)) {
                $manifestEntry.Status = 'timeout'
                $manifestEntry.Reason = ('parser exceeded the {0} second cap' -f $MaxEvtxParseSeconds)
                $failedChannels.Add($data.Channel) | Out-Null
                Write-LVLog -Level warn -Message ("Archived channel '{0}' exceeded the {1}-second offline parse cap." -f $data.Channel, $MaxEvtxParseSeconds)
                continue
            }
            if ($Channel -and $Channel -notcontains $data.Channel) {
                $manifestEntry.Status = 'filtered'
                $manifestEntry.Reason = 'channel filter excluded this source'
                continue
            }
            if ($data.Error) {
                $manifestEntry.Status = 'unreadable'
                $manifestEntry.Reason = [string]$data.Error
                $failedChannels.Add($data.Channel) | Out-Null
                $channelStatus[$data.Channel] = [pscustomobject]@{ Channel=$data.Channel; Access='unreadable'; Oldest=$data.Oldest; Origin='evidence' }
                Write-LVLog -Level warn -Message ("Archived channel '{0}' could not be read: {1}" -f $data.Channel, $data.Error)
                continue
            }
            $manifestEntry.Status = 'parsed'
            $parsedChannels.Add($data.Channel) | Out-Null
            $channelStatus[$data.Channel] = [pscustomobject]@{ Channel=$data.Channel; Access='readable'; Oldest=$data.Oldest; Origin='evidence' }
            foreach ($record in @($data.Records)) { $records.Add($record) | Out-Null }
            if ($data.Truncated) { $truncatedChannels.Add($data.Channel) | Out-Null }
        }

        $eventGrouping = Get-LVSignatureReduction -Record @($records.ToArray()) -WindowDays $effectiveDays
        $eventSignatures = @($eventGrouping.Signatures)
        $signatureByKey = @{}
        foreach ($signature in $eventSignatures) { $signatureByKey[$signature.Key] = $signature }

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

        $db = Get-LogVerdictDatabase -Path $DatabasePath
        Write-LVLog -Level info -Message ('Applying {0} rule(s) from the verdict database...' -f @($db.rules).Count)
        $findings = @(Resolve-LVVerdict -Signature $signatures -Database $db)
        $correlations = @(Resolve-LVCorrelation -Finding $findings -Database $db)
        if (-not $IncludeBenign) { $findings = @($findings | Where-Object { $_.Verdict -ne 'benign' }) }
        $modelRequested = [bool]($ExplainUnknown -or $PromoteToRule)
        $promotedDrafts = @()
        if ($modelRequested) {
            Write-LVLog -Level info -Message ('Requesting non-remedial draft explanations for unknown signatures from local Ollama model {0}...' -f $OllamaModel)
            $findings = @(Add-LVModelExplanation -Finding @($findings) -Model $OllamaModel -Endpoint $OllamaEndpoint)
        }
        if ($PromoteToRule) {
            $accepted = @($findings | Where-Object { $_.PSObject.Properties['ModelExplanation'] -and $_.ModelExplanation })
            if ($accepted.Count -eq 0) {
                Write-LVLog -Level warn -Message 'No safe model candidates were available to promote; the local rule file was not changed.'
            } else {
                $evidenceMachine = $null
                if ($sourceReport -and $sourceReport.MachineName) { $evidenceMachine = [string]$sourceReport.MachineName }
                elseif ($records.Count -gt 0 -and $records[0].MachineName) { $evidenceMachine = [string]$records[0].MachineName }
                $promotedDrafts = @(Write-LVModelDraftRule -Finding $accepted -Path $LocalRulePath -MachineName $evidenceMachine)
            }
        }

        $coverageNotes = New-Object System.Collections.Generic.List[string]
        $coverageNotes.Add('This is offline analysis. No event channel, text log, Reliability Monitor provider, or crash directory on the reviewing PC was queried.') | Out-Null
        foreach ($note in @($sourceReport.CoverageNotes | Where-Object { $_ })) { $coverageNotes.Add([string]$note) | Out-Null }
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
        if ($failedChannels.Count -gt 0) {
            $coverageNotes.Add(('Archived channel file(s) could not be read and only their report summaries were available: {0}.' -f ($failedChannels -join ', '))) | Out-Null
        }
        if ($truncatedChannels.Count -gt 0) {
            $coverageNotes.Add(('Archived channel file(s) hit the {0}-record offline cap: {1}.' -f $MaxPerChannel, ($truncatedChannels -join ', '))) | Out-Null
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
        foreach ($finding in @($findings) + @($correlations)) {
            if ((Get-LVVerdictRank -Verdict $finding.Verdict) -gt (Get-LVVerdictRank -Verdict $worst)) { $worst = $finding.Verdict }
        }
        $exitCode = 0
        switch ($worst) {
            'critical'    { $exitCode = 3 }
            'actionable'  { $exitCode = 2 }
            'investigate' { $exitCode = 1 }
            'unknown'     { $exitCode = 1 }
        }

        $machineName = '(offline evidence)'
        if ($sourceReport -and $sourceReport.MachineName) { $machineName = [string]$sourceReport.MachineName }
        elseif ($records.Count -gt 0 -and $records[0].MachineName) { $machineName = [string]$records[0].MachineName }

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
            $coverageSources.Add((New-LVCoverageRecord -Source 'offline-evtx' -Kind 'file' -Name $source.Name -Status $source.Status `
                -Reason $source.Reason -Path $source.Path -WindowStart ($started.AddDays(-1 * [Math]::Abs($effectiveDays))) -WindowEnd $started `
                -Cap $MaxPerChannel -ObservedRecords $source.RecordCount -RecordGap $null -ParserError $(if ($source.Status -eq 'unreadable') { $source.Reason } else { $null }) `
                -SizeBytes $source.SizeBytes -ParseMilliseconds $source.ParseMilliseconds -SHA256 $source.SHA256 -Origin 'offline')) | Out-Null
        }
        if ($sourceReport -and $sourceReport.PSObject.Properties['Coverage']) {
            foreach ($source in @($sourceReport.Coverage | Where-Object { $_ })) { $coverageSources.Add($source) | Out-Null }
        }

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
            MachineName    = $machineName
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
            Correlations   = @($correlations)
            CrashArtifacts = @($crash)
            EvidenceManifest = @($evtxPlan.Manifest)
            Coverage       = @($coverageSources.ToArray())
            HealthProfiles = @($healthProfiles)
            Horizon        = $horizon
            HorizonWarning = $horizonWarning
            Stability      = $stability
            ReliabilityAvailable = $reliabilityAvailable
            DatabaseName   = $db.name
            DatabaseDate   = $db.updated
            RuleCount      = @($db.rules).Count
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
