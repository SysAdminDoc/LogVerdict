# Optional local scan history. This is a bounded trend signal, never a verdict source.

$script:LVHistorySchemaVersion = 1
$script:LVHistoryMaxEntries = 30
$script:LVHistoryDefaultWindowDays = 30
$script:LVHistoryRelativeThreshold = 0.25
$script:LVHistoryAbsoluteThreshold = 0.10

function Get-LVHistoryEmptyBaseline {
    return [pscustomobject]@{
        Method      = 'Median per-day rate across prior bounded scans'
        SampleCount = 0
        ScanTimes   = @()
    }
}

function Get-LVHistoryThreshold {
    return [pscustomobject]@{
        RelativeIncrease = $script:LVHistoryRelativeThreshold
        AbsolutePerDay   = $script:LVHistoryAbsoluteThreshold
        Description      = 'Signal when the current rate is at least 25% above baseline and at least 0.10/day higher.'
    }
}

function Get-LVHistoryDisabledResult {
    param([ValidateRange(1, 3650)][int]$WindowDays = $script:LVHistoryDefaultWindowDays)

    return [pscustomobject]@{
        Enabled             = $false
        Status              = 'disabled'
        Persistence         = 'not-written'
        PathName            = $null
        EntriesStored       = 0
        Baseline            = Get-LVHistoryEmptyBaseline
        WindowDays          = $WindowDays
        Threshold           = Get-LVHistoryThreshold
        Signals             = @()
        AdvisoryOnly        = $true
        FalsePositiveCaveat = 'Trend history is opt-in. Missing history is not evidence of a healthy or unhealthy machine; history never changes Verdict, WorstVerdict, or ExitCode.'
    }
}

function ConvertTo-LVHistoryEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][datetime]$ScanTime,
        [Parameter(Mandatory)][int]$DaysBack,
        [Parameter(Mandatory)][int]$RecordCount,
        [Parameter(Mandatory)][int]$SignatureCount
    )

    $safeFindings = foreach ($item in @($Finding | Where-Object { $_ })) {
        [pscustomobject][ordered]@{
            Key      = [string]$item.Key
            Verdict  = [string]$item.Verdict
            Count    = [int]$item.Count
            PerDay   = [double]$item.PerDay
            RuleId   = if ($item.PSObject.Properties['RuleId']) { [string]$item.RuleId } else { $null }
            Curated  = [bool]($item.PSObject.Properties['RuleId'] -and $item.RuleId)
        }
    }

    return [pscustomobject][ordered]@{
        ScanTime       = $ScanTime.ToUniversalTime().ToString('o')
        DaysBack       = $DaysBack
        RecordCount    = $RecordCount
        SignatureCount = $SignatureCount
        Findings       = @($safeFindings)
    }
}

function Read-LVHistoryDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $leaf = Split-Path -Leaf $Path
    $base = [pscustomobject]@{
        PathName = $leaf
        Status   = 'missing'
        Document = $null
        Entries  = @()
    }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $base }
        $document = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -eq $document -or $null -eq $document.schemaVersion -or [int]$document.schemaVersion -ne $script:LVHistorySchemaVersion) {
            $base.Status = 'unreadable'
            return $base
        }
        if ($null -eq $document.entries -or $document.entries -is [string]) {
            $base.Status = 'unreadable'
            return $base
        }

        $entries = New-Object System.Collections.Generic.List[object]
        foreach ($entry in @($document.entries | Where-Object { $_ })) {
            $parsedTime = $null
            try { $parsedTime = [datetime]$entry.ScanTime } catch { $parsedTime = $null }
            if ($null -eq $parsedTime -or -not $entry.PSObject.Properties['Findings']) {
                $base.Status = 'unreadable'
                return $base
            }
            foreach ($finding in @($entry.Findings | Where-Object { $_ })) {
                if (-not $finding.PSObject.Properties['Key'] -or -not $finding.Key -or
                    -not $finding.PSObject.Properties['Verdict'] -or -not $finding.PSObject.Properties['PerDay']) {
                    $base.Status = 'unreadable'
                    return $base
                }
                try { [double]$finding.PerDay | Out-Null } catch {
                    $base.Status = 'unreadable'
                    return $base
                }
            }
            $entries.Add($entry) | Out-Null
        }
        $base.Status = 'loaded'
        $base.Document = $document
        $base.Entries = @($entries.ToArray() | Sort-Object { [datetime]$_.ScanTime } | Select-Object -Last $script:LVHistoryMaxEntries)
        return $base
    } catch {
        $base.Status = 'unreadable'
        return $base
    }
}

function Write-LVHistoryAtomic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Document
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temp = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N'))
    try {
        Write-LVTextFile -Path $temp -Content ($Document | ConvertTo-Json -Depth 12)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                [System.IO.File]::Replace($temp, $Path, $null, $true)
            } catch {
                Move-Item -LiteralPath $temp -Destination $Path -Force
            }
        } else {
            Move-Item -LiteralPath $temp -Destination $Path -Force
        }
        return $true
    } finally {
        if (Test-Path -LiteralPath $temp -PathType Leaf) {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-LVHistoryMedian {
    [CmdletBinding()]
    [OutputType([double])]
    param([AllowEmptyCollection()][double[]]$Value)

    $values = @($Value | Sort-Object)
    if ($values.Count -eq 0) { return 0.0 }
    $middle = [int][Math]::Floor($values.Count / 2)
    if (($values.Count % 2) -eq 1) { return [double]$values[$middle] }
    return [double](($values[$middle - 1] + $values[$middle]) / 2)
}

function Get-LVHistoryTrend {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PriorEntry,
        [Parameter(Mandatory)][datetime]$ScanTime,
        [ValidateRange(1, 3650)][int]$WindowDays = 30
    )

    $threshold = Get-LVHistoryThreshold
    $current = @{}
    foreach ($item in @($Finding | Where-Object { $_ })) {
        $current[[string]$item.Key] = [pscustomobject]@{
            Key      = [string]$item.Key
            Verdict  = [string]$item.Verdict
            Count    = [int]$item.Count
            PerDay   = [double]$item.PerDay
        }
    }

    $cutoff = $ScanTime.ToUniversalTime().AddDays(-1 * [Math]::Abs($WindowDays))
    $eligible = foreach ($entry in @($PriorEntry | Where-Object { $_ })) {
        try {
            $entryTime = ([datetime]$entry.ScanTime).ToUniversalTime()
            if ($entryTime -le $ScanTime.ToUniversalTime() -and $entryTime -ge $cutoff) { $entry }
        } catch { continue }
    }
    $eligible = @($eligible | Sort-Object { [datetime]$_.ScanTime })
    $baseline = [pscustomobject]@{
        Method      = 'Median per-day rate across prior bounded scans'
        SampleCount = $eligible.Count
        ScanTimes   = @($eligible | ForEach-Object { ([datetime]$_.ScanTime).ToUniversalTime().ToString('o') })
    }
    $caveat = 'Advisory only. Retention, collection bounds, workload, and missing history can create apparent changes; history never changes Verdict, WorstVerdict, or ExitCode.'
    if ($eligible.Count -eq 0) {
        return [pscustomobject]@{
            Status              = 'missing-history'
            AdvisoryOnly        = $true
            Baseline            = $baseline
            WindowDays          = $WindowDays
            Threshold           = $threshold
            Signals             = @()
            FalsePositiveCaveat = $caveat
        }
    }

    $keys = New-Object System.Collections.Generic.HashSet[string]
    foreach ($key in @($current.Keys)) { $keys.Add([string]$key) | Out-Null }
    foreach ($entry in $eligible) {
        foreach ($item in @($entry.Findings | Where-Object { $_ })) { $keys.Add([string]$item.Key) | Out-Null }
    }

    $signals = New-Object System.Collections.Generic.List[object]
    foreach ($key in @($keys)) {
        $currentItem = $null
        if ($current.ContainsKey($key)) { $currentItem = $current[$key] }
        $rates = New-Object System.Collections.Generic.List[double]
        $baselineItem = $null
        foreach ($entry in $eligible) {
            $entryItem = @($entry.Findings | Where-Object { [string]$_.Key -eq $key } | Select-Object -First 1)
            if ($entryItem.Count -gt 0) {
                $rates.Add([double]$entryItem[0].PerDay) | Out-Null
                $baselineItem = $entryItem[0]
            } else {
                $rates.Add(0.0) | Out-Null
            }
        }
        $median = Get-LVHistoryMedian -Value @($rates.ToArray())
        if ($null -eq $currentItem) {
            $lastItem = @($eligible[-1].Findings | Where-Object { [string]$_.Key -eq $key } | Select-Object -First 1)
            if ($lastItem.Count -gt 0) {
                $signals.Add([pscustomobject]@{
                    Type          = 'resolved'
                    Key           = $key
                    BeforeRate    = [double]$median
                    AfterRate     = 0.0
                    BeforeVerdict = [string]$lastItem[0].Verdict
                    AfterVerdict  = $null
                    Reason        = ('No current finding for this key; prior median was {0:N2}/day across the bounded baseline.' -f $median)
                }) | Out-Null
            }
            continue
        }
        if ($null -eq $baselineItem) {
            $signals.Add([pscustomobject]@{
                Type          = 'new'
                Key           = $key
                BeforeRate    = 0.0
                AfterRate     = [double]$currentItem.PerDay
                BeforeVerdict = $null
                AfterVerdict  = [string]$currentItem.Verdict
                Reason        = ('New key in the current scan; no matching key exists in the bounded baseline.')
            }) | Out-Null
            continue
        }
        $afterRate = [double]$currentItem.PerDay
        $absoluteRise = $afterRate - $median
        $relativeRise = if ($median -le 0) { [double]::PositiveInfinity } else { $absoluteRise / $median }
        if ($absoluteRise -ge $threshold.AbsolutePerDay -and ($median -le 0 -or $relativeRise -ge $threshold.RelativeIncrease)) {
            $signals.Add([pscustomobject]@{
                Type          = 'rate-increase'
                Key           = $key
                BeforeRate    = [double]$median
                AfterRate     = $afterRate
                BeforeVerdict = [string]$baselineItem.Verdict
                AfterVerdict  = [string]$currentItem.Verdict
                Reason        = ('Rate rose from a {0:N2}/day median baseline to {1:N2}/day in the current window; threshold is at least {2:P0} relative and {3:N2}/day absolute.' -f $median, $afterRate, $threshold.RelativeIncrease, $threshold.AbsolutePerDay)
            }) | Out-Null
        }
    }

    return [pscustomobject]@{
        Status              = if ($signals.Count -gt 0) { 'signals' } else { 'steady' }
        AdvisoryOnly        = $true
        Baseline            = $baseline
        WindowDays          = $WindowDays
        Threshold           = $threshold
        Signals             = @($signals.ToArray())
        FalsePositiveCaveat = $caveat
    }
}

function Update-LVScanHistory {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][datetime]$ScanTime,
        [Parameter(Mandatory)][int]$DaysBack,
        [Parameter(Mandatory)][int]$RecordCount,
        [Parameter(Mandatory)][int]$SignatureCount,
        [ValidateRange(1, 3650)][int]$WindowDays = 30,
        [ValidateRange(1, 3650)][int]$MaxEntries = 30
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return Get-LVHistoryDisabledResult -WindowDays $WindowDays }
    $read = Read-LVHistoryDocument -Path $Path
    if ($read.Status -eq 'unreadable') {
        $trend = Get-LVHistoryTrend -Finding $Finding -PriorEntry @() -ScanTime $ScanTime -WindowDays $WindowDays
        $trend.Status = 'unreadable'
        return [pscustomobject]@{
            Enabled             = $true
            Status              = 'unreadable'
            Persistence         = 'not-written'
            PathName            = $read.PathName
            EntriesStored       = 0
            Baseline            = $trend.Baseline
            WindowDays          = $trend.WindowDays
            Threshold           = $trend.Threshold
            Signals             = @()
            AdvisoryOnly        = $true
            FalsePositiveCaveat = $trend.FalsePositiveCaveat
        }
    }

    $prior = @($read.Entries)
    $trend = Get-LVHistoryTrend -Finding $Finding -PriorEntry $prior -ScanTime $ScanTime -WindowDays $WindowDays
    $newEntry = ConvertTo-LVHistoryEntry -Finding $Finding -ScanTime $ScanTime -DaysBack $DaysBack -RecordCount $RecordCount -SignatureCount $SignatureCount
    $entries = @($prior + $newEntry | Sort-Object { [datetime]$_.ScanTime } | Select-Object -Last ([Math]::Min($MaxEntries, $script:LVHistoryMaxEntries)))
    $document = [pscustomobject][ordered]@{
        SchemaVersion = $script:LVHistorySchemaVersion
        Updated       = $ScanTime.ToUniversalTime().ToString('o')
        Entries       = @($entries)
    }
    $persistence = 'saved'
    try {
        if ($PSCmdlet.ShouldProcess((Split-Path -Leaf $Path), 'Update local scan history')) {
            Write-LVHistoryAtomic -Path $Path -Document $document | Out-Null
        } else {
            $persistence = 'what-if'
        }
    } catch {
        $persistence = 'write-failed'
    }

    return [pscustomobject]@{
        Enabled             = $true
        Status              = $trend.Status
        Persistence         = if ($read.Status -eq 'missing' -and $persistence -eq 'saved') { 'created' } else { $persistence }
        PathName            = $read.PathName
        EntriesStored       = $entries.Count
        Baseline            = $trend.Baseline
        WindowDays          = $trend.WindowDays
        Threshold           = $trend.Threshold
        Signals             = @($trend.Signals)
        AdvisoryOnly        = $true
        FalsePositiveCaveat = $trend.FalsePositiveCaveat
    }
}
