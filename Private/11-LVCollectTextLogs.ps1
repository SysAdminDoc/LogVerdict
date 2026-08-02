# Collection layer: the plain-text logs Windows keeps outside the event channels.
# These carry the servicing, driver-install and setup failures that never reach
# Event Viewer, which is why "check Event Viewer" so often comes up empty.
#
# Timestamps here are parsed from the log content, never inherited from the file's
# LastWriteTime. Stamping every line with the file mtime collapses each file into a
# single instant, which makes first/last seen meaningless, makes the rate wrong, stops
# rate escalation from ever firing on a text rule, and quietly turns -DaysBack into a
# filter on the file rather than on the lines inside it.
#
# All timestamp parsing uses InvariantCulture: these formats are fixed by the writing
# component and do not follow the machine's locale.

$script:LVTextLogTarget = @(
    @{
        Name        = 'CBS'
        Path        = 'C:\Windows\Logs\CBS\CBS.log'
        # CBS writes ", Error  CSI ..." - anchoring on the column avoids matching
        # the thousands of benign lines that merely contain the word "error".
        Pattern     = ',\s*Error\s'
        TimePattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        TimeFormat  = 'yyyy-MM-dd HH:mm:ss'
        Area        = 'Component servicing'
        Hint        = 'Backs SFC, DISM and Windows Update payload installation.'
    },
    @{
        Name        = 'DISM'
        Path        = 'C:\Windows\Logs\DISM\dism.log'
        Pattern     = ',\s*Error\s'
        TimePattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        TimeFormat  = 'yyyy-MM-dd HH:mm:ss'
        Area        = 'Image servicing'
        Hint        = 'Written by DISM and by in-place upgrade servicing.'
    },
    @{
        Name = 'SetupAPI'
        Path = 'C:\Windows\INF\setupapi.dev.log'
        # SetupAPI marks errors with a triple bang and warnings with a single one.
        Pattern = '^\s*!!!'
        # Error lines carry no timestamp of their own; the time comes from the most
        # recent section header above them, so it is carried forward while streaming.
        SectionTimePattern = 'Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
        TimeFormat = 'yyyy/MM/dd HH:mm:ss'
        Area = 'Driver and device install'
        Hint = 'Every driver install, update and device enumeration on this PC.'
    },
    @{
        Name        = 'NetSetup'
        Path        = 'C:\Windows\debug\NetSetup.LOG'
        Pattern     = '(?i)(failed|error|0x[0-9A-Fa-f]{8})'
        TimePattern = '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'
        TimeFormat  = 'MM/dd/yyyy HH:mm:ss'
        Area        = 'Domain join and rename'
        Hint        = 'Survives in-place upgrades, unlike the event channels.'
    },
    @{
        Name        = 'PantherSetupAct'
        Path        = 'C:\Windows\Panther\setupact.log'
        Pattern     = '(?i)(\[error\]|fatal)'
        TimePattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        TimeFormat  = 'yyyy-MM-dd HH:mm:ss'
        Area        = 'Setup and upgrade'
        Hint        = 'Records the last feature update or in-place upgrade.'
    },
    @{
        Name        = 'MoSetupBlueBox'
        Path        = 'C:\Windows\Logs\MoSetup\BlueBox.log'
        Pattern     = '(?i)(error|failed)'
        TimePattern = '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        TimeFormat  = 'yyyy-MM-dd HH:mm:ss'
        Area        = 'Upgrade compatibility'
        Hint        = 'Upgrade blocks and compatibility appraiser results.'
    }
)

function ConvertFrom-LVLogTimestamp {
    <#
        .SYNOPSIS
        Parse a timestamp out of a log line. Returns $null when the line carries none.

        .DESCRIPTION
        InvariantCulture on purpose: these formats are fixed by whichever component
        writes the log and do not vary with the machine's locale, so parsing them with
        the current culture would fail on exactly the non-English machines that are
        hardest to debug.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Line,
        [string]$TimePattern,
        [string]$TimeFormat
    )

    if (-not $TimePattern -or -not $TimeFormat) { return $null }

    $m = [regex]::Match($Line, $TimePattern)
    if (-not $m.Success) { return $null }

    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact(
        $m.Groups[1].Value,
        $TimeFormat,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None,
        [ref]$parsed)

    if ($ok) { return $parsed }
    return $null
}

function Get-LVTextLogRecord {
    <#
        .SYNOPSIS
        Error-shaped lines from the well-known Windows text logs, with their real times.

        .DESCRIPTION
        Streams each file so a multi-hundred-megabyte CBS.log does not land in memory,
        and caps the matches per file so one runaway component cannot drown the report.

        Lines whose timestamp cannot be parsed are kept but marked undated rather than
        given a fabricated time - the tool does not invent evidence it does not have.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 30,
        [int]$MaxMatchesPerFile = 4000,
        # Injection seam: lets the suite exercise the real parser against fixture files
        # instead of whatever happens to be in C:\Windows on the machine running tests.
        [object[]]$Target = $script:LVTextLogTarget
    )

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $windowEnd = Get-Date
    $records = New-Object System.Collections.Generic.List[object]
    $coverage = New-Object System.Collections.Generic.List[object]

    foreach ($target in $Target) {
        $path = $target.Path
        if (-not (Test-Path -LiteralPath $path)) {
            Write-LVLog -Level info -Message ("{0}: not present on this machine" -f $target.Name)
            $coverage.Add((New-LVCoverageRecord -Source 'textlog' -Kind 'file' -Name $target.Name -Status 'not-observed' `
                -Reason 'The file is not present on this machine.' -Path $path -WindowStart $cutoff -WindowEnd $windowEnd -Cap $MaxMatchesPerFile -Origin 'live')) | Out-Null
            continue
        }

        $file = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $file) {
            $coverage.Add((New-LVCoverageRecord -Source 'textlog' -Kind 'file' -Name $target.Name -Status 'unreadable' `
                -Reason 'The file could not be opened for metadata.' -Path $path -WindowStart $cutoff -WindowEnd $windowEnd -Cap $MaxMatchesPerFile -Origin 'live')) | Out-Null
            continue
        }
        if ($file.LastWriteTime -lt $cutoff) {
            Write-LVLog -Level info -Message ("{0}: last written {1:yyyy-MM-dd}, outside the {2}-day window" -f $target.Name, $file.LastWriteTime, $DaysBack)
            $coverage.Add((New-LVCoverageRecord -Source 'textlog' -Kind 'file' -Name $target.Name -Status 'not-observed' `
                -Reason ('The file was last written {0:yyyy-MM-dd}, outside the requested window.' -f $file.LastWriteTime) -Path $path -WindowStart $cutoff -WindowEnd $windowEnd -Cap $MaxMatchesPerFile -SizeBytes $file.Length -Origin 'live')) | Out-Null
            continue
        }

        $matched = 0
        $skippedOld = 0
        $undated = 0
        $sectionTime = $null
        $reader = $null
        $parserError = $null

        try {
            $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $reader = New-Object System.IO.StreamReader($stream)
            $regex = [regex]$target.Pattern
            $sectionRegex = $null
            if ($target.SectionTimePattern) { $sectionRegex = [regex]$target.SectionTimePattern }

            while ($null -ne ($line = $reader.ReadLine())) {
                if ($matched -ge $MaxMatchesPerFile) { break }

                # Carry-forward timestamps: SetupAPI error lines are undated, and take
                # their time from the most recent section header above them.
                if ($sectionRegex) {
                    $sm = $sectionRegex.Match($line)
                    if ($sm.Success) {
                        $t = ConvertFrom-LVLogTimestamp -Line $line -TimePattern $target.SectionTimePattern -TimeFormat $target.TimeFormat
                        if ($t) { $sectionTime = $t }
                    }
                }

                if (-not $regex.IsMatch($line)) { continue }

                $when = $null
                if ($target.TimePattern) {
                    $when = ConvertFrom-LVLogTimestamp -Line $line -TimePattern $target.TimePattern -TimeFormat $target.TimeFormat
                } elseif ($sectionTime) {
                    $when = $sectionTime
                }

                if ($when) {
                    if ($when -lt $cutoff) { $skippedOld++; continue }
                } else {
                    $undated++
                }

                $matched++
                $records.Add([pscustomobject]@{
                    Source      = 'textlog'
                    Channel     = $target.Name
                    Provider    = $target.Name
                    Id          = 0
                    Level       = 2
                    LevelName   = 'Error'
                    TimeCreated = $when
                    Undated     = ($null -eq $when)
                    MachineName = $env:COMPUTERNAME
                    RecordId    = $matched
                    Area        = $target.Area
                    Hint        = $target.Hint
                    Message     = $line.Trim()
                }) | Out-Null
            }
        } catch {
            $parserError = $_.Exception.Message
            Write-LVLog -Level warn -Message ("{0}: unreadable ({1})" -f $target.Name, $_.Exception.Message)
            $coverage.Add((New-LVCoverageRecord -Source 'textlog' -Kind 'file' -Name $target.Name -Status 'unreadable' `
                -Reason 'The text-log parser failed before the file was fully observed.' -Path $path -WindowStart $cutoff -WindowEnd $windowEnd `
                -Cap $MaxMatchesPerFile -ParserError $parserError -SizeBytes $file.Length -Origin 'live')) | Out-Null
            continue
        } finally {
            if ($reader) { $reader.Dispose() }
        }

        if ($matched -ge $MaxMatchesPerFile) {
            Write-LVLog -Level warn -Message ("{0}: hit the {1}-match cap; report is truncated for this file" -f $target.Name, $MaxMatchesPerFile)
        }
        if ($matched -gt 0) {
            $detail = ''
            if ($skippedOld -gt 0) { $detail += (' ({0} older line(s) outside the window)' -f $skippedOld) }
            if ($undated -gt 0)    { $detail += (' ({0} undated line(s))' -f $undated) }
            Write-LVLog -Level ok -Message ("{0}: {1} error line(s){2}" -f $target.Name, $matched, $detail)
        }
        $status = if ($matched -ge $MaxMatchesPerFile) { 'truncated' } elseif ($matched -gt 0) { 'readable' } else { 'empty' }
        $reason = if ($status -eq 'truncated') {
            ('The per-file match cap of {0} was reached; observed lines are a lower bound.' -f $MaxMatchesPerFile)
        } elseif ($matched -eq 0 -and $skippedOld -gt 0) {
            ('No matching error line was observed in the requested window; {0} older line(s) were skipped.' -f $skippedOld)
        } elseif ($matched -eq 0) {
            'No matching error-shaped line was observed in the requested window.'
        } elseif ($undated -gt 0) {
            ('Observed {0} matching line(s); {1} had no parseable timestamp.' -f $matched, $undated)
        } else { $null }
        $coverage.Add((New-LVCoverageRecord -Source 'textlog' -Kind 'file' -Name $target.Name -Status $status `
            -Reason $reason -Path $path -WindowStart $cutoff -WindowEnd $windowEnd -Cap $MaxMatchesPerFile `
            -ObservedRecords $matched -SkippedRecords $skippedOld -SizeBytes $file.Length -ParserError $parserError -Origin 'live')) | Out-Null
    }

    $script:LVTextLogCoverage = @($coverage.ToArray())
    return ConvertTo-LVArrayOutput -Value @($records.ToArray())
}

function Test-LVSetupDiagExecutableTrust {
    <#
        .SYNOPSIS
        Accept only a Microsoft-signed SetupDiag executable on the production path.

        .DESCRIPTION
        SetupDiag is an optional executable rather than a bundled component. A file
        named SetupDiag.exe found through PATH or a mutable setup directory is not
        trustworthy merely because its name is familiar. The production discovery
        path therefore requires a valid Authenticode signature from Microsoft.
        Explicit CandidatePath input is reserved for the test seam and is handled
        by Get-LVSetupDiagExecutable without invoking this policy.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            Trusted = $false
            Reason  = ('Authenticode verification failed: {0}' -f $_.Exception.Message)
        }
    }

    if ([string]$signature.Status -ne 'Valid') {
        return [pscustomobject]@{
            Trusted = $false
            Reason  = ('Authenticode status is {0}, not Valid.' -f [string]$signature.Status)
        }
    }

    $subject = ''
    if ($signature.SignerCertificate) { $subject = [string]$signature.SignerCertificate.Subject }
    if ($subject -notmatch '(?i)(^|,\s*)CN=(Microsoft Corporation|Microsoft Windows)(,|$)') {
        return [pscustomobject]@{
            Trusted = $false
            Reason  = 'The Authenticode signer is not Microsoft Corporation or Microsoft Windows.'
        }
    }

    return [pscustomobject]@{
        Trusted = $true
        Reason  = ('Valid Microsoft Authenticode signature ({0}).' -f $subject)
    }
}

function Get-LVSetupDiagExecutable {
    <#
        .SYNOPSIS
        Find an already-present Microsoft SetupDiag executable without downloading it.

        .DESCRIPTION
        Explicit CandidatePath input is a test-only injection seam. Normal discovery
        verifies every existing candidate before returning it. Detailed output is
        private to the collector so rejected candidates can be surfaced as coverage
        without changing the historical path-returning helper contract.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$CandidatePath,
        [switch]$Detailed
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    $injected = $PSBoundParameters.ContainsKey('CandidatePath')
    if ($injected) {
        foreach ($path in @($CandidatePath)) { if ($path) { $candidates.Add($path) | Out-Null } }
    } else {
        $command = Get-Command 'SetupDiag.exe' -ErrorAction SilentlyContinue
        if ($command) {
            $commandPath = $null
            if ($command.PSObject.Properties['Path']) { $commandPath = [string]$command.Path }
            if (-not $commandPath -and $command.Source) { $commandPath = [string]$command.Source }
            if ($commandPath) { $candidates.Add($commandPath) | Out-Null }
        }

        $systemDrive = $env:SystemDrive
        if (-not $systemDrive) { $systemDrive = 'C:' }
        $windows = $env:windir
        if (-not $windows) { $windows = Join-Path $systemDrive 'Windows' }
        foreach ($path in @(
            (Join-Path $systemDrive '$Windows.~BT\Sources\SetupDiag.exe'),
            (Join-Path $systemDrive 'Windows.old\$Windows.~BT\Sources\SetupDiag.exe'),
            (Join-Path $windows 'System32\SetupDiag.exe'),
            (Join-Path $windows 'SetupDiag.exe')
        )) { $candidates.Add($path) | Out-Null }
    }

    $rejected = New-Object System.Collections.Generic.List[object]
    foreach ($path in @($candidates.ToArray() | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $fullPath = (Get-Item -LiteralPath $path -ErrorAction Stop).FullName
            if ($injected) {
                if ($Detailed) { return [pscustomobject]@{ Path=$fullPath; Rejected=@() } }
                return $fullPath
            }

            $trust = Test-LVSetupDiagExecutableTrust -Path $fullPath
            if ($trust.Trusted) {
                if ($Detailed) { return [pscustomobject]@{ Path=$fullPath; Rejected=@($rejected.ToArray()) } }
                return $fullPath
            }
            $rejected.Add([pscustomobject]@{ Path=$fullPath; Reason=$trust.Reason }) | Out-Null
        }
    }
    if ($Detailed) { return [pscustomobject]@{ Path=$null; Rejected=@($rejected.ToArray()) } }
    return $null
}

function Get-LVSetupDiagLogSet {
    <#
        .SYNOPSIS
        Choose the most recent supported Windows Setup log tree in the scan window.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 30,
        [AllowEmptyCollection()][string[]]$CandidatePath
    )

    if (-not $PSBoundParameters.ContainsKey('CandidatePath')) {
        $systemDrive = $env:SystemDrive
        if (-not $systemDrive) { $systemDrive = 'C:' }
        $windows = $env:windir
        if (-not $windows) { $windows = Join-Path $systemDrive 'Windows' }
        $CandidatePath = @(
            (Join-Path $systemDrive '$Windows.~BT\Sources'),
            (Join-Path $windows 'Panther'),
            (Join-Path $systemDrive 'Windows.old\$Windows.~BT\Sources')
        )
    }

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $sets = New-Object System.Collections.Generic.List[object]
    foreach ($path in @($CandidatePath | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
        $latest = Get-ChildItem -LiteralPath $path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)^(setupact|setuperr|bluebox).*\.log$' } |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First 1
        if ($latest) {
            $sets.Add([pscustomobject]@{ Path=(Get-Item -LiteralPath $path).FullName; Latest=$latest.LastWriteTime }) | Out-Null
        }
    }

    return @($sets.ToArray() | Where-Object { $_.Latest -ge $cutoff } | Sort-Object -Property Latest -Descending | Select-Object -First 1)
}

function Invoke-LVSetupDiagProcess {
    <#
        .SYNOPSIS
        Run SetupDiag without a window, telemetry, zip output, or registry changes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter(Mandatory)][string]$LogsPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [int]$TimeoutSeconds = 120
    )

    if ($LogsPath.Contains('"') -or $OutputPath.Contains('"')) {
        throw 'SetupDiag paths cannot contain a double quote.'
    }

    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $ExecutablePath
    $start.Arguments = '/Output:"{0}" /LogsPath:"{1}" /Format:json /ZipLogs:False /NoTel' -f $OutputPath, $LogsPath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'SetupDiag did not start.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $completed = $process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)
        if (-not $completed) {
            try { $process.Kill() } catch { Write-Verbose ('SetupDiag timeout cleanup failed: {0}' -f $_.Exception.Message) }
            $process.WaitForExit()
            return [pscustomobject]@{ ExitCode=$null; TimedOut=$true; StandardOutput=$stdoutTask.Result; StandardError=$stderrTask.Result }
        }
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            TimedOut = $false
            StandardOutput = $stdoutTask.Result
            StandardError = $stderrTask.Result
        }
    } finally {
        $process.Dispose()
    }
}

function Get-LVSetupDiagValue {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function ConvertTo-LVSetupDiagLine {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $line = ([string]$Value -replace '\s+', ' ').Trim()
    if ($line) { return $line }
    return $null
}

function ConvertFrom-LVSetupDiagDate {
    param(
        [AllowNull()]$Value,
        [Nullable[datetime]]$Fallback
    )

    if ($Value -is [datetime]) {
        if ($Value.Year -gt 1900) { return [datetime]$Value }
        return $Fallback
    }

    $text = [string]$Value
    $serialized = [regex]::Match($text, '^/Date\((-?\d+)(?:[+-]\d{4})?\)/$')
    if ($serialized.Success) {
        try {
            $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01 00:00:00', [DateTimeKind]::Utc)
            $date = $epoch.AddMilliseconds([double]$serialized.Groups[1].Value).ToLocalTime()
            if ($date.Year -gt 1900) { return $date }
        } catch { Write-Verbose ('SetupDiag serialized date could not be decoded: {0}' -f $_.Exception.Message) }
    }

    $parsed = [datetime]::MinValue
    if ($text -and [datetime]::TryParse(
        $text,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AllowWhiteSpaces,
        [ref]$parsed)) {
        if ($parsed.Year -gt 1900) { return $parsed }
    }
    return $Fallback
}

function ConvertFrom-LVSetupDiagJson {
    <#
        .SYNOPSIS
        Turn SetupDiag's documented JSON shape into one ordinary LogVerdict record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Json,
        [Nullable[datetime]]$FallbackWhen
    )

    try {
        $parsed = $Json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw ('SetupDiag returned invalid JSON: {0}' -f $_.Exception.Message)
    }

    $result = @($parsed | Where-Object { $_ -and (Get-LVSetupDiagValue -InputObject $_ -Name 'ProfileName') } | Select-Object -Last 1)
    if ($result.Count -eq 0) { throw 'SetupDiag JSON contains no ProfileName.' }
    $item = $result[0]
    $profileName = ConvertTo-LVSetupDiagLine (Get-LVSetupDiagValue -InputObject $item -Name 'ProfileName')
    $version = ConvertTo-LVSetupDiagLine (Get-LVSetupDiagValue -InputObject $item -Name 'Version')
    $guid = ConvertTo-LVSetupDiagLine (Get-LVSetupDiagValue -InputObject $item -Name 'ProfileGuid')

    $systemInfo = Get-LVSetupDiagValue -InputObject $item -Name 'SystemInfo'
    $when = $null
    if ($systemInfo) {
        $when = ConvertFrom-LVSetupDiagDate -Value (Get-LVSetupDiagValue -InputObject $systemInfo -Name 'UpgradeEndTime') -Fallback $null
        if ($null -eq $when) {
            $when = ConvertFrom-LVSetupDiagDate -Value (Get-LVSetupDiagValue -InputObject $systemInfo -Name 'UpgradeStartTime') -Fallback $null
        }
    }
    if ($null -eq $when) { $when = $FallbackWhen }

    if ($profileName -eq 'FindSuccessfulUpgrade') {
        return [pscustomobject]@{ Successful=$true; Profile=$profileName; Version=$version; Record=$null; When=$when }
    }

    $failure = New-Object System.Collections.Generic.List[string]
    foreach ($value in @(
        (Get-LVSetupDiagValue -InputObject $item -Name 'FailureDetails'),
        (Get-LVSetupDiagValue -InputObject $item -Name 'LogErrorLine')
    ) + @(Get-LVSetupDiagValue -InputObject $item -Name 'FailureData')) {
        $line = ConvertTo-LVSetupDiagLine $value
        if ($line -and -not $failure.Contains($line)) { $failure.Add($line) | Out-Null }
    }

    $remediation = New-Object System.Collections.Generic.List[string]
    foreach ($value in @(Get-LVSetupDiagValue -InputObject $item -Name 'Remediation')) {
        $line = ConvertTo-LVSetupDiagLine $value
        if ($line -and -not $remediation.Contains($line)) { $remediation.Add($line) | Out-Null }
    }

    $message = New-Object System.Collections.Generic.List[string]
    $identity = 'Microsoft SetupDiag'
    if ($version) { $identity += ' ' + $version }
    $identity += ' matched profile ' + $profileName
    if ($guid) { $identity += ' (' + $guid + ')' }
    $message.Add($identity + '.') | Out-Null
    if ($failure.Count -gt 0) { $message.Add('Failure: ' + ($failure -join ' | ')) | Out-Null }
    if ($remediation.Count -gt 0) { $message.Add('Remediation: ' + ($remediation -join ' | ')) | Out-Null }

    $record = [pscustomobject]@{
        Source = 'textlog'
        Channel = 'SetupDiag'
        Provider = 'Microsoft SetupDiag'
        Id = 0
        Level = 2
        LevelName = 'Error'
        TimeCreated = $when
        Undated = ($null -eq $when)
        MachineName = $env:COMPUTERNAME
        RecordId = 1
        Area = 'Setup and upgrade'
        Hint = 'Microsoft SetupDiag matched its curated upgrade-failure rules against the Panther log set.'
        SignatureKey = 'SetupDiag/' + $profileName.ToLowerInvariant()
        Message = $message -join ' '
    }

    return [pscustomobject]@{
        Successful = $false
        Profile = $profileName
        Version = $version
        Remediation = @($remediation.ToArray())
        Record = $record
        When = $when
    }
}

function Get-LVSetupDiagRecord {
    <#
        .SYNOPSIS
        Use SetupDiag when present, otherwise explicitly retain the Panther fallback.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 30,
        [AllowEmptyCollection()][string[]]$ExecutableCandidate,
        [AllowEmptyCollection()][string[]]$LogCandidate,
        [int]$TimeoutSeconds = 120
    )

    $executableArgs = @{ Detailed=$true }
    if ($PSBoundParameters.ContainsKey('ExecutableCandidate')) { $executableArgs['CandidatePath'] = $ExecutableCandidate }
    $executableResult = Get-LVSetupDiagExecutable @executableArgs
    $executable = $executableResult.Path
    if (-not $executable) {
        if (@($executableResult.Rejected).Count -gt 0) {
            $message = ('SetupDiag candidate(s) were rejected by the Microsoft Authenticode trust policy; built-in Panther rules remain active. Rejected candidate count: {0}.' -f @($executableResult.Rejected).Count)
            Write-LVLog -Level warn -Message $message
            return [pscustomobject]@{ Available=$false; Used=$false; Status='untrusted'; Message=$message; CoverageNote=$message; ExecutablePath=$null; LogsPath=$null; Profile=$null; Records=@() }
        }
        $message = 'SetupDiag is not present; Panther failures will use LogVerdict built-in text rules.'
        Write-LVLog -Level info -Message $message
        return [pscustomobject]@{ Available=$false; Used=$false; Status='absent'; Message=$message; ExecutablePath=$null; LogsPath=$null; Profile=$null; Records=@() }
    }

    $logArgs = @{ DaysBack=$DaysBack }
    if ($PSBoundParameters.ContainsKey('LogCandidate')) { $logArgs['CandidatePath'] = $LogCandidate }
    $logSet = @(Get-LVSetupDiagLogSet @logArgs)
    if ($logSet.Count -eq 0) {
        $message = 'SetupDiag is present, but no supported Panther log set was updated inside the scan window; built-in text rules remain active.'
        Write-LVLog -Level info -Message $message
        return [pscustomobject]@{ Available=$true; Used=$false; Status='no-recent-logs'; Message=$message; ExecutablePath=$executable; LogsPath=$null; Profile=$null; Records=@() }
    }

    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-SetupDiag-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $temporary
    $output = Join-Path $temporary 'SetupDiagResults.json'
    try {
        Write-LVLog -Level info -Message ('SetupDiag found; analyzing the recent Panther log set at {0}.' -f $logSet[0].Path)
        try {
            $process = Invoke-LVSetupDiagProcess -ExecutablePath $executable -LogsPath $logSet[0].Path `
                -OutputPath $output -WorkingDirectory $temporary -TimeoutSeconds $TimeoutSeconds
        } catch {
            $reason = $_.Exception.Message
            $status = 'execution-failed'
            if ($reason -match '(?i)elevat') { $status = 'requires-elevation' }
            $message = ('SetupDiag could not start ({0}); built-in Panther rules remain active.' -f $reason)
            Write-LVLog -Level warn -Message $message
            return [pscustomobject]@{ Available=$true; Used=$false; Status=$status; Message=$message; ExecutablePath=$executable; LogsPath=$logSet[0].Path; Profile=$null; Records=@() }
        }
        if ($process.TimedOut) {
            $message = ('SetupDiag exceeded the {0}-second limit; built-in Panther rules remain active.' -f $TimeoutSeconds)
            Write-LVLog -Level warn -Message $message
            return [pscustomobject]@{ Available=$true; Used=$true; Status='timeout'; Message=$message; ExecutablePath=$executable; LogsPath=$logSet[0].Path; Profile=$null; Records=@() }
        }
        if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
            $message = ('SetupDiag exited {0} without a JSON result; built-in Panther rules remain active.' -f $process.ExitCode)
            Write-LVLog -Level warn -Message $message
            return [pscustomobject]@{ Available=$true; Used=$true; Status='no-output'; Message=$message; ExecutablePath=$executable; LogsPath=$logSet[0].Path; Profile=$null; Records=@() }
        }

        try {
            $decoded = ConvertFrom-LVSetupDiagJson -Json (Get-Content -LiteralPath $output -Raw -ErrorAction Stop) -FallbackWhen $logSet[0].Latest
        } catch {
            $message = ('SetupDiag JSON could not be read ({0}); built-in Panther rules remain active.' -f $_.Exception.Message)
            Write-LVLog -Level warn -Message $message
            return [pscustomobject]@{ Available=$true; Used=$true; Status='invalid-output'; Message=$message; ExecutablePath=$executable; LogsPath=$logSet[0].Path; Profile=$null; Records=@() }
        }

        if ($decoded.Successful) {
            $message = ('SetupDiag matched {0}; no failure record was added and built-in Panther lines remain available.' -f $decoded.Profile)
            Write-LVLog -Level ok -Message $message
            return [pscustomobject]@{ Available=$true; Used=$true; Status='successful-upgrade'; Message=$message; ExecutablePath=$executable; LogsPath=$logSet[0].Path; Profile=$decoded.Profile; Records=@() }
        }

        $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
        if ($decoded.When -and $decoded.When -lt $cutoff) {
            $message = ('SetupDiag matched {0}, but the result predates the scan window; no failure record was added.' -f $decoded.Profile)
            Write-LVLog -Level info -Message $message
            return [pscustomobject]@{ Available=$true; Used=$true; Status='stale-result'; Message=$message; ExecutablePath=$executable; LogsPath=$logSet[0].Path; Profile=$decoded.Profile; Records=@() }
        }

        $message = ('SetupDiag matched {0}; its structured failure and remediation were merged into the scan.' -f $decoded.Profile)
        Write-LVLog -Level ok -Message $message
        return [pscustomobject]@{ Available=$true; Used=$true; Status='matched'; Message=$message; ExecutablePath=$executable; LogsPath=$logSet[0].Path; Profile=$decoded.Profile; Records=@($decoded.Record) }
    } finally {
        Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Select-LVWerValue {
    <#
        .SYNOPSIS
        Return the first non-empty WER field from a list of equivalent labels.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Field,
        [Parameter(Mandatory)][string[]]$Name
    )

    foreach ($candidate in $Name) {
        if ($Field.ContainsKey($candidate) -and $Field[$candidate]) {
            return ([string]$Field[$candidate]).Trim()
        }
    }
    return $null
}

function Get-LVWerReport {
    <#
        .SYNOPSIS
        Read the named problem-signature parameters from one Report.wer file.

        .DESCRIPTION
        WER parameter indexes are event-type specific. The parser pairs every
        Sig[n].Name with Sig[n].Value and selects fields by their labels instead of
        assuming that P3 always means a module. Unknown report types remain inventory
        items and never become guessed crash findings.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    } catch {
        return [pscustomobject]@{
            Decoded = $false; Reason = ('Report.wer is unreadable: {0}' -f $_.Exception.Message)
            EventType = $null; App = $null; AppVersion = $null; Module = $null; ExceptionCode = $null
        }
    }

    $field = @{}
    $signatureName = @{}
    $signatureValue = @{}

    foreach ($line in $lines) {
        $match = [regex]::Match([string]$line, '^([^=]+)=(.*)$')
        if (-not $match.Success) { continue }
        $name = $match.Groups[1].Value.Trim()
        $value = $match.Groups[2].Value.Trim()
        $field[$name] = $value

        $sig = [regex]::Match($name, '^Sig\[(\d+)\]\.(Name|Value)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $sig.Success) { continue }
        $index = $sig.Groups[1].Value
        if ($sig.Groups[2].Value -eq 'Name') { $signatureName[$index] = $value } else { $signatureValue[$index] = $value }
    }

    $named = @{}
    foreach ($index in $signatureName.Keys) {
        if ($signatureValue.ContainsKey($index) -and $signatureName[$index]) {
            $named[[string]$signatureName[$index]] = [string]$signatureValue[$index]
        }
    }

    $app = Select-LVWerValue -Field $field -Name @('AppName', 'ApplicationName')
    if (-not $app) { $app = Select-LVWerValue -Field $named -Name @('Application Name', 'App Name', 'AppName') }

    $appVersion = Select-LVWerValue -Field $field -Name @('AppVersion', 'ApplicationVersion')
    if (-not $appVersion) { $appVersion = Select-LVWerValue -Field $named -Name @('Application Version', 'App Version', 'AppVer') }

    $module = Select-LVWerValue -Field $named -Name @(
        'Fault Module Name', 'Faulting Module Name', 'Crashing Module Name',
        'Module Name', 'AsmAndModName'
    )
    if (-not $module) {
        foreach ($name in $named.Keys) {
            if ($name -match '(?i)(fault|crash).*(module|file).*name') { $module = [string]$named[$name]; break }
        }
    }

    $exceptionCode = Select-LVWerValue -Field $named -Name @(
        'Exception Code', 'ExceptionCode', 'Exception Type', 'ExceptionType', 'Error Code'
    )

    # A full path is useful evidence elsewhere in Report.wer, but the signature is a
    # component identity. Keep only the leaf so two installations of the same app group.
    if ($app) { $app = [IO.Path]::GetFileName($app) }
    if ($module) { $module = [IO.Path]::GetFileName($module) }

    $decoded = [bool]($app -and $module)
    $reason = $null
    if (-not $decoded) { $reason = 'Report.wer did not contain both application and fault-module parameters.' }

    return [pscustomobject]@{
        Decoded       = $decoded
        Reason        = $reason
        EventType     = Select-LVWerValue -Field $field -Name @('EventType')
        App           = $app
        AppVersion    = $appVersion
        Module        = $module
        ExceptionCode = $exceptionCode
    }
}

function Get-LVKernelDumpHeader {
    <#
        .SYNOPSIS
        Defensively read the bug-check fields from a Windows kernel dump header.

        .DESCRIPTION
        Reads at most 96 bytes. PAGEDU64 uses the DUMP_HEADER64 offsets and PAGEDUMP
        uses their 32-bit counterparts. Any other signature, a short read, a zero stop
        code, or an I/O error is returned as not decoded rather than interpreted.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $length = [int][Math]::Min([int64]0x60, $stream.Length)
        if ($length -lt 8) {
            return [pscustomobject]@{ Decoded = $false; Reason = 'The dump is shorter than its eight-byte signature.'; Architecture = $null; BugCheckCode = $null; BugCheckParameters = @() }
        }

        $buffer = New-Object byte[] $length
        $read = 0
        while ($read -lt $length) {
            $count = $stream.Read($buffer, $read, $length - $read)
            if ($count -le 0) { break }
            $read += $count
        }
        if ($read -lt 8) {
            return [pscustomobject]@{ Decoded = $false; Reason = 'The dump signature could not be read completely.'; Architecture = $null; BugCheckCode = $null; BugCheckParameters = @() }
        }

        $signature = [Text.Encoding]::ASCII.GetString($buffer, 0, 8)
        $architecture = $null
        $codeOffset = 0
        $parameterOffset = 0
        $parameterWidth = 0
        $required = 0
        switch ($signature) {
            'PAGEDU64' { $architecture = 'x64'; $codeOffset = 0x38; $parameterOffset = 0x40; $parameterWidth = 8; $required = 0x60 }
            'PAGEDUMP' { $architecture = 'x86'; $codeOffset = 0x28; $parameterOffset = 0x2c; $parameterWidth = 4; $required = 0x3c }
            default {
                return [pscustomobject]@{ Decoded = $false; Reason = ("Unrecognized dump signature '{0}'." -f $signature); Architecture = $null; BugCheckCode = $null; BugCheckParameters = @() }
            }
        }

        if ($read -lt $required) {
            return [pscustomobject]@{ Decoded = $false; Reason = ("The {0} dump header is truncated ({1} of {2} required bytes)." -f $architecture, $read, $required); Architecture = $architecture; BugCheckCode = $null; BugCheckParameters = @() }
        }

        $codeValue = [BitConverter]::ToUInt32($buffer, $codeOffset)
        if ($codeValue -eq 0) {
            return [pscustomobject]@{ Decoded = $false; Reason = 'The dump header contains a zero bug-check code.'; Architecture = $architecture; BugCheckCode = $null; BugCheckParameters = @() }
        }

        $parameters = New-Object System.Collections.Generic.List[string]
        foreach ($index in 0..3) {
            $offset = $parameterOffset + ($index * $parameterWidth)
            if ($parameterWidth -eq 8) {
                $parameters.Add(('0x{0:X16}' -f [BitConverter]::ToUInt64($buffer, $offset))) | Out-Null
            } else {
                $parameters.Add(('0x{0:X8}' -f [BitConverter]::ToUInt32($buffer, $offset))) | Out-Null
            }
        }

        return [pscustomobject]@{
            Decoded           = $true
            Reason            = $null
            Architecture      = $architecture
            BugCheckCode      = ('0x{0:X8}' -f $codeValue)
            BugCheckParameters = @($parameters.ToArray())
        }
    } catch {
        return [pscustomobject]@{ Decoded = $false; Reason = ('The dump header is unreadable: {0}' -f $_.Exception.Message); Architecture = $null; BugCheckCode = $null; BugCheckParameters = @() }
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function ConvertTo-LVCrashRecord {
    <#
        .SYNOPSIS
        Turn decoded crash metadata into one ordinary record for reduction and ruling.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Artifact)

    if (-not $Artifact.Decoded) { return $null }

    if ($Artifact.Kind -eq 'wer') {
        $app = [string]$Artifact.App
        $module = [string]$Artifact.Module
        if (-not $app -or -not $module) { return $null }

        $parts = New-Object System.Collections.Generic.List[string]
        $parts.Add(('application={0}' -f $app)) | Out-Null
        $parts.Add(('fault module={0}' -f $module)) | Out-Null
        if ($Artifact.AppVersion)    { $parts.Add(('application version={0}' -f $Artifact.AppVersion)) | Out-Null }
        if ($Artifact.ExceptionCode) { $parts.Add(('exception={0}' -f $Artifact.ExceptionCode)) | Out-Null }
        if ($Artifact.EventType)     { $parts.Add(('event type={0}' -f $Artifact.EventType)) | Out-Null }

        return [pscustomobject]@{
            Source = 'textlog'; Channel = 'WER'; Provider = 'Windows Error Reporting archive'; Id = 0
            Level = 2; LevelName = 'Error'; TimeCreated = $Artifact.When; Undated = ($null -eq $Artifact.When)
            MachineName = $env:COMPUTERNAME; RecordId = 0; Area = 'Application crash'
            Hint = 'Report.wer persists the application, faulting module and exception metadata.'
            SignatureKey = ('WER/{0}/{1}' -f $app.ToLowerInvariant(), $module.ToLowerInvariant())
            Message = ('Report.wer application crash: {0}' -f ($parts -join '; '))
        }
    }

    if ($Artifact.Kind -eq 'minidump' -and $Artifact.BugCheckCode) {
        return [pscustomobject]@{
            Source = 'textlog'; Channel = 'Minidump'; Provider = 'Kernel dump header'; Id = 0
            Level = 1; LevelName = 'Critical'; TimeCreated = $Artifact.When; Undated = ($null -eq $Artifact.When)
            MachineName = $env:COMPUTERNAME; RecordId = 0; Area = 'System crash'
            Hint = 'The fixed kernel dump header carries the stop code and four parameters without a debugger.'
            SignatureKey = ('Minidump/{0}' -f ([string]$Artifact.BugCheckCode).ToLowerInvariant())
            Message = ('Kernel minidump bug check {0}; parameters {1}' -f $Artifact.BugCheckCode, (@($Artifact.BugCheckParameters) -join ', '))
        }
    }

    return $null
}

function Get-LVCrashArtifact {
    <#
        .SYNOPSIS
        Inventory and bounded header metadata from kernel dumps and WER archives.
        .DESCRIPTION
        Reads Report.wer problem parameters and the fixed bug-check fields in a kernel
        dump header. It never walks a stack or names a driver: that still needs a debugger
        and symbols. Unrecognized or malformed artifacts remain visible as inventory.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 90,
        [string[]]$DumpPath = @('C:\Windows\Minidump', 'C:\Windows\MEMORY.DMP'),
        [string]$WerRoot = (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive')
    )

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $items = New-Object System.Collections.Generic.List[object]

    foreach ($p in $DumpPath) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $pathItem = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
        if ($null -eq $pathItem) { continue }
        $dump = @($pathItem)
        if ($pathItem.PSIsContainer) {
            $dump = @(Get-ChildItem -LiteralPath $p -Filter '*.dmp' -File -ErrorAction SilentlyContinue)
        }
        foreach ($file in @($dump | Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $cutoff })) {
            $header = Get-LVKernelDumpHeader -Path $file.FullName
            $items.Add([pscustomobject]@{
                Kind               = 'minidump'
                Path               = $file.FullName
                When               = $file.LastWriteTime
                Size               = $file.Length
                Decoded            = [bool]$header.Decoded
                DecodeStatus        = $(if ($header.Decoded) { 'decoded' } else { $header.Reason })
                Architecture       = $header.Architecture
                BugCheckCode       = $header.BugCheckCode
                BugCheckParameters = @($header.BugCheckParameters)
            }) | Out-Null
        }
    }

    if (Test-Path -LiteralPath $werRoot) {
        Get-ChildItem -LiteralPath $werRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff } |
            ForEach-Object {
                $wer = Join-Path $_.FullName 'Report.wer'
                $app = $_.Name
                $metadata = $null
                if (Test-Path -LiteralPath $wer) {
                    $metadata = Get-LVWerReport -Path $wer
                    if ($metadata.App) { $app = $metadata.App }
                } else {
                    $metadata = [pscustomobject]@{
                        Decoded = $false; Reason = 'The report directory contains no Report.wer file.'
                        EventType = $null; App = $null; AppVersion = $null; Module = $null; ExceptionCode = $null
                    }
                }
                $items.Add([pscustomobject]@{
                    Kind          = 'wer'
                    Path          = $_.FullName
                    ReportPath    = $wer
                    When          = $_.LastWriteTime
                    App           = $app
                    AppVersion    = $metadata.AppVersion
                    Module        = $metadata.Module
                    ExceptionCode = $metadata.ExceptionCode
                    EventType     = $metadata.EventType
                    Decoded       = [bool]$metadata.Decoded
                    DecodeStatus  = $(if ($metadata.Decoded) { 'decoded' } else { $metadata.Reason })
                }) | Out-Null
            }
    }

    return ConvertTo-LVArrayOutput -Value @($items.ToArray())
}
