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
    $records = New-Object System.Collections.Generic.List[object]

    foreach ($target in $Target) {
        $path = $target.Path
        if (-not (Test-Path -LiteralPath $path)) {
            Write-LVLog -Level info -Message ("{0}: not present on this machine" -f $target.Name)
            continue
        }

        $file = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $file) { continue }
        if ($file.LastWriteTime -lt $cutoff) {
            Write-LVLog -Level info -Message ("{0}: last written {1:yyyy-MM-dd}, outside the {2}-day window" -f $target.Name, $file.LastWriteTime, $DaysBack)
            continue
        }

        $matched = 0
        $skippedOld = 0
        $undated = 0
        $sectionTime = $null
        $reader = $null

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
            Write-LVLog -Level warn -Message ("{0}: unreadable ({1})" -f $target.Name, $_.Exception.Message)
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
    }

    return ConvertTo-LVArrayOutput -Value @($records.ToArray())
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
