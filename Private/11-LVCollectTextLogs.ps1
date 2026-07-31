# Collection layer: the plain-text logs Windows keeps outside the event channels.
# These carry the servicing, driver-install and setup failures that never reach
# Event Viewer, which is why "check Event Viewer" so often comes up empty.

$script:LVTextLogTarget = @(
    @{
        Name    = 'CBS'
        Path    = 'C:\Windows\Logs\CBS\CBS.log'
        # CBS writes ", Error  CSI ..." - anchoring on the column avoids matching
        # the thousands of benign lines that merely contain the word "error".
        Pattern = ',\s*Error\s'
        Area    = 'Component servicing'
        Hint    = 'Backs SFC, DISM and Windows Update payload installation.'
    },
    @{
        Name    = 'DISM'
        Path    = 'C:\Windows\Logs\DISM\dism.log'
        Pattern = ',\s*Error\s'
        Area    = 'Image servicing'
        Hint    = 'Written by DISM and by in-place upgrade servicing.'
    },
    @{
        Name    = 'SetupAPI'
        Path    = 'C:\Windows\INF\setupapi.dev.log'
        # SetupAPI marks errors with a triple bang and warnings with a single one.
        Pattern = '^\s*!!!'
        Area    = 'Driver and device install'
        Hint    = 'Every driver install, update and device enumeration on this PC.'
    },
    @{
        Name    = 'NetSetup'
        Path    = 'C:\Windows\debug\NetSetup.LOG'
        Pattern = '(?i)(failed|error|0x[0-9A-Fa-f]{8})'
        Area    = 'Domain join and rename'
        Hint    = 'Survives in-place upgrades, unlike the event channels.'
    },
    @{
        Name    = 'PantherSetupAct'
        Path    = 'C:\Windows\Panther\setupact.log'
        Pattern = '(?i)(\[error\]|fatal)'
        Area    = 'Setup and upgrade'
        Hint    = 'Records the last feature update or in-place upgrade.'
    },
    @{
        Name    = 'MoSetupBlueBox'
        Path    = 'C:\Windows\Logs\MoSetup\BlueBox.log'
        Pattern = '(?i)(error|failed)'
        Area    = 'Upgrade compatibility'
        Hint    = 'Upgrade blocks and compatibility appraiser results.'
    }
)

function Get-LVTextLogRecord {
    <#
        .SYNOPSIS
        Error-shaped lines from the well-known Windows text logs.
        .DESCRIPTION
        Streams each file so a multi-hundred-megabyte CBS.log does not land in memory,
        and caps the matches per file so one runaway component cannot drown the report.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysBack = 30,
        [int]$MaxMatchesPerFile = 4000
    )

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $records = New-Object System.Collections.Generic.List[object]

    foreach ($target in $script:LVTextLogTarget) {
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
        $reader = $null
        try {
            $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $reader = New-Object System.IO.StreamReader($stream)
            $regex = [regex]$target.Pattern

            while ($null -ne ($line = $reader.ReadLine())) {
                if ($matched -ge $MaxMatchesPerFile) { break }
                if (-not $regex.IsMatch($line)) { continue }
                $matched++

                $records.Add([pscustomobject]@{
                    Source      = 'textlog'
                    Channel     = $target.Name
                    Provider    = $target.Name
                    Id          = 0
                    Level       = 2
                    LevelName   = 'Error'
                    TimeCreated = $file.LastWriteTime
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
            Write-LVLog -Level ok -Message ("{0}: {1} error line(s)" -f $target.Name, $matched)
        }
    }

    return ConvertTo-LVArrayOutput -Value @($records.ToArray())
}

function Get-LVCrashArtifact {
    <#
        .SYNOPSIS
        Inventory of crash evidence: kernel minidumps and Windows Error Reporting archives.
        .DESCRIPTION
        Inventory only. Decoding a minidump needs a debugger and symbols, so this reports
        that the evidence exists and where it is rather than guessing at a culprit.
    #>
    [CmdletBinding()]
    param([int]$DaysBack = 90)

    $cutoff = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $items = New-Object System.Collections.Generic.List[object]

    $dumpPaths = @('C:\Windows\Minidump', 'C:\Windows\MEMORY.DMP')
    foreach ($p in $dumpPaths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        Get-ChildItem -LiteralPath $p -Filter '*.dmp' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff } |
            ForEach-Object {
                $items.Add([pscustomobject]@{
                    Kind = 'minidump'
                    Path = $_.FullName
                    When = $_.LastWriteTime
                    Size = $_.Length
                }) | Out-Null
            }
    }

    $werRoot = Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'
    if (Test-Path -LiteralPath $werRoot) {
        Get-ChildItem -LiteralPath $werRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff } |
            ForEach-Object {
                $wer = Join-Path $_.FullName 'Report.wer'
                $app = $_.Name
                if (Test-Path -LiteralPath $wer) {
                    $appLine = Select-String -LiteralPath $wer -Pattern '^AppName=' -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($appLine) { $app = ($appLine.Line -split '=', 2)[1] }
                }
                $items.Add([pscustomobject]@{
                    Kind = 'wer'
                    Path = $_.FullName
                    When = $_.LastWriteTime
                    App  = $app
                }) | Out-Null
            }
    }

    return ConvertTo-LVArrayOutput -Value @($items.ToArray())
}
