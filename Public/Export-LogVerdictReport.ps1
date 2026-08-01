function Export-LogVerdictReport {
    <#
        .SYNOPSIS
        Render a scan result to disk as text, JSON and a self-contained dark HTML page.

        .PARAMETER Result
        The object returned by Invoke-LogVerdictScan.

        .PARAMETER OutputDir
        Where to write. Defaults to a timestamped folder on the Desktop, which is safe
        even when the script is right-click-elevated and starts in System32.

        .PARAMETER Format
        Any of Text, Json, Html, or All. Default All.

        .PARAMETER Redact
        Mask the account name, machine name, profile paths, SIDs and mail addresses out
        of the captured log messages before writing them. Use when the report is going
        to a ticket or a vendor. The reports state that redaction was applied, so a
        reader never mistakes a masked report for a complete one.

        .EXAMPLE
        Invoke-LogVerdictScan | Export-LogVerdictReport

        .EXAMPLE
        Invoke-LogVerdictScan | Export-LogVerdictReport -Redact
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [string]$OutputDir,
        [ValidateSet('Text', 'Json', 'Html', 'All')][string[]]$Format = @('All'),
        [switch]$Redact
    )

    process {
        # Captured before redacting. The folder name keeps the real machine name because
        # the person running the scan has to find it on their own desktop - redaction is
        # about what leaves the machine, not about hiding the output from its author.
        $folderMachine = $Result.MachineName

        if ($Redact) {
            $Result = ConvertTo-LVRedactedResult -Result $Result
            Write-LVLog -Level info -Message 'Redacting account, machine and path identifiers from the written reports.'
        }

        if (-not $OutputDir) {
            $desktop = [Environment]::GetFolderPath('Desktop')
            $stamp = '{0:yyyyMMdd-HHmmss}' -f $Result.ScanTime
            $name = 'LogVerdict_{0}_{1}' -f (ConvertTo-LVSafeName -Text $folderMachine), $stamp
            $OutputDir = Join-Path $desktop $name
        }

        if (-not (Test-Path -LiteralPath $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }

        $wantAll = $Format -contains 'All'
        $written = New-Object System.Collections.Generic.List[string]

        if ($wantAll -or $Format -contains 'Text') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.txt'
            Write-LVTextFile -Path $p -Content (ConvertTo-LVTextReport -Result $Result)
            $written.Add($p) | Out-Null
        }

        if ($wantAll -or $Format -contains 'Json') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.json'
            # Depth 6 covers signature -> samples[] without dragging in the whole graph.
            Write-LVTextFile -Path $p -Content ($Result | ConvertTo-Json -Depth 6)
            $written.Add($p) | Out-Null
        }

        if ($wantAll -or $Format -contains 'Html') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.html'
            Write-LVTextFile -Path $p -Content (ConvertTo-LVHtmlReport -Result $Result)
            $written.Add($p) | Out-Null
        }

        $logPath = Join-Path $OutputDir 'LogVerdict-Run.log'
        Write-LVTextFile -Path $logPath -Content ((Get-LVLogTranscript) -join [Environment]::NewLine)
        $written.Add($logPath) | Out-Null

        foreach ($w in $written) {
            Write-LVLog -Level ok -Message ('Wrote {0}' -f $w)
        }

        return [pscustomobject]@{
            OutputDir = $OutputDir
            Files     = @($written.ToArray())
        }
    }
}
