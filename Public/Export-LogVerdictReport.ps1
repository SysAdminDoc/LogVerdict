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

        .EXAMPLE
        Invoke-LogVerdictScan | Export-LogVerdictReport
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [string]$OutputDir,
        [ValidateSet('Text', 'Json', 'Html', 'All')][string[]]$Format = @('All')
    )

    process {
        if (-not $OutputDir) {
            $desktop = [Environment]::GetFolderPath('Desktop')
            $stamp = '{0:yyyyMMdd-HHmmss}' -f $Result.ScanTime
            $name = 'LogVerdict_{0}_{1}' -f (ConvertTo-LVSafeName -Text $Result.MachineName), $stamp
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
