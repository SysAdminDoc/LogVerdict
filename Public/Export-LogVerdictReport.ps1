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
            ConvertTo-LVTextReport -Result $Result | Set-Content -LiteralPath $p -Encoding UTF8
            $written.Add($p) | Out-Null
        }

        if ($wantAll -or $Format -contains 'Json') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.json'
            # Depth 6 covers signature -> samples[] without dragging in the whole graph.
            $Result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $p -Encoding UTF8
            $written.Add($p) | Out-Null
        }

        if ($wantAll -or $Format -contains 'Html') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.html'
            ConvertTo-LVHtmlReport -Result $Result | Set-Content -LiteralPath $p -Encoding UTF8
            $written.Add($p) | Out-Null
        }

        $logPath = Join-Path $OutputDir 'LogVerdict-Run.log'
        Get-LVLogTranscript | Set-Content -LiteralPath $logPath -Encoding UTF8
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
