function Show-LogVerdictReport {
    <#
        .SYNOPSIS
        Print a scan result to the console, worst findings first.

        .PARAMETER Result
        The object returned by Invoke-LogVerdictScan.

        .EXAMPLE
        Invoke-LogVerdictScan | Show-LogVerdictReport
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$Result)

    process {
        $Result = Resolve-LVScanInput -InputObject $Result -Role 'result'
        Write-LVConsoleReport -Result $Result
    }
}
