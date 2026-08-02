function Test-LogVerdictAdvisoryDatabase {
    <#
        .SYNOPSIS
        Validate an advisory cache without making a network request.

        .PARAMETER Path
        Advisory cache JSON. Defaults to the local override or shipped cache.

        .PARAMETER Quiet
        Return only a Boolean pass/fail result.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$Quiet
    )

    try {
        $loaded = Read-LVAdvisoryDocument -Path $Path
        $problems = @(Get-LVAdvisoryDatabaseProblem -Database $loaded.Document)
    } catch {
        $problems = @($_.Exception.Message)
    }
    if ($Quiet) { return ($problems.Count -eq 0) }
    return $problems
}
