function Get-LogVerdictAdvisory {
    <#
        .SYNOPSIS
        Read the local dependency and tool advisory cache.

        .DESCRIPTION
        Loads and validates a versioned offline cache. With -Package and -Version,
        returns only advisories whose affected range contains that version. Returned
        records use FindingType=dependency-advisory and are never event findings.
        No network request is made.

        .PARAMETER Path
        Advisory cache JSON. Defaults to an optional local override and then the
        shipped cache.

        .PARAMETER Package
        Package name to match, such as PowerShell.

        .PARAMETER Version
        Package version to test against the cache's affected ranges.

        .EXAMPLE
        Get-LogVerdictAdvisory -Package PowerShell -Version 7.4.0
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Package,
        [string]$Version
    )

    $result = Get-LVAdvisoryFinding -Path $Path -Package $Package -Version $Version
    return $result.Records
}
