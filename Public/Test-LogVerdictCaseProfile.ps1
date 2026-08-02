function Test-LogVerdictCaseProfile {
    <#
        .SYNOPSIS
        Validate a LogVerdict case profile and its canonical SHA-256 identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Quiet
    )

    try {
        $profile = Read-LVCaseProfile -Path $Path
        if ($Quiet) { return $true }
        return $profile
    } catch {
        if ($Quiet) { return $false }
        throw
    }
}
