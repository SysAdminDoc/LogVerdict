function Test-LogVerdictProvider {
    <#
        .SYNOPSIS
        Validate a provider manifest and its pinned entrypoint without executing it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Quiet
    )

    try {
        $plan = Read-LVProviderPlan -Path $Path
        if ($Quiet) { return $true }
        return [pscustomobject][ordered]@{
            Valid = $true; ProviderId = $plan.Id; Name = $plan.Name; Version = $plan.Version
            Trust = $plan.Trust; Capabilities = @($plan.Capabilities); Entrypoint = $plan.EntrypointPath
            Reason = $null
        }
    } catch {
        if ($Quiet) { return $false }
        return [pscustomobject][ordered]@{ Valid=$false; ProviderId=$null; Name=$null; Version=$null; Trust=$null; Capabilities=@(); Entrypoint=$null; Reason=$_.Exception.Message }
    }
}
