function Invoke-LogVerdictProvider {
    <#
        .SYNOPSIS
        Execute one explicitly approved provider against a read-only context.

        .DESCRIPTION
        This low-level command is primarily for provider authors and contract tests.
        Every provider is untrusted, and -AllowUntrustedProvider is required even when
        the manifest is valid. The provider receives no curated rules and its output is
        normalized and redacted before it leaves this boundary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Provider,
        [Parameter(Mandatory)][hashtable]$Context,
        [switch]$AllowUntrustedProvider
    )

    return Invoke-LVProvider -Provider $Provider -Context $Context -AllowUntrustedProvider:$AllowUntrustedProvider
}
