function Get-LogVerdictErrorCatalog {
    <#
        .SYNOPSIS
        Query the bundled Microsoft Windows error and stop-code catalog.

        .DESCRIPTION
        Returns typed reference entries for Win32, HRESULT/facility, NTSTATUS,
        Setup/servicing, Windows Update, and Microsoft kernel bug-check codes.
        The catalog is local and does not make network calls.

        .PARAMETER Kind
        Restrict results to a typed catalog family.

        .PARAMETER Name
        Match a symbolic error or stop-code name.

        .PARAMETER Hex
        Match a hexadecimal code such as 0x80070005 or 0x00000124.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('win32', 'hresult', 'bugcheck', 'ntstatus', 'setup', 'windowsupdate')][string]$Kind,
        [string]$Name,
        [string]$Hex,
        [string]$Path
    )

    $catalog = Get-LVErrorCatalog -Path $Path
    $entries = @($catalog.entries)
    if ($Kind) { $entries = @($entries | Where-Object { $_.kind -eq $Kind }) }
    if ($Name -and $Name -notmatch '[*?]') {
        $nameKey = $Name.ToUpperInvariant()
        if ($catalog.LVIndexes.ByName.ContainsKey($nameKey)) {
            $entries = @($catalog.LVIndexes.ByName[$nameKey])
        } else {
            $entries = @()
        }
        if ($Kind) { $entries = @($entries | Where-Object { $_.kind -eq $Kind }) }
    } elseif ($Name) {
        $entries = @($entries | Where-Object { $_.name -like $Name })
    }
    if ($Hex) {
        $normalized = ConvertTo-LVErrorHex -Value $Hex
        if (-not $normalized) { return ConvertTo-LVArrayOutput -Value @() }
        $normalized = $normalized.ToUpperInvariant()
        if ($Kind -and $catalog.LVIndexes.ByKindHex.ContainsKey(('{0}|{1}' -f $Kind, $normalized))) {
            $entries = @($catalog.LVIndexes.ByKindHex[('{0}|{1}' -f $Kind, $normalized)])
        } elseif (-not $Kind -and $catalog.LVIndexes.ByHex.ContainsKey($normalized)) {
            $entries = @($catalog.LVIndexes.ByHex[$normalized])
        } else {
            $entries = @($entries | Where-Object { $_.normalized.hex.ToUpperInvariant() -eq $normalized })
        }
        if ($Name) { $entries = @($entries | Where-Object { $_.name -like $Name }) }
    }
    return ConvertTo-LVArrayOutput -Value $entries
}
