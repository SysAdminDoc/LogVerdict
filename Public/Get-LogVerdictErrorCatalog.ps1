function Get-LogVerdictErrorCatalog {
    <#
        .SYNOPSIS
        Query the bundled Microsoft Windows error and stop-code catalog.

        .DESCRIPTION
        Returns reference entries for Win32 GetLastError values, common HRESULTs,
        and Microsoft kernel bug-check codes. The catalog is local and does not
        make network calls.

        .PARAMETER Kind
        Restrict results to win32, hresult, or bugcheck entries.

        .PARAMETER Name
        Match a symbolic error or stop-code name.

        .PARAMETER Hex
        Match a hexadecimal code such as 0x80070005 or 0x00000124.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('win32', 'hresult', 'bugcheck')][string]$Kind,
        [string]$Name,
        [string]$Hex,
        [string]$Path
    )

    $entries = @((Get-LVErrorCatalog -Path $Path).entries)
    if ($Kind) { $entries = @($entries | Where-Object { $_.kind -eq $Kind }) }
    if ($Name) { $entries = @($entries | Where-Object { $_.name -like $Name }) }
    if ($Hex) {
        $normalized = $Hex.ToUpperInvariant()
        if ($normalized -notmatch '^0X') { $normalized = '0X' + $normalized }
        if ($normalized -match '^0X[0-9A-F]+$') {
            $normalized = '0X{0:X8}' -f [Convert]::ToUInt32($normalized.Substring(2), 16)
        }
        $entries = @($entries | Where-Object { $_.hex.ToUpperInvariant() -eq $normalized })
    }
    return ConvertTo-LVArrayOutput -Value $entries
}
