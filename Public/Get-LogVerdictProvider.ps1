function Get-LogVerdictProvider {
    <#
        .SYNOPSIS
        Discover validated local LogVerdict provider manifests.

        .DESCRIPTION
        Providers are never loaded implicitly into a scan. Use this command to inspect
        the manifest, entrypoint pin, capabilities and untrusted status before passing a
        manifest or provider directory to Invoke-LogVerdictScan.
    #>
    [CmdletBinding()]
    param([string[]]$Path)

    $roots = if ($Path) { @($Path) } else {
        @(
            (Join-Path $script:LVDataDir 'providers'),
            (Join-Path $env:LOCALAPPDATA 'LogVerdict/providers')
        )
    }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $item = Get-Item -LiteralPath $root -ErrorAction Stop
        $manifests = if ($item.PSIsContainer) {
            @(
                Get-ChildItem -LiteralPath $item.FullName -Filter 'manifest.json' -File -ErrorAction SilentlyContinue
                Get-ChildItem -LiteralPath $item.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $candidate = Join-Path $_.FullName 'manifest.json'
                    if (Test-Path -LiteralPath $candidate -PathType Leaf) { Get-Item -LiteralPath $candidate }
                }
            )
        } else { @($item) }
        foreach ($manifest in @($manifests | Sort-Object FullName -Unique)) {
            try { Read-LVProviderPlan -Path $manifest.FullName }
            catch { Write-Verbose ("Skipping provider manifest '{0}': {1}" -f $manifest.FullName, $_.Exception.Message) }
        }
    }
}
