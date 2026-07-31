function Get-LogVerdictDatabase {
    <#
        .SYNOPSIS
        Load the verdict database.

        .DESCRIPTION
        Reads Data/verdicts.json from the module, then optionally merges a local
        database so site-specific rules survive an update of the shipped one.
        Local rules take precedence over shipped rules at equal specificity.

        .PARAMETER Path
        Replace the shipped database entirely with this file.

        .PARAMETER AdditionalPath
        Merge extra rule files on top of the shipped database.

        .EXAMPLE
        Get-LogVerdictDatabase | Select-Object -ExpandProperty rules | Measure-Object
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string[]]$AdditionalPath
    )

    $basePath = $Path
    if (-not $basePath) { $basePath = Join-Path $script:LVDataDir 'verdicts.json' }

    if (-not (Test-Path -LiteralPath $basePath)) {
        throw ("Verdict database not found at '{0}'." -f $basePath)
    }

    $db = Get-Content -LiteralPath $basePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-LVSchemaVersion -Database $db -Path $basePath
    $rules = New-Object System.Collections.Generic.List[object]

    # Local overrides load first so they win ties against the shipped rules.
    $extra = @()
    if ($AdditionalPath) { $extra += $AdditionalPath }
    $conventionalLocal = Join-Path $script:LVDataDir 'verdicts.local.json'
    if (-not $Path -and (Test-Path -LiteralPath $conventionalLocal)) { $extra += $conventionalLocal }

    foreach ($p in $extra) {
        if (-not (Test-Path -LiteralPath $p)) {
            Write-LVLog -Level warn -Message ("Additional verdict file not found: {0}" -f $p)
            continue
        }
        $addl = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-LVSchemaVersion -Database $addl -Path $p
        foreach ($r in $addl.rules) { $rules.Add($r) | Out-Null }
        Write-LVLog -Level ok -Message ("Merged {0} rule(s) from {1}" -f @($addl.rules).Count, (Split-Path $p -Leaf))
    }

    foreach ($r in $db.rules) { $rules.Add($r) | Out-Null }

    return [pscustomobject]@{
        schemaVersion = $db.schemaVersion
        name          = $db.name
        updated       = $db.updated
        rules         = @($rules.ToArray())
    }
}
