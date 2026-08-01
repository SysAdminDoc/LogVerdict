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

    if (Test-Path -LiteralPath $basePath) {
        $db = Get-Content -LiteralPath $basePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $sourceLabel = $basePath
    } elseif (-not $Path -and $script:LVEmbeddedVerdictsJson) {
        # Single-file build: the database is compiled into the executable. A real
        # verdicts.json beside the .exe still wins, so a site can ship its own.
        $db = $script:LVEmbeddedVerdictsJson | ConvertFrom-Json
        $sourceLabel = '(embedded)'
    } else {
        throw ("Verdict database not found at '{0}'." -f $basePath)
    }

    Assert-LVSchemaVersion -Database $db -Path $sourceLabel
    $rules = New-Object System.Collections.Generic.List[object]

    # Local overrides load first so they win ties against the shipped rules.
    $extra = @()
    if ($AdditionalPath) { $extra += $AdditionalPath }
    if (-not $Path) {
        # Both locations are honoured so a compiled single-file build can still be
        # extended: Data\ beside the module, and verdicts.local.json beside the .exe.
        foreach ($candidate in @(
            (Join-Path $script:LVDataDir 'verdicts.local.json'),
            (Join-Path (Get-LVHostDirectory) 'verdicts.local.json')
        )) {
            if ((Test-Path -LiteralPath $candidate) -and ($extra -notcontains $candidate)) {
                $extra += $candidate
            }
        }
    }

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

    # Explicit tie-break ordinal. Sort-Object is NOT a stable sort in Windows
    # PowerShell 5.1 and has no -Stable switch, so two rules of equal specificity
    # would otherwise resolve in arbitrary order - which silently breaks the promise
    # that a local rule beats the shipped rule it is meant to override.
    $ordinal = 0
    foreach ($r in $rules) {
        $r | Add-Member -NotePropertyName 'lvOrdinal' -NotePropertyValue $ordinal -Force
        $ordinal++
    }

    # Correlations merge the same way rules do, local first, so a site can add its own
    # pairings. They carry no ordinal because nothing resolves between two competing
    # correlations - every one that fires is reported.
    $correlations = New-Object System.Collections.Generic.List[object]
    foreach ($p in $extra) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $addl = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($c in @($addl.correlations | Where-Object { $_ })) { $correlations.Add($c) | Out-Null }
    }
    foreach ($c in @($db.correlations | Where-Object { $_ })) { $correlations.Add($c) | Out-Null }

    return [pscustomobject]@{
        schemaVersion = $db.schemaVersion
        name          = $db.name
        updated       = $db.updated
        rules         = @($rules.ToArray())
        correlations  = @($correlations.ToArray())
    }
}
