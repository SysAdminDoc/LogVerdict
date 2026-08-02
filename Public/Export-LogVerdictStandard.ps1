function Export-LogVerdictStandard {
    <#
        .SYNOPSIS
        Export a scan result through a versioned ECS, OCSF, OpenTelemetry, or STIX adapter.

        .DESCRIPTION
        The adapter output is JSON and carries the same normalized findings, event/source
        fields, references, coverage, health profiles, timestamps, and explicit privacy
        state regardless of target standard. Use -Redact before writing a ticket or sharing
        the output outside the machine.

        .PARAMETER Result
        The object returned by Invoke-LogVerdictScan.

        .PARAMETER Format
        The target adapter: Ecs, Ocsf, OpenTelemetry, or Stix (STIX 2.1).

        .PARAMETER Path
        Optional JSON destination. The returned object always includes the projected
        document and the path when one was written.

        .PARAMETER Redact
        Mask captured identifiers before the adapter document is built.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [ValidateSet('Ecs', 'Ocsf', 'OpenTelemetry', 'Stix')][string]$Format = 'Ecs',
        [string]$Path,
        [switch]$Redact
    )

    process {
        $projected = if ($Redact) { ConvertTo-LVRedactedResult -Result $Result } else { $Result }
        $document = ConvertTo-LVStandardDocument -Result $projected -Format $Format
        if ($Path) {
            $parent = Split-Path -Parent $Path
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }
            Write-LVTextFile -Path $Path -Content ($document | ConvertTo-Json -Depth 30)
        }
        return [pscustomobject][ordered]@{ Format = $Format; Path = $Path; Document = $document }
    }
}
