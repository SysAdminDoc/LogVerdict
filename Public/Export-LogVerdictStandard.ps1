function Export-LogVerdictStandard {
    <#
        .SYNOPSIS
        Export a scan result through a versioned ECS, OCSF, OpenTelemetry, STIX, or JSONL timeline adapter.

        .DESCRIPTION
        The adapter output is JSON and carries the same normalized findings, event/source
        fields, references, coverage, health profiles, timestamps, and explicit privacy
        state regardless of target standard. Use -Redact before writing a ticket or sharing
        the output outside the machine.

        .PARAMETER Result
        The object returned by Invoke-LogVerdictScan.

        .PARAMETER Format
        The target adapter: Ecs, Ocsf, OpenTelemetry, Stix (STIX 2.1), or Jsonl.
        Jsonl emits one metadata, event, finding, correlation, coverage, or provider
        record per line and does not retain a second output graph.

        .PARAMETER Path
        Optional JSON or JSONL destination. Jsonl writes atomically and returns a line
        count; without -Path it streams compact JSON objects to the pipeline.

        .PARAMETER Redact
        Mask captured identifiers before the adapter document is built.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [ValidateSet('Ecs', 'Ocsf', 'OpenTelemetry', 'Stix', 'Jsonl')][string]$Format = 'Ecs',
        [string]$Path,
        [switch]$Redact
    )

    process {
        $Result = Resolve-LVScanInput -InputObject $Result -Role 'result'
        $projected = if ($Redact) { ConvertTo-LVRedactedResult -Result $Result } else { $Result }
        if ($Format -eq 'Jsonl') {
            $timelineRedact = [bool]($Redact -or ($projected.PSObject.Properties['Redacted'] -and $projected.Redacted))
            if ($Path) {
                $written = Write-LVJsonlTimeline -Result $projected -Path $Path -Redact:$timelineRedact
                return [pscustomobject][ordered]@{ Format = $Format; Path = $Path; LineCount = $written.LineCount; Document = $null }
            }
            foreach ($line in Get-LVTimelineLine -Result $projected -Redact:$timelineRedact) {
                $safeLine = ConvertTo-LVJsonSafeValue -Value $line
                $safeLine | ConvertTo-Json -Depth 30 -Compress
            }
            return
        }
        $document = ConvertTo-LVJsonSafeValue -Value (ConvertTo-LVStandardDocument -Result $projected -Format $Format)
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
