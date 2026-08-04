function Export-LogVerdictStandard {
    <#
        .SYNOPSIS
        Export a scan result through a versioned ECS, OCSF, SARIF, OpenTelemetry, STIX, or JSONL timeline adapter.

        .DESCRIPTION
        The adapter output is JSON and carries the same normalized findings, event/source
        fields, references, coverage, health profiles, timestamps, and explicit privacy
        state regardless of target standard. SARIF uses its native schema and stores the
        additional LogVerdict scan context in SARIF property bags. Use -Redact before
        writing a ticket or sharing the output outside the machine.

        .PARAMETER Result
        The object returned by Invoke-LogVerdictScan.

        .PARAMETER Format
        The target adapter: Ecs, Ocsf, Sarif (SARIF 2.1.0), OpenTelemetry, Stix (STIX 2.1), or Jsonl.
        Jsonl emits one metadata, event, finding, correlation, coverage, or provider
        record per line and does not retain a second output graph.

        .PARAMETER Path
        Optional JSON or JSONL destination. Line-oriented templates write atomically
        unless -Append is supplied; without -Path they stream compact JSON objects.

        .PARAMETER TemplatePath
        Optional standalone template or template registry JSON. A standalone template
        can project any normalized report-contract paths without a module code change.

        .PARAMETER Append
        Append JSON lines to -Path. This is rejected for single-document templates.

        .PARAMETER Redact
        Mask captured identifiers before the adapter document is built.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [string]$Format = 'Ecs',
        [string]$Path,
        [string]$TemplatePath,
        [switch]$Append,
        [switch]$Redact
    )

    process {
        $Result = Resolve-LVScanInput -InputObject $Result -Role 'result'
        $projected = if ($Redact) { ConvertTo-LVRedactedResult -Result $Result } else { $Result }
        $template = Get-LVStandardTemplate -Format $Format -Path $TemplatePath
        if ($Append -and -not $Path) {
            throw 'Template append mode requires -Path so records have a destination.'
        }
        if ($Append -and [string]$template.kind -ne 'line') {
            throw ("Template '{0}' is a single document; append mode is valid only for line-oriented templates." -f $template.id)
        }

        if ([string]$template.kind -eq 'line') {
            $model = Get-LVStandardModel -Result $projected
            $lines = @(ConvertTo-LVTemplateJsonLine -Model $model -Template $template)
            if ($Path) {
                Write-LVTemplateJsonl -Path $Path -Lines $lines -Append:$Append
                return [pscustomobject][ordered]@{
                    Format = [string]$template.id; TemplateName = [string]$template.id; Path = $Path
                    LineCount = $lines.Count; Document = $null; Appended = [bool]$Append
                }
            }
            $lines
            return
        }
        $model = Get-LVStandardModel -Result $projected
        $document = ConvertTo-LVJsonSafeValue -Value (ConvertTo-LVTemplateDocument -Model $model -Template $template)
        if ($Path) {
            $parent = Split-Path -Parent $Path
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }
            Write-LVTextFile -Path $Path -Content ($document | ConvertTo-Json -Depth 30)
        }
        return [pscustomobject][ordered]@{
            Format = [string]$template.id; TemplateName = [string]$template.id; Path = $Path
            Document = $document; Appended = $false
        }
    }
}
