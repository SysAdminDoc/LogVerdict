function New-LogVerdictCaseProfile {
    <#
        .SYNOPSIS
        Create a validated, hash-addressed collection and case profile from a scan.

        .DESCRIPTION
        Records the sources, time bounds, redaction policy, source hashes, analyst
        notes, and scan choices without copying raw event messages. The profile can be
        supplied to a later scan for attribution and to Export-LogVerdictHandoff.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [string]$Name = 'LogVerdict case',
        [string]$Purpose,
        [Alias('Notes')][string[]]$Note = @(),
        [string]$OperatorName,
        [string]$Ticket,
        [string]$Path,
        [switch]$Redact,
        [switch]$AllowRawEvidence
    )

    process {
        $normalized = Resolve-LVScanInput -InputObject $Result -Role 'result'
        $profile = New-LVCaseProfileObject -Result $normalized -Name $Name -Purpose $Purpose -Note $Note -OperatorName $OperatorName -Ticket $Ticket -Redact:$Redact -AllowRawEvidence:$AllowRawEvidence
        if ($Path) {
            $parent = Split-Path -Parent $Path
            if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Write-LVTextFile -Path $Path -Content ($profile | ConvertTo-Json -Depth 30)
        }
        return $profile
    }
}
