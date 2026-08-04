function Get-LogVerdictIntuneDigest {
    <#
        .SYNOPSIS
        Project a scan into the bounded stdout contract used by Intune remediations.

        Intune treats any non-zero exit as a finding and limits remediation output to
        2,048 characters. This function returns the digest and the normalized exit
        code so the console entry point can emit UTF-8 without a BOM and exit 0/1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [ValidateRange(128, 2047)][int]$MaxCharacters = 2047
    )

    $resolved = ConvertFrom-LVReportContract -InputObject (Resolve-LVScanInput -InputObject $Result -Role 'result')
    $findings = @(Get-LVReportIncident -Result $resolved | Where-Object {
        $_ -and (Get-LVVerdictRank -Verdict ([string]$_.Verdict)) -ge (Get-LVVerdictRank -Verdict 'unknown')
    })
    $correlations = @($resolved.Correlations | Where-Object {
        $_ -and (Get-LVVerdictRank -Verdict ([string]$_.Verdict)) -ge (Get-LVVerdictRank -Verdict 'unknown')
    })
    $nonBenign = @($findings) + @($correlations)
    $worst = if ($resolved.WorstVerdict) { [string]$resolved.WorstVerdict } else { 'benign' }
    $needsAttention = $nonBenign.Count -gt 0 -or (Get-LVVerdictRank -Verdict $worst) -ge (Get-LVVerdictRank -Verdict 'unknown')
    $status = if ($needsAttention) { 'NON-BENIGN' } else { 'OK' }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('LogVerdict {0}: {1}' -f $resolved.Version, $status)) | Out-Null
    $lines.Add(('Worst verdict: {0}; findings needing attention: {1}' -f $worst.ToUpperInvariant(), $nonBenign.Count)) | Out-Null
    $lines.Add(('Scanned UTC: {0}; rule database: {1} ({2})' -f (ConvertTo-LVTicketTimestamp $resolved.ScanTime), $resolved.DatabaseName, $resolved.DatabaseDate)) | Out-Null
    if ($resolved.Reduction) {
        $lines.Add(('Suppression: {0:N0} records -> {1:N0} signatures ({2}:1); incidents grouped: {3:P0}' -f `
                ([Math]::Max(0, [int64]$resolved.Reduction.RecordCount - [int64]$resolved.Reduction.SignatureCount)),
                [int64]$resolved.Reduction.SignatureCount, $resolved.Reduction.Ratio, $(if ($resolved.IncidentSummary) { $resolved.IncidentSummary.SuppressionRatio } else { 0 }))) | Out-Null
    }
    $index = 0
    foreach ($finding in @($nonBenign | Sort-Object @{ Expression = { Get-LVVerdictRank -Verdict ([string]$_.Verdict) }; Descending = $true },
            @{ Expression = { [int64]$_.Count }; Descending = $true }, Title | Select-Object -First 5)) {
        $index++
        $action = if ($finding.Action) { ([string]$finding.Action -replace '[\r\n]+', ' ').Trim() } else { 'Review full report.' }
        if ($action.Length -gt 240) { $action = $action.Substring(0, 237) + '...' }
        $title = ([string]$finding.Title -replace '[\r\n]+', ' ').Trim()
        if ($title.Length -gt 180) { $title = $title.Substring(0, 177) + '...' }
        $lines.Add(('{0}. {1}: {2} ({3:N0}); {4}' -f $index, ([string]$finding.Verdict).ToUpperInvariant(), $title, [int64]$finding.Count, $action)) | Out-Null
    }
    foreach ($caveat in @($resolved.CoverageNotes | Where-Object { $_ } | Select-Object -First 2)) {
        $lines.Add(('Coverage caveat: ' + (([string]$caveat -replace '[\r\n]+', ' ').Trim()))) | Out-Null
    }
    if ($nonBenign.Count -eq 0 -and @($resolved.CoverageNotes).Count -eq 0) {
        $lines.Add('No non-benign verdicts were reported. Full report mode is available for details.') | Out-Null
    }

    $text = ($lines.ToArray() -join [Environment]::NewLine).Trim()
    $suffix = [Environment]::NewLine + '... truncated; use the full report for details.'
    if ($text.Length -gt $MaxCharacters) {
        $text = $text.Substring(0, [Math]::Max(1, $MaxCharacters - $suffix.Length)).TrimEnd() + $suffix
    }
    if ([string]::IsNullOrWhiteSpace($text)) { $text = 'LogVerdict: no result details were available.' }

    return [pscustomobject][ordered]@{
        Text = $text
        ExitCode = if ($needsAttention) { 1 } else { 0 }
        CharacterCount = $text.Length
        Encoding = 'UTF-8 without BOM'
        MaxCharacters = $MaxCharacters
    }
}
