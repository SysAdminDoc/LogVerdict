function Resolve-LVScanInput {
    <#
        .SYNOPSIS
        Normalize a scan result object or JSON report path for comparison.
    #>
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Role
    )

    $report = $InputObject
    if ($InputObject -is [string] -or $InputObject -is [IO.FileInfo]) {
        $path = [string]$InputObject
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw ("The {0} scan report does not exist: {1}" -f $Role, $path)
        }
        try {
            $report = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw ("The {0} scan report is not readable JSON: {1}" -f $Role, $_.Exception.Message)
        }
    }

    if ($null -eq $report -or $null -eq $report.PSObject.Properties['Findings']) {
        throw ("The {0} input is not a LogVerdict scan result: it has no Findings collection." -f $Role)
    }
    return $report
}

function ConvertTo-LVFindingMap {
    <#
        .SYNOPSIS
        Index a result's findings by their stable signature key.
    #>
    param(
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)][string]$Role
    )

    $map = @{}
    foreach ($finding in @($Report.Findings)) {
        if ($null -eq $finding) { continue }
        $key = [string]$finding.Key
        if (-not $key) { throw ("The {0} scan contains a finding with no signature Key." -f $Role) }
        if ($map.ContainsKey($key)) { throw ("The {0} scan contains duplicate signature key '{1}'." -f $Role, $key) }
        $map[$key] = $finding
    }
    return $map
}

function Compare-LogVerdictScan {
    <#
        .SYNOPSIS
        Show what changed between a before-fix and after-fix LogVerdict scan.

        .DESCRIPTION
        Accepts scan result objects or JSON report paths and emits one flat object per
        new, resolved, or worsening signature. Unchanged and improving signatures are
        omitted so the output can be piped directly to Format-Table, Export-Csv, or a
        ticketing script.

        A persistent signature is worsening when its verdict becomes more severe, or
        when its verdict is unchanged and its per-day rate rises by at least 25 percent
        and 0.10/day. The absolute floor prevents rounding noise around rare events from
        reading as regression.

        .PARAMETER Before
        The scan result or JSON report captured before applying the fix.

        .PARAMETER After
        The scan result or JSON report captured after applying the fix.

        .EXAMPLE
        Compare-LogVerdictScan -Before .\before\LogVerdict-Report.json -After .\after\LogVerdict-Report.json

        .EXAMPLE
        Compare-LogVerdictScan $before $after | Where-Object Change -eq 'resolved'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]$Before,
        [Parameter(Mandatory, Position = 1)]$After
    )

    $beforeReport = Resolve-LVScanInput -InputObject $Before -Role 'before'
    $afterReport = Resolve-LVScanInput -InputObject $After -Role 'after'
    $beforeMap = ConvertTo-LVFindingMap -Report $beforeReport -Role 'before'
    $afterMap = ConvertTo-LVFindingMap -Report $afterReport -Role 'after'
    $changes = New-Object System.Collections.Generic.List[object]

    foreach ($key in @($afterMap.Keys | Sort-Object)) {
        $afterFinding = $afterMap[$key]
        if (-not $beforeMap.ContainsKey($key)) {
            $changes.Add([pscustomobject]@{
                Change = 'new'; Key = $key; Title = $afterFinding.Title
                BeforeVerdict = $null; AfterVerdict = $afterFinding.Verdict
                BeforeCount = $null; AfterCount = $afterFinding.Count
                BeforePerDay = $null; AfterPerDay = $afterFinding.PerDay
                RateDelta = $null; Reason = 'Signature did not appear in the before scan.'
                BeforeScanTime = $beforeReport.ScanTime; AfterScanTime = $afterReport.ScanTime
                Before = $null; After = $afterFinding
            }) | Out-Null
            continue
        }

        $beforeFinding = $beforeMap[$key]
        $beforeRank = Get-LVVerdictRank -Verdict $beforeFinding.Verdict
        $afterRank = Get-LVVerdictRank -Verdict $afterFinding.Verdict
        $beforeRate = [double]$beforeFinding.PerDay
        $afterRate = [double]$afterFinding.PerDay
        $rateDelta = [Math]::Round($afterRate - $beforeRate, 2)
        $verdictWorse = ($afterRank -gt $beforeRank)
        $rateWorse = ($afterRank -eq $beforeRank -and $rateDelta -ge 0.10 -and `
            ($beforeRate -le 0 -or $afterRate -ge ($beforeRate * 1.25)))

        if ($verdictWorse -or $rateWorse) {
            $reason = 'Rate rose from {0:0.00}/day to {1:0.00}/day.' -f $beforeRate, $afterRate
            if ($verdictWorse) {
                $reason = 'Verdict became more severe: {0} to {1}.' -f $beforeFinding.Verdict, $afterFinding.Verdict
            }
            $changes.Add([pscustomobject]@{
                Change = 'worsening'; Key = $key; Title = $afterFinding.Title
                BeforeVerdict = $beforeFinding.Verdict; AfterVerdict = $afterFinding.Verdict
                BeforeCount = $beforeFinding.Count; AfterCount = $afterFinding.Count
                BeforePerDay = $beforeRate; AfterPerDay = $afterRate
                RateDelta = $rateDelta; Reason = $reason
                BeforeScanTime = $beforeReport.ScanTime; AfterScanTime = $afterReport.ScanTime
                Before = $beforeFinding; After = $afterFinding
            }) | Out-Null
        }
    }

    foreach ($key in @($beforeMap.Keys | Sort-Object)) {
        if ($afterMap.ContainsKey($key)) { continue }
        $beforeFinding = $beforeMap[$key]
        $changes.Add([pscustomobject]@{
            Change = 'resolved'; Key = $key; Title = $beforeFinding.Title
            BeforeVerdict = $beforeFinding.Verdict; AfterVerdict = $null
            BeforeCount = $beforeFinding.Count; AfterCount = $null
            BeforePerDay = $beforeFinding.PerDay; AfterPerDay = $null
            RateDelta = $null; Reason = 'Signature did not appear in the after scan.'
            BeforeScanTime = $beforeReport.ScanTime; AfterScanTime = $afterReport.ScanTime
            Before = $beforeFinding; After = $null
        }) | Out-Null
    }

    $order = @{ worsening = 0; new = 1; resolved = 2 }
    $sorted = @($changes.ToArray() | Sort-Object `
        @{ Expression = { $order[$_.Change] }; Ascending = $true }, `
        @{ Expression = {
            if ($_.AfterVerdict) { Get-LVVerdictRank -Verdict $_.AfterVerdict }
            else { Get-LVVerdictRank -Verdict $_.BeforeVerdict }
        }; Descending = $true }, `
        Key)
    return ConvertTo-LVArrayOutput -Value $sorted
}
