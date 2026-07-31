function Test-LogVerdictDatabase {
    <#
        .SYNOPSIS
        Validate a verdict database before it ships or before a scan trusts it.

        .DESCRIPTION
        Checks that every rule has the fields the reporter renders, that ids are
        unique, that verdicts use the known vocabulary, and that every regex in a
        messagePattern actually compiles. A malformed rule that only fails at scan
        time would fail in front of whoever is troubleshooting a broken machine.

        .PARAMETER Quiet
        Return $true/$false instead of the problem list.

        .EXAMPLE
        Test-LogVerdictDatabase -Quiet
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$Quiet
    )

    $db = Get-LogVerdictDatabase -Path $Path
    $problems = New-Object System.Collections.Generic.List[object]
    $seenIds = @{}

    $required = @('id', 'verdict', 'title', 'plain', 'why', 'action', 'confidence')
    $validVerdicts = @($script:LVVerdictRank.Keys)
    $schemaVersion = [int]$db.schemaVersion

    # Provenance is only required from the schema version that introduced it, so a
    # hand-written v1 local database keeps validating.
    if ($schemaVersion -ge 2) { $required += @('status', 'verified') }

    $staleBefore = (Get-Date).AddMonths(-1 * $script:LVVerificationMaxAgeMonths)

    foreach ($rule in $db.rules) {
        $id = $rule.id
        if (-not $id) { $id = '(missing id)' }

        foreach ($field in $required) {
            $value = $rule.$field
            if ([string]::IsNullOrWhiteSpace([string]$value)) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("missing required field '{0}'" -f $field) }) | Out-Null
            }
        }

        if ($seenIds.ContainsKey($id)) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'duplicate rule id' }) | Out-Null
        }
        $seenIds[$id] = $true

        if ($rule.verdict -and $validVerdicts -notcontains $rule.verdict) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("unknown verdict '{0}'; valid: {1}" -f $rule.verdict, ($validVerdicts -join ', ')) }) | Out-Null
        }

        if ($null -eq $rule.match) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'no match block' }) | Out-Null
        } elseif ($rule.match.messagePattern) {
            try {
                [void][regex]::new($rule.match.messagePattern)
            } catch {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("messagePattern is not a valid regex: {0}" -f $_.Exception.Message) }) | Out-Null
            }
        }

        if ($rule.status -and $script:LVRuleStatus -notcontains $rule.status) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("unknown status '{0}'; valid: {1}" -f $rule.status, ($script:LVRuleStatus -join ', ')) }) | Out-Null
        }

        if ($rule.verified) {
            $verifiedOn = [datetime]::MinValue
            $parsed = [datetime]::TryParseExact(
                [string]$rule.verified, 'yyyy-MM-dd',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$verifiedOn)

            if (-not $parsed) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("verified '{0}' is not an ISO date (yyyy-MM-dd)" -f $rule.verified) }) | Out-Null
            } elseif ($verifiedOn -lt $staleBefore -and $rule.status -ne 'deprecated') {
                # Guidance ages. A rule asserting what Microsoft recommends can quietly
                # become wrong across Windows releases, so re-verification is enforced.
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("last verified {0}, older than {1} months; re-verify or mark deprecated" -f $rule.verified, $script:LVVerificationMaxAgeMonths) }) | Out-Null
            }
        }

        if ($null -ne $rule.falsepositives -and $rule.falsepositives -isnot [array] -and $rule.falsepositives -isnot [System.Collections.IEnumerable]) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'falsepositives must be a list' }) | Out-Null
        }

        if ($rule.match -and $rule.match.messagePattern) {
            $src = $rule.match.source
            if ((-not $src -or $src -eq 'event') -and -not $rule.locale) {
                # Event message text is localized, so a pattern written against English
                # will silently stop matching on a non-English Windows. Declaring the
                # locale makes the rule skip instead of quietly failing.
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = "messagePattern matches localized event text but declares no 'locale'" }) | Out-Null
            }
        }

        if ($rule.escalate) {
            if ($null -eq $rule.escalate.perDay) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'escalate block without perDay threshold' }) | Out-Null
            }
            if ($rule.escalate.verdict -and $validVerdicts -notcontains $rule.escalate.verdict) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("escalate uses unknown verdict '{0}'" -f $rule.escalate.verdict) }) | Out-Null
            }
        }
    }

    if ($Quiet) { return ($problems.Count -eq 0) }

    if ($problems.Count -eq 0) {
        Write-LVLog -Level ok -Message ("Verdict database valid: {0} rule(s)." -f @($db.rules).Count)
    } else {
        Write-LVLog -Level error -Message ("Verdict database has {0} problem(s)." -f $problems.Count)
    }
    return ConvertTo-LVArrayOutput -Value @($problems.ToArray())
}
