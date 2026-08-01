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

        .PARAMETER IncludeWarnings
        Also return quality warnings - a rule with no source, for instance. Warnings are
        excluded by default because they describe a database that could be better, not
        one that is malformed, and mixing the two would mean a documentation gap failed
        the same check as a broken regex.

        .PARAMETER FixturePath
        Regression fixtures to resolve against this database. Defaults to fixtures.json
        beside the database being validated. When no fixture file exists the fixture
        checks are skipped, so a hand-written local database still validates.

        .PARAMETER SkipFixture
        Validate structure only. Useful when the fixtures belong to a different database
        than the one under test.

        .EXAMPLE
        Test-LogVerdictDatabase -Quiet

        .EXAMPLE
        Test-LogVerdictDatabase -IncludeWarnings | Where-Object Severity -eq 'warning'
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$Quiet,
        [switch]$IncludeWarnings,
        [string]$FixturePath,
        [switch]$SkipFixture
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

        # Provenance. A ruling nobody can check is an assertion, and this tool exists to
        # be trusted; a rule derived from a licensed corpus additionally carries legal
        # obligations that only travel if they are recorded here.
        # Filtered, not just wrapped: @($null) is a one-element array holding null, so a
        # rule with no sources would otherwise iterate once over a phantom entry and be
        # reported as having a source with no uri.
        $ruleSources = @($rule.sources | Where-Object { $_ })
        if ($ruleSources.Count -eq 0 -and @($rule.references | Where-Object { $_ }).Count -eq 0) {
            # A warning, not an error. An unsourced ruling is weaker than a sourced one
            # but it is still structurally sound and still loads; treating it as invalid
            # would make the shipped database refuse to load over a documentation gap.
            $problems.Add([pscustomobject]@{ RuleId = $id; Severity = 'warning'; Problem = 'no sources[] and no references; the ruling cannot be checked' }) | Out-Null
        }
        foreach ($source in $ruleSources) {
            if (-not $source.uri) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'sources[] entry without a uri' }) | Out-Null
            }
            if ($source.retrieved -and $source.retrieved -notmatch '^\d{4}-\d{2}-\d{2}$') {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("source retrieved '{0}' is not an ISO date (yyyy-MM-dd)" -f $source.retrieved) }) | Out-Null
            }
            # DRL-1.1 obliges the author be shown wherever the rule matches, so a rule
            # that names that licence without naming an author cannot be rendered legally.
            if ($source.licence -like 'DRL*' -and -not $source.author) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'DRL-licensed source must name an author; the licence requires it be shown on every match' }) | Out-Null
            }
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

    # Structure is only half the question. A database can be perfectly well formed and
    # still have a rule that no longer matches anything it was written for, which is
    # invisible in the report - an unmatched signature reads as a coverage gap, not as
    # a broken rule. Resolving the fixtures through the real resolver is what catches it.
    if (-not $SkipFixture) {
        $fixtureSource = $FixturePath
        if (-not $fixtureSource -and $Path) {
            # Fixtures live beside the database they describe, so validating an explicit
            # database looks next to that file rather than at the shipped fixtures.
            $fixtureSource = Join-Path (Split-Path -Parent $Path) 'fixtures.json'
        }
        $fixtureSet = Get-LVFixtureSet -Path $fixtureSource
        if ($null -ne $fixtureSet) {
            foreach ($p in (Test-LVFixtureResolution -Database $db -FixtureSet $fixtureSet)) {
                $problems.Add($p) | Out-Null
            }
        }
    }

    # Problems default to errors; only those explicitly marked otherwise are warnings.
    foreach ($p in $problems) {
        if (-not $p.PSObject.Properties['Severity']) {
            $p | Add-Member -NotePropertyName 'Severity' -NotePropertyValue 'error' -Force
        }
    }
    $errors = @($problems | Where-Object { $_.Severity -ne 'warning' })
    $warnings = @($problems | Where-Object { $_.Severity -eq 'warning' })

    # Validity is about structure. A warning says the database could be better, not that
    # it cannot be trusted to load.
    if ($Quiet) { return ($errors.Count -eq 0) }

    $unsourced = @($warnings | Where-Object { $_.Problem -like 'no sources*' })
    if ($unsourced.Count -gt 0) {
        Write-LVLog -Level warn -Message ("{0} rule(s) carry no source; their rulings cannot be checked by a reader." -f $unsourced.Count)
    }
    $unfixtured = @($warnings | Where-Object { $_.Problem -like 'no regression fixture*' })
    if ($unfixtured.Count -gt 0) {
        Write-LVLog -Level warn -Message ("{0} rule(s) carry no regression fixture; nothing would notice if they stopped matching." -f $unfixtured.Count)
    }

    if ($errors.Count -eq 0) {
        Write-LVLog -Level ok -Message ("Verdict database valid: {0} rule(s)." -f @($db.rules).Count)
    } else {
        Write-LVLog -Level error -Message ("Verdict database has {0} problem(s)." -f $errors.Count)
    }
    if ($IncludeWarnings) { return ConvertTo-LVArrayOutput -Value @($problems.ToArray()) }
    return ConvertTo-LVArrayOutput -Value $errors
}
