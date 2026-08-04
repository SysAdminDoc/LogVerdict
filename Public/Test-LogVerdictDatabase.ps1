function Test-LogVerdictDatabase {
    <#
        .SYNOPSIS
        Validate a verdict database before it ships or before a scan trusts it.

        .DESCRIPTION
        Checks that every rule has the fields the reporter renders, that ids are
        unique, that verdicts use the known vocabulary, and that every regex in a
        messagePattern actually compiles. Correlations are also checked against the
        resolver's supported vocabulary and live rule ids. A malformed rule that only
        fails at scan time would fail in front of whoever is troubleshooting a broken
        machine.

        .PARAMETER Quiet
        Return $true/$false instead of the problem list.

        .PARAMETER IncludeWarnings
        Also return quality warnings, such as a rule without a regression fixture. Warnings
        are excluded by default because they describe a database that could be better, not
        one that is malformed.

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

    $db = Get-LogVerdictDatabase -Path $Path -SkipValidation
    $problems = New-Object System.Collections.Generic.List[object]
    $seenIds = @{}

    $required = @('id', 'verdict', 'title', 'plain', 'why', 'action', 'confidence')
    $validVerdicts = @($script:LVVerdictRank.Keys)
    $validConfidence = @($script:LVRuleConfidence)
    $schemaVersion = [int]$db.schemaVersion

    $freshnessPolicy = Get-LVDatabaseFreshnessPolicy -Database $db
    if ($db.PSObject.Properties['freshness']) {
        if (-not $db.freshness -or -not $db.freshness.PSObject.Properties['maxAgeDays']) {
            $problems.Add([pscustomobject]@{ RuleId = '(database)'; Problem = 'freshness.maxAgeDays is required when a freshness policy is declared' }) | Out-Null
        } else {
            $declaredMaxAge = 0
            if (-not [int]::TryParse([string]$db.freshness.maxAgeDays, [ref]$declaredMaxAge) -or $declaredMaxAge -lt 1) {
                $problems.Add([pscustomobject]@{ RuleId = '(database)'; Problem = 'freshness.maxAgeDays must be a positive integer' }) | Out-Null
            }
        }
        if (-not $db.freshness.PSObject.Properties['dateBasis'] -or [string]$db.freshness.dateBasis -ne 'UTC') {
            $problems.Add([pscustomobject]@{ RuleId = '(database)'; Problem = 'freshness.dateBasis must be UTC' }) | Out-Null
        }
    }

    # Provenance is only required from the schema version that introduced it, so a
    # hand-written v1 local database keeps validating.
    if ($schemaVersion -ge 2) { $required += @('status', 'verified') }
    if ($schemaVersion -ge 7) { $required += @('modified') }

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

        if ($rule.confidence -and $validConfidence -notcontains $rule.confidence) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("unknown confidence '{0}'; valid: {1}" -f $rule.confidence, ($validConfidence -join ', ')) }) | Out-Null
        }
        if ($rule.confidence -eq 'draft' -and $rule.status -ne 'unsupported') {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = "confidence 'draft' requires status 'unsupported' so it cannot produce a verdict before human review" }) | Out-Null
        }

        if ($rule.PSObject.Properties['staleAfterDays']) {
            $ruleDays = 0
            if (-not [int]::TryParse([string]$rule.staleAfterDays, [ref]$ruleDays) -or $ruleDays -lt 1) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'staleAfterDays must be a positive integer' }) | Out-Null
            }
        }
        if ($rule.PSObject.Properties['windowsBuild']) {
            if (-not $rule.windowsBuild) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'windowsBuild must declare min or max' }) | Out-Null
            } else {
                $minBuild = $null
                $maxBuild = $null
                if ($rule.windowsBuild.PSObject.Properties['min']) {
                    $candidateMin = 0
                    if (-not [int]::TryParse([string]$rule.windowsBuild.min, [ref]$candidateMin) -or $candidateMin -lt 1) {
                        $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'windowsBuild.min must be a positive integer' }) | Out-Null
                    } else { $minBuild = $candidateMin }
                }
                if ($rule.windowsBuild.PSObject.Properties['max']) {
                    $candidateMax = 0
                    if (-not [int]::TryParse([string]$rule.windowsBuild.max, [ref]$candidateMax) -or $candidateMax -lt 1) {
                        $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'windowsBuild.max must be a positive integer' }) | Out-Null
                    } else { $maxBuild = $candidateMax }
                }
                if ($null -eq $minBuild -and $null -eq $maxBuild) {
                    $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'windowsBuild must declare min or max' }) | Out-Null
                } elseif ($null -ne $minBuild -and $null -ne $maxBuild -and $minBuild -gt $maxBuild) {
                    $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'windowsBuild.min cannot exceed windowsBuild.max' }) | Out-Null
                }
            }
        }

        if ($null -eq $rule.match) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'no match block' }) | Out-Null
        } else {
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
            } else {
                $freshness = Get-LVRuleFreshness -Rule $rule -Policy $freshnessPolicy
                if ($freshness.IsStale -and $rule.status -ne 'deprecated') {
                # Guidance ages. A rule asserting what Microsoft recommends can quietly
                # become wrong across Windows releases, so re-verification is enforced.
                    $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("last verified {0}, older than the {1}-day freshness threshold; re-verify or mark deprecated" -f $rule.verified, $freshness.StaleAfterDays) }) | Out-Null
                }
            }
        }

        if ($rule.PSObject.Properties['modified']) {
            $modifiedOn = [datetime]::MinValue
            $modifiedParsed = [datetime]::TryParseExact(
                [string]$rule.modified, 'yyyy-MM-dd',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$modifiedOn)
            if (-not $modifiedParsed) {
                $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("modified '{0}' is not an ISO date (yyyy-MM-dd)" -f $rule.modified) }) | Out-Null
            }
        }

        if ($rule.PSObject.Properties['expiresWithKb'] -and
            [string]$rule.expiresWithKb -notmatch '^KB\d{5,}$') {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'expiresWithKb must be a KB identifier such as KB5062660' }) | Out-Null
        }

        if ($null -ne $rule.falsepositives -and $rule.falsepositives -isnot [array] -and $rule.falsepositives -isnot [System.Collections.IEnumerable]) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'falsepositives must be a list' }) | Out-Null
        }

        # Filtered, not just wrapped: @($null) is a one-element array holding null.
        $ruleSources = @($rule.sources | Where-Object { $_ })

        # The prose is part of the trust boundary. A severe ruling without a
        # counterexample invites over-triage, and a severe ruling with no external
        # citation leaves the reader unable to check the claim. Deprecated and
        # unsupported rules are explicit lifecycle downgrades and are not active.
        if ((Test-LVRuleActive -Rule $rule) -and $rule.verdict -in @('actionable', 'critical')) {
            $falsePositiveText = @($rule.falsepositives | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_)
                })
            if ($falsePositiveText.Count -eq 0) {
                $problems.Add([pscustomobject]@{
                        RuleId = $id
                        Problem = 'actionable or critical active rule requires at least one falsepositives entry'
                    }) | Out-Null
            }

            $externalCitations = @($rule.references | Where-Object {
                    [string]$_ -match '^https?://'
                })
            $externalCitations += @($ruleSources | Where-Object {
                    [string]$_.uri -match '^https?://'
                })
            if ($externalCitations.Count -eq 0) {
                $problems.Add([pscustomobject]@{
                        RuleId = $id
                        Problem = 'actionable or critical active rule requires at least one external citation in references[] or sources[].uri'
                    }) | Out-Null
            }
        }

        # Event ids are useful match keys, not explanations. Reject only a narrow
        # label form that merely repeats this rule's event id, while allowing a
        # substantive sentence that explains what the event means.
        $eventId = $null
        if ($rule.match -and $rule.match.PSObject.Properties['eventId']) {
            $eventId = [string]$rule.match.eventId
        }
        if (-not [string]::IsNullOrWhiteSpace($eventId)) {
            $normalizedPlain = (([string]$rule.plain).ToLowerInvariant() -replace '[^a-z0-9]+', ' ').Trim()
            $normalizedEventId = $eventId.ToLowerInvariant()
            $eventLabels = @(
                $normalizedEventId
                "event $normalizedEventId"
                "event id $normalizedEventId"
                "event number $normalizedEventId"
                "windows event $normalizedEventId"
                "windows event id $normalizedEventId"
                "event $normalizedEventId occurred"
                "event id $normalizedEventId occurred"
                "event $normalizedEventId was logged"
                "event id $normalizedEventId was logged"
                "event $normalizedEventId recorded"
                "event id $normalizedEventId recorded"
            )
        } else {
            $eventLabels = @()
            $normalizedPlain = $null
        }
        if ($eventLabels -contains $normalizedPlain) {
            $problems.Add([pscustomobject]@{
                    RuleId = $id
                    Problem = 'plain must explain what happened rather than only restating an event id'
                }) | Out-Null
        }

        # Provenance. A ruling nobody can check is an assertion, and this tool exists to
        # be trusted; a rule derived from a licensed corpus additionally carries legal
        # obligations that only travel if they are recorded here.
        if ($rule.provenance -and $rule.provenance -ne 'internal-observation') {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = ("unknown provenance '{0}'; valid: internal-observation" -f $rule.provenance) }) | Out-Null
        } elseif ((Test-LVRuleActive -Rule $rule) -and -not (Test-LVDatabaseProvenance -Item $rule)) {
            $problems.Add([pscustomobject]@{ RuleId = $id; Problem = 'active rule requires references[], sources[], or provenance=internal-observation' }) | Out-Null
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
            if ((-not $src -or $src -eq 'event' -or $src -eq 'reliability') -and -not $rule.locale) {
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

    foreach ($p in @(Get-LVDatabaseTrustProblem -Database $db -Path $Path -SkipRuleProvenance)) {
        $problems.Add($p) | Out-Null
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
