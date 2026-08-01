# Rule regression fixtures.
#
# The verdict database is the product, and nothing in the code detects a rule that
# has quietly stopped matching. That failure is silent by construction: a rule which
# no longer fires produces no error, it produces an "unknown" signature that looks
# exactly like a gap in coverage. Every rule therefore carries a minimal signature it
# must still claim, resolved through the real Resolve-LVVerdict rather than through a
# reimplementation of the matcher.
#
# This catches three regressions that no other test does:
#   - a masking or collector change that alters the shape a rule matches against
#   - a new rule that shadows an existing one by being broader at equal specificity
#   - a verdict edited in one place and not the other
#
# Fixtures are test data and are deliberately NOT compiled into the executables.

function Get-LVFixtureSet {
    <#
        .SYNOPSIS
        Load the rule regression fixtures. Returns $null when there are none.

        .DESCRIPTION
        Absence is not an error. A site running a hand-written verdicts.local.json has
        no fixture file and must still be able to validate its database.
    #>
    [CmdletBinding()]
    param([string]$Path)

    $target = $Path
    if (-not $target) { $target = Join-Path $script:LVDataDir 'fixtures.json' }
    if (-not (Test-Path -LiteralPath $target)) { return $null }

    $set = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
    return $set
}

function ConvertTo-LVFixtureSignature {
    <#
        .SYNOPSIS
        Project a fixture into the signature shape the reduction layer emits.

        .DESCRIPTION
        The property names must match Group-LVSignature's output exactly, because the
        whole point is to drive the real resolver. PerDay defaults to zero so a rule's
        base verdict applies; a fixture that wants to exercise rate escalation states
        its own rate.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Fixture)

    $s = $Fixture.signature
    $perDay = 0
    if ($null -ne $Fixture.perDay) { $perDay = [double]$Fixture.perDay }

    $id = 0
    if ($null -ne $s.Id) { $id = [int]$s.Id }

    return [pscustomobject]@{
        Key           = ('fixture/{0}' -f $Fixture.ruleId)
        Source        = $s.Source
        Channel       = $s.Channel
        Provider      = $s.Provider
        Id            = $id
        SampleMessage = [string]$s.SampleMessage
        Samples       = @([string]$s.SampleMessage)
        Count         = 1
        PerDay        = $perDay
        SpanDays      = 0
        FirstSeen     = $null
        LastSeen      = $null
        UndatedCount  = 0
        WorstLevel    = 2
        LevelName     = 'Error'
        Template      = $null
        Area          = 'fixture'
    }
}

function Test-LVFixtureResolution {
    <#
        .SYNOPSIS
        Resolve every fixture against a database and report what did not hold.

        .DESCRIPTION
        Three distinct failures, reported separately because they need different fixes:

        A fixture naming a rule the database does not contain means the rule was deleted
        or renamed without its fixture following.

        A fixture resolving to a DIFFERENT rule means shadowing - almost always a newly
        added rule that is broader than it looks. The winner is named, because the
        useful question is which rule stole the match, not merely that one did.

        A fixture resolving to the right rule with the wrong verdict means the ruling
        changed without the fixture being updated to agree.

        A rule carrying no fixture at all is a warning: the database is still sound, it
        is merely unprotected. The test suite holds the shipped database to zero.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)]$FixtureSet
    )

    $problems = New-Object System.Collections.Generic.List[object]
    $fixtures = @($FixtureSet.fixtures | Where-Object { $_ })
    if ($fixtures.Count -eq 0) { return ConvertTo-LVArrayOutput -Value @() }

    $ruleById = @{}
    foreach ($r in $Database.rules) { $ruleById[$r.id] = $r }

    $covered = @{}

    foreach ($fixture in $fixtures) {
        $ruleId = $fixture.ruleId
        $label = $ruleId
        if ($fixture.name) { $label = '{0} ({1})' -f $ruleId, $fixture.name }

        if (-not $ruleById.ContainsKey($ruleId)) {
            $problems.Add([pscustomobject]@{
                RuleId  = $ruleId
                Problem = ("fixture '{0}' names a rule that is not in the database" -f $label)
            }) | Out-Null
            continue
        }
        $covered[$ruleId] = $true

        $signature = ConvertTo-LVFixtureSignature -Fixture $fixture
        $resolved = @(Resolve-LVVerdict -Signature @($signature) -Database $Database) | Select-Object -First 1

        if ($null -eq $resolved) {
            $problems.Add([pscustomobject]@{ RuleId = $ruleId; Problem = ("fixture '{0}' resolved to nothing" -f $label) }) | Out-Null
            continue
        }

        if ($resolved.RuleId -ne $ruleId) {
            $winner = $resolved.RuleId
            if (-not $winner) { $winner = 'no rule at all (reported as unknown)' }
            $problems.Add([pscustomobject]@{
                RuleId  = $ruleId
                Problem = ("fixture '{0}' resolved to {1}; the rule no longer claims its own sample" -f $label, $winner)
            }) | Out-Null
            continue
        }

        if ($fixture.expect -and $resolved.Verdict -ne $fixture.expect) {
            $problems.Add([pscustomobject]@{
                RuleId  = $ruleId
                Problem = ("fixture '{0}' expected verdict '{1}' but resolved to '{2}'" -f $label, $fixture.expect, $resolved.Verdict)
            }) | Out-Null
        }
    }

    foreach ($rule in $Database.rules) {
        if (-not (Test-LVRuleActive -Rule $rule)) { continue }
        if ($covered.ContainsKey($rule.id)) { continue }
        $problems.Add([pscustomobject]@{
            RuleId   = $rule.id
            Severity = 'warning'
            Problem  = 'no regression fixture; nothing would notice if this rule stopped matching'
        }) | Out-Null
    }

    return ConvertTo-LVArrayOutput -Value @($problems.ToArray())
}
