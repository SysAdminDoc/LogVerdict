# Ruling layer: match each signature against the verdict database.
# Deliberately deterministic. Everything a reader sees here is either a curated
# human-written explanation or an honest admission that the signature is unrecognized.

function Assert-LVSchemaVersion {
    <#
        .SYNOPSIS
        Refuse to read a verdict database this module does not understand.

        .DESCRIPTION
        Loading a newer schema on a best-effort basis would mean ruling on signatures
        using only the fields this code happens to recognize, and reporting the result
        with the same confidence as a fully understood rule. Failing loudly is the only
        honest option for a tool whose output people act on.
    #>
    param(
        [Parameter(Mandatory)]$Database,
        [string]$Path
    )

    $version = $Database.schemaVersion
    if ($null -eq $version) {
        throw ("Verdict database '{0}' declares no schemaVersion. Expected {1}-{2}." -f $Path, $script:LVSchemaVersionMin, $script:LVSchemaVersionMax)
    }
    $v = [int]$version
    if ($v -lt $script:LVSchemaVersionMin -or $v -gt $script:LVSchemaVersionMax) {
        throw ("Verdict database '{0}' uses schemaVersion {1}, but this build of LogVerdict supports {2}-{3}. Upgrade LogVerdict to read it." -f `
            $Path, $v, $script:LVSchemaVersionMin, $script:LVSchemaVersionMax)
    }
}

function Test-LVRuleActive {
    <#
        .SYNOPSIS
        Whether a rule is eligible to produce a verdict.

        .DESCRIPTION
        Deprecated and unsupported rules stay in the database so their ids remain
        resolvable and their history is not lost, but they must never rule on a
        signature. A rule with no status predates the status field and is treated as
        active, which keeps schema v1 databases working.
    #>
    param([Parameter(Mandatory)]$Rule)

    if (-not $Rule.status) { return $true }
    return ($script:LVActiveRuleStatus -contains $Rule.status)
}

function Get-LVRuleSpecificity {
    <#
        .SYNOPSIS
        How narrowly a rule is targeted. Higher wins when several rules match.
        .DESCRIPTION
        A rule naming a provider AND an event id must beat a provider-wide catch-all,
        otherwise the broad rule shadows every precise one behind it.
    #>
    param([Parameter(Mandatory)]$Rule)

    $score = 0
    $m = $Rule.match
    if ($null -ne $m.eventId)        { $score += 8 }
    if ($m.messagePattern)           { $score += 4 }
    if ($m.provider)                 { $score += 2 }
    if ($m.channel)                  { $score += 2 }
    if ($m.source)                   { $score += 1 }
    return $score
}

function Test-LVRuleMatch {
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)]$Signature
    )

    $m = $Rule.match

    if ($m.source   -and $m.source  -ne $Signature.Source)  { return $false }
    if ($m.channel  -and $m.channel -ne $Signature.Channel) { return $false }
    if ($m.provider -and $m.provider -ne $Signature.Provider) {
        # Allow a trailing wildcard so a provider family can be covered in one rule.
        if (-not ($m.provider.EndsWith('*') -and $Signature.Provider -like $m.provider)) { return $false }
    }
    if ($null -ne $m.eventId -and [int]$m.eventId -ne [int]$Signature.Id) { return $false }

    if ($m.messagePattern) {
        # Event messages are rendered from the provider's localized MUI resources, so an
        # English pattern silently stops matching on a German or Japanese install. Text
        # logs (CBS, DISM, SetupAPI) are written in invariant English by the component
        # that produces them, so they need no such guard.
        if (Test-LVLocaleSensitiveMatch -Rule $Rule) {
            $assumed = $Rule.locale
            if ($assumed -and -not (Test-LVLocaleMatch -Assumed $assumed)) { return $false }
        }

        $haystack = $Signature.SampleMessage
        if (-not $haystack) { $haystack = '' }
        if ($haystack -notmatch $m.messagePattern) { return $false }
    }

    return $true
}

function Test-LVLocaleSensitiveMatch {
    <#
        .SYNOPSIS
        Whether a rule's messagePattern is matched against localized text.
    #>
    param([Parameter(Mandatory)]$Rule)

    if (-not $Rule.match.messagePattern) { return $false }
    # Absent source means events, which is the localized case.
    $source = $Rule.match.source
    return (-not $source -or $source -eq 'event')
}

function Test-LVLocaleMatch {
    <#
        .SYNOPSIS
        Whether the machine's UI language matches what a rule assumes.

        .DESCRIPTION
        Compared on the language part only: a rule written against 'en-US' message text
        matches an 'en-GB' machine, because the provider's English resources are the
        same strings.
    #>
    param([Parameter(Mandatory)][string]$Assumed)

    $current = $script:LVUICulture
    if (-not $current) { return $true }
    $a = ($Assumed -split '-')[0]
    $c = ($current -split '-')[0]
    return ($a -eq $c)
}

function Resolve-LVVerdict {
    <#
        .SYNOPSIS
        Attach a verdict to every signature.
        .OUTPUTS
        The signature objects with Verdict/Title/Plain/Why/Action/RuleId/Confidence added.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Signature,
        [Parameter(Mandatory)]$Database
    )

    $rules = @($Database.rules |
        Where-Object { Test-LVRuleActive -Rule $_ } |
        Sort-Object -Property @{ Expression = { Get-LVRuleSpecificity -Rule $_ } } -Descending)
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($original in $Signature) {
        # Copy before annotating. Add-Member -Force on the caller's object means
        # resolving the same signatures against a second database leaves stale verdict
        # properties from the first pass on objects the caller still holds.
        $sig = [pscustomobject]@{}
        foreach ($prop in $original.PSObject.Properties) {
            $sig | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
        }

        $hit = $null
        foreach ($rule in $rules) {
            if (Test-LVRuleMatch -Rule $rule -Signature $sig) { $hit = $rule; break }
        }

        if ($null -eq $hit) {
            $sig | Add-Member -NotePropertyName 'RuleId'     -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'Verdict'    -NotePropertyValue 'unknown' -Force
            $sig | Add-Member -NotePropertyName 'Title'      -NotePropertyValue ('Unrecognized: {0}' -f $sig.Key) -Force
            $sig | Add-Member -NotePropertyName 'Plain'      -NotePropertyValue 'No rule in the verdict database covers this signature, so LogVerdict will not guess at what it means. The raw message below is the evidence, unedited.' -Force
            $sig | Add-Member -NotePropertyName 'Why'        -NotePropertyValue 'Reported so that an unknown problem is visible rather than silently dropped.' -Force
            $sig | Add-Member -NotePropertyName 'Action'     -NotePropertyValue 'Read the sample message. If you identify it, add a rule to Data/verdicts.json so the next scan explains it.' -Force
            $sig | Add-Member -NotePropertyName 'Confidence' -NotePropertyValue 'none' -Force
            $sig | Add-Member -NotePropertyName 'Reference'  -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'References' -NotePropertyValue @() -Force
            $sig | Add-Member -NotePropertyName 'Status'     -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'Verified'   -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'FalsePositives' -NotePropertyValue @() -Force
            $results.Add($sig) | Out-Null
            continue
        }

        $verdict = $hit.verdict
        $why = $hit.why

        # Rate-based escalation: the same signature can be background noise at a trickle
        # and a genuine fault at volume. Corrected hardware errors are the canonical case.
        if ($hit.escalate -and $null -ne $hit.escalate.perDay) {
            if ($sig.PerDay -ge [double]$hit.escalate.perDay) {
                $verdict = $hit.escalate.verdict
                $why = '{0} Escalated: this signature is running at {1}/day, at or above the {2}/day threshold. {3}' -f $why, $sig.PerDay, $hit.escalate.perDay, $hit.escalate.why
            }
        }

        $sig | Add-Member -NotePropertyName 'RuleId'     -NotePropertyValue $hit.id -Force
        $sig | Add-Member -NotePropertyName 'Verdict'    -NotePropertyValue $verdict -Force
        $sig | Add-Member -NotePropertyName 'Title'      -NotePropertyValue $hit.title -Force
        $sig | Add-Member -NotePropertyName 'Plain'      -NotePropertyValue $hit.plain -Force
        $sig | Add-Member -NotePropertyName 'Why'        -NotePropertyValue $why -Force
        $sig | Add-Member -NotePropertyName 'Action'     -NotePropertyValue $hit.action -Force
        # Schema v2 carries a references list; v1 carried a single reference. Accept
        # both so a local database written against the old shape keeps working.
        $refs = @()
        if ($hit.references) { $refs = @($hit.references) }
        elseif ($hit.reference) { $refs = @($hit.reference) }

        $sig | Add-Member -NotePropertyName 'Confidence' -NotePropertyValue $hit.confidence -Force
        $sig | Add-Member -NotePropertyName 'Reference'  -NotePropertyValue (@($refs) | Select-Object -First 1) -Force
        $sig | Add-Member -NotePropertyName 'References' -NotePropertyValue @($refs) -Force
        $sig | Add-Member -NotePropertyName 'Status'     -NotePropertyValue $hit.status -Force
        $sig | Add-Member -NotePropertyName 'Verified'   -NotePropertyValue $hit.verified -Force
        $sig | Add-Member -NotePropertyName 'FalsePositives' -NotePropertyValue @($hit.falsepositives) -Force
        $results.Add($sig) | Out-Null
    }

    # Worst first, then loudest. Sorting on the rank rather than the label keeps
    # "unknown" above "informational" where it belongs.
    $sorted = $results.ToArray() |
        Sort-Object -Property @{ Expression = { Get-LVVerdictRank -Verdict $_.Verdict }; Descending = $true },
                              @{ Expression = { $_.Count }; Descending = $true }

    return ConvertTo-LVArrayOutput -Value @($sorted)
}
