# Ruling layer: match each signature against the verdict database.
# Deliberately deterministic. Everything a reader sees here is either a curated
# human-written explanation or an honest admission that the signature is unrecognized.

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
        $haystack = $Signature.SampleMessage
        if (-not $haystack) { $haystack = '' }
        if ($haystack -notmatch $m.messagePattern) { return $false }
    }

    return $true
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

    $rules = @($Database.rules | Sort-Object -Property @{ Expression = { Get-LVRuleSpecificity -Rule $_ } } -Descending)
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($sig in $Signature) {
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
        $sig | Add-Member -NotePropertyName 'Confidence' -NotePropertyValue $hit.confidence -Force
        $sig | Add-Member -NotePropertyName 'Reference'  -NotePropertyValue $hit.reference -Force
        $results.Add($sig) | Out-Null
    }

    # Worst first, then loudest. Sorting on the rank rather than the label keeps
    # "unknown" above "informational" where it belongs.
    $sorted = $results.ToArray() |
        Sort-Object -Property @{ Expression = { Get-LVVerdictRank -Verdict $_.Verdict }; Descending = $true },
                              @{ Expression = { $_.Count }; Descending = $true }

    return ConvertTo-LVArrayOutput -Value @($sorted)
}
