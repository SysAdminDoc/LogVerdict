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

function Test-LVDatabaseProvenance {
    <#
        A live rule must be checkable by a reader. References and source records are
        the normal path; internal-observation is explicit provenance for a ruling
        derived from repeatable in-repository observation rather than a published
        document.
    #>
    param([Parameter(Mandatory)]$Item)

    if (@($Item.sources | Where-Object { $_ }).Count -gt 0) { return $true }
    if (@($Item.references | Where-Object { $_ }).Count -gt 0) { return $true }
    return ($Item.provenance -eq 'internal-observation')
}

function Get-LVDatabaseTrustProblem {
    <#
        Validate fields that the resolver consumes but JSON Schema cannot express:
        correlation vocabulary, references to live rules, supported fields, unique ids
        and provenance on active rules. This is deliberately separate from fixture
        matching so loading a malformed local database fails before a scan starts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [string]$Path = '(database)',
        [switch]$SkipRuleProvenance
    )

    $problems = New-Object System.Collections.Generic.List[object]
    $ruleById = @{}
    $allIds = @{}

    foreach ($rule in @($Database.rules | Where-Object { $_ })) {
        $id = [string]$rule.id
        if (-not $id) {
            $problems.Add([pscustomobject]@{ RuleId='(missing id)'; Problem='rule has no id' }) | Out-Null
            continue
        }
        if ($allIds.ContainsKey($id)) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem='duplicate id shared by rules or correlations' }) | Out-Null
        }
        $allIds[$id] = $true
        $ruleById[$id] = $rule

        if (-not $SkipRuleProvenance -and (Test-LVRuleActive -Rule $rule)) {
            if ($rule.provenance -and $rule.provenance -ne 'internal-observation') {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("unknown provenance '{0}'; valid: internal-observation" -f $rule.provenance) }) | Out-Null
            } elseif (-not (Test-LVDatabaseProvenance -Item $rule)) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem='active rule requires references[], sources[], or provenance=internal-observation' }) | Out-Null
            }
        }
        if ($rule.match -and $rule.match.eventData) {
            foreach ($problem in @(Get-LVStructuredConditionProblems -Condition $rule.match.eventData)) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem=[string]$problem }) | Out-Null
            }
        }
    }

    foreach ($correlationRule in @($Database.correlations | Where-Object { $_ })) {
        $id = [string]$correlationRule.id
        if (-not $id) {
            $problems.Add([pscustomobject]@{ RuleId='(missing id)'; Problem='correlation has no id' }) | Out-Null
            continue
        }
        if ($allIds.ContainsKey($id)) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem='duplicate id shared by rules or correlations' }) | Out-Null
        }
        $allIds[$id] = $true

        if (Test-LVRuleActive -Rule $correlationRule) {
            if ($correlationRule.provenance -and $correlationRule.provenance -ne 'internal-observation') {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("unknown provenance '{0}'; valid: internal-observation" -f $correlationRule.provenance) }) | Out-Null
            } elseif (-not (Test-LVDatabaseProvenance -Item $correlationRule)) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem='active correlation requires references[], sources[], or provenance=internal-observation' }) | Out-Null
            }
        }

        $correlation = $correlationRule.correlation
        if ($null -eq $correlation) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem='correlation has no correlation block' }) | Out-Null
            continue
        }

        foreach ($property in @($correlation.PSObject.Properties.Name)) {
            if (@('type', 'rules', 'timespan', 'group-by') -notcontains $property) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("unsupported correlation field '{0}' would be ignored" -f $property) }) | Out-Null
            }
        }

        $type = [string]$correlation.type
        if ($script:LVCorrelationType -notcontains $type) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("unknown correlation type '{0}'; valid: {1}" -f $type, ($script:LVCorrelationType -join ', ')) }) | Out-Null
        }
        if ($type -eq 'event_count') {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem="correlation type 'event_count' is not implemented and cannot be loaded" }) | Out-Null
        }

        $rawRules = $correlation.PSObject.Properties['rules']
        if ($null -eq $rawRules -or $null -eq $rawRules.Value -or $rawRules.Value -is [string]) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem='correlation.rules must be an array of rule ids' }) | Out-Null
            $refs = @()
        } else {
            $refs = @($rawRules.Value | Where-Object { $_ })
        }
        if ($type -ne 'event_count' -and $refs.Count -lt 2) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("{0} correlation requires at least two rule ids" -f $type) }) | Out-Null
        }
        if (@($refs | Select-Object -Unique).Count -ne $refs.Count) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem='correlation.rules contains duplicate rule ids' }) | Out-Null
        }
        foreach ($ref in $refs) {
            $refId = [string]$ref
            if (-not $ruleById.ContainsKey($refId)) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("correlation references missing rule '{0}'" -f $refId) }) | Out-Null
            } elseif (-not (Test-LVRuleActive -Rule $ruleById[$refId])) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("correlation references inactive rule '{0}'" -f $refId) }) | Out-Null
            }
        }

        if ($correlation.PSObject.Properties['group-by']) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem="correlation field 'group-by' is not implemented and cannot be loaded" }) | Out-Null
        }
        $span = ConvertFrom-LVTimespan -Text ([string]$correlation.timespan)
        if ($null -eq $span) {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem=("correlation timespan '{0}' is unreadable" -f $correlation.timespan) }) | Out-Null
        }
    }

    return @($problems.ToArray())
}

function Assert-LVDatabaseTrust {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Database, [string]$Path = '(database)')

    $problems = @(Get-LVDatabaseTrustProblem -Database $Database -Path $Path)
    if ($problems.Count -gt 0) {
        $detail = ($problems | ForEach-Object { '{0}: {1}' -f $_.RuleId, $_.Problem }) -join '; '
        throw ("Verdict database '{0}' failed trust validation: {1}" -f $Path, $detail)
    }
}

function Test-LVRuleActive {
    <#
        .SYNOPSIS
        Whether a rule is eligible to produce a verdict.

        .DESCRIPTION
        Deprecated, unsupported, and model-generated draft rules stay in the database
        so their ids remain resolvable and their history is not lost, but they must
        never rule on a signature. A rule with no status predates the status field and
        is treated as active, which keeps schema v1 databases working.
    #>
    param([Parameter(Mandatory)]$Rule)

    if ($Rule.confidence -eq 'draft') { return $false }
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
    if ($m.resultCode)               { $score += 8 }
    if ($m.extendCode)               { $score += 4 }
    if ($m.phase)                    { $score += 2 }
    if ($m.operation)                { $score += 2 }
    if ($m.providerLocale)            { $score += 1 }
    if ($m.eventData)                 { $score += 10 }
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

    # Extension records are evidence, not a way for a provider to inherit or
    # accidentally trigger a curated Windows rule. An explicitly reviewed rule
    # can be added later through the normal database path, but an extension never
    # gets a verdict merely because it happens to share an event ID or source.
    if ($Signature.PSObject.Properties['ProviderExtension'] -and $Signature.ProviderExtension) { return $false }

    $m = $Rule.match

    if ($m.source   -and $m.source  -ne $Signature.Source)  { return $false }
    if ($m.channel  -and $m.channel -ne $Signature.Channel) { return $false }
    if ($m.provider -and $m.provider -ne $Signature.Provider) {
        # Allow a trailing wildcard so a provider family can be covered in one rule.
        if (-not ($m.provider.EndsWith('*') -and $Signature.Provider -like $m.provider)) { return $false }
    }
    if ($null -ne $m.eventId -and [int]$m.eventId -ne [int]$Signature.Id) { return $false }

    if ($m.resultCode) {
        $actual = ConvertTo-LVErrorHex -Value ([string](Get-LVErrorContextField -InputObject $Signature -Name 'ResultCode'))
        $expected = ConvertTo-LVErrorHex -Value ([string]$m.resultCode)
        if (-not $actual -or -not $expected -or $actual -ne $expected) { return $false }
    }
    if ($m.extendCode) {
        $actual = ConvertTo-LVErrorHex -Value ([string](Get-LVErrorContextField -InputObject $Signature -Name 'ExtendCode'))
        $expected = ConvertTo-LVErrorHex -Value ([string]$m.extendCode)
        if (-not $actual -or -not $expected -or $actual -ne $expected) { return $false }
    }
    if ($m.phase) {
        $actual = [string](Get-LVErrorContextField -InputObject $Signature -Name 'Phase')
        if (-not $actual -or $actual -ine [string]$m.phase) { return $false }
    }
    if ($m.operation) {
        $actual = [string](Get-LVErrorContextField -InputObject $Signature -Name 'Operation')
        if (-not $actual -or $actual -ine [string]$m.operation) { return $false }
    }
    if ($m.providerLocale) {
        $actual = [string](Get-LVErrorContextField -InputObject $Signature -Name 'ProviderLocale')
        if (-not $actual -or (($actual -split '-')[0] -ine (([string]$m.providerLocale) -split '-')[0])) { return $false }
    }

    if ($m.eventData) {
        if ($Signature.Source -notin @('event', 'reliability')) { return $false }
        if (-not (Test-LVStructuredCondition -Condition $m.eventData -Signature $Signature)) { return $false }
    }

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
    # Absent source means events, which is the localized case. Reliability Monitor
    # renders its Message from the same provider resources, so it is localized too.
    $source = $Rule.match.source
    return (-not $source -or $source -eq 'event' -or $source -eq 'reliability')
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

    # Specificity first, then load order. The second key is what makes local rules
    # beat shipped ones at equal specificity - PowerShell 5.1's Sort-Object is not
    # stable, so without an explicit tie-break the winner is arbitrary.
    $rules = @($Database.rules |
        Where-Object { Test-LVRuleActive -Rule $_ } |
        Sort-Object -Property `
            @{ Expression = { Get-LVRuleSpecificity -Rule $_ }; Descending = $true }, `
            @{ Expression = { [int]$_.lvOrdinal }; Descending = $false })
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
            $sig | Add-Member -NotePropertyName 'Action'     -NotePropertyValue 'Read the sample message. If you identify it, add a reviewed rule to Data/verdicts.local.json so the next scan explains it.' -Force
            $sig | Add-Member -NotePropertyName 'Confidence' -NotePropertyValue 'none' -Force
            $sig | Add-Member -NotePropertyName 'Reference'  -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'References' -NotePropertyValue @() -Force
            $sig | Add-Member -NotePropertyName 'Sources'    -NotePropertyValue @() -Force
            $sig | Add-Member -NotePropertyName 'Status'     -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'Verified'   -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'FalsePositives' -NotePropertyValue @() -Force
            $catalogMatch = Get-LVErrorCatalogMatch -Signature $sig
            Add-LVErrorCatalogContext -Signature $sig -Match $catalogMatch
            if ($catalogMatch -and $catalogMatch.Entry) {
                $entry = $catalogMatch.Entry
                $sig.Title = ('Microsoft catalog: {0} ({1})' -f $entry.name, $catalogMatch.RawCode)
                $sig.Plain = '{0} {1}' -f $entry.description, $entry.explanation
                $sig.Why = 'The code has an official Microsoft reference, but a code-level description is not the same as a root-cause diagnosis. Provider and operation context still decide what happened.'
                if ($entry.kind -eq 'bugcheck') {
                    $sig.Action = 'Preserve the dump and inspect its parameters with WinDbg; do not assign a responsible driver from the stop code alone.'
                } else {
                    $sig.Action = 'Read the provider and operation around this code, then follow the Microsoft reference before choosing a remediation.'
                }
                $sig.Reference = $entry.reference
                $sig.References = @($entry.reference)
            }
            Add-LVUnknownBurstContext -Signature $sig
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
        # Provenance travels with the finding, not just with the rule: attribution that
        # only exists in the database is attribution the reader never sees, and CC-BY
        # and DRL both require it be visible wherever the ruling is.
        $sig | Add-Member -NotePropertyName 'Sources'    -NotePropertyValue @($hit.sources) -Force
        $sig | Add-Member -NotePropertyName 'Status'     -NotePropertyValue $hit.status -Force
        $sig | Add-Member -NotePropertyName 'Verified'   -NotePropertyValue $hit.verified -Force
        $sig | Add-Member -NotePropertyName 'FalsePositives' -NotePropertyValue @($hit.falsepositives) -Force
        Add-LVErrorCatalogContext -Signature $sig -Match (Get-LVErrorCatalogMatch -Signature $sig)
        Add-LVUnknownBurstContext -Signature $sig
        $results.Add($sig) | Out-Null
    }

    # Worst first, then loudest. Sorting on the rank rather than the label keeps
    # "unknown" above "informational" where it belongs.
    $sorted = $results.ToArray() |
        Sort-Object -Property @{ Expression = { Get-LVVerdictRank -Verdict $_.Verdict }; Descending = $true },
                              @{ Expression = { $_.Count }; Descending = $true }

    return ConvertTo-LVArrayOutput -Value @($sorted)
}
