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

function Get-LVDatabaseFreshnessPolicy {
    [CmdletBinding()]
    param([AllowNull()]$Database)

    $maxAgeDays = $script:LVDefaultStaleAfterDays
    $dateBasis = 'UTC'
    if ($Database -and $Database.PSObject.Properties['freshness'] -and $Database.freshness) {
        if ($Database.freshness.PSObject.Properties['maxAgeDays'] -and
            [int]::TryParse([string]$Database.freshness.maxAgeDays, [ref]$maxAgeDays)) {
            if ($maxAgeDays -lt 1) { $maxAgeDays = $script:LVDefaultStaleAfterDays }
        } else {
            $maxAgeDays = $script:LVDefaultStaleAfterDays
        }
        if ($Database.freshness.PSObject.Properties['dateBasis'] -and $Database.freshness.dateBasis) {
            $dateBasis = [string]$Database.freshness.dateBasis
        }
    }

    return [pscustomobject][ordered]@{
        MaxAgeDays = [int]$maxAgeDays
        DateBasis  = $dateBasis
    }
}

function Get-LVRuleFreshness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)]$Policy,
        [datetime]$AsOf = ([datetime]::UtcNow.Date)
    )

    $verified = [string]$Rule.verified
    $verifiedOn = [datetime]::MinValue
    $parsed = [datetime]::TryParseExact(
        $verified, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$verifiedOn)
    $staleAfterDays = [int]$Policy.MaxAgeDays
    if ($Rule.PSObject.Properties['staleAfterDays'] -and $Rule.staleAfterDays) {
        $candidateDays = 0
        if ([int]::TryParse([string]$Rule.staleAfterDays, [ref]$candidateDays) -and $candidateDays -gt 0) {
            $staleAfterDays = $candidateDays
        }
    }
    $staleOn = $null
    $isStale = $false
    if ($parsed) {
        $staleOn = $verifiedOn.Date.AddDays($staleAfterDays)
        $isStale = $staleOn -lt $AsOf.Date
    }

    return [pscustomobject][ordered]@{
        RuleId        = [string]$Rule.id
        Status        = [string]$Rule.status
        Verified      = if ($verified) { $verified } else { $null }
        VerifiedOn    = if ($parsed) { $verifiedOn.Date } else { $null }
        StaleAfterDays = $staleAfterDays
        StaleOn       = $staleOn
        IsStale       = [bool]$isStale
        DateBasis     = [string]$Policy.DateBasis
        Parseable     = [bool]$parsed
    }
}

function Get-LVDatabaseFreshnessSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [datetime]$AsOf = ([datetime]::UtcNow.Date)
    )

    $policy = Get-LVDatabaseFreshnessPolicy -Database $Database
    $stale = New-Object System.Collections.Generic.List[object]
    foreach ($rule in @($Database.rules | Where-Object { $_ -and (Test-LVRuleActive -Rule $_) })) {
        $freshness = Get-LVRuleFreshness -Rule $rule -Policy $policy -AsOf $AsOf
        if (-not $freshness.IsStale) { continue }
        $stale.Add([pscustomobject][ordered]@{
            RuleId         = $freshness.RuleId
            Status         = $freshness.Status
            Verified       = $freshness.Verified
            StaleAfterDays = $freshness.StaleAfterDays
            StaleOn        = $freshness.StaleOn
            WindowsBuild   = if ($rule.PSObject.Properties['windowsBuild']) { $rule.windowsBuild } else { $null }
        }) | Out-Null
    }

    return [pscustomobject][ordered]@{
        DateBasis          = $policy.DateBasis
        DefaultStaleAfterDays = $policy.MaxAgeDays
        AsOf               = $AsOf.Date
        StaleRuleCount     = $stale.Count
        StaleRules         = @($stale.ToArray() | Sort-Object RuleId)
    }
}

function Get-LVCurrentWindowsBuild {
    [CmdletBinding()]
    param()

    try {
        $build = [int][Environment]::OSVersion.Version.Build
        if ($build -gt 0) { return $build }
    } catch { Write-Verbose 'Windows build could not be determined from the runtime.' }
    return $null
}

function Test-LVWindowsBuildMatch {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Rule)

    if (-not $Rule.PSObject.Properties['windowsBuild'] -or -not $Rule.windowsBuild) { return $true }
    $current = Get-LVCurrentWindowsBuild
    if ($null -eq $current) { return $false }
    $range = $Rule.windowsBuild
    if ($range.PSObject.Properties['min'] -and $current -lt [int]$range.min) { return $false }
    if ($range.PSObject.Properties['max'] -and $current -gt [int]$range.max) { return $false }
    return $true
}

function Get-LVSignatureInstalledKbs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'KB is an identifier acronym; this helper returns the installed KB set.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Signature)

    $values = New-Object System.Collections.Generic.List[object]
    foreach ($propertyName in @('InstalledKbs', 'InstalledKBs', 'HotFixIds', 'HotFixes')) {
        if (-not $Signature.PSObject.Properties[$propertyName]) { continue }
        foreach ($value in @($Signature.$propertyName)) {
            if ($null -eq $value) { continue }
            if ($value -is [string]) {
                $values.Add($value) | Out-Null
                continue
            }
            foreach ($field in @('HotFixID', 'HotFixId', 'KB', 'Kb', 'Id')) {
                if ($value.PSObject.Properties[$field] -and $value.$field) {
                    $values.Add([string]$value.$field) | Out-Null
                    break
                }
            }
        }
    }

    return @($values.ToArray() |
        ForEach-Object { [string]$_ -replace '^\s+', '' -replace '\s+$', '' } |
        Where-Object { $_ -match '^KB\d{5,}$' } |
        ForEach-Object { $_.ToUpperInvariant() } |
        Select-Object -Unique)
}

function Get-LVInstalledKbInventory {
    [CmdletBinding()]
    param()

    $raw = @()
    $queried = $false
    if (Get-Command -Name Get-HotFix -ErrorAction SilentlyContinue) {
        try {
            $raw = @(Get-HotFix -ErrorAction Stop)
            $queried = $true
        } catch {
            $raw = @()
        }
    }
    if (-not $queried -and (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        try {
            $raw = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop)
            $queried = $true
        } catch {
            $raw = @()
        }
    }
    if (-not $queried) {
        # Patch inventory is advisory context. A provider failure must not turn a
        # scan into a guessed expiry decision; an empty inventory leaves the rule
        # eligible and the finding explicit.
        return @()
    }

    return @(Get-LVSignatureInstalledKbs -Signature ([pscustomobject]@{ HotFixes = $raw }))
}

function Test-LVRuleKbExpiry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)]$Signature
    )

    if (-not $Rule.PSObject.Properties['expiresWithKb'] -or -not $Rule.expiresWithKb) { return $true }
    $installed = @(Get-LVSignatureInstalledKbs -Signature $Signature)
    # Missing patch inventory is not evidence that the KB is installed. Keep the
    # ruling eligible and let the report remain honest about the evidence it has.
    if ($installed.Count -eq 0) { return $true }
    $expiryKb = ([string]$Rule.expiresWithKb).ToUpperInvariant()
    return ($installed -notcontains $expiryKb)
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

function Get-LVDatabaseUriProblem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Item,
        [Parameter(Mandatory)][string]$RuleId
    )

    foreach ($reference in @($Item.references)) {
        if ($null -eq $reference) { continue }
        $problem = Get-LVAllowedUriProblem -Uri ([string]$reference)
        if ($problem) {
            [pscustomobject]@{
                RuleId = $RuleId
                Problem = ("references[]: {0}" -f $problem)
            }
        }
    }
    foreach ($source in @($Item.sources)) {
        if ($null -eq $source -or -not $source.uri) { continue }
        $problem = Get-LVAllowedUriProblem -Uri ([string]$source.uri)
        if ($problem) {
            [pscustomobject]@{
                RuleId = $RuleId
                Problem = ("sources[].uri: {0}" -f $problem)
            }
        }
    }
}

function Get-LVCompiledRegex {
    <#
        Compile one rule pattern for the lifetime of the module. A timeout is part
        of the Regex object, so matching cannot inherit the unbounded default used by
        PowerShell's -match operator.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Pattern)

    if (-not $script:LVCompiledRegexCache) { $script:LVCompiledRegexCache = @{} }
    if ($script:LVCompiledRegexCache.ContainsKey($Pattern)) {
        return $script:LVCompiledRegexCache[$Pattern]
    }
    $timeout = $script:LVRuleRegexMatchTimeout
    $compiled = [regex]::new($Pattern,
        [Text.RegularExpressions.RegexOptions]::IgnoreCase,
        $timeout)
    $script:LVCompiledRegexCache[$Pattern] = $compiled
    return $compiled
}

function Get-LVRegexPatternProblem {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Pattern,
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $null }
    try {
        [void](Get-LVCompiledRegex -Pattern $Pattern)
    } catch {
        return [pscustomobject]@{
            RuleId = $RuleId
            Problem = ("{0} is not a valid regex: {1}" -f $Path, $_.Exception.Message)
        }
    }
    return $null
}

function Get-LVStructuredRegexProblems {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The function returns every regex validation problem in a condition tree.')]
    param(
        [AllowNull()]$Condition,
        [Parameter(Mandatory)][string]$RuleId,
        [string]$Path = 'eventData',
        [int]$Depth = 0
    )

    $problems = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Condition -or $Depth -gt 16) { return @($problems.ToArray()) }
    if ($Condition.PSObject.Properties['field']) {
        if ($Condition.PSObject.Properties['regex']) {
            $problem = Get-LVRegexPatternProblem -Pattern ([string]$Condition.regex) -RuleId $RuleId -Path ("{0}.regex" -f $Path)
            if ($problem) { $problems.Add($problem) | Out-Null }
        }
        return @($problems.ToArray())
    }
    foreach ($operator in @('all', 'any')) {
        if (-not $Condition.PSObject.Properties[$operator]) { continue }
        $children = @($Condition.$operator)
        for ($i = 0; $i -lt $children.Count; $i++) {
            foreach ($problem in @(Get-LVStructuredRegexProblems -Condition $children[$i] -RuleId $RuleId -Path ("{0}.{1}[{2}]" -f $Path, $operator, $i) -Depth ($Depth + 1))) {
                $problems.Add($problem) | Out-Null
            }
        }
    }
    if ($Condition.PSObject.Properties['not']) {
        foreach ($problem in @(Get-LVStructuredRegexProblems -Condition $Condition.not -RuleId $RuleId -Path ("{0}.not" -f $Path) -Depth ($Depth + 1))) {
            $problems.Add($problem) | Out-Null
        }
    }
    return @($problems.ToArray())
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

    if ($Database.PSObject.Properties['freshness']) {
        if (-not $Database.freshness -or -not $Database.freshness.PSObject.Properties['maxAgeDays']) {
            $problems.Add([pscustomobject]@{ RuleId='(database)'; Problem='freshness.maxAgeDays is required when a freshness policy is declared' }) | Out-Null
        } else {
            $maxAgeDays = 0
            if (-not [int]::TryParse([string]$Database.freshness.maxAgeDays, [ref]$maxAgeDays) -or $maxAgeDays -lt 1) {
                $problems.Add([pscustomobject]@{ RuleId='(database)'; Problem='freshness.maxAgeDays must be a positive integer' }) | Out-Null
            }
        }
        if (-not $Database.freshness.PSObject.Properties['dateBasis'] -or [string]$Database.freshness.dateBasis -ne 'UTC') {
            $problems.Add([pscustomobject]@{ RuleId='(database)'; Problem='freshness.dateBasis must be UTC' }) | Out-Null
        }
    }

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

        if ($rule.PSObject.Properties['staleAfterDays']) {
            $staleAfterDays = 0
            if (-not [int]::TryParse([string]$rule.staleAfterDays, [ref]$staleAfterDays) -or $staleAfterDays -lt 1) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem='staleAfterDays must be a positive integer' }) | Out-Null
            }
        }
        if (-not $rule.PSObject.Properties['modified'] -or [string]::IsNullOrWhiteSpace([string]$rule.modified)) {
            if ([int]$Database.schemaVersion -ge 7) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem='schemaVersion 7 rules require modified date' }) | Out-Null
            }
        } else {
            $modifiedOn = [datetime]::MinValue
            $modifiedParsed = [datetime]::TryParseExact(
                [string]$rule.modified, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$modifiedOn)
            if (-not $modifiedParsed) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem='modified must be an ISO date (yyyy-MM-dd)' }) | Out-Null
            }
        }
        if ($rule.PSObject.Properties['expiresWithKb'] -and
            [string]$rule.expiresWithKb -notmatch '^KB\d{5,}$') {
            $problems.Add([pscustomobject]@{ RuleId=$id; Problem='expiresWithKb must be a KB identifier such as KB5062660' }) | Out-Null
        }
        if ($rule.PSObject.Properties['windowsBuild']) {
            if (-not $rule.windowsBuild) {
                $problems.Add([pscustomobject]@{ RuleId=$id; Problem='windowsBuild must declare min or max' }) | Out-Null
            } else {
                $minBuild = $null
                $maxBuild = $null
                if ($rule.windowsBuild.PSObject.Properties['min']) {
                    $value = 0
                    if (-not [int]::TryParse([string]$rule.windowsBuild.min, [ref]$value) -or $value -lt 1) {
                        $problems.Add([pscustomobject]@{ RuleId=$id; Problem='windowsBuild.min must be a positive integer' }) | Out-Null
                    } else { $minBuild = $value }
                }
                if ($rule.windowsBuild.PSObject.Properties['max']) {
                    $value = 0
                    if (-not [int]::TryParse([string]$rule.windowsBuild.max, [ref]$value) -or $value -lt 1) {
                        $problems.Add([pscustomobject]@{ RuleId=$id; Problem='windowsBuild.max must be a positive integer' }) | Out-Null
                    } else { $maxBuild = $value }
                }
                if ($null -eq $minBuild -and $null -eq $maxBuild) {
                    $problems.Add([pscustomobject]@{ RuleId=$id; Problem='windowsBuild must declare min or max' }) | Out-Null
                } elseif ($null -ne $minBuild -and $null -ne $maxBuild -and $minBuild -gt $maxBuild) {
                    $problems.Add([pscustomobject]@{ RuleId=$id; Problem='windowsBuild.min cannot exceed windowsBuild.max' }) | Out-Null
                }
            }
        }

        foreach ($uriProblem in @(Get-LVDatabaseUriProblem -Item $rule -RuleId $id)) {
            $problems.Add($uriProblem) | Out-Null
        }

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
        if ($rule.match -and $rule.match.messagePattern) {
            $problem = Get-LVRegexPatternProblem -Pattern ([string]$rule.match.messagePattern) -RuleId $id -Path 'messagePattern'
            if ($problem) { $problems.Add($problem) | Out-Null }
        }
        if ($rule.match -and $rule.match.eventData) {
            foreach ($problem in @(Get-LVStructuredRegexProblems -Condition $rule.match.eventData -RuleId $id)) {
                $problems.Add($problem) | Out-Null
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

        foreach ($uriProblem in @(Get-LVDatabaseUriProblem -Item $correlationRule -RuleId $id)) {
            $problems.Add($uriProblem) | Out-Null
        }

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

    foreach ($rule in @($Database.rules | Where-Object { $_ })) {
        foreach ($related in @($rule.related | Where-Object { $_ })) {
            $targetId = [string]$related.id
            if (-not $targetId) {
                $problems.Add([pscustomobject]@{ RuleId=[string]$rule.id; Problem='related entry requires a target id' }) | Out-Null
            } elseif (-not $allIds.ContainsKey($targetId)) {
                $problems.Add([pscustomobject]@{ RuleId=[string]$rule.id; Problem=("related target '{0}' is not a rule or correlation" -f $targetId) }) | Out-Null
            } elseif ($targetId -eq [string]$rule.id) {
                $problems.Add([pscustomobject]@{ RuleId=[string]$rule.id; Problem='related entry cannot point to itself' }) | Out-Null
            }
            if (-not $related.PSObject.Properties['type'] -or [string]::IsNullOrWhiteSpace([string]$related.type)) {
                $problems.Add([pscustomobject]@{ RuleId=[string]$rule.id; Problem='related entry requires a type' }) | Out-Null
            } elseif (@('derived', 'obsolete', 'merged', 'renamed', 'similar') -notcontains [string]$related.type) {
                $problems.Add([pscustomobject]@{ RuleId=[string]$rule.id; Problem=("related type '{0}' is not supported" -f $related.type) }) | Out-Null
            }
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
        [Parameter(Mandatory)]$Signature,
        [AllowNull()][ref]$RegexFailure
    )

    # Extension records are evidence, not a way for a provider to inherit or
    # accidentally trigger a curated Windows rule. An explicitly reviewed rule
    # can be added later through the normal database path, but an extension never
    # gets a verdict merely because it happens to share an event ID or source.
    if ($Signature.PSObject.Properties['ProviderExtension'] -and $Signature.ProviderExtension) { return $false }

    if (-not (Test-LVRuleKbExpiry -Rule $Rule -Signature $Signature)) { return $false }

    if (-not (Test-LVWindowsBuildMatch -Rule $Rule)) { return $false }

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
        $conditionArgs = @{ Condition = $m.eventData; Signature = $Signature; RuleId = [string]$Rule.id }
        if ($RegexFailure) { $conditionArgs.RegexFailure = $RegexFailure }
        if (-not (Test-LVStructuredCondition @conditionArgs)) { return $false }
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
        try {
            $regex = Get-LVCompiledRegex -Pattern ([string]$m.messagePattern)
            if (-not $regex.IsMatch([string]$haystack)) { return $false }
        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
            if ($RegexFailure) { $RegexFailure.Value = [string]$Rule.id }
            Write-LVLog -Level warn -Message ("Rule '{0}' regex timed out; signature will remain unknown." -f $Rule.id)
            return $false
        } catch {
            Write-LVLog -Level warn -Message ("Rule '{0}' regex could not be evaluated; signature will remain unknown." -f $Rule.id)
            return $false
        }
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
        $regexFailure = $null
        foreach ($rule in $rules) {
            if (Test-LVRuleMatch -Rule $rule -Signature $sig -RegexFailure ([ref]$regexFailure)) { $hit = $rule; break }
            if ($regexFailure) { break }
        }

        if ($null -eq $hit) {
            $sig | Add-Member -NotePropertyName 'RuleId'     -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'Verdict'    -NotePropertyValue 'unknown' -Force
            $sig | Add-Member -NotePropertyName 'Title'      -NotePropertyValue ('Unrecognized: {0}' -f $sig.Key) -Force
            $sig | Add-Member -NotePropertyName 'Plain'      -NotePropertyValue $(if ($regexFailure) { 'A verdict rule could not be evaluated within its safety timeout, so LogVerdict refused to guess. The raw message below is the evidence, unedited.' } else { 'No rule in the verdict database covers this signature, so LogVerdict will not guess at what it means. The raw message below is the evidence, unedited.' }) -Force
            $sig | Add-Member -NotePropertyName 'Why'        -NotePropertyValue $(if ($regexFailure) { "Rule '$regexFailure' exceeded the regex match timeout; the signature remains unknown until the rule is corrected." } else { 'Reported so that an unknown problem is visible rather than silently dropped.' }) -Force
            $sig | Add-Member -NotePropertyName 'Action'     -NotePropertyValue 'Read the sample message. If you identify it, add a reviewed rule to Data/verdicts.local.json so the next scan explains it.' -Force
            $sig | Add-Member -NotePropertyName 'Confidence' -NotePropertyValue 'none' -Force
            $sig | Add-Member -NotePropertyName 'Reference'  -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'References' -NotePropertyValue @() -Force
            $sig | Add-Member -NotePropertyName 'Sources'    -NotePropertyValue @() -Force
            $sig | Add-Member -NotePropertyName 'Status'     -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'Verified'   -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'RuleStale'  -NotePropertyValue $false -Force
            $sig | Add-Member -NotePropertyName 'RuleFreshness' -NotePropertyValue $null -Force
            $sig | Add-Member -NotePropertyName 'FalsePositives' -NotePropertyValue @() -Force
            $sig | Add-Member -NotePropertyName 'RegexMatchTimeout' -NotePropertyValue ([bool]$regexFailure) -Force
            $sig | Add-Member -NotePropertyName 'RegexRuleId' -NotePropertyValue $regexFailure -Force
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
                $sig.References = @($entry.reference | Where-Object { $_ })
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
        if ($hit.references) { $refs = @($hit.references | Where-Object { $_ }) }
        elseif ($hit.reference) { $refs = @($hit.reference) }

        $sig | Add-Member -NotePropertyName 'Confidence' -NotePropertyValue $hit.confidence -Force
        $sig | Add-Member -NotePropertyName 'Reference'  -NotePropertyValue (@($refs) | Select-Object -First 1) -Force
        $sig | Add-Member -NotePropertyName 'References' -NotePropertyValue @($refs) -Force
        # Provenance travels with the finding, not just with the rule: attribution that
        # only exists in the database is attribution the reader never sees, and CC-BY
        # and DRL both require it be visible wherever the ruling is.
        $sig | Add-Member -NotePropertyName 'Sources'    -NotePropertyValue @($hit.sources | Where-Object { $_ }) -Force
        $sig | Add-Member -NotePropertyName 'Status'     -NotePropertyValue $hit.status -Force
        $sig | Add-Member -NotePropertyName 'Verified'   -NotePropertyValue $hit.verified -Force
        $freshness = Get-LVRuleFreshness -Rule $hit -Policy (Get-LVDatabaseFreshnessPolicy -Database $Database)
        $sig | Add-Member -NotePropertyName 'RuleStale' -NotePropertyValue ([bool]$freshness.IsStale) -Force
        $sig | Add-Member -NotePropertyName 'RuleFreshness' -NotePropertyValue $freshness -Force
        $sig | Add-Member -NotePropertyName 'FalsePositives' -NotePropertyValue @($hit.falsepositives | Where-Object { $_ }) -Force
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

function Test-LVConfidenceIncluded {
    <#
        .SYNOPSIS
        Whether a resolved finding belongs in the default result set.

        .DESCRIPTION
        Confidence is deliberately an inclusion boundary, not decoration. Unknown
        findings have confidence 'none' and remain visible; only curated low-confidence
        rulings are hidden unless the caller explicitly opts in.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Finding,
        [switch]$IncludeLowConfidence
    )

    if ($IncludeLowConfidence) { return $true }
    if (-not $Finding.PSObject.Properties['Confidence']) { return $true }
    return ([string]$Finding.Confidence -ine 'low')
}

function Get-LVIncidentCodeSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding)

    $resultCodes = New-Object 'System.Collections.Generic.List[string]'
    $extendCodes = New-Object 'System.Collections.Generic.List[string]'
    $errorCodes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($propertyName in @('ResultCodes', 'ResultCode')) {
        if (-not $Finding.PSObject.Properties[$propertyName]) { continue }
        foreach ($value in @($Finding.$propertyName)) {
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $resultCodes.Add([string]$value) | Out-Null
            }
        }
    }
    foreach ($propertyName in @('ExtendCodes', 'ExtendCode')) {
        if (-not $Finding.PSObject.Properties[$propertyName]) { continue }
        foreach ($value in @($Finding.$propertyName)) {
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $extendCodes.Add([string]$value) | Out-Null
            }
        }
    }
    foreach ($propertyName in @('ErrorCodes', 'ErrorCode')) {
        if (-not $Finding.PSObject.Properties[$propertyName]) { continue }
        foreach ($value in @($Finding.$propertyName)) {
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $errorCodes.Add([string]$value) | Out-Null
            }
        }
    }

    $result = @($resultCodes.ToArray() | Sort-Object -Unique)
    $extend = @($extendCodes.ToArray() | Sort-Object -Unique)
    $errors = @($errorCodes.ToArray() | Sort-Object -Unique)
    return [pscustomobject][ordered]@{
        ResultCodes = $result
        ExtendCodes = $extend
        ErrorCodes  = $errors
        DistinctCodes = @($result + $extend + $errors | Sort-Object -Unique)
    }
}

function Get-LVIncidentConfidenceRank {
    param([AllowNull()][string]$Confidence)

    switch ($Confidence.ToLowerInvariant()) {
        'high'   { return 3 }
        'medium' { return 2 }
        'low'    { return 1 }
        default  { return 0 }
    }
}

function Get-LVIncidentReduction {
    <#
        .SYNOPSIS
        Collapse resolved signatures into rule-level incidents.

        .DESCRIPTION
        A rule is the stable unit of explanation. A single rule can match several
        provider/error-code signatures, so presenting those signatures as separate
        findings makes one incident look like many problems. The original signature
        findings remain available to correlations and compatibility consumers; this
        projection is what reports and the GUI use for the reader-facing result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $groups = [ordered]@{}
    foreach ($findingItem in @($Finding | Where-Object { $_ })) {
        $ruleText = ''
        if ($findingItem.PSObject.Properties['RuleId'] -and $null -ne $findingItem.RuleId) {
            $ruleText = [string]$findingItem.RuleId
        }
        $keyText = if ($ruleText) { 'rule:' + $ruleText } else { 'signature:' + [string]$findingItem.Key }
        if (-not $groups.Contains($keyText)) {
            $groups[$keyText] = New-Object 'System.Collections.Generic.List[object]'
        }
        $groups[$keyText].Add($findingItem) | Out-Null
    }

    $incidents = New-Object System.Collections.Generic.List[object]
    foreach ($groupKey in $groups.Keys) {
        $members = @($groups[$groupKey].ToArray())
        $representative = @($members | Sort-Object -Property `
            @{ Expression = { Get-LVVerdictRank -Verdict $_.Verdict }; Descending = $true }, `
            @{ Expression = { [int64]$_.Count }; Descending = $true }, `
            @{ Expression = { [string]$_.Key }; Descending = $false } | Select-Object -First 1)[0]

        $ruleId = $null
        if ($groupKey.StartsWith('rule:', [StringComparison]::OrdinalIgnoreCase)) {
            $ruleId = $groupKey.Substring(5)
        }
        $incidentId = if ($ruleId) { 'Incident/' + $ruleId } else { 'Incident/' + [string]$representative.Key }

        [int64]$combinedCount = 0
        [double]$combinedPerDay = 0
        $firstSeenValues = New-Object System.Collections.Generic.List[datetime]
        $lastSeenValues = New-Object System.Collections.Generic.List[datetime]
        $times = New-Object 'System.Collections.Generic.List[datetime]'
        $signatureKeys = New-Object 'System.Collections.Generic.List[string]'
        $signatureSummaries = New-Object System.Collections.Generic.List[object]
        $resultCodes = New-Object 'System.Collections.Generic.List[string]'
        $extendCodes = New-Object 'System.Collections.Generic.List[string]'
        $errorCodes = New-Object 'System.Collections.Generic.List[string]'
        $confidenceRank = 3

        foreach ($member in $members) {
            if ($member.PSObject.Properties['Count'] -and $null -ne $member.Count) { $combinedCount += [int64]$member.Count }
            if ($member.PSObject.Properties['PerDay'] -and $null -ne $member.PerDay) { $combinedPerDay += [double]$member.PerDay }
            if ($member.PSObject.Properties['FirstSeen'] -and $member.FirstSeen) { $firstSeenValues.Add([datetime]$member.FirstSeen) | Out-Null }
            if ($member.PSObject.Properties['LastSeen'] -and $member.LastSeen) { $lastSeenValues.Add([datetime]$member.LastSeen) | Out-Null }
            if ($member.PSObject.Properties['Times']) {
                foreach ($time in @($member.Times | Where-Object { $_ })) { $times.Add([datetime]$time) | Out-Null }
            }
            if ($member.Key) { $signatureKeys.Add([string]$member.Key) | Out-Null }

            $codeSet = Get-LVIncidentCodeSet -Finding $member
            foreach ($code in @($codeSet.ResultCodes)) { $resultCodes.Add($code) | Out-Null }
            foreach ($code in @($codeSet.ExtendCodes)) { $extendCodes.Add($code) | Out-Null }
            foreach ($code in @($codeSet.ErrorCodes)) { $errorCodes.Add($code) | Out-Null }

            $memberConfidence = if ($member.PSObject.Properties['Confidence']) { [string]$member.Confidence } else { 'none' }
            $confidenceRank = [Math]::Min($confidenceRank, (Get-LVIncidentConfidenceRank -Confidence $memberConfidence))
            $summary = [pscustomobject][ordered]@{
                Key           = [string]$member.Key
                Source        = [string]$member.Source
                Channel       = [string]$member.Channel
                Provider      = [string]$member.Provider
                Id            = $member.Id
                Count         = if ($member.PSObject.Properties['Count']) { $member.Count } else { 0 }
                PerDay        = if ($member.PSObject.Properties['PerDay']) { $member.PerDay } else { 0 }
                FirstSeen     = if ($member.PSObject.Properties['FirstSeen']) { $member.FirstSeen } else { $null }
                LastSeen      = if ($member.PSObject.Properties['LastSeen']) { $member.LastSeen } else { $null }
                Verdict       = [string]$member.Verdict
                RuleId        = if ($member.PSObject.Properties['RuleId']) { $member.RuleId } else { $null }
                Confidence    = $memberConfidence
                ResultCodes   = @($codeSet.ResultCodes)
                ExtendCodes   = @($codeSet.ExtendCodes)
                ErrorCodes    = @($codeSet.ErrorCodes)
                DistinctCodes = @($codeSet.DistinctCodes)
            }
            $signatureSummaries.Add($summary) | Out-Null
        }

        $firstSeen = if ($firstSeenValues.Count -gt 0) { @($firstSeenValues.ToArray() | Sort-Object | Select-Object -First 1)[0] } else { $null }
        $lastSeen = if ($lastSeenValues.Count -gt 0) { @($lastSeenValues.ToArray() | Sort-Object -Descending | Select-Object -First 1)[0] } else { $null }
        $distinctResultCodes = @($resultCodes.ToArray() | Sort-Object -Unique)
        $distinctExtendCodes = @($extendCodes.ToArray() | Sort-Object -Unique)
        $distinctErrorCodes = @($errorCodes.ToArray() | Sort-Object -Unique)
        $distinctCodes = @($distinctResultCodes + $distinctExtendCodes + $distinctErrorCodes | Sort-Object -Unique)
        $confidence = switch ($confidenceRank) {
            3 { 'high' }
            2 { 'medium' }
            1 { 'low' }
            default { 'none' }
        }

        $incident = [pscustomobject]@{}
        foreach ($property in $representative.PSObject.Properties) {
            $incident | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
        }
        $incident | Add-Member -NotePropertyName 'Key' -NotePropertyValue $incidentId -Force
        $incident | Add-Member -NotePropertyName 'IncidentId' -NotePropertyValue $incidentId -Force
        $incident | Add-Member -NotePropertyName 'Grouping' -NotePropertyValue $(if ($ruleId) { 'RuleId' } else { 'Signature' }) -Force
        $incident | Add-Member -NotePropertyName 'RuleId' -NotePropertyValue $ruleId -Force
        $incident | Add-Member -NotePropertyName 'Count' -NotePropertyValue $combinedCount -Force
        $incident | Add-Member -NotePropertyName 'CombinedCount' -NotePropertyValue $combinedCount -Force
        $incident | Add-Member -NotePropertyName 'PerDay' -NotePropertyValue ([Math]::Round($combinedPerDay, 4)) -Force
        $incident | Add-Member -NotePropertyName 'FirstSeen' -NotePropertyValue $firstSeen -Force
        $incident | Add-Member -NotePropertyName 'LastSeen' -NotePropertyValue $lastSeen -Force
        $incident | Add-Member -NotePropertyName 'Times' -NotePropertyValue @($times.ToArray() | Sort-Object -Unique) -Force
        $incident | Add-Member -NotePropertyName 'SignatureCount' -NotePropertyValue $members.Count -Force
        $incident | Add-Member -NotePropertyName 'SignatureKeys' -NotePropertyValue @($signatureKeys.ToArray() | Sort-Object -Unique) -Force
        $incident | Add-Member -NotePropertyName 'Signatures' -NotePropertyValue @($signatureSummaries.ToArray()) -Force
        $incident | Add-Member -NotePropertyName 'ConstituentSignatures' -NotePropertyValue @($signatureSummaries.ToArray()) -Force
        $incident | Add-Member -NotePropertyName 'ResultCodes' -NotePropertyValue $distinctResultCodes -Force
        $incident | Add-Member -NotePropertyName 'ExtendCodes' -NotePropertyValue $distinctExtendCodes -Force
        $incident | Add-Member -NotePropertyName 'ErrorCodes' -NotePropertyValue $distinctErrorCodes -Force
        $incident | Add-Member -NotePropertyName 'DistinctCodes' -NotePropertyValue $distinctCodes -Force
        $incident | Add-Member -NotePropertyName 'Confidence' -NotePropertyValue $confidence -Force
        if ($members.Count -gt 1) {
            $incident | Add-Member -NotePropertyName 'IncidentNote' -NotePropertyValue ('{0} distinct signature(s) matched this ruling and were combined into one incident.' -f $members.Count) -Force
        } else {
            $incident | Add-Member -NotePropertyName 'IncidentNote' -NotePropertyValue 'One signature produced this incident.' -Force
        }
        $incidents.Add($incident) | Out-Null
    }

    $sortedIncidents = @($incidents.ToArray() |
        Sort-Object -Property @{ Expression = { Get-LVVerdictRank -Verdict $_.Verdict }; Descending = $true },
            @{ Expression = { [int64]$_.Count }; Descending = $true },
            @{ Expression = { [string]$_.IncidentId }; Descending = $false })
    $signatureCount = @($Finding | Where-Object { $_ }).Count
    $incidentCount = $sortedIncidents.Count
    $suppressedCount = [Math]::Max(0, $signatureCount - $incidentCount)
    $suppressionRatio = if ($signatureCount -gt 0) { [Math]::Round($suppressedCount / [double]$signatureCount, 4) } else { 0 }

    return [pscustomobject][ordered]@{
        Incidents = ConvertTo-LVArrayOutput -Value $sortedIncidents
        Summary = [pscustomobject][ordered]@{
            SignatureCount = $signatureCount
            IncidentCount = $incidentCount
            SuppressedSignatureCount = $suppressedCount
            SuppressionRatio = $suppressionRatio
            SuppressionPercent = [Math]::Round($suppressionRatio * 100, 1)
        }
    }
}
