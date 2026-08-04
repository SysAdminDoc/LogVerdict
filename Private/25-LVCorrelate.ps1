# Correlation: the step a human does first and the report currently makes the
# reader do by hand.
#
# An Application Error 1000 and a Service Control Manager 7031 thirty seconds apart
# are one incident described twice, not two findings. Reported separately they sit in
# different places in a list sorted by count, and the reader has to notice the
# timestamps line up. Reported together they name a cause.
#
# ## Why the window slides
#
# The rule vocabulary here is Sigma's - `temporal`, `temporal_ordered`, `event_count`,
# with `rules`, `timespan` and `group-by` - so anyone who can read a Sigma correlation
# can read one of these. The windowing is deliberately NOT Sigma's.
#
# Sigma buckets time into fixed intervals: with a 1h timespan, everything from 09:00
# to 10:00 is one bucket. A crash at 09:59 and the service death it caused at 10:01
# fall in different buckets and never correlate, while two unrelated events at 09:01
# and 09:59 - fifty-eight minutes apart - do. On a single machine, where the whole
# point is "these happened together", that is backwards. This implementation slides
# the window instead, the way Elastic EQL's `sequence ... with maxspan` does, so the
# only question asked is whether the occurrences were actually within `timespan` of
# each other.
#
# ## What a match is
#
# A match is a concrete window of time containing at least one occurrence of every
# referenced rule. The window's own bounds are reported, not the signature spans, so
# the reader gets the moment to look at rather than a range of days.

function ConvertFrom-LVTimespan {
    <#
        .SYNOPSIS
        Parse a Sigma-style duration - 30s, 5m, 2h, 1d - into a TimeSpan.
        .DESCRIPTION
        Returns $null for anything unparseable rather than guessing a default. A
        correlation rule whose window silently became "1 second" because of a typo
        would simply never fire, which is the failure mode this project cares most
        about avoiding: a rule that is present, looks fine, and does nothing.
    #>
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text.Trim(), '^(\d+)\s*([smhd])$', 'IgnoreCase')
    if (-not $m.Success) { return $null }

    $n = [int]$m.Groups[1].Value
    if ($n -le 0) { return $null }

    switch ($m.Groups[2].Value.ToLowerInvariant()) {
        's' { return [timespan]::FromSeconds($n) }
        'm' { return [timespan]::FromMinutes($n) }
        'h' { return [timespan]::FromHours($n) }
        'd' { return [timespan]::FromDays($n) }
    }
    return $null
}

function Get-LVCorrelationOccurrence {
    <#
        .SYNOPSIS
        Every occurrence of the referenced rules, merged into one time-ordered list.
        .DESCRIPTION
        Each entry carries the rule that produced it, because the sliding window's
        question is "does this window hold one of each", not "how many are in here".
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][string[]]$RuleId
    )

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in $Finding) {
        if (-not $f.RuleId -or $RuleId -notcontains $f.RuleId) { continue }
        foreach ($t in @($f.Times)) {
            if ($null -eq $t) { continue }
            $items.Add([pscustomobject]@{ Time = [datetime]$t; RuleId = $f.RuleId; Key = $f.Key }) | Out-Null
        }
    }
    return ConvertTo-LVArrayOutput -Value @($items.ToArray() | Sort-Object Time)
}

function Get-LVCorrelationMatch {
    <#
        .SYNOPSIS
        Windows in which every referenced rule occurred, using a sliding window.

        .DESCRIPTION
        Two pointers over the merged occurrence list. The right pointer admits the next
        occurrence; the left pointer is advanced until the window is no longer wider
        than timespan. Whenever the window holds at least one occurrence of every
        required rule, that is a match.

        Matches are then de-overlapped: a burst of twenty crashes beside twenty service
        deaths is one incident to report, not four hundred. The first window of a run is
        kept and subsequent windows that start before the kept one ended are folded into
        it, so the reported window covers the whole episode.

        temporal_ordered additionally requires that the FIRST occurrence of each rule
        inside the window follows the declared order, which is what separates "the crash
        took the service down" from "the service death crashed the app".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Occurrence,
        [Parameter(Mandatory)][string[]]$RuleId,
        [Parameter(Mandatory)][timespan]$Timespan,
        [switch]$Ordered
    )

    $found = New-Object System.Collections.Generic.List[object]
    $items = @($Occurrence)
    if ($items.Count -eq 0) { return ConvertTo-LVArrayOutput -Value @() }

    $required = @($RuleId | Select-Object -Unique)
    $counts = @{}
    $firstIndices = @{}
    foreach ($r in $required) {
        $counts[$r] = 0
        $firstIndices[$r] = New-Object 'System.Collections.Generic.Queue[int]'
    }
    $distinct = 0
    $left = 0

    for ($right = 0; $right -lt $items.Count; $right++) {
        $rid = $items[$right].RuleId
        if ($counts.ContainsKey($rid)) {
            if ($counts[$rid] -eq 0) { $distinct++ }
            $counts[$rid]++
            $firstIndices[$rid].Enqueue($right)
        }

        # Shrink from the left until the window fits inside the timespan.
        while ($left -le $right -and ($items[$right].Time - $items[$left].Time) -gt $Timespan) {
            $lid = $items[$left].RuleId
            if ($counts.ContainsKey($lid)) {
                $counts[$lid]--
                if ($counts[$lid] -eq 0) { $distinct-- }
                if ($firstIndices[$lid].Count -gt 0 -and $firstIndices[$lid].Peek() -eq $left) {
                    [void]$firstIndices[$lid].Dequeue()
                }
            }
            $left++
        }

        if ($distinct -ne $required.Count) { continue }

        if ($Ordered -and -not (Test-LVCorrelationOrder -Window @() -RuleId $RuleId -FirstIndices $firstIndices)) { continue }

        # Keep only interval endpoints while the window slides. The occurrence
        # ranges are materialized once by Merge-LVCorrelationMatch after the
        # overlapping intervals have been folded.
        $found.Add([pscustomobject]@{
            Start       = $items[$left].Time
            End         = $items[$right].Time
            StartIndex  = $left
            EndIndex    = $right
        }) | Out-Null
    }

    return ConvertTo-LVArrayOutput -Value @(Merge-LVCorrelationMatch -Match $found.ToArray() -OccurrenceItems $items -AlreadySorted)
}

function Test-LVCorrelationOrder {
    <#
        .SYNOPSIS
        Whether each rule's first occurrence in the window follows the declared order.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Window,
        [Parameter(Mandatory)][string[]]$RuleId,
        [AllowNull()][hashtable]$FirstIndices
    )

    if ($null -ne $FirstIndices) {
        $previous = -1
        foreach ($r in @($RuleId | Select-Object -Unique)) {
            $queue = $FirstIndices[$r]
            if ($null -eq $queue -or $queue.Count -eq 0) { return $false }
            $first = $queue.Peek()
            if ($first -lt $previous) { return $false }
            $previous = $first
        }
        return $true
    }

    $firstAt = @{}
    for ($i = 0; $i -lt $Window.Count; $i++) {
        $rid = $Window[$i].RuleId
        if (-not $firstAt.ContainsKey($rid)) { $firstAt[$rid] = $i }
    }

    $previous = -1
    foreach ($r in $RuleId) {
        if (-not $firstAt.ContainsKey($r)) { return $false }
        if ($firstAt[$r] -lt $previous) { return $false }
        $previous = $firstAt[$r]
    }
    return $true
}

function Merge-LVCorrelationMatch {
    <#
        .SYNOPSIS
        Fold overlapping windows into one incident each.
        .DESCRIPTION
        The sliding window emits a match at every position where the condition holds, so
        a single episode produces one match per occurrence in it. Reporting those
        separately would replace the two findings this feature exists to merge with
        several hundred, which is worse than doing nothing.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Match,
        [AllowNull()][object[]]$OccurrenceItems,
        [switch]$AlreadySorted
    )

    $merged = New-Object System.Collections.Generic.List[object]
    $orderedMatches = if ($AlreadySorted) { @($Match) } else { @($Match | Sort-Object Start) }
    foreach ($m in $orderedMatches) {
        $overlaps = $merged.Count -gt 0 -and $m.Start -le $merged[$merged.Count - 1].End
        if ($overlaps) {
            $last = $merged[$merged.Count - 1]
            if ($m.End -gt $last.End) { $last.End = $m.End }

            if ($null -ne $OccurrenceItems -and $null -ne $m.StartIndex -and $null -ne $m.EndIndex) {
                # Both pointers are monotonic. Only the portion after the prior
                # candidate's right edge can add a new occurrence to this union;
                # this is the part that avoids rebuilding the growing window.
                $startIndex = [Math]::Max([int]$m.StartIndex, [int]$last.LastEndIndex + 1)
                $endIndex = [int]$m.EndIndex
                for ($i = $startIndex; $i -le $endIndex; $i++) {
                    $o = $OccurrenceItems[$i]
                    $key = '{0:o}|{1}' -f $o.Time, $o.RuleId
                    if ($last.OccurrenceIndex.ContainsKey($key)) {
                        $last.OccurrenceList[$last.OccurrenceIndex[$key]] = $o
                    } else {
                        $last.OccurrenceIndex[$key] = $last.OccurrenceList.Count
                        $last.OccurrenceList.Add($o) | Out-Null
                    }
                }
            } else {
                # Retain the helper's historical standalone behavior for callers
                # that provide already-materialized matches. The scan path above
                # always supplies source indices and remains linear.
                foreach ($o in @($m.Occurrences)) {
                    $key = '{0:o}|{1}' -f $o.Time, $o.RuleId
                    if ($last.OccurrenceIndex.ContainsKey($key)) {
                        $last.OccurrenceList[$last.OccurrenceIndex[$key]] = $o
                    } else {
                        $last.OccurrenceIndex[$key] = $last.OccurrenceList.Count
                        $last.OccurrenceList.Add($o) | Out-Null
                    }
                }
            }
            if ($null -ne $m.EndIndex) { $last.LastEndIndex = [int]$m.EndIndex }
            continue
        }

        $state = [pscustomobject]@{
            Start = $m.Start
            End = $m.End
            LastEndIndex = -1
            OccurrenceList = New-Object System.Collections.Generic.List[object]
            OccurrenceIndex = New-Object 'System.Collections.Generic.Dictionary[string,int]'
        }

        if ($null -ne $OccurrenceItems -and $null -ne $m.StartIndex -and $null -ne $m.EndIndex) {
            $startIndex = [int]$m.StartIndex
            $endIndex = [int]$m.EndIndex
            for ($i = $startIndex; $i -le $endIndex; $i++) {
                $o = $OccurrenceItems[$i]
                $key = '{0:o}|{1}' -f $o.Time, $o.RuleId
                if ($state.OccurrenceIndex.ContainsKey($key)) {
                    $state.OccurrenceList[$state.OccurrenceIndex[$key]] = $o
                } else {
                    $state.OccurrenceIndex[$key] = $state.OccurrenceList.Count
                    $state.OccurrenceList.Add($o) | Out-Null
                }
            }
            $state.LastEndIndex = $endIndex
        } else {
            foreach ($o in @($m.Occurrences)) {
                $key = '{0:o}|{1}' -f $o.Time, $o.RuleId
                if ($state.OccurrenceIndex.ContainsKey($key)) {
                    $state.OccurrenceList[$state.OccurrenceIndex[$key]] = $o
                } else {
                    $state.OccurrenceIndex[$key] = $state.OccurrenceList.Count
                    $state.OccurrenceList.Add($o) | Out-Null
                }
            }
        }
        $merged.Add($state) | Out-Null
    }

    $output = New-Object System.Collections.Generic.List[object]
    foreach ($state in $merged) {
        $output.Add([pscustomobject]@{
            Start = $state.Start
            End = $state.End
            Occurrences = @($state.OccurrenceList.ToArray() | Sort-Object Time)
        }) | Out-Null
    }
    return ConvertTo-LVArrayOutput -Value @($output.ToArray())
}

function Resolve-LVCorrelation {
    <#
        .SYNOPSIS
        Apply the database's correlation rules to a set of resolved findings.

        .OUTPUTS
        One object per correlation rule that fired, carrying its windows, the findings
        involved, and the ruling prose. Returns an empty array when nothing correlates,
        which is the normal case on a healthy machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)]$Database
    )

    $results = New-Object System.Collections.Generic.List[object]
    $rules = @($Database.correlations | Where-Object { $_ })
    if ($rules.Count -eq 0) { return ConvertTo-LVArrayOutput -Value @() }

    foreach ($rule in $rules) {
        if (-not (Test-LVRuleActive -Rule $rule)) { continue }

        $c = $rule.correlation
        if ($null -eq $c) { continue }

        $refs = @($c.rules | Where-Object { $_ })
        if ($refs.Count -lt 2 -and $c.type -ne 'event_count') { continue }

        $span = ConvertFrom-LVTimespan -Text $c.timespan
        if ($null -eq $span) {
            # Loud, because a correlation rule with an unreadable window is a rule that
            # silently never fires - and a rule that never fires looks exactly like a
            # machine with nothing wrong.
            Write-LVLog -Level warn -Message ("Correlation {0} declares an unreadable timespan '{1}' and was skipped." -f $rule.id, $c.timespan)
            continue
        }

        $occurrences = @(Get-LVCorrelationOccurrence -Finding $Finding -RuleId $refs)
        # Every referenced rule has to be present at all before windowing is worth doing.
        $present = @($occurrences | Select-Object -ExpandProperty RuleId -Unique)
        if (@($refs | Where-Object { $present -notcontains $_ }).Count -gt 0) { continue }

        $ordered = ($c.type -eq 'temporal_ordered')
        $windows = @(Get-LVCorrelationMatch -Occurrence $occurrences -RuleId $refs -Timespan $span -Ordered:$ordered)
        if ($windows.Count -eq 0) { continue }

        $involved = @($Finding | Where-Object { $_.RuleId -and $refs -contains $_.RuleId })

        $results.Add([pscustomobject]@{
            Id            = $rule.id
            Type          = $c.type
            Timespan      = $c.timespan
            RuleIds       = @($refs)
            Verdict       = $rule.verdict
            Title         = $rule.title
            Plain         = $rule.plain
            Why           = $rule.why
            Action        = $rule.action
            Confidence    = $rule.confidence
            References    = @($rule.references | Where-Object { $_ })
            Sources       = @($rule.sources | Where-Object { $_ })
            FalsePositives = @($rule.falsepositives | Where-Object { $_ })
            Windows       = @($windows)
            OccurrenceCount = @($windows | ForEach-Object { @($_.Occurrences).Count } | Measure-Object -Sum).Sum
            InvolvedKeys  = @($involved | Select-Object -ExpandProperty Key)
            InvolvedTitles = @($involved | Select-Object -ExpandProperty Title)
        }) | Out-Null
    }

    # Worst first, then by how many times the pairing actually happened.
    $sorted = $results.ToArray() |
        Sort-Object -Property @{ Expression = { Get-LVVerdictRank -Verdict $_.Verdict }; Descending = $true },
                              @{ Expression = { @($_.Windows).Count }; Descending = $true }

    return ConvertTo-LVArrayOutput -Value @($sorted)
}
