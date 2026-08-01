# Reduction layer: collapse thousands of records into the handful of distinct
# things that actually happened. This is the step that makes the whole tool work -
# on a typical machine it turns roughly 1,800 error records into 70 signatures,
# and the noisiest single signature is usually one Microsoft documents as harmless.

function Group-LVSignature {
    <#
        .SYNOPSIS
        Deduplicate normalized records into signatures.
        .DESCRIPTION
        Event records key on Provider + EventID, which is the identity Windows itself
        uses. Text-log lines have no such identity, so they key on a masked template
        (numbers, GUIDs, paths and timestamps replaced) which groups the same failure
        recurring with different parameters.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [int]$WindowDays = 30
    )

    if ($Record.Count -eq 0) { return @() }

    $buckets = @{}

    foreach ($r in $Record) {
        if ($r.PSObject.Properties['SignatureKey'] -and $r.SignatureKey) {
            # Decoded crash artifacts already have a small, stable identity: WER uses
            # application + faulting module, and a kernel dump uses its stop code.
            # Hashing their prose would hide that identity and couple it to wording.
            $key = [string]$r.SignatureKey
            $template = ConvertTo-LVTemplate -Text $r.Message
        } elseif ($r.Source -eq 'event') {
            $key = '{0}/{1}' -f $r.Provider, $r.Id
            $template = $null
        } elseif ($r.Source -eq 'reliability') {
            # Reliability records are structured like events and carry the same identity,
            # so they key the same way - but under their own prefix. Without it a
            # reliability record and a channel record for the same provider and id would
            # land in one bucket, and the count that rate escalation reads would be the
            # sum of two views of a single incident rather than the incident itself.
            $key = 'Reliability/{0}/{1}' -f $r.Provider, $r.Id
            $template = $null
        } else {
            $template = ConvertTo-LVTemplate -Text $r.Message
            $key = '{0}/{1}' -f $r.Channel, (Get-LVShortHash -Text $template)
        }

        if (-not $buckets.ContainsKey($key)) {
            $buckets[$key] = [pscustomobject]@{
                Key           = $key
                Source        = $r.Source
                Channel       = $r.Channel
                Provider      = $r.Provider
                Id            = $r.Id
                Template      = $template
                Count         = 0
                UndatedCount  = 0
                FirstSeen     = $null
                LastSeen      = $null
                WorstLevel    = $r.Level
                LevelName     = $r.LevelName
                SampleMessage = $r.Message
                Samples       = (New-Object System.Collections.Generic.List[string])
                # Every occurrence time, capped. FirstSeen and LastSeen describe the span
                # but say nothing about what happened INSIDE it, and correlation is
                # entirely a question about the inside: two signatures whose spans overlap
                # may still never have occurred within minutes of each other.
                Times         = (New-Object System.Collections.Generic.List[datetime])
                Area          = $r.PSObject.Properties['Area'] | ForEach-Object { $_.Value }
            }
        }

        $b = $buckets[$key]
        $b.Count++

        # Undated records carry a null time (text-log lines with no parseable
        # timestamp). PowerShell compares $null as less than any date, so guarding
        # here is what stops one undated line from dragging FirstSeen to null and
        # silently destroying the span for the whole signature.
        if ($null -eq $r.TimeCreated) {
            $b.UndatedCount++
        } else {
            if ($null -eq $b.FirstSeen -or $r.TimeCreated -lt $b.FirstSeen) { $b.FirstSeen = $r.TimeCreated }
            if ($null -eq $b.LastSeen  -or $r.TimeCreated -gt $b.LastSeen)  { $b.LastSeen  = $r.TimeCreated }
            # Capped so one runaway signature cannot hold a hundred thousand timestamps.
            # The cap is a correctness statement, not just a memory one: past this many
            # occurrences the signature is a continuous stream, and "did it coincide with
            # something" stops being a meaningful question about it.
            if ($b.Times.Count -lt $script:LVMaxSignatureTimes) { $b.Times.Add($r.TimeCreated) | Out-Null }
        }
        # Windows levels run 1=Critical .. 4=Information, so the lower number wins.
        if ($r.Level -gt 0 -and $r.Level -lt $b.WorstLevel) {
            $b.WorstLevel = $r.Level
            $b.LevelName  = $r.LevelName
        }
        if ($b.Samples.Count -lt 3) { $b.Samples.Add($r.Message) | Out-Null }
    }

    $days = [Math]::Max(1, $WindowDays)
    $signatures = foreach ($b in $buckets.Values) {
        # A signature made up entirely of undated lines has no measurable span, so it
        # is rated across the observation window rather than given a fabricated one.
        if ($null -eq $b.FirstSeen -or $null -eq $b.LastSeen) {
            $spanDays = 0
        } else {
            $spanDays = ($b.LastSeen - $b.FirstSeen).TotalDays
            if ($spanDays -lt 0) { $spanDays = 0 }
        }

        # A lone occurrence has no span to measure. Dividing by a floor of one day
        # would report it as "1/day", which reads as a daily recurrence when it
        # happened exactly once all month. Rate singletons across the whole window.
        if ($b.Count -le 1) {
            $denominator = $days
        } else {
            $denominator = [Math]::Min($days, [Math]::Max(1, $spanDays))
        }

        $b | Add-Member -NotePropertyName 'PerDay'   -NotePropertyValue ([Math]::Round($b.Count / $denominator, 2)) -Force
        $b | Add-Member -NotePropertyName 'SpanDays' -NotePropertyValue ([Math]::Round($spanDays, 1)) -Force
        $b | Add-Member -NotePropertyName 'Samples'  -NotePropertyValue (@($b.Samples.ToArray())) -Force
        # Sorted once here rather than by every consumer. The correlator's sliding window
        # is only correct over an ordered sequence, and records do not arrive in time
        # order - channels are read one after another, each already sorted within itself.
        $b | Add-Member -NotePropertyName 'Times'    -NotePropertyValue (@($b.Times.ToArray() | Sort-Object)) -Force
        $b
    }

    return ConvertTo-LVArrayOutput -Value @($signatures | Sort-Object -Property Count -Descending)
}

function Get-LVReductionStat {
    <#
        .SYNOPSIS
        The headline number: how much noise the reduction removed.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Signature
    )

    $ratio = 0
    if ($Signature.Count -gt 0) { $ratio = [Math]::Round($Record.Count / $Signature.Count, 1) }

    $loudest = $Signature | Select-Object -First 1
    $loudestShare = 0
    $loudestKey = $null
    if ($loudest) {
        $loudestKey = $loudest.Key
        if ($Record.Count -gt 0) {
            $loudestShare = [Math]::Round(100 * $loudest.Count / $Record.Count, 1)
        }
    }

    return [pscustomobject]@{
        RecordCount    = $Record.Count
        SignatureCount = $Signature.Count
        Ratio          = $ratio
        LoudestKey     = $loudestKey
        LoudestShare   = $loudestShare
    }
}
