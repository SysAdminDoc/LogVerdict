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
        if ($r.Source -eq 'event') {
            $key = '{0}/{1}' -f $r.Provider, $r.Id
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
                FirstSeen     = $r.TimeCreated
                LastSeen      = $r.TimeCreated
                WorstLevel    = $r.Level
                LevelName     = $r.LevelName
                SampleMessage = $r.Message
                Samples       = (New-Object System.Collections.Generic.List[string])
                Area          = $r.PSObject.Properties['Area'] | ForEach-Object { $_.Value }
            }
        }

        $b = $buckets[$key]
        $b.Count++
        if ($r.TimeCreated -lt $b.FirstSeen) { $b.FirstSeen = $r.TimeCreated }
        if ($r.TimeCreated -gt $b.LastSeen)  { $b.LastSeen  = $r.TimeCreated }
        # Windows levels run 1=Critical .. 4=Information, so the lower number wins.
        if ($r.Level -gt 0 -and $r.Level -lt $b.WorstLevel) {
            $b.WorstLevel = $r.Level
            $b.LevelName  = $r.LevelName
        }
        if ($b.Samples.Count -lt 3) { $b.Samples.Add($r.Message) | Out-Null }
    }

    $days = [Math]::Max(1, $WindowDays)
    $signatures = foreach ($b in $buckets.Values) {
        $spanDays = ($b.LastSeen - $b.FirstSeen).TotalDays
        if ($spanDays -lt 0) { $spanDays = 0 }

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
