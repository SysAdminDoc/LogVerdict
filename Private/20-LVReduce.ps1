# Reduction layer: collapse thousands of records into the handful of distinct
# things that actually happened. This is the step that makes the whole tool work -
# on a typical machine it turns roughly 1,800 error records into 70 signatures,
# and the noisiest single signature is usually one Microsoft documents as harmless.

function Get-LVSignatureReduction {
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

    if ($Record.Count -eq 0) {
        return [pscustomobject]@{ Signatures=@(); InitialSignatureCount=0; PromotedSlotCount=0 }
    }

    # Pass one: capture typed slots and count their distinct values inside each masked
    # template family. The channel and original token count are part of family identity;
    # two lines do not become relatives merely because masking erased their structure.
    $prepared = New-Object System.Collections.Generic.List[object]
    $families = @{}
    $initialKeys = @{}
    foreach ($r in $Record) {
        $recordContext = New-LVErrorContext -InputObject $r -Message ([string]$r.Message) `
            -FallbackMessage ([string](Get-LVErrorContextField -InputObject $r -Name 'FallbackMessage'))
        $kind = 'stable'
        $initialKey = $null
        $data = $null
        if ($r.PSObject.Properties['SignatureKey'] -and $r.SignatureKey) {
            $initialKey = [string]$r.SignatureKey
        } elseif ($r.Source -eq 'event') {
            $initialKey = '{0}/{1}' -f $r.Provider, $r.Id
        } elseif ($r.Source -eq 'reliability') {
            $initialKey = 'Reliability/{0}/{1}' -f $r.Provider, $r.Id
        } else {
            $kind = 'text'
            $data = ConvertTo-LVTemplateData -Text $r.Message
            $familyKey = '{0}|{1}|{2}' -f $r.Channel, $data.TokenCount, $data.MaskedTemplate
            $hashInput = '{0}|{1}' -f $data.TokenCount, $data.MaskedTemplate
            $initialKey = '{0}/{1}' -f $r.Channel, (Get-LVShortHash -Text $hashInput)
            if (-not $families.ContainsKey($familyKey)) {
                $families[$familyKey] = [pscustomobject]@{ Values=@{}; Types=@{} }
            }
            $family = $families[$familyKey]
            foreach ($slot in @($data.Slots)) {
                $slotKey = '{0}|{1}' -f $slot.Index, $slot.Type
                if (-not $family.Values.ContainsKey($slotKey)) { $family.Values[$slotKey] = @{} }
                $family.Values[$slotKey][[string]$slot.Value] = $true
                $family.Types[$slotKey] = [string]$slot.Type
            }
        }

        $initialKeys[$initialKey] = $true
        $prepared.Add([pscustomobject]@{
            Record=$r; Kind=$kind; InitialKey=$initialKey; TemplateData=$data
            FamilyKey=$(if ($kind -eq 'text') { $familyKey } else { $null }); Context=$recordContext
        }) | Out-Null
    }

    # One promotion decision per family slot, made from the whole corpus rather than
    # from whichever line happens to arrive first.
    $promotion = @{}
    $promotedSlotCount = 0
    foreach ($familyKey in $families.Keys) {
        $promotion[$familyKey] = @{}
        $family = $families[$familyKey]
        foreach ($slotKey in $family.Values.Keys) {
            $promote = ($script:LVPromotableTemplateSlot -contains $family.Types[$slotKey] -and
                $family.Values[$slotKey].Count -le $script:LVLowCardinalityMax)
            $promotion[$familyKey][$slotKey] = $promote
            if ($promote) { $promotedSlotCount++ }
        }
    }

    # Pass two: build final keys with promoted values, then aggregate exactly as before.
    $buckets = @{}
    foreach ($item in $prepared) {
        $r = $item.Record
        $promotedSlots = @()
        $templateTokenCount = 0
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
            $data = $item.TemplateData
            $template = $data.MarkedTemplate
            $templateTokenCount = $data.TokenCount
            $promoted = New-Object System.Collections.Generic.List[string]
            foreach ($slot in @($data.Slots)) {
                $slotKey = '{0}|{1}' -f $slot.Index, $slot.Type
                if ($promotion[$item.FamilyKey][$slotKey]) {
                    $literal = '<{0}:{1}>' -f $slot.Type, $slot.Value
                    $template = $template.Replace($slot.Marker, $literal)
                    $promoted.Add($literal) | Out-Null
                } else {
                    $template = $template.Replace($slot.Marker, ('<{0}>' -f $slot.Type))
                }
            }
            $promotedSlots = @($promoted.ToArray())
            $hashInput = '{0}|{1}' -f $templateTokenCount, $template
            $key = '{0}/{1}' -f $r.Channel, (Get-LVShortHash -Text $hashInput)
        }

        if (-not $buckets.ContainsKey($key)) {
            $buckets[$key] = [pscustomobject]@{
                Key           = $key
                Source        = $r.Source
                Channel       = $r.Channel
                Provider      = $r.Provider
                Id            = $r.Id
                Template      = $template
                TemplateTokenCount = $templateTokenCount
                PromotedSlots = @($promotedSlots)
                Count         = 0
                UndatedCount  = 0
                FirstSeen     = $null
                LastSeen      = $null
                WorstLevel    = $r.Level
                LevelName     = $r.LevelName
                SampleMessage = $r.Message
                Samples       = (New-Object System.Collections.Generic.List[string])
                ResultCodes   = New-Object 'System.Collections.Generic.HashSet[string]'
                ExtendCodes   = New-Object 'System.Collections.Generic.HashSet[string]'
                Phases        = New-Object 'System.Collections.Generic.HashSet[string]'
                Operations    = New-Object 'System.Collections.Generic.HashSet[string]'
                ProviderLocales = New-Object 'System.Collections.Generic.HashSet[string]'
                FallbackMessages = New-Object 'System.Collections.Generic.HashSet[string]'
                ProviderTemplateSources = New-Object 'System.Collections.Generic.HashSet[string]'
                # Every occurrence time, capped. FirstSeen and LastSeen describe the span
                # but say nothing about what happened INSIDE it, and correlation is
                # entirely a question about the inside: two signatures whose spans overlap
                # may still never have occurred within minutes of each other.
                Times         = (New-Object System.Collections.Generic.List[datetime])
                RecordIds     = (New-Object System.Collections.Generic.List[object])
                StructuredData = $null
                StructuredDataAccumulator = $null
                ProviderExtension = if ($r.PSObject.Properties['ProviderExtension']) { $r.ProviderExtension } else { $null }
                Area          = $r.PSObject.Properties['Area'] | ForEach-Object { $_.Value }
            }
        }

        $b = $buckets[$key]
        $b.Count++
        if ($r.PSObject.Properties['RecordId'] -and $null -ne $r.RecordId -and $b.RecordIds.Count -lt $script:LVMaxSignatureRecordIds) {
            $recordId = [string]$r.RecordId
            if ($recordId -and -not $b.RecordIds.Contains($recordId)) { $b.RecordIds.Add($recordId) | Out-Null }
        }
        if ($r.PSObject.Properties['StructuredData'] -and $r.StructuredData) {
            if (-not $b.StructuredDataAccumulator) {
                $b.StructuredDataAccumulator = New-LVStructuredDataAccumulator
            }
            Add-LVEventStructuredDataToAccumulator -Accumulator $b.StructuredDataAccumulator -Incoming $r.StructuredData
        }

        foreach ($field in @(
            @{ Context = 'ResultCode'; Bucket = 'ResultCodes' },
            @{ Context = 'ExtendCode'; Bucket = 'ExtendCodes' },
            @{ Context = 'Phase'; Bucket = 'Phases' },
            @{ Context = 'Operation'; Bucket = 'Operations' },
            @{ Context = 'ProviderLocale'; Bucket = 'ProviderLocales' },
            @{ Context = 'FallbackMessage'; Bucket = 'FallbackMessages' }
        )) {
            $value = ConvertTo-LVErrorContextText $item.Context.($field.Context)
            if ($value) { [void]$b.($field.Bucket).Add($value) }
        }
        if ($r.PSObject.Properties['ProviderTemplateSource'] -and $r.ProviderTemplateSource) {
            [void]$b.ProviderTemplateSources.Add([string]$r.ProviderTemplateSource)
        }

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
        $resultCodes = @($b.ResultCodes | Sort-Object)
        $extendCodes = @($b.ExtendCodes | Sort-Object)
        $phases = @($b.Phases | Sort-Object)
        $operations = @($b.Operations | Sort-Object)
        $providerLocales = @($b.ProviderLocales | Sort-Object)
        $fallbackMessages = @($b.FallbackMessages | Sort-Object)
        $providerTemplateSources = @($b.ProviderTemplateSources | Sort-Object)
        $resultCode = if ($resultCodes.Count -gt 0) { $resultCodes[0] } else { $null }
        $extendCode = if ($extendCodes.Count -gt 0) { $extendCodes[0] } else { $null }
        $phase = if ($phases.Count -gt 0) { $phases[0] } else { $null }
        $operation = if ($operations.Count -gt 0) { $operations[0] } else { $null }
        $providerLocale = if ($providerLocales.Count -gt 0) { $providerLocales[0] } else { $null }
        $fallbackMessage = if ($fallbackMessages.Count -gt 0) { $fallbackMessages[0] } else { $null }
        $providerTemplateSource = if ($providerTemplateSources.Count -gt 0) { $providerTemplateSources[0] } else { $null }
        $b | Add-Member -NotePropertyName 'ResultCodes' -NotePropertyValue $resultCodes -Force
        $b | Add-Member -NotePropertyName 'ExtendCodes' -NotePropertyValue $extendCodes -Force
        $b | Add-Member -NotePropertyName 'Phases' -NotePropertyValue $phases -Force
        $b | Add-Member -NotePropertyName 'Operations' -NotePropertyValue $operations -Force
        $b | Add-Member -NotePropertyName 'ProviderLocales' -NotePropertyValue $providerLocales -Force
        $b | Add-Member -NotePropertyName 'FallbackMessages' -NotePropertyValue $fallbackMessages -Force
        $b | Add-Member -NotePropertyName 'ResultCode' -NotePropertyValue $resultCode -Force
        $b | Add-Member -NotePropertyName 'ExtendCode' -NotePropertyValue $extendCode -Force
        $b | Add-Member -NotePropertyName 'Phase' -NotePropertyValue $phase -Force
        $b | Add-Member -NotePropertyName 'Operation' -NotePropertyValue $operation -Force
        $b | Add-Member -NotePropertyName 'ProviderLocale' -NotePropertyValue $providerLocale -Force
        $b | Add-Member -NotePropertyName 'FallbackMessage' -NotePropertyValue $fallbackMessage -Force
        $b | Add-Member -NotePropertyName 'ProviderTemplateSources' -NotePropertyValue $providerTemplateSources -Force
        $b | Add-Member -NotePropertyName 'ProviderTemplateSource' -NotePropertyValue $providerTemplateSource -Force
        $b | Add-Member -NotePropertyName 'ErrorContext' -NotePropertyValue ([pscustomobject][ordered]@{
            ResultCodes=$resultCodes; ExtendCodes=$extendCodes; Phases=$phases; Operations=$operations
            ProviderLocales=$providerLocales; FallbackMessages=$fallbackMessages; ProviderTemplateSources=$providerTemplateSources
        }) -Force
        # Sorted once here rather than by every consumer. The correlator's sliding window
        # is only correct over an ordered sequence, and records do not arrive in time
        # order - channels are read one after another, each already sorted within itself.
        $b | Add-Member -NotePropertyName 'Times'    -NotePropertyValue (@($b.Times.ToArray() | Sort-Object)) -Force
        $recordIds = @($b.RecordIds.ToArray())
        $b | Add-Member -NotePropertyName 'RecordIds' -NotePropertyValue $recordIds -Force
        $b | Add-Member -NotePropertyName 'RecordId' -NotePropertyValue ($recordIds | Select-Object -First 1) -Force
        if ($b.StructuredDataAccumulator) {
            $b | Add-Member -NotePropertyName 'StructuredData' -NotePropertyValue (ConvertTo-LVStructuredDataProjection -Accumulator $b.StructuredDataAccumulator) -Force
        }
        $b.PSObject.Properties.Remove('StructuredDataAccumulator')
        $b
    }

    return [pscustomobject]@{
        Signatures = @($signatures | Sort-Object -Property Count -Descending)
        InitialSignatureCount = $initialKeys.Count
        PromotedSlotCount = $promotedSlotCount
    }
}

function Get-LVUnknownBurstProfile {
    <#
        .SYNOPSIS
        Find a compact cluster inside a signature's observed timestamps.

        .DESCRIPTION
        This is deliberately a small, dependency-free timing signal rather than a
        verdict. Three events close together can be the start of a new failure, while
        a regular hourly trickle should remain an ordinary unknown. The profile is
        returned only when the closest three-event window is compact enough to call a
        burst; callers keep the verdict unknown and explain that timing is not cause.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Signature)

    $times = @(
        foreach ($value in @($Signature.Times)) {
            if ($null -eq $value) { continue }
            try { [datetime]$value } catch { continue }
        }
    ) | Sort-Object
    if ($times.Count -lt 3) { return $null }

    $bestStart = 0
    $bestSeconds = [double]::PositiveInfinity
    for ($i = 0; $i -le ($times.Count - 3); $i++) {
        $seconds = [Math]::Max(0, ($times[$i + 2] - $times[$i]).TotalSeconds)
        if ($seconds -lt $bestSeconds) {
            $bestSeconds = $seconds
            $bestStart = $i
        }
    }

    $spanMinutes = [Math]::Max(0, ($times[-1] - $times[0]).TotalMinutes)
    $windowMinutes = [Math]::Round($bestSeconds / 60, 2)

    # A compact three-event window is the primary signal. The second condition lets
    # a five-or-more-event ramp inside two hours show up even when its three-event
    # window is a little wider; hourly (or slower) trickles do not meet either test.
    $compactBurst = ($windowMinutes -le 15)
    $shortRamp = ($times.Count -ge 5 -and $windowMinutes -le 30 -and $spanMinutes -le 120)
    if (-not ($compactBurst -or $shortRamp)) { return $null }

    $reason = if ($shortRamp -and -not $compactBurst) {
        'multiple occurrences ramped inside a two-hour window'
    } else {
        'three occurrences clustered inside a fifteen-minute window'
    }

    return [pscustomobject]@{
        IsBurst       = $true
        Onset         = $times[$bestStart]
        ClusterCount  = 3
        WindowMinutes = $windowMinutes
        TotalCount    = $times.Count
        Reason        = $reason
    }
}

function Add-LVUnknownBurstContext {
    <#
        .SYNOPSIS
        Attach burst timing context without changing a signature's verdict.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Signature)

    $Signature | Add-Member -NotePropertyName 'Burst' -NotePropertyValue $false -Force
    $Signature | Add-Member -NotePropertyName 'BurstOnset' -NotePropertyValue $null -Force
    $Signature | Add-Member -NotePropertyName 'BurstCount' -NotePropertyValue $null -Force
    $Signature | Add-Member -NotePropertyName 'BurstWindowMinutes' -NotePropertyValue $null -Force
    $Signature | Add-Member -NotePropertyName 'BurstReason' -NotePropertyValue $null -Force

    if ($Signature.Verdict -ne 'unknown') { return }
    $burstProfile = Get-LVUnknownBurstProfile -Signature $Signature
    if ($null -eq $burstProfile) { return }

    $onset = $burstProfile.Onset.ToString('yyyy-MM-dd HH:mm:ss')
    $summary = 'Timing signal: {0} began around {1}, with {2} occurrences in {3} minute(s). This is a burst indicator, not a root-cause diagnosis.' -f `
        $burstProfile.Reason, $onset, $burstProfile.ClusterCount, $burstProfile.WindowMinutes
    $Signature | Add-Member -NotePropertyName 'Burst' -NotePropertyValue $true -Force
    $Signature | Add-Member -NotePropertyName 'BurstOnset' -NotePropertyValue $burstProfile.Onset -Force
    $Signature | Add-Member -NotePropertyName 'BurstCount' -NotePropertyValue $burstProfile.ClusterCount -Force
    $Signature | Add-Member -NotePropertyName 'BurstWindowMinutes' -NotePropertyValue $burstProfile.WindowMinutes -Force
    $Signature | Add-Member -NotePropertyName 'BurstReason' -NotePropertyValue $burstProfile.Reason -Force
    $Signature.Plain = '{0} {1}' -f $Signature.Plain, $summary
    $Signature.Why = '{0} The compact timing cluster means this unknown signature deserves attention even though its cause is not established.' -f $Signature.Why
    $Signature.Action = 'Start triage with evidence around {0}; preserve the surrounding event window and add a reviewed rule only after identifying the provider operation.' -f $onset
}

function Group-LVSignature {
    <#
        .SYNOPSIS
        Deduplicate normalized records into signatures.

        .DESCRIPTION
        Compatibility wrapper returning only signatures. Scan callers use
        Get-LVSignatureReduction so they can also report the masked first pass.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [int]$WindowDays = 30
    )

    $grouped = Get-LVSignatureReduction -Record $Record -WindowDays $WindowDays
    return ConvertTo-LVArrayOutput -Value @($grouped.Signatures)
}

function Get-LVReductionStat {
    <#
        .SYNOPSIS
        The headline number: how much noise the reduction removed.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Signature,
        [Nullable[int]]$InitialSignatureCount,
        [int]$PromotedSlotCount = 0
    )

    $ratio = 0
    if ($Signature.Count -gt 0) { $ratio = [Math]::Round($Record.Count / $Signature.Count, 1) }
    $initialCount = $Signature.Count
    if ($null -ne $InitialSignatureCount) { $initialCount = [int]$InitialSignatureCount }
    $initialRatio = 0
    if ($initialCount -gt 0) { $initialRatio = [Math]::Round($Record.Count / $initialCount, 1) }

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
        InitialSignatureCount = $initialCount
        InitialRatio   = $initialRatio
        SignatureCount = $Signature.Count
        Ratio          = $ratio
        PromotedSlotCount = $PromotedSlotCount
        LoudestKey     = $loudestKey
        LoudestShare   = $loudestShare
    }
}
