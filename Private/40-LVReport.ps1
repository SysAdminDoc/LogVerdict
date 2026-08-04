# Presentation layer. Console, plain text and a self-contained dark HTML page.
# No external stylesheets or fonts: the report has to open on an air-gapped machine
# or out of a zip on someone else's PC.

$script:LVVerdictColor = @{
    'critical'      = 'Red'
    'actionable'    = 'Red'
    'investigate'   = 'Yellow'
    'unknown'       = 'Magenta'
    'informational' = 'Cyan'
    'benign'        = 'DarkGray'
}

$script:LVVerdictHex = @{
    'critical'      = '#f38ba8'
    'actionable'    = '#fab387'
    'investigate'   = '#f9e2af'
    'unknown'       = '#cba6f7'
    'informational' = '#89b4fa'
    'benign'        = '#a6e3a1'
}

function Add-LVLine {
    <#
        .SYNOPSIS
        Append one already-formatted line to a StringBuilder.

        .DESCRIPTION
        Exists to sidestep a PowerShell parsing trap, not for convenience. Inside a
        METHOD call's parentheses a comma separates arguments, so

            $sb.AppendLine('{0} {1}' -f $a, $b)

        parses as AppendLine(('{0} {1}' -f $a), $b) and the format operator receives
        one argument for two placeholders. Routing through a cmdlet means the
        parentheses are a grouping expression and the comma builds an array as
        intended. Every line in this file goes through here so the trap cannot
        reappear the next time a line is added.
    #>
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [Parameter()][AllowEmptyString()][AllowNull()][string]$Text = ''
    )
    [void]$Builder.AppendLine((ConvertTo-LVLocalizedReportLine -Text $Text))
}

function Format-LVWhen {
    <#
        .SYNOPSIS
        Render a timestamp, or say plainly that there is not one.

        .DESCRIPTION
        Text-log lines whose timestamp cannot be parsed carry a null time. Formatting
        a null date yields an empty string, which reads as a rendering bug and hides
        the fact that the tool genuinely does not know when the line was written.
    #>
    param($When)
    if ($null -eq $When) { return 'undated' }
    return ('{0:yyyy-MM-dd HH:mm}' -f $When)
}

function ConvertTo-LVTicketSummary {
    <#
        .SYNOPSIS
        Render the bounded, prose-first Markdown handoff an MSP can paste into a ticket.

        .DESCRIPTION
        This deliberately projects the scan rather than copying the full report. It
        leads with the worst curated verdict, keeps only findings that need attention,
        explains how many repeated records were suppressed, and carries the coverage
        caveats that keep a partial scan from sounding clean. The GUI uses this same
        function for its clipboard action, so the pasted text cannot drift from the
        file written by Export-LogVerdictReport.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [switch]$Redact,
        [AllowNull()][string]$MachineName,
        [AllowNull()][string]$UserName
    )

    $resolved = Resolve-LVScanInput -InputObject $Result -Role 'result'
    $resolved = ConvertFrom-LVReportContract -InputObject $resolved
    $builder = New-Object System.Text.StringBuilder

    $clean = {
        param([AllowNull()]$Value, [int]$Limit = 2000)
        if ($null -eq $Value) { return '' }
        $text = ([string]$Value) -replace '[\r\n]+', ' '
        $text = $text.Trim()
        if ($text.Length -gt $Limit) { return $text.Substring(0, $Limit - 3) + '...' }
        return $text
    }
    $add = {
        param([AllowEmptyString()][string]$Line = '')
        [void]$builder.AppendLine($Line)
    }

    $version = if ($resolved.Version) { [string]$resolved.Version } else { [string]$script:LVVersion }
    $databaseName = if ($resolved.DatabaseName) { [string]$resolved.DatabaseName } else { 'bundled database' }
    $databaseDate = if ($resolved.DatabaseDate) { [string]$resolved.DatabaseDate } else { 'unknown' }
    $worst = if ($resolved.WorstVerdict) { [string]$resolved.WorstVerdict } else { 'unknown' }
    $findings = @($resolved.Findings | Where-Object {
        $_ -and (Get-LVVerdictRank -Verdict ([string]$_.Verdict)) -ge (Get-LVVerdictRank -Verdict 'unknown')
    } | Sort-Object @{ Expression = { Get-LVVerdictRank -Verdict ([string]$_.Verdict) }; Descending = $true },
        @{ Expression = { [int64]$_.Count }; Descending = $true }, Title)
    $reduction = $resolved.Reduction
    $recordCount = if ($reduction) { [int64]$reduction.RecordCount } else { 0 }
    $signatureCount = if ($reduction) { [int64]$reduction.SignatureCount } else { 0 }
    $suppressed = [Math]::Max(0, $recordCount - $signatureCount)
    $ratio = if ($reduction -and $null -ne $reduction.Ratio) { [string]$reduction.Ratio } else { 'n/a' }

    & $add '# LogVerdict ticket summary'
    & $add ''
    & $add ('- **Worst verdict:** **{0}**' -f (& $clean $worst).ToUpperInvariant())
    & $add ('- **Machine:** {0}' -f (& $clean $resolved.MachineName))
    & $add ('- **Scanned:** {0} (last {1} day(s))' -f (& $clean $resolved.ScanTime), (& $clean $resolved.DaysBack))
    & $add ('- **Tool:** LogVerdict {0}' -f (& $clean $version))
    & $add ('- **Rule database:** {0}, updated {1}' -f (& $clean $databaseName), (& $clean $databaseDate))
    & $add ('- **Suppressed repeats:** {0:N0} record(s) reduced to {1:N0} signature(s) ({2}:1)' -f $suppressed, $signatureCount, (& $clean $ratio))
    & $add ('- **Findings needing attention:** {0}' -f $findings.Count)
    & $add ''

    & $add '## Findings needing attention'
    if ($findings.Count -eq 0) {
        & $add '- None. The scan produced no unknown, investigate, actionable, or critical findings.'
    } else {
        $index = 0
        foreach ($finding in $findings) {
            $index++
            $verdict = (& $clean $finding.Verdict).ToUpperInvariant()
            $action = if ($finding.Action) { & $clean $finding.Action } else { 'Review the full finding details.' }
            & $add ('{0}. **{1} - {2}**' -f $index, $verdict, (& $clean $finding.Title))
            & $add ('   - **Action:** {0}' -f $action)
            & $add ('   - **Occurrences:** {0:N0} ({1}/day); last seen {2}' -f [int64]$finding.Count, (& $clean $finding.PerDay), (& $clean (Format-LVWhen $finding.LastSeen)))
            & $add ('   - **Signature:** `{0}`' -f (& $clean $finding.Key))
        }
    }
    & $add ''

    $caveats = New-Object 'System.Collections.Generic.List[string]'
    $seenCaveats = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($note in @($resolved.CoverageNotes | Where-Object { $_ })) {
        $text = & $clean $note
        if ($text -and $seenCaveats.Add($text)) { $caveats.Add($text) | Out-Null }
    }
    if ($resolved.HorizonWarning) {
        $text = & $clean $resolved.HorizonWarning
        if ($text -and $seenCaveats.Add($text)) { $caveats.Add($text) | Out-Null }
    }
    foreach ($source in @($resolved.Coverage | Where-Object { $_ -and $_.Status -notin @('readable', 'empty') })) {
        $text = '{0}/{1} is {2}{3}' -f (& $clean $source.Source), (& $clean $source.Name), (& $clean $source.Status),
            $(if ($source.Reason) { ': ' + (& $clean $source.Reason) } else { '' })
        if ($seenCaveats.Add($text)) { $caveats.Add($text) | Out-Null }
    }
    foreach ($health in @($resolved.HealthProfiles | Where-Object { $_ -and $_.Status -notin @('available', 'healthy', 'readable') })) {
        $text = 'Health profile {0} is {1}{2}' -f (& $clean $health.Name), (& $clean $health.Status),
            $(if ($health.Advice) { ': ' + (& $clean $health.Advice) } elseif ($health.Reason) { ': ' + (& $clean $health.Reason) } else { '' })
        if ($seenCaveats.Add($text)) { $caveats.Add($text) | Out-Null }
    }

    & $add '## Coverage caveats'
    if ($caveats.Count -eq 0) {
        & $add '- No coverage caveats were reported.'
    } else {
        foreach ($caveat in $caveats) { & $add ('- {0}' -f $caveat) }
    }
    & $add ''
    & $add '> This is a ticket summary. Attach the full LogVerdict report when raw evidence or complete source detail is needed.'

    $text = $builder.ToString().TrimEnd()
    if ($Redact) {
        $machine = if ($MachineName) { $MachineName } else { [string]$resolved.MachineName }
        $user = if ($UserName) { $UserName } else { [string]$env:USERNAME }
        $text = ConvertTo-LVRedactedText -Text $text -MachineName $machine -UserName $user
    }

    # Keep clipboard and attachment payloads comfortably below service-desk limits,
    # even if a corrupted result contains thousands of unusually long findings.
    $maxBytes = 24MB
    $textBytes = [System.Text.Encoding]::UTF8.GetByteCount($text)
    if ($textBytes -gt $maxBytes) {
        $suffix = [Environment]::NewLine + [Environment]::NewLine + '> Summary truncated to remain below 24 MiB.'
        $targetBytes = $maxBytes - [System.Text.Encoding]::UTF8.GetByteCount($suffix)
        $targetChars = [Math]::Min($text.Length, [Math]::Max(0, [int]($text.Length * ($targetBytes / [double]$textBytes))))
        while ($targetChars -gt 0 -and [System.Text.Encoding]::UTF8.GetByteCount($text.Substring(0, $targetChars)) -gt $targetBytes) {
            $targetChars = [Math]::Max(0, $targetChars - 4096)
        }
        $text = $text.Substring(0, $targetChars).TrimEnd() + $suffix
    }
    return $text
}

function Write-LVConsoleReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    $stat = $Result.Reduction
    Write-Host ''
    Write-LVLog -Level step -Message ('LogVerdict {0} - {1}' -f $script:LVVersion, $Result.MachineName)
    Write-Host ''
    Write-Host ('  Window          : last {0} day(s), through {1:yyyy-MM-dd HH:mm}' -f $Result.DaysBack, $Result.ScanTime)
    Write-Host ('  Records read    : {0}' -f $stat.RecordCount)
    Write-Host ('  Signatures      : {0}  (reduction {1}:1)' -f $stat.SignatureCount, $stat.Ratio)
    if ($stat.PSObject.Properties['InitialSignatureCount']) {
        Write-Host ('  Template passes : {0} masked ({1}:1) -> {2} after slot promotion ({3}:1)' -f `
            $stat.InitialSignatureCount, $stat.InitialRatio, $stat.SignatureCount, $stat.Ratio)
    }
    if ($stat.LoudestKey) {
        Write-Host ('  Loudest         : {0} at {1}% of all records' -f $stat.LoudestKey, $stat.LoudestShare)
    }
    Write-Host ('  Elevated        : {0}' -f $Result.Elevated)
    if ($Result.Stability) {
        $s = $Result.Stability
        Write-Host ('  Stability       : {0}/10, {1} over the window (low {2})' -f $s.Current, $s.Direction, $s.Lowest)
    }
    if ($Result.PSObject.Properties['SetupDiag'] -and $Result.SetupDiag) {
        Write-Host ('  SetupDiag       : {0} - {1}' -f $Result.SetupDiag.Status, $Result.SetupDiag.Message)
    }
    Write-Host ''

    foreach ($note in @($Result.CoverageNotes)) {
        Write-Host ('  NOT SCANNED     : {0}' -f $note) -ForegroundColor Yellow
    }
    if (@($Result.CoverageNotes).Count -gt 0) { Write-Host '' }

    $coverageGaps = @($Result.Coverage | Where-Object { $_ -and $_.Status -in @('disabled', 'policy-disabled', 'provider-absent') })
    if ($coverageGaps.Count -gt 0) {
        Write-Host '  COVERAGE DETAIL : explicitly unavailable sources' -ForegroundColor Yellow
        foreach ($source in $coverageGaps) {
            $detail = '{0}/{1} {2} - {3}' -f $source.Source, $source.Kind, $source.Name, $source.Status
            if ($source.Reason) { $detail += '; ' + [string]$source.Reason }
            Write-Host ('    - ' + $detail) -ForegroundColor Yellow
        }
        Write-Host ''
    }

    $staleRules = @()
    if ($Result.PSObject.Properties['DatabaseFreshness'] -and $Result.DatabaseFreshness) {
        $staleRules = @($Result.DatabaseFreshness.StaleRules | Where-Object { $_ })
    } else {
        $staleRules = @($Result.Findings | Where-Object { $_.PSObject.Properties['RuleStale'] -and $_.RuleStale } |
            ForEach-Object { [pscustomobject]@{ RuleId = $_.RuleId; Verified = $_.Verified; StaleAfterDays = $_.RuleFreshness.StaleAfterDays } })
    }
    if ($staleRules.Count -gt 0) {
        $threshold = if ($Result.DatabaseFreshness.DefaultStaleAfterDays) { $Result.DatabaseFreshness.DefaultStaleAfterDays } else { $script:LVDefaultStaleAfterDays }
        Write-Host '  STALE RULE GUIDANCE' -ForegroundColor Yellow
        Write-Host ('    {0} active rule(s) are past their freshness threshold ({1} default day(s)); they still match but need re-verification.' -f $staleRules.Count, $threshold) -ForegroundColor Yellow
        foreach ($staleRule in @($staleRules | Select-Object -First 20)) {
            Write-Host ('    - {0}: last verified {1}; stale after {2} day(s)' -f $staleRule.RuleId, $staleRule.Verified, $staleRule.StaleAfterDays) -ForegroundColor Yellow
        }
        if ($staleRules.Count -gt 20) {
            Write-Host ('    - {0} more stale rule(s) omitted from this summary.' -f ($staleRules.Count - 20)) -ForegroundColor Yellow
        }
        Write-Host ''
    }

    if ($Result.PSObject.Properties['History'] -and $Result.History) {
        $history = $Result.History
        Write-Host '  BASELINE (ADVISORY ONLY)' -ForegroundColor Cyan
        Write-Host ('    Status        : {0}; persistence {1}' -f $history.Status, $history.Persistence) -ForegroundColor DarkGray
        Write-Host ('    Baseline      : {0} prior scan(s), window {1} day(s)' -f $history.Baseline.SampleCount, $history.WindowDays) -ForegroundColor DarkGray
        Write-Host ('    Threshold     : {0}' -f $history.Threshold.Description) -ForegroundColor DarkGray
        foreach ($signal in @($history.Signals | Where-Object { $_ })) {
            Write-Host ('    Signal        : [{0}] {1} - {2}' -f $signal.Type, $signal.Key, $signal.Reason) -ForegroundColor Yellow
        }
        Write-Host ('    Caveat        : {0}' -f $history.FalsePositiveCaveat) -ForegroundColor DarkGray
        Write-Host '    Trend signals never change curated verdicts, WorstVerdict, or ExitCode.' -ForegroundColor DarkGray
        Write-Host ''
    }

    if ($Result.PSObject.Properties['AdvisoryStatus']) {
        Write-Host '  DEPENDENCY ADVISORIES (SEPARATE FROM EVENT FINDINGS)' -ForegroundColor Cyan
        Write-Host '    These are package/tool knowledge records, not Windows event verdicts.' -ForegroundColor DarkGray
        Write-Host ('    Status        : {0}' -f $Result.AdvisoryStatus) -ForegroundColor DarkGray
        if ($Result.AdvisoryCache) {
            Write-Host ('    Cache         : {0}, {1} entry(s), updated {2}, source {3}' -f `
                $Result.AdvisoryCache.Name, $Result.AdvisoryCache.EntryCount, $Result.AdvisoryCache.Updated, $Result.AdvisoryCache.Source) -ForegroundColor DarkGray
            Write-Host ('    Cache hash    : {0}' -f $Result.AdvisoryCache.SourceHash) -ForegroundColor DarkGray
        }
        foreach ($advisory in @($Result.Advisories | Where-Object { $_ })) {
            $state = if ($advisory.Matched) { 'AFFECTED' } else { 'CACHE ENTRY' }
            Write-Host ('    [{0}] {1} - {2} {3}' -f $state, $advisory.Id, $advisory.Package, $(if ($advisory.Version) { $advisory.Version } else { '' })) -ForegroundColor Yellow
            Write-Host ('      Range/fix   : {0} / {1}' -f $advisory.AffectedRange, $advisory.FixedVersion)
            Write-Host ('      CVSS/KEV    : {0} / {1} (KEV date: {2})' -f $advisory.CVSS, $advisory.KEV, $(if ($advisory.KEVDate) { $advisory.KEVDate } else { 'n/a' }))
            Write-Host ('      Published   : {0}; modified {1}' -f $advisory.PublishedDate, $advisory.ModifiedDate) -ForegroundColor DarkGray
            Write-Host ('      Source      : {0} ({1}); hash {2}' -f $advisory.Source, $advisory.SourceUri, $advisory.SourceHash) -ForegroundColor DarkGray
        }
        if (@($Result.Advisories).Count -eq 0 -and $Result.AdvisoryStatus -eq 'no-match') {
            Write-Host '    No advisory in the supplied cache matches the requested package/version.' -ForegroundColor DarkGray
        }
        Write-Host ''
    }

    if ($Result.PSObject.Properties['CaseProfile'] -and $Result.CaseProfile) {
        Write-Host '  CASE PROFILE / HANDOFF' -ForegroundColor Cyan
        Write-Host '    Collection metadata and operator context; this is not a verdict.' -ForegroundColor DarkGray
        Write-Host ('    Profile ID    : {0}' -f $Result.CaseProfile.profileId) -ForegroundColor DarkGray
        Write-Host ('    Name          : {0}; sources {1}; redacted {2}' -f $Result.CaseProfile.name, @($Result.CaseProfile.sources).Count, $Result.CaseProfile.redaction.requested) -ForegroundColor DarkGray
        foreach ($note in @($Result.CaseProfile.notes | Where-Object { $_ })) {
            Write-Host ('    Note          : {0}' -f $note) -ForegroundColor DarkGray
        }
        Write-Host ''
    }

    if ($Result.PSObject.Properties['ProviderExtensions'] -and @($Result.ProviderExtensions).Count -gt 0) {
        Write-Host '  PROVIDER EXTENSIONS (EXPLICIT, UNTRUSTED)' -ForegroundColor Cyan
        Write-Host '    Extensions contributed redacted evidence only; curated verdicts and rule IDs remain core-owned.' -ForegroundColor DarkGray
        foreach ($extension in @($Result.ProviderExtensions | Where-Object { $_ })) {
            Write-Host ('    Provider       : {0} {1}; {2} record(s), {3} rejected, trust {4}' -f `
                $extension.Id, $extension.Version, $extension.RecordCount, $extension.RejectedRecords, $extension.Trust) -ForegroundColor DarkGray
        }
        foreach ($projection in @($Result.ProviderProjections | Where-Object { $_ })) {
            Write-Host ('    Projection     : {0}' -f $projection.ProviderId) -ForegroundColor DarkGray
            foreach ($field in @($projection.Fields.PSObject.Properties | Where-Object { $_ })) {
                Write-Host ('      {0}: {1}' -f $field.Name, $field.Value) -ForegroundColor DarkGray
            }
        }
        Write-Host ''
    }

    $tally = $Result.Findings | Group-Object -Property Verdict
    foreach ($name in @('critical', 'actionable', 'investigate', 'unknown', 'informational', 'benign')) {
        $g = $tally | Where-Object { $_.Name -eq $name }
        $n = 0
        if ($g) { $n = $g.Count }
        if ($n -eq 0) { continue }
        Write-Host ('  {0,-14}: {1}' -f $name, $n) -ForegroundColor $script:LVVerdictColor[$name]
    }
    Write-Host ''

    # Filtered, not merely wrapped. A result object from an older build - or one that
    # has been through JSON and back - has no Correlations property at all, and @() on a
    # missing property yields a one-element array holding null, which would crash the
    # renderer on the first property access.
    $correlated = @($Result.Correlations | Where-Object { $_ })

    # Correlations first, deliberately. Printed after the flat list they are a footnote
    # to conclusions the reader has already drawn from the individual parts, which is
    # the exact mistake this feature exists to prevent.
    foreach ($c in $correlated) {
        Write-Host ''
        Write-Host ('  [TOGETHER: {0}] {1}' -f $c.Verdict.ToUpper(), $c.Title) -ForegroundColor $script:LVVerdictColor[$c.Verdict]
        Write-Host ('    {0} occurred within {1} of each other, {2} time(s)' -f (@($c.RuleIds) -join ' + '), $c.Timespan, @($c.Windows).Count) -ForegroundColor DarkGray
        foreach ($w in @($c.Windows | Select-Object -First 3)) {
            Write-Host ('    when          : {0:yyyy-MM-dd HH:mm:ss} to {1:HH:mm:ss}' -f $w.Start, $w.End) -ForegroundColor DarkGray
        }
        Write-Host ('    What it means : {0}' -f $c.Plain)
        Write-Host ('    Why it matters: {0}' -f $c.Why)
        Write-Host ('    Do this       : {0}' -f $c.Action) -ForegroundColor White
    }

    $notable = @($Result.Findings | Where-Object { (Get-LVVerdictRank -Verdict $_.Verdict) -ge (Get-LVVerdictRank -Verdict 'unknown') })
    if ($notable.Count -eq 0 -and $correlated.Count -eq 0) {
        Write-LVLog -Level ok -Message 'Nothing above the informational line in this window.'
    }

    foreach ($f in $notable) {
        $color = $script:LVVerdictColor[$f.Verdict]
        Write-Host ''
        Write-Host ('  [{0}] {1}' -f $f.Verdict.ToUpper(), $f.Title) -ForegroundColor $color
        Write-Host ('    {0}  x{1}  ({2}/day, last seen {3})' -f $f.Key, $f.Count, $f.PerDay, (Format-LVWhen $f.LastSeen)) -ForegroundColor DarkGray
        if ($f.PSObject.Properties['Burst'] -and $f.Burst) {
            Write-Host ('    Burst         : began {0}; {1} occurrence(s) in {2} minute(s)' -f (Format-LVWhen $f.BurstOnset), $f.BurstCount, $f.BurstWindowMinutes) -ForegroundColor Yellow
        }
        Write-Host ('    What it means : {0}' -f $f.Plain)
        Write-Host ('    Why it matters: {0}' -f $f.Why)
        Write-Host ('    Do this       : {0}' -f $f.Action) -ForegroundColor White
        if ($f.PSObject.Properties['ModelExplanation'] -and $f.ModelExplanation) {
            $draft = $f.ModelExplanation
            Write-Host ('    {0}' -f $draft.Label) -ForegroundColor Yellow
            Write-Host ('      Possible meaning: {0}' -f $draft.Summary)
            foreach ($evidence in @($draft.Evidence)) {
                Write-Host ('      Evidence cited  : {0}' -f $evidence) -ForegroundColor DarkGray
            }
            Write-Host ('      Uncertainty     : {0}' -f $draft.Uncertainty) -ForegroundColor DarkGray
            Write-Host ('      Local model     : {0}' -f $draft.Model) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
}

function ConvertTo-LVFlatFindingRow {
    <#
        .SYNOPSIS
        Project findings into the stable, one-row-per-finding CSV contract.

        .DESCRIPTION
        CSV is for pipelines, not for reproducing the nested JSON report. Keep the
        columns scalar and predictable so the output can flow directly to Export-Csv,
        Out-GridView, or a ticket import without knowing the internal signature shape.
        Correlations remain in the richer reports; each row here is one ordinary finding.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    foreach ($finding in @($Result.Findings | Where-Object { $_ })) {
        [pscustomobject][ordered]@{
            RowType           = 'finding'
            ScanTime          = ConvertTo-LVUtcTimestamp $Result.ScanTime
            MachineName       = $Result.MachineName
            DaysBack          = $Result.DaysBack
            Elevated          = $Result.Elevated
            Channel           = $finding.Channel
            Source            = $finding.Source
            Provider          = $finding.Provider
            Id                = $finding.Id
            Key               = $finding.Key
            Count             = $finding.Count
            PerDay            = $finding.PerDay
            FirstSeen         = ConvertTo-LVUtcTimestamp $finding.FirstSeen
            LastSeen          = ConvertTo-LVUtcTimestamp $finding.LastSeen
            Verdict           = $finding.Verdict
            Title             = $finding.Title
            RuleId            = $finding.RuleId
            Confidence        = $finding.Confidence
            Plain             = $finding.Plain
            Why               = $finding.Why
            Action            = $finding.Action
            SampleMessage     = $finding.SampleMessage
            ResultCode        = $finding.ResultCode
            ExtendCode        = $finding.ExtendCode
            Phase             = $finding.Phase
            Operation         = $finding.Operation
            ProviderLocale    = $finding.ProviderLocale
            FallbackMessage   = $finding.FallbackMessage
            ErrorCode         = $finding.ErrorCode
            ErrorCatalogKind  = $finding.ErrorCatalogKind
            ErrorName         = $finding.ErrorName
            ErrorPhase        = $finding.ErrorPhase
            ErrorOperation    = $finding.ErrorOperation
            Reference         = $finding.Reference
            Burst             = if ($finding.PSObject.Properties['Burst']) { $finding.Burst } else { $false }
            BurstOnset        = if ($finding.PSObject.Properties['BurstOnset']) { ConvertTo-LVUtcTimestamp $finding.BurstOnset } else { $null }
            BurstCount        = if ($finding.PSObject.Properties['BurstCount']) { $finding.BurstCount } else { $null }
            BurstWindowMinutes = if ($finding.PSObject.Properties['BurstWindowMinutes']) { $finding.BurstWindowMinutes } else { $null }
            CoverageSource    = $null; CoverageKind = $null; CoverageName = $null; CoverageStatus = $null
            CoverageReason    = $null; CoveragePath = $null; CoverageWindowStart = $null; CoverageWindowEnd = $null
            CoverageCap       = $null; CoverageObservedRecords = $null; CoverageSkippedRecords = $null
            CoverageRecordGap = $null; CoverageParserError = $null; CoverageSizeBytes = $null
         CoverageParseMilliseconds = $null; CoverageSHA256 = $null; CoverageOrigin = $null
         CoveragePollCount = $null; CoveragePollErrors = $null; CoverageReconnectCount = $null; CoverageDroppedRecords = $null
         CoverageAverageLatencyMilliseconds = $null; CoverageMaxLatencyMilliseconds = $null
            HealthProfile = $null; HealthSource = $null; HealthName = $null; HealthStatus = $null
            HealthRequiredConfiguration = $null; HealthObservedConfiguration = $null
            HealthEnabledEventIds = $null; HealthFilteredEventIds = $null; HealthProvider = $null; HealthProviderId = $null; HealthChannel = $null
            HealthEventIds = $null; HealthEventVersions = $null; HealthMetadataStatus = $null
            HealthReadExistingEvents = $null; HealthHeartbeatIntervalSeconds = $null; HealthBookmarkState = $null
         HealthRetentionMode = $null; HealthRecordCount = $null; HealthOldestRecord = $null; HealthMaximumSizeBytes = $null
         HealthClockOffsetMinutes = $null; HealthReason = $null; HealthAdvice = $null; HealthPath = $null
            PerformanceSource = $null; PerformanceKind = $null; PerformanceName = $null; PerformanceStatus = $null
            PerformanceObservedRecords = $null; PerformanceSkippedRecords = $null; PerformanceCap = $null
            PerformanceElapsedMilliseconds = $null; PerformanceSlow = $null; PerformanceSlowThresholdMilliseconds = $null; PerformanceOrigin = $null
        }
    }
}

function ConvertTo-LVCoverageCsvRow {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Coverage)

    return [pscustomobject][ordered]@{
        RowType           = 'coverage'
        ScanTime          = ConvertTo-LVUtcTimestamp $Result.ScanTime
        MachineName       = $Result.MachineName
        DaysBack          = $Result.DaysBack
        Elevated          = $Result.Elevated
        Channel           = $null; Source = $null; Provider = $null; Id = $null; Key = $null
        Count             = $null; PerDay = $null; FirstSeen = $null; LastSeen = $null
        Verdict           = $null; Title = $null; RuleId = $null; Confidence = $null
        Plain             = $null; Why = $null; Action = $null; SampleMessage = $null
        ResultCode        = $null; ExtendCode = $null; Phase = $null; Operation = $null; ProviderLocale = $null; FallbackMessage = $null
        ErrorCode         = $null; ErrorCatalogKind = $null; ErrorName = $null; ErrorPhase = $null; ErrorOperation = $null; Reference = $null
        Burst             = $null; BurstOnset = $null; BurstCount = $null; BurstWindowMinutes = $null
        CoverageSource    = $Coverage.Source; CoverageKind = $Coverage.Kind; CoverageName = $Coverage.Name
        CoverageStatus    = $Coverage.Status; CoverageReason = $Coverage.Reason; CoveragePath = $Coverage.Path
        CoverageWindowStart = ConvertTo-LVUtcTimestamp $Coverage.WindowStart
        CoverageWindowEnd = ConvertTo-LVUtcTimestamp $Coverage.WindowEnd
        CoverageCap       = $Coverage.Cap; CoverageObservedRecords = $Coverage.ObservedRecords
        CoverageSkippedRecords = $Coverage.SkippedRecords; CoverageRecordGap = $Coverage.RecordGap
        CoverageParserError = $Coverage.ParserError; CoverageSizeBytes = $Coverage.SizeBytes
        CoverageParseMilliseconds = $Coverage.ParseMilliseconds; CoverageSHA256 = $Coverage.SHA256
        CoverageOrigin    = $Coverage.Origin
        CoveragePollCount = if ($Coverage.PSObject.Properties['PollCount']) { $Coverage.PollCount } else { $null }
        CoveragePollErrors = if ($Coverage.PSObject.Properties['PollErrors']) { $Coverage.PollErrors } else { $null }
        CoverageReconnectCount = if ($Coverage.PSObject.Properties['ReconnectCount']) { $Coverage.ReconnectCount } else { $null }
        CoverageDroppedRecords = if ($Coverage.PSObject.Properties['DroppedRecords']) { $Coverage.DroppedRecords } else { $null }
        CoverageAverageLatencyMilliseconds = if ($Coverage.PSObject.Properties['AverageLatencyMilliseconds']) { $Coverage.AverageLatencyMilliseconds } else { $null }
        CoverageMaxLatencyMilliseconds = if ($Coverage.PSObject.Properties['MaxLatencyMilliseconds']) { $Coverage.MaxLatencyMilliseconds } else { $null }
        HealthProfile = $null; HealthSource = $null; HealthName = $null; HealthStatus = $null
        HealthRequiredConfiguration = $null; HealthObservedConfiguration = $null
        HealthEnabledEventIds = $null; HealthFilteredEventIds = $null; HealthProvider = $null; HealthProviderId = $null; HealthChannel = $null
        HealthEventIds = $null; HealthEventVersions = $null; HealthMetadataStatus = $null
        HealthReadExistingEvents = $null; HealthHeartbeatIntervalSeconds = $null; HealthBookmarkState = $null
        HealthRetentionMode = $null; HealthRecordCount = $null; HealthOldestRecord = $null; HealthMaximumSizeBytes = $null
        HealthClockOffsetMinutes = $null; HealthReason = $null; HealthAdvice = $null; HealthPath = $null
        PerformanceSource = $null; PerformanceKind = $null; PerformanceName = $null; PerformanceStatus = $null
        PerformanceObservedRecords = $null; PerformanceSkippedRecords = $null; PerformanceCap = $null
        PerformanceElapsedMilliseconds = $null; PerformanceSlow = $null; PerformanceSlowThresholdMilliseconds = $null; PerformanceOrigin = $null
    }
}

function ConvertTo-LVHealthCsvRow {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Health)

    return [pscustomobject][ordered]@{
        RowType = 'health'
        ScanTime = ConvertTo-LVUtcTimestamp $Result.ScanTime
        MachineName = $Result.MachineName; DaysBack = $Result.DaysBack; Elevated = $Result.Elevated
        Channel = $null; Source = $null; Provider = $null; Id = $null; Key = $null
        Count = $null; PerDay = $null; FirstSeen = $null; LastSeen = $null
        Verdict = $null; Title = $null; RuleId = $null; Confidence = $null
        Plain = $null; Why = $null; Action = $null; SampleMessage = $null
        ResultCode = $null; ExtendCode = $null; Phase = $null; Operation = $null; ProviderLocale = $null; FallbackMessage = $null
        ErrorCode = $null; ErrorCatalogKind = $null; ErrorName = $null; ErrorPhase = $null; ErrorOperation = $null; Reference = $null
        Burst = $null; BurstOnset = $null; BurstCount = $null; BurstWindowMinutes = $null
        CoverageSource = $null; CoverageKind = $null; CoverageName = $null; CoverageStatus = $null
        CoverageReason = $null; CoveragePath = $null; CoverageWindowStart = $null; CoverageWindowEnd = $null
        CoverageCap = $null; CoverageObservedRecords = $null; CoverageSkippedRecords = $null
        CoverageRecordGap = $null; CoverageParserError = $null; CoverageSizeBytes = $null
        CoverageParseMilliseconds = $null; CoverageSHA256 = $null; CoverageOrigin = $null
        HealthProfile = $Health.Profile; HealthSource = $Health.Source; HealthName = $Health.Name; HealthStatus = $Health.Status
        HealthRequiredConfiguration = $Health.RequiredConfiguration; HealthObservedConfiguration = $Health.ObservedConfiguration
        HealthEnabledEventIds = @($Health.EnabledEventIds) -join ';'; HealthFilteredEventIds = @($Health.FilteredEventIds) -join ';'
        HealthProvider = $Health.Provider; HealthProviderId = $Health.ProviderId; HealthChannel = $Health.Channel
        HealthEventIds = @($Health.EventIds) -join ';'; HealthEventVersions = @($Health.EventVersions) -join ';'
        HealthMetadataStatus = $Health.MetadataStatus; HealthReadExistingEvents = $Health.ReadExistingEvents
        HealthHeartbeatIntervalSeconds = $Health.HeartbeatIntervalSeconds; HealthBookmarkState = $Health.BookmarkState
        HealthRetentionMode = $Health.RetentionMode; HealthRecordCount = $Health.RecordCount
        HealthOldestRecord = ConvertTo-LVUtcTimestamp $Health.OldestRecord
         HealthMaximumSizeBytes = $Health.MaximumSizeBytes; HealthClockOffsetMinutes = $Health.ClockOffsetMinutes
         HealthReason = $Health.Reason; HealthAdvice = $Health.Advice; HealthPath = $Health.Path
         HealthPollErrors = if ($Health.PSObject.Properties['PollErrors']) { $Health.PollErrors } else { $null }
         HealthReconnectCount = if ($Health.PSObject.Properties['ReconnectCount']) { $Health.ReconnectCount } else { $null }
         HealthDroppedRecords = if ($Health.PSObject.Properties['DroppedRecords']) { $Health.DroppedRecords } else { $null }
         HealthAverageLatencyMilliseconds = if ($Health.PSObject.Properties['AverageLatencyMilliseconds']) { $Health.AverageLatencyMilliseconds } else { $null }
         HealthMaxLatencyMilliseconds = if ($Health.PSObject.Properties['MaxLatencyMilliseconds']) { $Health.MaxLatencyMilliseconds } else { $null }
        PerformanceSource = $null; PerformanceKind = $null; PerformanceName = $null; PerformanceStatus = $null
        PerformanceObservedRecords = $null; PerformanceSkippedRecords = $null; PerformanceCap = $null
        PerformanceElapsedMilliseconds = $null; PerformanceSlow = $null; PerformanceSlowThresholdMilliseconds = $null; PerformanceOrigin = $null
    }
}

function ConvertTo-LVPerformanceCsvRow {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Performance)

    # Reuse the complete coverage projection so the CSV header remains stable even
    # when a clean scan emits telemetry as its only non-empty row type.
    $row = ConvertTo-LVCoverageCsvRow -Result $Result -Coverage ([pscustomobject]@{})
    $row.RowType = 'performance'
    $row.PerformanceSource = $Performance.Source
    $row.PerformanceKind = $Performance.Kind
    $row.PerformanceName = $Performance.Name
    $row.PerformanceStatus = $Performance.Status
    $row.PerformanceObservedRecords = $Performance.ObservedRecords
    $row.PerformanceSkippedRecords = $Performance.SkippedRecords
    $row.PerformanceCap = $Performance.Cap
    $row.PerformanceElapsedMilliseconds = $Performance.ElapsedMilliseconds
    $row.PerformanceSlow = $Performance.Slow
    $row.PerformanceSlowThresholdMilliseconds = $Performance.SlowThresholdMilliseconds
    $row.PerformanceOrigin = $Performance.Origin
    return $row
}

function ConvertTo-LVCsvReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    $rows = @(ConvertTo-LVFlatFindingRow -Result $Result)
    foreach ($coverage in @($Result.Coverage | Where-Object { $_ })) {
        $rows += ConvertTo-LVCoverageCsvRow -Result $Result -Coverage $coverage
    }
    foreach ($health in @($Result.HealthProfiles | Where-Object { $_ })) {
        $rows += ConvertTo-LVHealthCsvRow -Result $Result -Health $health
    }
    foreach ($performance in @($Result.Performance | Where-Object { $_ })) {
        $rows += ConvertTo-LVPerformanceCsvRow -Result $Result -Performance $performance
    }
    if ($rows.Count -gt 0) {
        $csvLines = @($rows | ConvertTo-Csv -NoTypeInformation)
        if ($csvLines.Count -gt 0) { $csvLines[0] = ConvertTo-LVLocalizedCsvHeader -Header $csvLines[0] }
        return ($csvLines -join [Environment]::NewLine) + [Environment]::NewLine
    }

    # Preserve the header even when a clean scan has no findings, so a downstream
    # importer can bind columns without a special empty-file branch.
    $header = [pscustomobject][ordered]@{
        RowType = $null
        ScanTime = $null; MachineName = $null; DaysBack = $null; Elevated = $null
        Channel = $null; Source = $null; Provider = $null; Id = $null; Key = $null
        Count = $null; PerDay = $null; FirstSeen = $null; LastSeen = $null
        Verdict = $null; Title = $null; RuleId = $null; Confidence = $null
        Plain = $null; Why = $null; Action = $null; SampleMessage = $null
        ResultCode = $null; ExtendCode = $null; Phase = $null; Operation = $null; ProviderLocale = $null; FallbackMessage = $null
        ErrorCode = $null; ErrorCatalogKind = $null; ErrorName = $null; ErrorPhase = $null; ErrorOperation = $null; Reference = $null
        Burst = $null; BurstOnset = $null; BurstCount = $null; BurstWindowMinutes = $null
        CoverageSource = $null; CoverageKind = $null; CoverageName = $null; CoverageStatus = $null
        CoverageReason = $null; CoveragePath = $null; CoverageWindowStart = $null; CoverageWindowEnd = $null
        CoverageCap = $null; CoverageObservedRecords = $null; CoverageSkippedRecords = $null
        CoverageRecordGap = $null; CoverageParserError = $null; CoverageSizeBytes = $null
        CoverageParseMilliseconds = $null; CoverageSHA256 = $null; CoverageOrigin = $null
        HealthProfile = $null; HealthSource = $null; HealthName = $null; HealthStatus = $null
        HealthRequiredConfiguration = $null; HealthObservedConfiguration = $null
        HealthEnabledEventIds = $null; HealthFilteredEventIds = $null; HealthProvider = $null; HealthProviderId = $null; HealthChannel = $null
        HealthEventIds = $null; HealthEventVersions = $null; HealthMetadataStatus = $null
        HealthReadExistingEvents = $null; HealthHeartbeatIntervalSeconds = $null; HealthBookmarkState = $null
        HealthRetentionMode = $null; HealthRecordCount = $null; HealthOldestRecord = $null; HealthMaximumSizeBytes = $null
        HealthClockOffsetMinutes = $null; HealthReason = $null; HealthAdvice = $null; HealthPath = $null
        PerformanceSource = $null; PerformanceKind = $null; PerformanceName = $null; PerformanceStatus = $null
        PerformanceObservedRecords = $null; PerformanceSkippedRecords = $null; PerformanceCap = $null
        PerformanceElapsedMilliseconds = $null; PerformanceSlow = $null; PerformanceSlowThresholdMilliseconds = $null; PerformanceOrigin = $null
    }
    $headerLine = ConvertTo-LVLocalizedCsvHeader -Header (@($header | ConvertTo-Csv -NoTypeInformation)[0])
    return ([string]$headerLine) + [Environment]::NewLine
}

function ConvertTo-LVTextReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    $sb = New-Object System.Text.StringBuilder

    Add-LVLine $sb ('LogVerdict {0} report' -f $Result.Version)
    Add-LVLine $sb ('=' * 78)
    Add-LVLine $sb ('Machine       : {0}' -f $Result.MachineName)
    Add-LVLine $sb ('Scanned       : {0:yyyy-MM-dd HH:mm:ss}' -f $Result.ScanTime)
    Add-LVLine $sb ('Window        : last {0} day(s)' -f $Result.DaysBack)
    Add-LVLine $sb ('Elevated      : {0}' -f $Result.Elevated)
    Add-LVLine $sb ('Channels      : {0}' -f ($Result.Channels -join ', '))
    Add-LVLine $sb ('Records read  : {0}' -f $Result.Reduction.RecordCount)
    Add-LVLine $sb ('Signatures    : {0} (reduction {1}:1)' -f $Result.Reduction.SignatureCount, $Result.Reduction.Ratio)
    if ($Result.Reduction.PSObject.Properties['InitialSignatureCount']) {
        Add-LVLine $sb ('Template pass : {0} masked ({1}:1) -> {2} after low-cardinality promotion ({3}:1; {4} slot(s) promoted)' -f `
            $Result.Reduction.InitialSignatureCount, $Result.Reduction.InitialRatio, $Result.Reduction.SignatureCount,
            $Result.Reduction.Ratio, $Result.Reduction.PromotedSlotCount)
    }
    if ($Result.Stability) {
        # Windows' own 1-10 stability score. Rate escalation answers "is this signature
        # frequent"; this answers "is the machine getting worse", which a single scan
        # otherwise has no way to see.
        Add-LVLine $sb ('Stability     : {0}/10, {1} over the window (started {2}, low {3}, {4} sample(s))' -f `
            $Result.Stability.Current, $Result.Stability.Direction, $Result.Stability.Starting, $Result.Stability.Lowest, $Result.Stability.SampleCount)
    }
    if ($Result.PSObject.Properties['SetupDiag'] -and $Result.SetupDiag) {
        Add-LVLine $sb ('SetupDiag     : {0} - {1}' -f $Result.SetupDiag.Status, $Result.SetupDiag.Message)
    }
    if ($Result.PSObject.Properties['Redacted'] -and $Result.Redacted) {
        Add-LVLine $sb 'Redacted      : yes - account, machine, profile paths, SIDs and mail addresses were masked in the evidence below. Identifiers Windows wrote in a form this tool does not recognize may remain, so read before sending.'
    }
    Add-LVLine $sb ('Verdict DB    : {0}, {1} rule(s), updated {2}' -f $Result.DatabaseName, $Result.RuleCount, $Result.DatabaseDate)
    Add-LVLine $sb ('Worst verdict : {0}' -f $Result.WorstVerdict)
    Add-LVLine $sb

    $staleRules = @()
    if ($Result.PSObject.Properties['DatabaseFreshness'] -and $Result.DatabaseFreshness) {
        $staleRules = @($Result.DatabaseFreshness.StaleRules | Where-Object { $_ })
    } else {
        $staleRules = @($Result.Findings | Where-Object { $_.PSObject.Properties['RuleStale'] -and $_.RuleStale } |
            ForEach-Object { [pscustomobject]@{ RuleId = $_.RuleId; Verified = $_.Verified; StaleAfterDays = $_.RuleFreshness.StaleAfterDays } })
    }
    if ($staleRules.Count -gt 0) {
        $threshold = if ($Result.DatabaseFreshness.DefaultStaleAfterDays) { $Result.DatabaseFreshness.DefaultStaleAfterDays } else { $script:LVDefaultStaleAfterDays }
        Add-LVLine $sb 'STALE RULE GUIDANCE'
        Add-LVLine $sb ('{0} active rule(s) are past the {1}-day freshness threshold; they still match but need re-verification.' -f $staleRules.Count, $threshold)
        foreach ($staleRule in @($staleRules | Select-Object -First 20)) {
            Add-LVLine $sb ('  - {0}: last verified {1}; stale after {2} day(s)' -f $staleRule.RuleId, $staleRule.Verified, $staleRule.StaleAfterDays)
        }
        if ($staleRules.Count -gt 20) {
            Add-LVLine $sb ('  - {0} more stale rule(s) omitted from this summary.' -f ($staleRules.Count - 20))
        }
        Add-LVLine $sb
    }

    if ($Result.PSObject.Properties['History'] -and $Result.History) {
        $history = $Result.History
        Add-LVLine $sb 'BASELINE (ADVISORY ONLY)'
        Add-LVLine $sb ('Status        : {0}; persistence {1}' -f $history.Status, $history.Persistence)
        Add-LVLine $sb ('Baseline      : {0} prior scan(s), window {1} day(s); {2}' -f $history.Baseline.SampleCount, $history.WindowDays, $history.Baseline.Method)
        Add-LVLine $sb ('Threshold     : {0}' -f $history.Threshold.Description)
        foreach ($signal in @($history.Signals | Where-Object { $_ })) {
            Add-LVLine $sb ('Signal        : [{0}] {1} - {2}' -f $signal.Type, $signal.Key, $signal.Reason)
        }
        Add-LVLine $sb ('Caveat        : {0}' -f $history.FalsePositiveCaveat)
        Add-LVLine $sb 'Trend signals never change curated verdicts, WorstVerdict, or ExitCode.'
        Add-LVLine $sb
    }

    if ($Result.PSObject.Properties['AdvisoryStatus']) {
        Add-LVLine $sb 'DEPENDENCY ADVISORIES (SEPARATE FROM EVENT FINDINGS)'
        Add-LVLine $sb 'These are package/tool knowledge records, not Windows event verdicts.'
        Add-LVLine $sb ('Status        : {0}' -f $Result.AdvisoryStatus)
        if ($Result.AdvisoryCache) {
            Add-LVLine $sb ('Cache         : {0}, {1} entry(s), updated {2}, source {3}' -f `
                $Result.AdvisoryCache.Name, $Result.AdvisoryCache.EntryCount, $Result.AdvisoryCache.Updated, $Result.AdvisoryCache.Source)
            Add-LVLine $sb ('Cache hash    : {0}' -f $Result.AdvisoryCache.SourceHash)
        }
        foreach ($advisory in @($Result.Advisories | Where-Object { $_ })) {
            Add-LVLine $sb ('[{0}] {1} - {2} {3}' -f $(if ($advisory.Matched) { 'AFFECTED' } else { 'CACHE ENTRY' }), $advisory.Id, $advisory.Package, $advisory.Version)
            Add-LVLine $sb ('  Range/fix   : {0} / {1}' -f $advisory.AffectedRange, $advisory.FixedVersion)
            Add-LVLine $sb ('  CVSS/KEV    : {0} / {1} (KEV date: {2})' -f $advisory.CVSS, $advisory.KEV, $(if ($advisory.KEVDate) { $advisory.KEVDate } else { 'n/a' }))
            Add-LVLine $sb ('  Published   : {0}; modified {1}' -f $advisory.PublishedDate, $advisory.ModifiedDate)
            Add-LVLine $sb ('  Source      : {0} ({1}); hash {2}' -f $advisory.Source, $advisory.SourceUri, $advisory.SourceHash)
            Add-LVLine $sb ('  Description : {0}' -f $advisory.Description)
        }
        if (@($Result.Advisories).Count -eq 0 -and $Result.AdvisoryStatus -eq 'no-match') {
            Add-LVLine $sb 'No advisory in the supplied cache matches the requested package/version.'
        }
        Add-LVLine $sb
    }

    if ($Result.PSObject.Properties['CaseProfile'] -and $Result.CaseProfile) {
        Add-LVLine $sb 'CASE PROFILE / HANDOFF'
        Add-LVLine $sb 'Collection metadata and operator context; this is not a verdict.'
        Add-LVLine $sb ('Profile ID    : {0}' -f $Result.CaseProfile.profileId)
        Add-LVLine $sb ('Name          : {0}; sources {1}; redacted {2}' -f $Result.CaseProfile.name, @($Result.CaseProfile.sources).Count, $Result.CaseProfile.redaction.requested)
        foreach ($note in @($Result.CaseProfile.notes | Where-Object { $_ })) { Add-LVLine $sb ('Note          : {0}' -f $note) }
        Add-LVLine $sb
    }

    if ($Result.PSObject.Properties['ProviderExtensions'] -and @($Result.ProviderExtensions).Count -gt 0) {
        Add-LVLine $sb 'PROVIDER EXTENSIONS (EXPLICIT, UNTRUSTED)'
        Add-LVLine $sb 'Extensions contributed redacted evidence only; curated verdicts and rule IDs remain core-owned.'
        foreach ($extension in @($Result.ProviderExtensions | Where-Object { $_ })) {
            Add-LVLine $sb ('Provider       : {0} {1}; {2} record(s), {3} rejected, trust {4}' -f `
                $extension.Id, $extension.Version, $extension.RecordCount, $extension.RejectedRecords, $extension.Trust)
        }
        foreach ($projection in @($Result.ProviderProjections | Where-Object { $_ })) {
            Add-LVLine $sb ('Projection     : {0}' -f $projection.ProviderId)
            foreach ($field in @($projection.Fields.PSObject.Properties | Where-Object { $_ })) {
                Add-LVLine $sb ('  {0}: {1}' -f $field.Name, $field.Value)
            }
        }
        Add-LVLine $sb
    }

    if (@($Result.CoverageNotes).Count -gt 0) {
        Add-LVLine $sb 'COVERAGE - what this scan could NOT see:'
        foreach ($note in @($Result.CoverageNotes)) {
            Add-LVLine $sb ('  - {0}' -f $note)
        }
        Add-LVLine $sb
    }
    if (@($Result.Coverage).Count -gt 0) {
        Add-LVLine $sb 'COVERAGE DETAIL - per-source status:'
        foreach ($source in @($Result.Coverage | Where-Object { $_ })) {
            $detail = '{0}/{1} {2} - {3}' -f $source.Source, $source.Kind, $source.Name, $source.Status
            if ($source.Reason) { $detail += ('; ' + $source.Reason) }
            if ($null -ne $source.ObservedRecords) { $detail += ('; {0} observed' -f $source.ObservedRecords) }
            if ($null -ne $source.Cap) { $detail += ('; cap {0}' -f $source.Cap) }
            if ($source.RecordGap) { $detail += ('; gap: ' + $source.RecordGap) }
            if ($source.ParserError) { $detail += ('; parser: ' + $source.ParserError) }
            if ($source.PSObject.Properties['ReconnectCount']) { $detail += ('; reconnects {0}' -f $source.ReconnectCount) }
            if ($source.PSObject.Properties['DroppedRecords']) { $detail += ('; dropped {0}' -f $source.DroppedRecords) }
            if ($source.PSObject.Properties['AverageLatencyMilliseconds']) { $detail += ('; average latency {0} ms' -f $source.AverageLatencyMilliseconds) }
            if ($source.PSObject.Properties['MaxLatencyMilliseconds']) { $detail += ('; max latency {0} ms' -f $source.MaxLatencyMilliseconds) }
            Add-LVLine $sb ('  - ' + $detail)
        }
        Add-LVLine $sb
    }
    if (@($Result.HealthProfiles).Count -gt 0) {
        Add-LVLine $sb 'CONFIGURATION HEALTH - advisory profiles:'
        foreach ($health in @($Result.HealthProfiles | Where-Object { $_ })) {
            $detail = '{0}/{1} {2} - {3}' -f $health.Source, $health.Profile, $health.Name, $health.Status
            if ($health.ObservedConfiguration) { $detail += '; observed: ' + $health.ObservedConfiguration }
            if ($health.Reason) { $detail += '; reason: ' + $health.Reason }
            if ($health.Advice) { $detail += '; advice: ' + $health.Advice }
            Add-LVLine $sb ('  - ' + $detail)
        }
        Add-LVLine $sb
    }
    $performanceRows = @($Result.Performance | Where-Object { $_ })
    if ($performanceRows.Count -gt 0) {
        Add-LVLine $sb 'PERFORMANCE TELEMETRY (OPT-IN; CONTENT-FREE)'
        Add-LVLine $sb 'Source class, bounded counts and elapsed time only; messages, paths, identifiers and signatures are not recorded.'
        foreach ($metric in $performanceRows) {
            $state = [string]$metric.Status
            if ($metric.Slow) { $state += ' (slow)' }
            $detail = '{0}/{1} {2} - {3}; elapsed {4} ms' -f $metric.Source, $metric.Kind, $metric.Name, $state, $metric.ElapsedMilliseconds
            if ($null -ne $metric.ObservedRecords) { $detail += ('; {0} observed' -f $metric.ObservedRecords) }
            if ($null -ne $metric.SkippedRecords) { $detail += ('; {0} skipped' -f $metric.SkippedRecords) }
            if ($null -ne $metric.Cap) { $detail += ('; cap {0}' -f $metric.Cap) }
            Add-LVLine $sb ('  - ' + $detail)
        }
        Add-LVLine $sb
    }

    foreach ($h in $Result.Horizon.Keys) {
        Add-LVLine $sb ('Oldest record in {0}: {1:yyyy-MM-dd}' -f $h, $Result.Horizon[$h])
    }
    if ($Result.HorizonWarning) {
        Add-LVLine $sb
        Add-LVLine $sb ('WARNING: {0}' -f $Result.HorizonWarning)
    }
    Add-LVLine $sb
    Add-LVLine $sb ('-' * 78)
    Add-LVLine $sb

    $correlated = @($Result.Correlations | Where-Object { $_ })
    if ($correlated.Count -gt 0) {
        Add-LVLine $sb 'THINGS THAT HAPPENED TOGETHER'
        Add-LVLine $sb 'These signatures also appear individually below. Read them here first: apart'
        Add-LVLine $sb 'they describe symptoms, together they name a cause.'
        Add-LVLine $sb
        foreach ($c in $correlated) {
            Add-LVLine $sb ('[TOGETHER: {0}] {1}' -f $c.Verdict.ToUpper(), $c.Title)
            Add-LVLine $sb ('  Correlation : {0} ({1}, within {2})' -f $c.Id, $c.Type, $c.Timespan)
            Add-LVLine $sb ('  Signatures  : {0}' -f (@($c.InvolvedKeys) -join ', '))
            Add-LVLine $sb ('  Occurred    : {0} time(s)' -f @($c.Windows).Count)
            foreach ($w in @($c.Windows | Select-Object -First 10)) {
                Add-LVLine $sb ('    {0:yyyy-MM-dd HH:mm:ss} to {1:HH:mm:ss} ({2} record(s))' -f $w.Start, $w.End, @($w.Occurrences).Count)
            }
            if (@($c.Windows).Count -gt 10) {
                Add-LVLine $sb ('    ... and {0} more' -f (@($c.Windows).Count - 10))
            }
            Add-LVLine $sb ('  What it means: {0}' -f $c.Plain)
            Add-LVLine $sb ('  Why it matters: {0}' -f $c.Why)
            Add-LVLine $sb ('  Do this      : {0}' -f $c.Action)
            foreach ($fp in @($c.FalsePositives | Where-Object { $_ })) {
                Add-LVLine $sb ('  Could be innocent when: {0}' -f $fp)
            }
            Add-LVLine $sb
        }
        Add-LVLine $sb ('-' * 78)
        Add-LVLine $sb
    }

    foreach ($f in $Result.Findings) {
        Add-LVLine $sb ('[{0}] {1}' -f $f.Verdict.ToUpper(), $f.Title)
        Add-LVLine $sb ('  Signature   : {0}' -f $f.Key)
        Add-LVLine $sb ('  Occurrences : {0} ({1}/day) between {2} and {3}' -f $f.Count, $f.PerDay, (Format-LVWhen $f.FirstSeen), (Format-LVWhen $f.LastSeen))
        if ($f.PSObject.Properties['Burst'] -and $f.Burst) {
            Add-LVLine $sb ('  Burst       : began {0}; {1} occurrence(s) in {2} minute(s)' -f (Format-LVWhen $f.BurstOnset), $f.BurstCount, $f.BurstWindowMinutes)
        }
        $context = @()
        if ($f.ResultCode) { $context += 'result ' + [string]$f.ResultCode }
        if ($f.ExtendCode) { $context += 'extend ' + [string]$f.ExtendCode }
        if ($f.Phase) { $context += 'phase ' + [string]$f.Phase }
        if ($f.Operation) { $context += 'operation ' + [string]$f.Operation }
        if ($f.ProviderLocale) { $context += 'provider locale ' + [string]$f.ProviderLocale }
        if ($f.ErrorPhase -and $f.ErrorPhase -ne $f.Phase) { $context += 'catalog phase ' + [string]$f.ErrorPhase }
        if ($f.ErrorOperation -and $f.ErrorOperation -ne $f.Operation) { $context += 'catalog operation ' + [string]$f.ErrorOperation }
        if ($context.Count -gt 0) { Add-LVLine $sb ('  Structured   : {0}' -f ($context -join '; ')) }
        if ($f.FallbackMessage) { Add-LVLine $sb ('  Fallback text: {0}' -f $f.FallbackMessage) }
        Add-LVLine $sb ('  Rule        : {0} (confidence: {1}{2})' -f $f.RuleId, $f.Confidence, $(if ($f.Verified) { ', verified ' + $f.Verified } else { '' }))
        foreach ($fp in @($f.FalsePositives)) {
            Add-LVLine $sb ('  Not this if : {0}' -f $fp)
        }
        Add-LVLine $sb ('  Means       : {0}' -f $f.Plain)
        Add-LVLine $sb ('  Matters     : {0}' -f $f.Why)
        Add-LVLine $sb ('  Do this     : {0}' -f $f.Action)
        if ($f.PSObject.Properties['ModelExplanation'] -and $f.ModelExplanation) {
            $draft = $f.ModelExplanation
            Add-LVLine $sb ('  {0}' -f $draft.Label)
            Add-LVLine $sb ('    Possible meaning: {0}' -f $draft.Summary)
            foreach ($evidence in @($draft.Evidence)) {
                Add-LVLine $sb ('    Evidence cited  : {0}' -f $evidence)
            }
            Add-LVLine $sb ('    Uncertainty     : {0}' -f $draft.Uncertainty)
            Add-LVLine $sb ('    Local model     : {0}' -f $draft.Model)
        }
        if ($f.Reference) { Add-LVLine $sb ('  Reference   : {0}' -f $f.Reference) }
        foreach ($src in @($f.Sources)) {
            if (-not $src.uri) { continue }
            # Attribution is rendered next to the ruling it backs, because that is where
            # a reader decides whether to believe it - and where CC-BY and DRL require it.
            $credit = @($src.author, $src.licence) | Where-Object { $_ }
            if ($credit.Count -gt 0) {
                Add-LVLine $sb ('  Source      : {0} ({1})' -f $src.uri, ($credit -join ', '))
            } else {
                Add-LVLine $sb ('  Source      : {0}' -f $src.uri)
            }
        }
        Add-LVLine $sb ('  Evidence    : {0}' -f $f.SampleMessage)
        Add-LVLine $sb
    }

    if (@($Result.CrashArtifacts).Count -gt 0) {
        Add-LVLine $sb ('-' * 78)
        Add-LVLine $sb 'Crash evidence on disk (header metadata decoded when supported):'
        foreach ($c in $Result.CrashArtifacts) {
            Add-LVLine $sb ('  {0,-10} {1:yyyy-MM-dd HH:mm}  {2}' -f $c.Kind, $c.When, $c.Path)
            if ($c.Kind -eq 'minidump' -and $c.BugCheckCode) {
                Add-LVLine $sb ('             bug check {0} ({1}); parameters {2}' -f $c.BugCheckCode, $c.Architecture, (@($c.BugCheckParameters) -join ', '))
            } elseif ($c.Kind -eq 'wer' -and $c.Decoded) {
                Add-LVLine $sb ('             application {0}; module {1}; exception {2}' -f $c.App, $c.Module, $c.ExceptionCode)
            } elseif ($c.DecodeStatus) {
                Add-LVLine $sb ('             not decoded: {0}' -f $c.DecodeStatus)
            }
        }
        Add-LVLine $sb
    }

    return $sb.ToString()
}

function ConvertTo-LVHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    $sb = New-Object System.Text.StringBuilder

    $reportLocale = Get-LVLocalizationLocale
    Add-LVLine $sb ('<!DOCTYPE html><html lang="{0}"><head><meta charset="utf-8">' -f (ConvertTo-LVHtmlEncoded $reportLocale))
    Add-LVLine $sb '<meta name="viewport" content="width=device-width,initial-scale=1">'
    Add-LVLine $sb ('<title>LogVerdict - {0}</title>' -f (ConvertTo-LVHtmlEncoded $Result.MachineName))
    Add-LVLine $sb '<style>'
    Add-LVLine $sb @'
:root{--base:#1e1e2e;--mantle:#181825;--crust:#11111b;--s0:#313244;--s1:#45475a;
--text:#cdd6f4;--sub:#a6adc8;--over:#9399b2;--blue:#89b4fa;--mauve:#cba6f7}
/* --over carries the signature key, counts, dates and rule id at 11-13px, so it
   is content, not decoration, and must clear WCAG AA 4.5:1 for small text.
   Measured against the two surfaces it sits on: 6.22:1 on --mantle #181825,
   5.81:1 on --base #1e1e2e. The previous #6c7086 measured 3.59 and 3.36. */
*{box-sizing:border-box}
body{margin:0;background:var(--base);color:var(--text);
font:15px/1.6 "Segoe UI",system-ui,-apple-system,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 72px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.4px}
h1 span{color:var(--mauve)}
.sub{color:var(--over);font-size:13px;margin-bottom:28px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:28px}
.stat{background:var(--mantle);border:1px solid var(--s0);border-radius:10px;padding:14px 16px}
.stat .k{color:var(--over);font-size:11px;text-transform:uppercase;letter-spacing:.9px}
.stat .v{font-size:22px;font-weight:600;margin-top:4px}
.warn{background:#3a2b33;border:1px solid #f38ba8;border-left-width:4px;border-radius:8px;
padding:12px 16px;margin-bottom:24px;color:#f5c2d3;font-size:14px}
.warn ul{margin:8px 0 0;padding-left:20px}
.warn li{margin:4px 0}
.f{background:var(--mantle);border:1px solid var(--s0);border-left:4px solid var(--over);
border-radius:10px;padding:16px 18px;margin-bottom:14px}
.f h2{font-size:17px;margin:0 0 2px;font-weight:600}
.meta{color:var(--over);font-size:12px;font-family:Consolas,monospace;margin-bottom:12px;
word-break:break-word}
.badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:1.1px;
text-transform:uppercase;padding:3px 9px;border-radius:999px;margin-right:8px;
background:var(--s0);vertical-align:2px}
.row{display:flex;gap:10px;margin:7px 0;font-size:14px}
.row .lbl{color:var(--over);min-width:96px;flex-shrink:0;font-size:12px;
text-transform:uppercase;letter-spacing:.6px;padding-top:2px}
.act{color:#a6e3a1}
.model{background:var(--crust);border:1px dashed var(--mauve);border-radius:7px;
padding:10px 12px;margin:12px 0;color:var(--sub)}
.model strong{color:var(--mauve);font-size:11px;letter-spacing:.7px}
.model ul{margin:5px 0;padding-left:20px}
ul.fp{margin:0;padding-left:18px}
ul.fp li{margin:2px 0}
.filterbar{display:none;background:var(--mantle);border:1px solid var(--s0);border-radius:10px;
padding:14px 16px;margin:0 0 18px}
.filters-ready .filterbar{display:block}
.filter-title{font-size:13px;font-weight:700;margin-bottom:9px}
.filter-controls{display:flex;flex-wrap:wrap;align-items:end;gap:8px}
.toggle{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--s1);
border-radius:999px;padding:5px 10px;color:var(--sub);font-size:12px;cursor:pointer}
.toggle:focus-within{outline:2px solid var(--blue);outline-offset:2px}
.toggle input{margin:0;accent-color:var(--blue)}
.toggle b{color:var(--over);font-weight:500}
.search{display:flex;flex:1 1 260px;flex-direction:column;gap:3px;color:var(--over);
font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.search input{width:100%;min-height:34px;border:1px solid var(--s1);border-radius:7px;
background:var(--crust);color:var(--text);padding:6px 10px;font:14px "Segoe UI",sans-serif}
.search input:focus{outline:2px solid var(--blue);outline-offset:1px}
.reset{min-height:34px;border:1px solid var(--s1);border-radius:7px;background:var(--s0);
color:var(--text);padding:6px 12px;cursor:pointer}
.reset:hover{border-color:var(--blue)}
.filter-status{color:var(--over);font-size:12px;margin-top:9px}
.finding[hidden],.empty[hidden]{display:none}
.empty{border:1px dashed var(--s1);border-radius:8px;color:var(--sub);padding:20px;
text-align:center;margin-bottom:14px}
pre.ev{background:var(--crust);border:1px solid var(--s0);border-radius:6px;padding:10px 12px;
margin:12px 0 0;font:12px/1.5 Consolas,monospace;color:var(--sub);
white-space:pre-wrap;word-break:break-word;max-height:180px;overflow:auto}
a{color:var(--blue)}
footer{color:var(--over);font-size:12px;margin-top:36px;border-top:1px solid var(--s0);padding-top:16px}
@media(max-width:560px){.row{flex-direction:column;gap:2px}.row .lbl{padding-top:0}}
@media print{
  @page{margin:16mm}
  :root{--base:#fff;--mantle:#fff;--crust:#fff;--s0:#b8b8b8;--s1:#777;
  --text:#111;--sub:#222;--over:#444;--blue:#000;--mauve:#000}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  body{background:#fff;color:#111;font-size:10.5pt}
  .wrap{max-width:none;margin:0;padding:0}
  .filterbar,.no-script{display:none!important}
  .grid{grid-template-columns:repeat(4,1fr);gap:6mm;margin-bottom:8mm}
  .stat,.f,.warn,.model,pre.ev{background:#fff!important;color:#111!important;
  box-shadow:none}
  .stat,.f,.warn,.model{border-color:#777}
  .f,.stat,.warn,.model{break-inside:avoid-page;page-break-inside:avoid}
  pre.ev{max-height:none;overflow:visible;white-space:pre-wrap;border-color:#aaa}
  .sub,.meta,.row .lbl,footer{color:#333}
  .act,a{color:#000;text-decoration:none}
  footer{border-top-color:#777}
}
'@
    Add-LVLine $sb '</style></head><body><div class="wrap">'

    Add-LVLine $sb '<h1>Log<span>Verdict</span></h1>'
    Add-LVLine $sb ('<div class="sub">{0} &middot; scanned {1:yyyy-MM-dd HH:mm} &middot; last {2} day(s) &middot; elevated: {3} &middot; v{4}</div>' -f (ConvertTo-LVHtmlEncoded $Result.MachineName), $Result.ScanTime, $Result.DaysBack, $Result.Elevated, $Result.Version)

    $needsAttention = @($Result.Findings | Where-Object { (Get-LVVerdictRank -Verdict $_.Verdict) -ge (Get-LVVerdictRank -Verdict 'unknown') }).Count
    $staleRules = @()
    if ($Result.PSObject.Properties['DatabaseFreshness'] -and $Result.DatabaseFreshness) {
        $staleRules = @($Result.DatabaseFreshness.StaleRules | Where-Object { $_ })
    } else {
        $staleRules = @($Result.Findings | Where-Object { $_.PSObject.Properties['RuleStale'] -and $_.RuleStale } |
            ForEach-Object { [pscustomobject]@{ RuleId = $_.RuleId; Verified = $_.Verified; StaleAfterDays = $_.RuleFreshness.StaleAfterDays } })
    }

    Add-LVLine $sb '<div class="grid">'
    Add-LVLine $sb ('<div class="stat"><div class="k">Records read</div><div class="v">{0}</div></div>' -f $Result.Reduction.RecordCount)
    Add-LVLine $sb ('<div class="stat"><div class="k">Signatures</div><div class="v">{0}</div></div>' -f $Result.Reduction.SignatureCount)
    Add-LVLine $sb ('<div class="stat"><div class="k">Noise removed</div><div class="v">{0}:1</div></div>' -f $Result.Reduction.Ratio)
    Add-LVLine $sb ('<div class="stat"><div class="k">Needs attention</div><div class="v">{0}</div></div>' -f $needsAttention)
    if ($Result.Stability) {
        Add-LVLine $sb ('<div class="stat"><div class="k">Stability ({0})</div><div class="v">{1}/10</div></div>' -f (ConvertTo-LVHtmlEncoded $Result.Stability.Direction), $Result.Stability.Current)
    }
    Add-LVLine $sb ('<div class="stat"><div class="k">Stale rulings</div><div class="v">{0}</div></div>' -f $staleRules.Count)
    Add-LVLine $sb '</div>'
    if ($Result.Reduction.PSObject.Properties['InitialSignatureCount']) {
        Add-LVLine $sb ('<div class="sub">Template passes: {0} fully masked signatures ({1}:1 reduction) &rarr; {2} signatures after promoting {3} low-cardinality slot(s) ({4}:1 reduction).</div>' -f `
            $Result.Reduction.InitialSignatureCount, $Result.Reduction.InitialRatio, $Result.Reduction.SignatureCount,
            $Result.Reduction.PromotedSlotCount, $Result.Reduction.Ratio)
    }

    if ($Result.PSObject.Properties['SetupDiag'] -and $Result.SetupDiag) {
        Add-LVLine $sb ('<div class="sub">SetupDiag: {0}</div>' -f (ConvertTo-LVHtmlEncoded $Result.SetupDiag.Message))
    }

    if ($Result.PSObject.Properties['Redacted'] -and $Result.Redacted) {
        Add-LVLine $sb '<div class="warn"><strong>Redacted.</strong> Account name, machine name, profile paths, SIDs and mail addresses were masked in the evidence below. Identifiers Windows wrote in a form this tool does not recognize may remain, so read this before sending it on.</div>'
    }

    if ($Result.HorizonWarning) {
        Add-LVLine $sb ('<div class="warn"><strong>Coverage warning.</strong> {0}</div>' -f (ConvertTo-LVHtmlEncoded $Result.HorizonWarning))
    }

    if (@($Result.CoverageNotes).Count -gt 0) {
        Add-LVLine $sb '<div class="warn"><strong>What this scan could not see.</strong><ul>'
        foreach ($note in @($Result.CoverageNotes)) {
            Add-LVLine $sb ('<li>{0}</li>' -f (ConvertTo-LVHtmlEncoded $note))
        }
        Add-LVLine $sb '</ul></div>'
    }
    if ($Result.PSObject.Properties['History'] -and $Result.History) {
        $history = $Result.History
        Add-LVLine $sb '<div class="warn"><strong>BASELINE (ADVISORY ONLY).</strong>'
        Add-LVLine $sb ('<div>Status: {0}; persistence: {1}; {2} prior scan(s) in a {3}-day window.</div>' -f `
            (ConvertTo-LVHtmlEncoded $history.Status), (ConvertTo-LVHtmlEncoded $history.Persistence),
            $history.Baseline.SampleCount, $history.WindowDays)
        Add-LVLine $sb ('<div>Threshold: {0}</div>' -f (ConvertTo-LVHtmlEncoded $history.Threshold.Description))
        foreach ($signal in @($history.Signals | Where-Object { $_ })) {
            Add-LVLine $sb ('<div>Signal [{0}] {1}: {2}</div>' -f (ConvertTo-LVHtmlEncoded $signal.Type),
                (ConvertTo-LVHtmlEncoded $signal.Key), (ConvertTo-LVHtmlEncoded $signal.Reason))
        }
        Add-LVLine $sb ('<div>{0}</div><div>Trend signals never change curated verdicts, WorstVerdict, or ExitCode.</div></div>' -f `
            (ConvertTo-LVHtmlEncoded $history.FalsePositiveCaveat))
    }
    if ($Result.PSObject.Properties['AdvisoryStatus']) {
        Add-LVLine $sb '<div class="warn"><strong>DEPENDENCY ADVISORIES (SEPARATE FROM EVENT FINDINGS).</strong><div>These are package/tool knowledge records, not Windows event verdicts.</div>'
        Add-LVLine $sb ('<div>Status: {0}</div>' -f (ConvertTo-LVHtmlEncoded $Result.AdvisoryStatus))
        if ($Result.AdvisoryCache) {
            Add-LVLine $sb ('<div>Cache: {0}; {1} entry(s); updated {2}; source {3}; hash {4}</div>' -f `
                (ConvertTo-LVHtmlEncoded $Result.AdvisoryCache.Name), $Result.AdvisoryCache.EntryCount,
                (ConvertTo-LVHtmlEncoded $Result.AdvisoryCache.Updated), (ConvertTo-LVHtmlEncoded $Result.AdvisoryCache.Source),
                (ConvertTo-LVHtmlEncoded $Result.AdvisoryCache.SourceHash))
        }
        foreach ($advisory in @($Result.Advisories | Where-Object { $_ })) {
            $advisoryState = if ($advisory.Matched) { 'AFFECTED' } else { 'CACHE ENTRY' }
            Add-LVLine $sb ('<div><strong>[{0}] {1}</strong> - {2} {3}; range {4}; fixed {5}; CVSS {6}; KEV {7}; published {8}; modified {9}</div>' -f `
                (ConvertTo-LVHtmlEncoded $advisoryState), (ConvertTo-LVHtmlEncoded $advisory.Id),
                (ConvertTo-LVHtmlEncoded $advisory.Package), (ConvertTo-LVHtmlEncoded $advisory.Version),
                (ConvertTo-LVHtmlEncoded $advisory.AffectedRange), (ConvertTo-LVHtmlEncoded $advisory.FixedVersion),
                $advisory.CVSS, $advisory.KEV, (ConvertTo-LVHtmlEncoded $advisory.PublishedDate), (ConvertTo-LVHtmlEncoded $advisory.ModifiedDate))
            $advisoryUri = [string]$advisory.SourceUri
            $advisoryUriText = ConvertTo-LVHtmlEncoded $advisoryUri
            if (Test-LVAllowedUri -Uri $advisoryUri) {
                Add-LVLine $sb ('<div>{0}: <a href="{1}">{1}</a>; hash {2}</div>' -f `
                    (ConvertTo-LVHtmlEncoded $advisory.Source), $advisoryUriText,
                    (ConvertTo-LVHtmlEncoded $advisory.SourceHash))
            } else {
                Add-LVLine $sb ('<div>{0}: <span>{1}</span> (not a link: only http/https URIs are allowed); hash {2}</div>' -f `
                    (ConvertTo-LVHtmlEncoded $advisory.Source), $advisoryUriText,
                    (ConvertTo-LVHtmlEncoded $advisory.SourceHash))
            }
            Add-LVLine $sb ('<div>{0}</div>' -f (ConvertTo-LVHtmlEncoded $advisory.Description))
        }
        if (@($Result.Advisories).Count -eq 0 -and $Result.AdvisoryStatus -eq 'no-match') {
            Add-LVLine $sb '<div>No advisory in the supplied cache matches the requested package/version.</div>'
        }
        Add-LVLine $sb '</div>'
    }
    if ($staleRules.Count -gt 0) {
        $threshold = if ($Result.DatabaseFreshness.DefaultStaleAfterDays) { $Result.DatabaseFreshness.DefaultStaleAfterDays } else { $script:LVDefaultStaleAfterDays }
        Add-LVLine $sb '<div class="warn"><strong>Stale rule guidance.</strong> These active rules still match, but their guidance is past the declared freshness threshold and needs re-verification.'
        Add-LVLine $sb ('<div>Default threshold: {0} day(s); as of {1}. Showing up to 20 rule ids.</div><ul>' -f $threshold, (ConvertTo-LVHtmlEncoded ([string]$Result.DatabaseFreshness.AsOf)))
        foreach ($staleRule in @($staleRules | Select-Object -First 20)) {
            Add-LVLine $sb ('<li>{0}: last verified {1}; stale after {2} day(s)</li>' -f (ConvertTo-LVHtmlEncoded $staleRule.RuleId), (ConvertTo-LVHtmlEncoded $staleRule.Verified), $staleRule.StaleAfterDays)
        }
        Add-LVLine $sb '</ul></div>'
    }
    if ($Result.PSObject.Properties['CaseProfile'] -and $Result.CaseProfile) {
        Add-LVLine $sb '<div class="warn"><strong>CASE PROFILE / HANDOFF.</strong><div>Collection metadata and operator context; this is not a verdict.</div>'
        Add-LVLine $sb ('<div>Profile ID: {0}; name: {1}; sources: {2}; redacted: {3}</div>' -f `
            (ConvertTo-LVHtmlEncoded $Result.CaseProfile.profileId), (ConvertTo-LVHtmlEncoded $Result.CaseProfile.name),
            @($Result.CaseProfile.sources).Count, $Result.CaseProfile.redaction.requested)
        foreach ($note in @($Result.CaseProfile.notes | Where-Object { $_ })) {
            Add-LVLine $sb ('<div>Note: {0}</div>' -f (ConvertTo-LVHtmlEncoded $note))
        }
        Add-LVLine $sb '</div>'
    }
    if ($Result.PSObject.Properties['ProviderExtensions'] -and @($Result.ProviderExtensions).Count -gt 0) {
        Add-LVLine $sb '<div class="warn"><strong>PROVIDER EXTENSIONS (EXPLICIT, UNTRUSTED).</strong><div>Extensions contributed redacted evidence only; curated verdicts and rule IDs remain core-owned.</div>'
        foreach ($extension in @($Result.ProviderExtensions | Where-Object { $_ })) {
            Add-LVLine $sb ('<div>Provider: {0} {1}; {2} record(s); {3} rejected; trust: {4}</div>' -f `
                (ConvertTo-LVHtmlEncoded $extension.Id), (ConvertTo-LVHtmlEncoded $extension.Version),
                $extension.RecordCount, $extension.RejectedRecords, (ConvertTo-LVHtmlEncoded $extension.Trust))
        }
        foreach ($projection in @($Result.ProviderProjections | Where-Object { $_ })) {
            Add-LVLine $sb ('<div>Projection: {0}</div>' -f (ConvertTo-LVHtmlEncoded $projection.ProviderId))
            foreach ($field in @($projection.Fields.PSObject.Properties | Where-Object { $_ })) {
                Add-LVLine $sb ('<div>{0}: {1}</div>' -f (ConvertTo-LVHtmlEncoded $field.Name), (ConvertTo-LVHtmlEncoded ([string]$field.Value)))
            }
        }
        Add-LVLine $sb '</div>'
    }
    if (@($Result.Coverage).Count -gt 0) {
        Add-LVLine $sb '<h2>Coverage detail</h2><div class="sub">Every source is classified separately: empty means observed with no matching event; other statuses describe evidence that was not observed or could not be read.</div>'
        foreach ($source in @($Result.Coverage | Where-Object { $_ })) {
            $label = '{0}/{1} - {2}' -f $source.Source, $source.Kind, $source.Name
            $detail = New-Object 'System.Collections.Generic.List[string]'
            $detail.Add([string]$source.Status) | Out-Null
            if ($source.Reason) { $detail.Add([string]$source.Reason) | Out-Null }
            if ($null -ne $source.ObservedRecords) { $detail.Add(('{0} observed' -f $source.ObservedRecords)) | Out-Null }
            if ($source.RecordGap) { $detail.Add(('gap: ' + [string]$source.RecordGap)) | Out-Null }
            if ($source.ParserError) { $detail.Add(('parser: ' + [string]$source.ParserError)) | Out-Null }
            if ($source.PSObject.Properties['ReconnectCount']) { $detail.Add(('reconnects: ' + [string]$source.ReconnectCount)) | Out-Null }
            if ($source.PSObject.Properties['DroppedRecords']) { $detail.Add(('dropped: ' + [string]$source.DroppedRecords)) | Out-Null }
            if ($source.PSObject.Properties['AverageLatencyMilliseconds']) { $detail.Add(('average latency: ' + [string]$source.AverageLatencyMilliseconds + ' ms')) | Out-Null }
            if ($source.PSObject.Properties['MaxLatencyMilliseconds']) { $detail.Add(('max latency: ' + [string]$source.MaxLatencyMilliseconds + ' ms')) | Out-Null }
            Add-LVLine $sb ('<div class="row"><div class="lbl">{0}</div><div>{1}</div></div>' -f (ConvertTo-LVHtmlEncoded $label), (ConvertTo-LVHtmlEncoded ($detail -join '; ')))
        }
    }
    if (@($Result.HealthProfiles).Count -gt 0) {
        Add-LVLine $sb '<h2>Configuration health</h2><div class="sub">These profiles describe collection prerequisites and retention context. They are advisory coverage facts, never malicious verdicts.</div>'
        foreach ($health in @($Result.HealthProfiles | Where-Object { $_ })) {
            $label = '{0}/{1} - {2}' -f $health.Source, $health.Profile, $health.Name
            $detail = New-Object 'System.Collections.Generic.List[string]'
            $detail.Add([string]$health.Status) | Out-Null
            if ($health.ObservedConfiguration) { $detail.Add('observed: ' + [string]$health.ObservedConfiguration) | Out-Null }
            if ($health.RequiredConfiguration) { $detail.Add('required: ' + [string]$health.RequiredConfiguration) | Out-Null }
            if ($health.Reason) { $detail.Add('reason: ' + [string]$health.Reason) | Out-Null }
            if ($health.Advice) { $detail.Add('advice: ' + [string]$health.Advice) | Out-Null }
            Add-LVLine $sb ('<div class="row"><div class="lbl">{0}</div><div>{1}</div></div>' -f (ConvertTo-LVHtmlEncoded $label), (ConvertTo-LVHtmlEncoded ($detail -join '; ')))
        }
    }
    $performanceRows = @($Result.Performance | Where-Object { $_ })
    if ($performanceRows.Count -gt 0) {
        Add-LVLine $sb '<h2>Performance telemetry (opt-in; content-free)</h2><div class="sub">Source class, bounded counts and elapsed time only. Messages, paths, identifiers and signatures are not recorded.</div>'
        foreach ($metric in $performanceRows) {
            $state = [string]$metric.Status
            if ($metric.Slow) { $state += ' (slow)' }
            $label = '{0}/{1} - {2}' -f $metric.Source, $metric.Kind, $metric.Name
            $detail = '{0}; elapsed {1} ms; {2} observed; {3} skipped' -f $state, $metric.ElapsedMilliseconds, $metric.ObservedRecords, $metric.SkippedRecords
            if ($null -ne $metric.Cap) { $detail += '; cap ' + [string]$metric.Cap }
            Add-LVLine $sb ('<div class="row"><div class="lbl">{0}</div><div>{1}</div></div>' -f (ConvertTo-LVHtmlEncoded $label), (ConvertTo-LVHtmlEncoded $detail))
        }
    }

    $correlated = @($Result.Correlations | Where-Object { $_ })
    if ($correlated.Count -gt 0) {
        Add-LVLine $sb '<h2>Things that happened together</h2>'
        Add-LVLine $sb '<div class="sub">These signatures also appear individually below. Apart they describe symptoms; together they name a cause.</div>'
        foreach ($c in $correlated) {
            $chex = $script:LVVerdictHex[$c.Verdict]
            if (-not $chex) { $chex = '#6c7086' }

            Add-LVLine $sb ('<div class="f" style="border-left-color:{0}">' -f $chex)
            Add-LVLine $sb ('<div class="h"><span class="v" style="background:{0}">{1}</span> {2}</div>' -f `
                $chex, (ConvertTo-LVHtmlEncoded $c.Verdict.ToUpper()), (ConvertTo-LVHtmlEncoded $c.Title))
            Add-LVLine $sb ('<div class="meta">{0} &middot; {1} within {2} &middot; {3} occurrence(s)</div>' -f `
                (ConvertTo-LVHtmlEncoded ((@($c.RuleIds) -join ' + '))), (ConvertTo-LVHtmlEncoded $c.Type),
                (ConvertTo-LVHtmlEncoded $c.Timespan), @($c.Windows).Count)
            $when = (@($c.Windows | Select-Object -First 10 | ForEach-Object { '{0:yyyy-MM-dd HH:mm:ss} to {1:HH:mm:ss}' -f $_.Start, $_.End }) -join '; ')
            Add-LVLine $sb ('<div class="row"><div class="lbl">When</div><div class="val">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $when))
            Add-LVLine $sb ('<div class="row"><div class="lbl">Signatures</div><div class="val">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded ((@($c.InvolvedKeys) -join ', '))))
            Add-LVLine $sb ('<div class="row"><div class="lbl">What it means</div><div class="val">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $c.Plain))
            Add-LVLine $sb ('<div class="row"><div class="lbl">Why it matters</div><div class="val">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $c.Why))
            Add-LVLine $sb ('<div class="row"><div class="lbl">Do this</div><div class="val">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $c.Action))
            foreach ($fp in @($c.FalsePositives | Where-Object { $_ })) {
                Add-LVLine $sb ('<div class="row"><div class="lbl">Could be innocent when</div><div class="val">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $fp))
            }
            Add-LVLine $sb '</div>'
        }
        Add-LVLine $sb '<h2 id="findings-heading">Every signature</h2>'
    } else {
        Add-LVLine $sb '<h2 id="findings-heading">Findings</h2>'
    }

    Add-LVLine $sb '<div class="filterbar" id="finding-filters" aria-labelledby="filter-title">'
    Add-LVLine $sb '<div class="filter-title" id="filter-title">Filter findings</div><div class="filter-controls">'
    foreach ($verdict in @('critical', 'actionable', 'investigate', 'unknown', 'informational', 'benign')) {
        $count = @($Result.Findings | Where-Object { $_.Verdict -eq $verdict }).Count
        if ($count -eq 0) { continue }
        Add-LVLine $sb ('<label class="toggle"><input type="checkbox" data-filter-verdict="{0}" checked><span>{1}</span><b>{2}</b></label>' -f `
            (ConvertTo-LVHtmlEncoded $verdict), (ConvertTo-LVHtmlEncoded $verdict), $count)
    }
    Add-LVLine $sb '<label class="search" for="finding-search"><span>Search findings</span><input id="finding-search" type="search" autocomplete="off" placeholder="Title, provider, event ID, evidence..."></label>'
    Add-LVLine $sb '<button class="reset" id="reset-filters" type="button">Reset</button></div>'
    Add-LVLine $sb '<div class="filter-status" id="filter-status" aria-live="polite"></div></div>'
    Add-LVLine $sb '<noscript><div class="sub no-script">Filtering is unavailable because scripting is disabled; all findings are shown.</div></noscript>'
    Add-LVLine $sb '<div id="finding-list" aria-labelledby="findings-heading">'
    foreach ($f in $Result.Findings) {
        $hex = $script:LVVerdictHex[$f.Verdict]
        if (-not $hex) { $hex = '#6c7086' }

        Add-LVLine $sb ('<article class="f finding" data-verdict="{0}" style="border-left-color:{1}">' -f `
            (ConvertTo-LVHtmlEncoded $f.Verdict), $hex)
        Add-LVLine $sb ('<h2><span class="badge" style="color:{0}">{1}</span>{2}</h2>' -f $hex, $f.Verdict, (ConvertTo-LVHtmlEncoded $f.Title))
        Add-LVLine $sb ('<div class="meta">{0} &middot; {1} occurrence(s) &middot; {2}/day &middot; {3} to {4} &middot; rule {5} ({6}{7}{8})</div>' -f (ConvertTo-LVHtmlEncoded $f.Key), $f.Count, $f.PerDay, (Format-LVWhen $f.FirstSeen), (Format-LVWhen $f.LastSeen), $f.RuleId, $f.Confidence, $(if ($f.Verified) { ', verified ' + $f.Verified } else { '' }), $(if ($f.PSObject.Properties['RuleStale'] -and $f.RuleStale) { ', stale guidance' } else { '' }))
        if ($f.PSObject.Properties['Burst'] -and $f.Burst) {
            Add-LVLine $sb ('<div class="row"><div class="lbl">Burst</div><div>{0} &middot; {1} occurrence(s) in {2} minute(s)</div></div>' -f (Format-LVWhen $f.BurstOnset), $f.BurstCount, $f.BurstWindowMinutes)
        }
        $context = @()
        if ($f.ResultCode) { $context += 'result ' + [string]$f.ResultCode }
        if ($f.ExtendCode) { $context += 'extend ' + [string]$f.ExtendCode }
        if ($f.Phase) { $context += 'phase ' + [string]$f.Phase }
        if ($f.Operation) { $context += 'operation ' + [string]$f.Operation }
        if ($f.ProviderLocale) { $context += 'provider locale ' + [string]$f.ProviderLocale }
        if ($f.ErrorPhase -and $f.ErrorPhase -ne $f.Phase) { $context += 'catalog phase ' + [string]$f.ErrorPhase }
        if ($f.ErrorOperation -and $f.ErrorOperation -ne $f.Operation) { $context += 'catalog operation ' + [string]$f.ErrorOperation }
        if ($context.Count -gt 0) {
            Add-LVLine $sb ('<div class="row"><div class="lbl">Structured context</div><div>{0}</div></div>' -f (ConvertTo-LVHtmlEncoded ($context -join '; ')))
        }
        if ($f.FallbackMessage) {
            Add-LVLine $sb ('<div class="row"><div class="lbl">Fallback text</div><div>{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $f.FallbackMessage))
        }
        Add-LVLine $sb ('<div class="row"><div class="lbl">Means</div><div>{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $f.Plain))
        Add-LVLine $sb ('<div class="row"><div class="lbl">Matters</div><div>{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $f.Why))
        Add-LVLine $sb ('<div class="row"><div class="lbl">Do this</div><div class="act">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $f.Action))
        if ($f.PSObject.Properties['ModelExplanation'] -and $f.ModelExplanation) {
            $draft = $f.ModelExplanation
            $modelEvidence = ((@($draft.Evidence) | ForEach-Object { '<li>' + (ConvertTo-LVHtmlEncoded $_) + '</li>' }) -join '')
            Add-LVLine $sb ('<div class="model"><strong>{0}</strong><div>Possible meaning: {1}</div><ul>{2}</ul><div>Uncertainty: {3}</div><div class="meta">Local model: {4}</div></div>' -f `
                (ConvertTo-LVHtmlEncoded $draft.Label), (ConvertTo-LVHtmlEncoded $draft.Summary), $modelEvidence,
                (ConvertTo-LVHtmlEncoded $draft.Uncertainty), (ConvertTo-LVHtmlEncoded $draft.Model))
        }
        if (@($f.FalsePositives).Count -gt 0) {
            $fpItems = ((@($f.FalsePositives) | ForEach-Object { '<li>' + (ConvertTo-LVHtmlEncoded $_) + '</li>' }) -join '')
            Add-LVLine $sb ('<div class="row"><div class="lbl">Not this if</div><div><ul class="fp">{0}</ul></div></div>' -f $fpItems)
        }
        foreach ($src in @($f.Sources)) {
            if (-not $src.uri) { continue }
            $rawUri = [string]$src.uri
            $uri = ConvertTo-LVHtmlEncoded $rawUri
            $credit = @($src.author, $src.licence) | Where-Object { $_ }
            $suffix = ''
            if ($credit.Count -gt 0) { $suffix = ' ' + (ConvertTo-LVHtmlEncoded (('({0})' -f ($credit -join ', ')))) }
            if (Test-LVAllowedUri -Uri $rawUri) {
                Add-LVLine $sb ('<div class="row"><div class="lbl">Source</div><div><a href="{0}">{1}</a>{2}</div></div>' -f $uri, $uri, $suffix)
            } else {
                Add-LVLine $sb ('<div class="row"><div class="lbl">Source</div><div><span>{0}</span> (not a link: only http/https URIs are allowed){1}</div></div>' -f $uri, $suffix)
            }
        }
        if ($f.Reference) {
            $rawReference = [string]$f.Reference
            $ref = ConvertTo-LVHtmlEncoded $rawReference
            if (Test-LVAllowedUri -Uri $rawReference) {
                Add-LVLine $sb ('<div class="row"><div class="lbl">Reference</div><div><a href="{0}">{1}</a></div></div>' -f $ref, $ref)
            } else {
                Add-LVLine $sb ('<div class="row"><div class="lbl">Reference</div><div><span>{0}</span> (not a link: only http/https URIs are allowed)</div></div>' -f $ref)
            }
        }
        Add-LVLine $sb ('<pre class="ev">{0}</pre>' -f (ConvertTo-LVHtmlEncoded $f.SampleMessage))
        Add-LVLine $sb '</article>'
    }
    Add-LVLine $sb '<div class="empty" id="filter-empty" hidden>No findings match the selected filters.</div></div>'

    if (@($Result.CrashArtifacts).Count -gt 0) {
        Add-LVLine $sb '<div class="f" style="border-left-color:#cba6f7"><h2>Crash evidence on disk</h2>'
        Add-LVLine $sb '<div class="meta">Report.wer fields and supported kernel dump headers are decoded. Naming a driver from a dump stack still needs a debugger and symbols.</div>'
        foreach ($c in $Result.CrashArtifacts) {
            Add-LVLine $sb ('<div class="row"><div class="lbl">{0}</div><div>{1:yyyy-MM-dd HH:mm} &middot; {2}</div></div>' -f $c.Kind, $c.When, (ConvertTo-LVHtmlEncoded $c.Path))
            if ($c.Kind -eq 'minidump' -and $c.BugCheckCode) {
                Add-LVLine $sb ('<div class="meta">Bug check {0} ({1}); parameters {2}</div>' -f (ConvertTo-LVHtmlEncoded $c.BugCheckCode), (ConvertTo-LVHtmlEncoded $c.Architecture), (ConvertTo-LVHtmlEncoded (@($c.BugCheckParameters) -join ', ')))
            } elseif ($c.Kind -eq 'wer' -and $c.Decoded) {
                Add-LVLine $sb ('<div class="meta">Application {0}; module {1}; exception {2}</div>' -f (ConvertTo-LVHtmlEncoded $c.App), (ConvertTo-LVHtmlEncoded $c.Module), (ConvertTo-LVHtmlEncoded $c.ExceptionCode))
            } elseif ($c.DecodeStatus) {
                Add-LVLine $sb ('<div class="meta">Not decoded: {0}</div>' -f (ConvertTo-LVHtmlEncoded $c.DecodeStatus))
            }
        }
        Add-LVLine $sb '</div>'
    }

    if (@($Result.Findings | Where-Object { $_.PSObject.Properties['ModelExplanation'] -and $_.ModelExplanation }).Count -gt 0) {
        Add-LVLine $sb '<footer>Generated by LogVerdict. Verdicts, actions and unlabelled explanations come only from the curated rule database. Any optional local-model text is isolated inside a MODEL-GENERATED CANDIDATE block, contains no remediation, and is not a ruling.</footer>'
    } else {
        Add-LVLine $sb '<footer>Generated by LogVerdict. Every explanation above comes from a curated rule in the verdict database, not from a language model. Signatures with no matching rule are reported as unknown, with their raw evidence and no guess at a cause.</footer>'
    }
    Add-LVLine $sb @'
<script>
(function(){
  var panel=document.getElementById('finding-filters');
  var list=document.getElementById('finding-list');
  if(!panel||!list){return;}
  document.documentElement.classList.add('filters-ready');
  var cards=Array.prototype.slice.call(list.querySelectorAll('.finding'));
  var checks=Array.prototype.slice.call(panel.querySelectorAll('[data-filter-verdict]'));
  var search=document.getElementById('finding-search');
  var status=document.getElementById('filter-status');
  var empty=document.getElementById('filter-empty');
  function apply(){
    var enabled={};
    checks.forEach(function(box){enabled[box.getAttribute('data-filter-verdict')]=box.checked;});
    var query=search.value.trim().toLowerCase();
    var shown=0;
    cards.forEach(function(card){
      var visible=enabled[card.getAttribute('data-verdict')]!==false&&
        (!query||card.textContent.toLowerCase().indexOf(query)!==-1);
      card.hidden=!visible;
      if(visible){shown++;}
    });
    empty.hidden=shown!==0;
    status.textContent='Showing '+shown+' of '+cards.length+' findings';
  }
  checks.forEach(function(box){box.addEventListener('change',apply);});
  search.addEventListener('input',apply);
  document.getElementById('reset-filters').addEventListener('click',function(){
    checks.forEach(function(box){box.checked=true;});
    search.value='';
    apply();
    search.focus();
  });
  apply();
})();
</script>
'@
    Add-LVLine $sb '</div></body></html>'

    return ConvertTo-LVLocalizedMarkup -Markup $sb.ToString()
}
