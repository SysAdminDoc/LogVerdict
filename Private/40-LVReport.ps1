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
    [void]$Builder.AppendLine($Text)
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
            ScanTime          = if ($Result.ScanTime) { ([datetime]$Result.ScanTime).ToString('o') } else { $null }
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
            FirstSeen         = if ($finding.FirstSeen) { ([datetime]$finding.FirstSeen).ToString('o') } else { $null }
            LastSeen          = if ($finding.LastSeen) { ([datetime]$finding.LastSeen).ToString('o') } else { $null }
            Verdict           = $finding.Verdict
            Title             = $finding.Title
            RuleId            = $finding.RuleId
            Confidence        = $finding.Confidence
            Plain             = $finding.Plain
            Why               = $finding.Why
            Action            = $finding.Action
            SampleMessage     = $finding.SampleMessage
            ErrorCode         = $finding.ErrorCode
            ErrorCatalogKind  = $finding.ErrorCatalogKind
            ErrorName         = $finding.ErrorName
            Reference         = $finding.Reference
            Burst             = if ($finding.PSObject.Properties['Burst']) { $finding.Burst } else { $false }
            BurstOnset        = if ($finding.PSObject.Properties['BurstOnset'] -and $finding.BurstOnset) { ([datetime]$finding.BurstOnset).ToString('o') } else { $null }
            BurstCount        = if ($finding.PSObject.Properties['BurstCount']) { $finding.BurstCount } else { $null }
            BurstWindowMinutes = if ($finding.PSObject.Properties['BurstWindowMinutes']) { $finding.BurstWindowMinutes } else { $null }
            CoverageSource    = $null; CoverageKind = $null; CoverageName = $null; CoverageStatus = $null
            CoverageReason    = $null; CoveragePath = $null; CoverageWindowStart = $null; CoverageWindowEnd = $null
            CoverageCap       = $null; CoverageObservedRecords = $null; CoverageSkippedRecords = $null
            CoverageRecordGap = $null; CoverageParserError = $null; CoverageSizeBytes = $null
            CoverageParseMilliseconds = $null; CoverageSHA256 = $null; CoverageOrigin = $null
        }
    }
}

function ConvertTo-LVCoverageCsvRow {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)]$Coverage)

    return [pscustomobject][ordered]@{
        RowType           = 'coverage'
        ScanTime          = if ($Result.ScanTime) { ([datetime]$Result.ScanTime).ToString('o') } else { $null }
        MachineName       = $Result.MachineName
        DaysBack          = $Result.DaysBack
        Elevated          = $Result.Elevated
        Channel           = $null; Source = $null; Provider = $null; Id = $null; Key = $null
        Count             = $null; PerDay = $null; FirstSeen = $null; LastSeen = $null
        Verdict           = $null; Title = $null; RuleId = $null; Confidence = $null
        Plain             = $null; Why = $null; Action = $null; SampleMessage = $null
        ErrorCode         = $null; ErrorCatalogKind = $null; ErrorName = $null; Reference = $null
        Burst             = $null; BurstOnset = $null; BurstCount = $null; BurstWindowMinutes = $null
        CoverageSource    = $Coverage.Source; CoverageKind = $Coverage.Kind; CoverageName = $Coverage.Name
        CoverageStatus    = $Coverage.Status; CoverageReason = $Coverage.Reason; CoveragePath = $Coverage.Path
        CoverageWindowStart = if ($Coverage.WindowStart) { ([datetime]$Coverage.WindowStart).ToString('o') } else { $null }
        CoverageWindowEnd = if ($Coverage.WindowEnd) { ([datetime]$Coverage.WindowEnd).ToString('o') } else { $null }
        CoverageCap       = $Coverage.Cap; CoverageObservedRecords = $Coverage.ObservedRecords
        CoverageSkippedRecords = $Coverage.SkippedRecords; CoverageRecordGap = $Coverage.RecordGap
        CoverageParserError = $Coverage.ParserError; CoverageSizeBytes = $Coverage.SizeBytes
        CoverageParseMilliseconds = $Coverage.ParseMilliseconds; CoverageSHA256 = $Coverage.SHA256
        CoverageOrigin    = $Coverage.Origin
    }
}

function ConvertTo-LVCsvReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result)

    $rows = @(ConvertTo-LVFlatFindingRow -Result $Result)
    foreach ($coverage in @($Result.Coverage | Where-Object { $_ })) {
        $rows += ConvertTo-LVCoverageCsvRow -Result $Result -Coverage $coverage
    }
    if ($rows.Count -gt 0) {
        return (($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine
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
        ErrorCode = $null; ErrorCatalogKind = $null; ErrorName = $null; Reference = $null
        Burst = $null; BurstOnset = $null; BurstCount = $null; BurstWindowMinutes = $null
        CoverageSource = $null; CoverageKind = $null; CoverageName = $null; CoverageStatus = $null
        CoverageReason = $null; CoveragePath = $null; CoverageWindowStart = $null; CoverageWindowEnd = $null
        CoverageCap = $null; CoverageObservedRecords = $null; CoverageSkippedRecords = $null
        CoverageRecordGap = $null; CoverageParserError = $null; CoverageSizeBytes = $null
        CoverageParseMilliseconds = $null; CoverageSHA256 = $null; CoverageOrigin = $null
    }
    $headerLine = @($header | ConvertTo-Csv -NoTypeInformation)[0]
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

    Add-LVLine $sb '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
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

    Add-LVLine $sb '<div class="grid">'
    Add-LVLine $sb ('<div class="stat"><div class="k">Records read</div><div class="v">{0}</div></div>' -f $Result.Reduction.RecordCount)
    Add-LVLine $sb ('<div class="stat"><div class="k">Signatures</div><div class="v">{0}</div></div>' -f $Result.Reduction.SignatureCount)
    Add-LVLine $sb ('<div class="stat"><div class="k">Noise removed</div><div class="v">{0}:1</div></div>' -f $Result.Reduction.Ratio)
    Add-LVLine $sb ('<div class="stat"><div class="k">Needs attention</div><div class="v">{0}</div></div>' -f $needsAttention)
    if ($Result.Stability) {
        Add-LVLine $sb ('<div class="stat"><div class="k">Stability ({0})</div><div class="v">{1}/10</div></div>' -f (ConvertTo-LVHtmlEncoded $Result.Stability.Direction), $Result.Stability.Current)
    }
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
            Add-LVLine $sb ('<div class="row"><div class="lbl">{0}</div><div>{1}</div></div>' -f (ConvertTo-LVHtmlEncoded $label), (ConvertTo-LVHtmlEncoded ($detail -join '; ')))
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
        Add-LVLine $sb ('<div class="meta">{0} &middot; {1} occurrence(s) &middot; {2}/day &middot; {3} to {4} &middot; rule {5} ({6}{7})</div>' -f (ConvertTo-LVHtmlEncoded $f.Key), $f.Count, $f.PerDay, (Format-LVWhen $f.FirstSeen), (Format-LVWhen $f.LastSeen), $f.RuleId, $f.Confidence, $(if ($f.Verified) { ', verified ' + $f.Verified } else { '' }))
        if ($f.PSObject.Properties['Burst'] -and $f.Burst) {
            Add-LVLine $sb ('<div class="row"><div class="lbl">Burst</div><div>{0} &middot; {1} occurrence(s) in {2} minute(s)</div></div>' -f (Format-LVWhen $f.BurstOnset), $f.BurstCount, $f.BurstWindowMinutes)
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
            $uri = ConvertTo-LVHtmlEncoded $src.uri
            $credit = @($src.author, $src.licence) | Where-Object { $_ }
            $suffix = ''
            if ($credit.Count -gt 0) { $suffix = ' ' + (ConvertTo-LVHtmlEncoded (('({0})' -f ($credit -join ', ')))) }
            Add-LVLine $sb ('<div class="row"><div class="lbl">Source</div><div><a href="{0}">{1}</a>{2}</div></div>' -f $uri, $uri, $suffix)
        }
        if ($f.Reference) {
            $ref = ConvertTo-LVHtmlEncoded $f.Reference
            Add-LVLine $sb ('<div class="row"><div class="lbl">Reference</div><div><a href="{0}">{1}</a></div></div>' -f $ref, $ref)
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

    return $sb.ToString()
}
