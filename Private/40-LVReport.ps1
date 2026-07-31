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
    if ($stat.LoudestKey) {
        Write-Host ('  Loudest         : {0} at {1}% of all records' -f $stat.LoudestKey, $stat.LoudestShare)
    }
    Write-Host ('  Elevated        : {0}' -f $Result.Elevated)
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

    $notable = @($Result.Findings | Where-Object { (Get-LVVerdictRank -Verdict $_.Verdict) -ge (Get-LVVerdictRank -Verdict 'unknown') })
    if ($notable.Count -eq 0) {
        Write-LVLog -Level ok -Message 'Nothing above the informational line in this window.'
    }

    foreach ($f in $notable) {
        $color = $script:LVVerdictColor[$f.Verdict]
        Write-Host ''
        Write-Host ('  [{0}] {1}' -f $f.Verdict.ToUpper(), $f.Title) -ForegroundColor $color
        Write-Host ('    {0}  x{1}  ({2}/day, last seen {3})' -f $f.Key, $f.Count, $f.PerDay, (Format-LVWhen $f.LastSeen)) -ForegroundColor DarkGray
        Write-Host ('    What it means : {0}' -f $f.Plain)
        Write-Host ('    Why it matters: {0}' -f $f.Why)
        Write-Host ('    Do this       : {0}' -f $f.Action) -ForegroundColor White
    }
    Write-Host ''
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

    foreach ($f in $Result.Findings) {
        Add-LVLine $sb ('[{0}] {1}' -f $f.Verdict.ToUpper(), $f.Title)
        Add-LVLine $sb ('  Signature   : {0}' -f $f.Key)
        Add-LVLine $sb ('  Occurrences : {0} ({1}/day) between {2} and {3}' -f $f.Count, $f.PerDay, (Format-LVWhen $f.FirstSeen), (Format-LVWhen $f.LastSeen))
        Add-LVLine $sb ('  Rule        : {0} (confidence: {1})' -f $f.RuleId, $f.Confidence)
        Add-LVLine $sb ('  Means       : {0}' -f $f.Plain)
        Add-LVLine $sb ('  Matters     : {0}' -f $f.Why)
        Add-LVLine $sb ('  Do this     : {0}' -f $f.Action)
        if ($f.Reference) { Add-LVLine $sb ('  Reference   : {0}' -f $f.Reference) }
        Add-LVLine $sb ('  Evidence    : {0}' -f $f.SampleMessage)
        Add-LVLine $sb
    }

    if (@($Result.CrashArtifacts).Count -gt 0) {
        Add-LVLine $sb ('-' * 78)
        Add-LVLine $sb 'Crash evidence on disk (collected, not decoded - decoding needs a debugger):'
        foreach ($c in $Result.CrashArtifacts) {
            Add-LVLine $sb ('  {0,-10} {1:yyyy-MM-dd HH:mm}  {2}' -f $c.Kind, $c.When, $c.Path)
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
--text:#cdd6f4;--sub:#a6adc8;--over:#6c7086;--blue:#89b4fa;--mauve:#cba6f7}
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
pre.ev{background:var(--crust);border:1px solid var(--s0);border-radius:6px;padding:10px 12px;
margin:12px 0 0;font:12px/1.5 Consolas,monospace;color:var(--sub);
white-space:pre-wrap;word-break:break-word;max-height:180px;overflow:auto}
a{color:var(--blue)}
footer{color:var(--over);font-size:12px;margin-top:36px;border-top:1px solid var(--s0);padding-top:16px}
@media(max-width:560px){.row{flex-direction:column;gap:2px}.row .lbl{padding-top:0}}
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
    Add-LVLine $sb '</div>'

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

    foreach ($f in $Result.Findings) {
        $hex = $script:LVVerdictHex[$f.Verdict]
        if (-not $hex) { $hex = '#6c7086' }

        Add-LVLine $sb ('<div class="f" style="border-left-color:{0}">' -f $hex)
        Add-LVLine $sb ('<h2><span class="badge" style="color:{0}">{1}</span>{2}</h2>' -f $hex, $f.Verdict, (ConvertTo-LVHtmlEncoded $f.Title))
        Add-LVLine $sb ('<div class="meta">{0} &middot; {1} occurrence(s) &middot; {2}/day &middot; {3} to {4} &middot; rule {5} ({6})</div>' -f (ConvertTo-LVHtmlEncoded $f.Key), $f.Count, $f.PerDay, (Format-LVWhen $f.FirstSeen), (Format-LVWhen $f.LastSeen), $f.RuleId, $f.Confidence)
        Add-LVLine $sb ('<div class="row"><div class="lbl">Means</div><div>{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $f.Plain))
        Add-LVLine $sb ('<div class="row"><div class="lbl">Matters</div><div>{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $f.Why))
        Add-LVLine $sb ('<div class="row"><div class="lbl">Do this</div><div class="act">{0}</div></div>' -f (ConvertTo-LVHtmlEncoded $f.Action))
        if ($f.Reference) {
            $ref = ConvertTo-LVHtmlEncoded $f.Reference
            Add-LVLine $sb ('<div class="row"><div class="lbl">Reference</div><div><a href="{0}">{1}</a></div></div>' -f $ref, $ref)
        }
        Add-LVLine $sb ('<pre class="ev">{0}</pre>' -f (ConvertTo-LVHtmlEncoded $f.SampleMessage))
        Add-LVLine $sb '</div>'
    }

    if (@($Result.CrashArtifacts).Count -gt 0) {
        Add-LVLine $sb '<div class="f" style="border-left-color:#cba6f7"><h2>Crash evidence on disk</h2>'
        Add-LVLine $sb '<div class="meta">Collected, not decoded. Reading a minidump needs a debugger and symbols.</div>'
        foreach ($c in $Result.CrashArtifacts) {
            Add-LVLine $sb ('<div class="row"><div class="lbl">{0}</div><div>{1:yyyy-MM-dd HH:mm} &middot; {2}</div></div>' -f $c.Kind, $c.When, (ConvertTo-LVHtmlEncoded $c.Path))
        }
        Add-LVLine $sb '</div>'
    }

    Add-LVLine $sb '<footer>Generated by LogVerdict. Every explanation above comes from a curated rule in the verdict database, not from a language model. Signatures with no matching rule are reported as unknown, with their raw evidence and no guess at a cause.</footer>'
    Add-LVLine $sb '</div></body></html>'

    return $sb.ToString()
}
