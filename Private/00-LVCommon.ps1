# Shared helpers. Loaded first (numeric filename prefix controls dot-source order).

# Verdict vocabulary, ordered least to most alarming. The rank drives report sorting
# and the exit code. "unknown" outranks "informational" on purpose: an unrecognized
# error is a lead, not background noise.
$script:LVVerdictRank = @{
    'benign'        = 0
    'informational' = 1
    'unknown'       = 2
    'investigate'   = 3
    'actionable'    = 4
    'critical'      = 5
}

# Verdict database schema versions this module understands. Loading a newer database
# than the code knows about is a hard failure, not a best effort: silently mis-reading
# rules would produce confident rulings from fields the code never looked at.
$script:LVSchemaVersionMin = 1
$script:LVSchemaVersionMax = 5

# How many occurrence timestamps a single signature retains for correlation. Past
# this the signature is a continuous stream rather than a set of incidents, and
# "did it coincide with something" is no longer a meaningful question about it.
$script:LVMaxSignatureTimes = 2000

# Correlation types, from the Sigma Correlation Rules Specification v2.1.0. Named
# after Sigma's vocabulary on purpose: anyone who can read a Sigma correlation can
# read one of these. The window is NOT Sigma's, though - see 25-LVCorrelate.ps1.
$script:LVCorrelationType = @('temporal', 'temporal_ordered', 'event_count')

# Whether Reliability Monitor answered on this scan. Declared here so the variable
# always exists: a scan that skipped the source and a scan whose provider is missing
# have to be distinguishable from one that read it, and "absent" must never be
# reported as "clean".
$script:LVReliabilityAvailable = $true
$script:LVReliabilitySkipReason = $null

# Rule lifecycle, aligned with the Sigma specification's 'status' vocabulary.
# Only these statuses are ever applied to a signature; deprecated and unsupported
# rules stay in the database for traceability but never produce a verdict.
$script:LVRuleStatus = @('stable', 'test', 'experimental', 'deprecated', 'unsupported')
$script:LVActiveRuleStatus = @('stable', 'test', 'experimental')

# A ruling that asserts "Microsoft says ignore this" is only as good as the day it was
# checked. Rules older than this without re-verification are reported as stale.
$script:LVVerificationMaxAgeMonths = 24

# The machine's UI language, captured once. Rules whose messagePattern is matched
# against localized event text declare the locale they were written for, and are
# skipped when it does not match rather than silently failing to fire.
$script:LVUICulture = (Get-UICulture).Name

$script:LVLogLines = New-Object System.Collections.Generic.List[string]

# Optional live feed of log lines, set by a caller that cannot see Write-Host output.
# The GUI runs a scan in a background runspace, where Write-Host goes nowhere a user
# can read; it hands in a concurrent queue here and drains it from the UI thread.
# Declared here so the variable always exists and Write-LVLog never has to test for
# its absence.
$script:LVLogSink = $null

function Write-LVLog {
    <#
        .SYNOPSIS
        Console + in-memory diagnostic line. Never writes to the output stream,
        so callers capturing a function's return value do not swallow log text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('info', 'ok', 'warn', 'error', 'step')][string]$Level = 'info'
    )

    $marks = @{ info = '[ ]'; ok = '[+]'; warn = '[!]'; error = '[x]'; step = '==='; }
    $colors = @{ info = 'Gray'; ok = 'Green'; warn = 'Yellow'; error = 'Red'; step = 'Cyan'; }

    $line = '{0} {1}' -f $marks[$Level], $Message
    $stamped = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $line
    $script:LVLogLines.Add($stamped)

    # Enqueue, never invoke a callback: the scan runs on a worker thread and touching
    # a WPF control from there throws. A queue lets the UI thread pull on its own timer.
    #
    # Three pipe-separated fields, and the reader splits with a cap of 3 so a message
    # containing its own pipes stays intact. The timestamp travels rather than being
    # stamped on arrival, so a transcript rebuilt by the reader records when the line
    # was written and not when the UI happened to drain it.
    if ($null -ne $script:LVLogSink) {
        try {
            $payload = '{0}|{1:yyyy-MM-dd HH:mm:ss}|{2}' -f $Level, (Get-Date), $Message
            $script:LVLogSink.Enqueue($payload)
        } catch {
            # A disposed queue must not take a scan down with it.
            Write-Verbose ("Log sink dropped: {0}" -f $_.Exception.Message)
            $script:LVLogSink = $null
        }
    }

    Write-Host $line -ForegroundColor $colors[$Level]
}

function ConvertTo-LVArrayOutput {
    <#
        .SYNOPSIS
        Return an array from a function without PowerShell unrolling it, and without
        the empty-collection trap.

        .DESCRIPTION
        Two idioms are wrong here and this avoids both.

        `return , $array` keeps a populated array intact but turns an EMPTY one into a
        single-element array whose only element is the empty array, so callers iterate
        once over a phantom item.

        Mixing the two - nothing for empty, a wrapped array otherwise - is worse still,
        because `@(f).Count` then answers 0 for an empty result and 1 for a result of
        fifty records. Callers cannot write uniform code against that.

        The contract is therefore plain PowerShell streaming: emit each element, emit
        nothing when there are none. `@(f)` counts correctly in every case, and
        `foreach ($x in (f))` iterates correctly in every case.
    #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Value)

    if ($null -eq $Value -or $Value.Count -eq 0) { return @() }
    return $Value
}

function Get-LVHostDirectory {
    <#
        .SYNOPSIS
        The directory the tool is running from, module or compiled executable.

        .DESCRIPTION
        $PSScriptRoot is empty inside a ps2exe-compiled binary, so the single-file build
        would otherwise lose track of where it lives and stop honouring a
        verdicts.local.json sitting next to the .exe. Falls back to the host process
        path, which is the .exe in a compiled build.
    #>
    if ($script:LVModuleRoot) { return $script:LVModuleRoot }
    try {
        $proc = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        if ($proc) { return (Split-Path -Parent $proc) }
    } catch {
        # Reading MainModule can be refused by a host or a security product. That is
        # not worth failing a scan over, so fall back to the working directory - but
        # say so, because it changes where verdicts.local.json is looked for.
        Write-Verbose ("Could not resolve the host executable path ({0}); using the working directory." -f $_.Exception.Message)
    }
    return (Get-Location).Path
}

function Write-LVTextFile {
    <#
        .SYNOPSIS
        Write UTF-8 text with no byte order mark.

        .DESCRIPTION
        `Set-Content -Encoding UTF8` emits a BOM under Windows PowerShell 5.1 (PS 7
        does not, so the bug is invisible if you only test on pwsh). A BOM makes the
        JSON report unreadable to strict parsers - Python's json.load raises
        "Unexpected UTF-8 BOM" - and the JSON report is the machine-readable contract
        this tool offers, so it has to be clean.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Get-LVLogTranscript {
    return ConvertTo-LVArrayOutput -Value @($script:LVLogLines.ToArray())
}

function Test-LVElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LVVerdictRank {
    param([string]$Verdict)
    if ($script:LVVerdictRank.ContainsKey($Verdict)) { return $script:LVVerdictRank[$Verdict] }
    return $script:LVVerdictRank['unknown']
}

function ConvertTo-LVTemplate {
    <#
        .SYNOPSIS
        Collapses the variable parts of a log line so that repeated occurrences
        group into one signature. This is the same idea as Drain template mining,
        reduced to a masking pass that needs no dependencies.

        .DESCRIPTION
        Order matters: longer/more specific patterns are masked before shorter ones,
        otherwise the number mask eats the insides of GUIDs and paths.

        One value is deliberately NOT masked. On CBS, DISM and Windows Update the error
        code IS the diagnosis - 0x800f081f (no source), 0x80073712 (component store
        corrupt) and 0x800f0922 (system partition full) are three different problems
        with three different fixes. Masking them reported all three as one finding,
        which defeated the whole point of the tool on the log families it is most
        useful for. Short hex is therefore preserved inside the placeholder; long hex
        is an address or a handle and stays masked.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $t = $Text

    # Structured identities first. Each contains digits, hex and dots that the generic
    # masks below would otherwise chew apart from the inside out.
    $t = $t -replace '\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?', '<GUID>'
    # Windows package identity: name~publicKeyToken~arch~language~version. Masked whole
    # so one servicing failure recurring across thirty updates is one signature and not
    # thirty. The trailing version is consumed here, which is also what stops it being
    # misread as an IP address below.
    $t = $t -replace '[\w.\-]+~[0-9A-Fa-f]{16}~\w*~\w*~[\d.]+', '<PKG>'
    $t = $t -replace '\bKB\d{5,}\b', '<KB>'
    $t = $t -replace '\b[A-Za-z]:\\[^\s,;"'')]*', '<PATH>'
    $t = $t -replace '\\\\[^\s,;"'')]+', '<UNC>'

    # A build number and an IPv4 address are both dotted integers, so the octet range
    # is what separates them: no octet can exceed 255, but a version segment routinely
    # does. Anything dotted that fails the address test is treated as a version.
    $t = $t -replace '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b', '<IP>'
    $t = $t -replace '\b\d+(?:\.\d+){2,}\b', '<VER>'

    $t = $t -replace '\b\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2}\S*)?', '<TIME>'
    $t = $t -replace '\b\d{2}:\d{2}:\d{2}(\.\d+)?\b', '<TIME>'
    $t = $t -replace '\b\d+\b', '<NUM>'

    # Error codes run AFTER the number mask, not before. The preserved value sits
    # between non-word characters, so an all-digit code such as 0x12345678 would
    # otherwise be re-masked into <HEX:<NUM>>. Normalized to lower case so 0x800F081F
    # and 0x800f081f are the same signature.
    $t = [regex]::Replace($t, '\b0x([0-9A-Fa-f]{1,8})\b', {
        param($Match)
        '<HEX:' + $Match.Groups[1].Value.ToLowerInvariant() + '>'
    })
    $t = $t -replace '\b0x[0-9A-Fa-f]{9,}\b', '<ADDR>'
    $t = $t -replace '\b[0-9A-Fa-f]{16,}\b', '<ADDR>'

    $t = $t -replace '\s+', ' '
    return $t.Trim()
}

function ConvertTo-LVRedactedText {
    <#
        .SYNOPSIS
        Mask the identifiers a log message carries about the machine it came from.

        .DESCRIPTION
        Windows log messages routinely name the account, the machine, the profile path
        and the account SID. That is exactly what makes them useful evidence locally and
        exactly what makes them a liability the moment a report is attached to a ticket
        or sent to a vendor.

        Order matters, and two orderings here are load bearing.

        Mail addresses and UPNs are masked BEFORE the account name, because a UPN
        contains the account name: masking the name first turns jsmith@contoso.com into
        <USER>@contoso.com, which no longer looks like an address to the address pattern
        and so keeps the domain in the report.

        The account and machine names are matched with non-word lookarounds rather than
        as bare substrings. A short account name is otherwise catastrophic - an account
        called "u" would rewrite C:\Users\Public into C:\<USER>sers\P<USER>blic and
        corrupt every path in the report. Lookarounds rather than \b because the name
        itself may begin or end with a non-word character, which would make \b fail to
        match at exactly the boundary it was added to protect.

        This is deliberately not a promise of anonymity. It removes the identifiers this
        tool knows Windows puts in these messages; a log line can always carry a name in
        a form nothing can recognize as one, and the report says so rather than implying
        the output is safe to publish unread.
    #>
    param(
        [AllowEmptyString()][AllowNull()][string]$Text,
        [string]$UserName = $env:USERNAME,
        [string]$MachineName = $env:COMPUTERNAME
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text

    $t = $t -replace 'S-1-5-21-[\d-]+', 'S-1-5-21-<SID>'
    $t = $t -replace 'S-1-15-[\d-]+', 'S-1-15-<SID>'

    # UPNs and mail addresses, which appear in identity, Kerberos and Entra events.
    # Ahead of the account name on purpose - see the ordering note above.
    $t = $t -replace '[\w.+-]+@[\w-]+\.[\w.-]+', '<UPN>'

    # Alphanumeric lookarounds, NOT \w. \w includes the underscore, and the report
    # folder is named LogVerdict_<MACHINE>_<timestamp> - so a \w boundary refuses to
    # match the machine name in exactly the place it most reliably appears. The run
    # transcript is full of that path.
    $edge = '[\p{L}\p{N}]'
    if ($MachineName) { $t = $t -replace ('(?i)(?<!' + $edge + ')' + [regex]::Escape($MachineName) + '(?!' + $edge + ')'), '<MACHINE>' }
    if ($UserName)    { $t = $t -replace ('(?i)(?<!' + $edge + ')' + [regex]::Escape($UserName) + '(?!' + $edge + ')'), '<USER>' }

    # Any other account's profile directory, whoever it belongs to. Only the account
    # segment is replaced, so the rest of the path survives and stays diagnostic.
    $t = [regex]::Replace($t, '(?i)([A-Z]:\\Users\\)([^\\/:*?"<>|\r\n]+)', {
        param($Match)
        $account = $Match.Groups[2].Value
        # These are Windows' own fixed profile names, not anybody's identity.
        if ($account -in @('Default', 'Default User', 'Public', 'All Users', '<USER>')) {
            return $Match.Value
        }
        return $Match.Groups[1].Value + '<USER>'
    })

    return $t
}

function ConvertTo-LVRedactedResult {
    <#
        .SYNOPSIS
        A copy of a scan result with the machine's identifiers masked out of everything
        that gets written to disk.

        .DESCRIPTION
        Copies before editing. Redacting in place would mean a caller who exports a
        redacted report and then reads $result.Findings gets the masked text back, which
        silently destroys the evidence they still needed for the machine in front of them.

        The rule prose is left alone: it is written by us, ships in the database, and
        contains nothing about the machine. Only the captured evidence is masked.
    #>
    param([Parameter(Mandatory)]$Result)

    $machine = $Result.MachineName
    $copy = [pscustomobject]@{}
    foreach ($prop in $Result.PSObject.Properties) {
        $copy | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
    }

    $findings = foreach ($f in @($Result.Findings)) {
        $c = [pscustomobject]@{}
        foreach ($prop in $f.PSObject.Properties) {
            $c | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
        }
        if ($c.PSObject.Properties['SampleMessage']) {
            $c.SampleMessage = ConvertTo-LVRedactedText -Text $c.SampleMessage -MachineName $machine
        }
        if ($c.PSObject.Properties['Samples']) {
            $c.Samples = @(@($f.Samples) | ForEach-Object { ConvertTo-LVRedactedText -Text $_ -MachineName $machine })
        }
        if ($f.PSObject.Properties['ModelExplanation'] -and $f.ModelExplanation) {
            $draft = [pscustomobject]@{}
            foreach ($prop in $f.ModelExplanation.PSObject.Properties) {
                $draft | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
            }
            foreach ($name in @('Summary', 'Uncertainty')) {
                if ($draft.PSObject.Properties[$name]) {
                    $draft.$name = ConvertTo-LVRedactedText -Text ([string]$draft.$name) -MachineName $machine
                }
            }
            if ($draft.PSObject.Properties['Evidence']) {
                $draft.Evidence = @(@($draft.Evidence) | ForEach-Object { ConvertTo-LVRedactedText -Text $_ -MachineName $machine })
            }
            $c.ModelExplanation = $draft
        }
        $c
    }

    $crash = foreach ($a in @($Result.CrashArtifacts)) {
        $c = [pscustomobject]@{}
        foreach ($prop in $a.PSObject.Properties) {
            $c | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
        }
        # WER paths and decode errors can carry profile paths; application and module
        # leaves can also embed an account name. Redact every textual crash field that
        # can originate in a path or in the report rather than only the primary path.
        foreach ($name in @('Path', 'ReportPath', 'App', 'Module', 'DecodeStatus')) {
            if ($c.PSObject.Properties[$name]) {
                $c.$name = ConvertTo-LVRedactedText -Text ([string]$c.$name) -MachineName $machine
            }
        }
        $c
    }

    $copy.Findings = @($findings)
    $copy.CrashArtifacts = @($crash)
    if ($copy.PSObject.Properties['CoverageNotes']) {
        $copy.CoverageNotes = @(@($Result.CoverageNotes) | ForEach-Object { ConvertTo-LVRedactedText -Text $_ -MachineName $machine })
    }
    $copy.MachineName = '<MACHINE>'
    $copy | Add-Member -NotePropertyName 'Redacted' -NotePropertyValue $true -Force

    return $copy
}

function Get-LVShortHash {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return (($bytes[0..5] | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-LVSafeName {
    param([Parameter(Mandatory)][string]$Text)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = '[{0}]' -f [regex]::Escape($invalid)
    return ($Text -replace $pattern, '_')
}

function ConvertTo-LVHtmlEncoded {
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    $t = $Text -replace '&', '&amp;'
    $t = $t -replace '<', '&lt;'
    $t = $t -replace '>', '&gt;'
    $t = $t -replace '"', '&quot;'
    return $t
}
