# Evidence bundle: one zip an admin can attach to a ticket.
#
# The report says what LogVerdict concluded. The bundle carries what it concluded it
# FROM, so somebody else can check the working - which is the difference between a
# finding and an assertion, and the same reason rules carry sources.
#
# Two rules govern what goes in.
#
# The first is size. CBS.log alone routinely runs to hundreds of megabytes and almost
# none of it is evidence, so the bundle carries the matching lines rather than the
# files. Event channels are exported whole because .evtx has no line-level export and
# the per-channel record cap already bounds them.
#
# The second is that a redacted bundle must actually be redacted. Raw .evtx is a binary
# format holding the same account names, hostnames and SIDs that -Redact strips out of
# the text - shipping both would produce a bundle that claims to be sanitized and is
# not, which is worse than one that never claimed it. Channel exports are therefore
# refused under -Redact, and the manifest says so.

function Export-LVChannelEvidence {
    <#
        .SYNOPSIS
        Export the readable scanned channels as .evtx into a directory.

        .DESCRIPTION
        Uses wevtutil, which ships with Windows and needs no module. Channels that were
        denied or missing during the scan are skipped rather than retried - the scan
        already established they could not be read, and failing again here would only
        add noise to the run log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Destination,
        [int]$MaxChannel = 12
    )

    $exported = New-Object System.Collections.Generic.List[string]
    $skipped = New-Object System.Collections.Generic.List[string]

    if ($Result.PSObject.Properties['Offline'] -and $Result.Offline) {
        $skipped.Add('Event channels were not re-exported from an offline analysis. Keep the original evidence bundle as the raw source.') | Out-Null
        return [pscustomobject]@{ Exported=@(); Skipped=@($skipped.ToArray()) }
    }

    $readable = @()
    if ($Result.ChannelStatus) {
        $readable = @($Result.ChannelStatus.Values |
            Where-Object { $_.Access -eq 'readable' } |
            Select-Object -ExpandProperty Channel)
    }
    if ($readable.Count -eq 0) { $readable = @($Result.Channels | Where-Object { $_ }) }

    # An -AllChannels scan touches well over a hundred channels; zipping every one of
    # them produces an artefact nobody can mail. The cap is reported, never silent.
    $take = @($readable | Select-Object -First $MaxChannel)
    if ($readable.Count -gt $take.Count) {
        $skipped.Add(('{0} further channel(s) were not exported; the bundle caps channel exports at {1}.' -f ($readable.Count - $take.Count), $MaxChannel)) | Out-Null
    }

    $wevtutil = Join-Path $env:SystemRoot 'System32\wevtutil.exe'
    foreach ($channel in $take) {
        $safe = ConvertTo-LVSafeName -Text $channel
        $target = Join-Path $Destination ('{0}.evtx' -f $safe)
        try {
            # /ow:true so a re-export into the same folder replaces rather than fails.
            $output = & $wevtutil epl "$channel" "$target" /ow:true 2>&1
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
                $skipped.Add(('{0}: export failed ({1})' -f $channel, ($output | Select-Object -First 1))) | Out-Null
                continue
            }
            $exported.Add($target) | Out-Null
        } catch {
            $skipped.Add(('{0}: export failed ({1})' -f $channel, $_.Exception.Message)) | Out-Null
        }
    }

    return [pscustomobject]@{
        Exported = @($exported.ToArray())
        Skipped  = @($skipped.ToArray())
    }
}

function Export-LVTextLogEvidence {
    <#
        .SYNOPSIS
        Write the matching lines from each text-log signature, not the whole log.

        .DESCRIPTION
        The samples the scan already captured are the evidence; the surrounding
        hundreds of megabytes are not. Honours redaction, because these are plain text
        and there is no reason for them not to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$Redact
    )

    $written = New-Object System.Collections.Generic.List[string]
    $byChannel = @{}

    foreach ($f in @($Result.Findings | Where-Object { $_ -and $_.Source -eq 'textlog' })) {
        $channel = $f.Channel
        if (-not $channel) { $channel = 'unknown' }
        if (-not $byChannel.ContainsKey($channel)) {
            $byChannel[$channel] = New-Object System.Collections.Generic.List[string]
        }
        $byChannel[$channel].Add(('--- {0}  ({1} occurrence(s), {2} to {3}) ---' -f `
            $f.Key, $f.Count, (Format-LVWhen $f.FirstSeen), (Format-LVWhen $f.LastSeen))) | Out-Null
        foreach ($s in @($f.Samples | Where-Object { $_ })) {
            $line = [string]$s
            if ($Redact) { $line = ConvertTo-LVRedactedText -Text $line -MachineName $Result.MachineName }
            $byChannel[$channel].Add($line) | Out-Null
        }
        $byChannel[$channel].Add('') | Out-Null
    }

    foreach ($channel in $byChannel.Keys) {
        $target = Join-Path $Destination ('{0}-excerpt.txt' -f (ConvertTo-LVSafeName -Text $channel))
        Write-LVTextFile -Path $target -Content (($byChannel[$channel].ToArray()) -join [Environment]::NewLine)
        $written.Add($target) | Out-Null
    }

    return ConvertTo-LVArrayOutput -Value @($written.ToArray())
}

function Format-LVEvidenceManifest {
    <#
        .SYNOPSIS
        A plain-text index of what is in the bundle and what deliberately is not.
        .DESCRIPTION
        The omissions matter more than the contents. Somebody opening this months later
        needs to know that channel exports were withheld because the bundle was
        redacted, rather than concluding those channels were clean.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Content,
        [AllowEmptyCollection()][string[]]$Omission = @(),
        [switch]$Redact
    )

    $sb = New-Object System.Text.StringBuilder
    Add-LVLine $sb ('LogVerdict {0} evidence bundle' -f $Result.Version)
    Add-LVLine $sb ('=' * 78)
    Add-LVLine $sb ('Machine   : {0}' -f $Result.MachineName)
    Add-LVLine $sb ('Scanned   : {0:yyyy-MM-dd HH:mm:ss}' -f $Result.ScanTime)
    Add-LVLine $sb ('Window    : last {0} day(s)' -f $Result.DaysBack)
    Add-LVLine $sb ('Elevated  : {0}' -f $Result.Elevated)
    Add-LVLine $sb ('Redacted  : {0}' -f $(if ($Redact) { 'yes' } else { 'no' }))
    Add-LVLine $sb
    Add-LVLine $sb 'CONTENTS'
    foreach ($c in $Content) { Add-LVLine $sb ('  {0}' -f (Split-Path -Leaf $c)) }
    Add-LVLine $sb

    if ($Result.PSObject.Properties['EvidenceManifest'] -and @($Result.EvidenceManifest).Count -gt 0) {
        Add-LVLine $sb 'SOURCE EVIDENCE MANIFEST'
        foreach ($source in @($Result.EvidenceManifest)) {
            $hash = if ($source.SHA256) { [string]$source.SHA256 } else { 'unavailable' }
            $timing = if ($null -ne $source.ParseMilliseconds) { ('; parse {0} ms' -f $source.ParseMilliseconds) } else { '' }
            $reason = if ($source.Reason) { ('; {0}' -f $source.Reason) } else { '' }
            Add-LVLine $sb ('  {0}: {1}, {2} bytes, SHA-256 {3}{4}{5}' -f $source.Name, $source.Status, $source.SizeBytes, $hash, $timing, $reason)
        }
        Add-LVLine $sb
    }

    Add-LVLine $sb 'WHAT IS DELIBERATELY NOT HERE'
    if ($Redact) {
        Add-LVLine $sb '  - Event channel exports (.evtx). This bundle is redacted, and .evtx is a binary'
        Add-LVLine $sb '    format carrying the same account names, hostnames and SIDs that redaction'
        Add-LVLine $sb '    removes from the text. Including them would make the bundle claim to be'
        Add-LVLine $sb '    sanitized while not being sanitized. Re-run without -Redact to include them.'
    }
    Add-LVLine $sb '  - The complete text logs. CBS.log alone routinely runs to hundreds of megabytes'
    Add-LVLine $sb '    and almost none of it is evidence, so the matching lines travel instead.'
    foreach ($o in @($Omission | Where-Object { $_ })) { Add-LVLine $sb ('  - {0}' -f $o) }
    Add-LVLine $sb

    if (@($Result.CoverageNotes).Count -gt 0) {
        Add-LVLine $sb 'WHAT THE SCAN ITSELF COULD NOT SEE'
        foreach ($note in @($Result.CoverageNotes)) { Add-LVLine $sb ('  - {0}' -f $note) }
    }

    return $sb.ToString()
}

function New-LVEvidenceBundle {
    <#
        .SYNOPSIS
        Zip the report and its supporting evidence into one file beside the output folder.
        .OUTPUTS
        The path to the zip, or $null when nothing could be gathered.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ReportFile,
        [switch]$Redact
    )

    if (-not $PSCmdlet.ShouldProcess($OutputDir, 'Write an evidence bundle')) { return $null }

    $staging = Join-Path $OutputDir 'evidence'
    if (-not (Test-Path -LiteralPath $staging)) {
        New-Item -ItemType Directory -Path $staging -Force | Out-Null
    }

    $content = New-Object System.Collections.Generic.List[string]
    $omission = New-Object System.Collections.Generic.List[string]

    foreach ($r in @($ReportFile | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        Copy-Item -LiteralPath $r -Destination $staging -Force
        $content.Add($r) | Out-Null
    }

    foreach ($t in @(Export-LVTextLogEvidence -Result $Result -Destination $staging -Redact:$Redact)) {
        $content.Add($t) | Out-Null
    }

    if ($Redact) {
        Write-LVLog -Level warn -Message 'Redacted bundle: event channel exports are omitted, because .evtx carries the identifiers redaction removes from the text.'
    } else {
        $channels = Export-LVChannelEvidence -Result $Result -Destination $staging
        foreach ($e in @($channels.Exported)) { $content.Add($e) | Out-Null }
        foreach ($s in @($channels.Skipped)) { $omission.Add($s) | Out-Null }
    }

    Write-LVTextFile -Path (Join-Path $staging 'MANIFEST.txt') `
        -Content (Format-LVEvidenceManifest -Result $Result -Content @($content.ToArray()) -Omission @($omission.ToArray()) -Redact:$Redact)

    $zip = Join-Path $OutputDir ('LogVerdict-Evidence_{0}_{1:yyyyMMdd-HHmmss}.zip' -f `
        (ConvertTo-LVSafeName -Text $Result.MachineName), $Result.ScanTime)
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        [System.IO.Compression.ZipFile]::CreateFromDirectory($staging, $zip)
    } catch {
        Write-LVLog -Level error -Message ('Could not write the evidence bundle: {0}' -f $_.Exception.Message)
        return $null
    }

    # The staging directory is removed only after the zip exists, so a failure leaves
    # the gathered evidence on disk rather than destroying it.
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue

    $size = [math]::Round((Get-Item -LiteralPath $zip).Length / 1MB, 1)
    Write-LVLog -Level ok -Message ('Evidence bundle: {0} ({1} MB)' -f $zip, $size)
    return $zip
}
