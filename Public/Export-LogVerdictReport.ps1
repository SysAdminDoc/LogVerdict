function Export-LogVerdictReport {
    <#
        .SYNOPSIS
        Render a scan result to disk as text, JSON, CSV, and a self-contained dark HTML page.

        .PARAMETER Result
        The object returned by Invoke-LogVerdictScan.

        .PARAMETER OutputDir
        Where to write. Defaults to a timestamped folder on the Desktop, which is safe
        even when the script is right-click-elevated and starts in System32.

        .PARAMETER Format
        Any of Text, Json, Csv, Html, Markdown, TicketText, TicketHtml, or All.
        Markdown writes a bounded, prose-first ticket summary plus matching plain-text
        and email-safe HTML bodies. TicketText and TicketHtml select those bodies
        individually. Default All. Csv writes one scalar row per finding with a stable
        pipeline-friendly column contract.

        .PARAMETER Redact
        Mask the account name, machine name, profile paths, SIDs and mail addresses out
        of the captured log messages before writing them. Use when the report is going
        to a ticket or a vendor. The reports state that redaction was applied, so a
        reader never mistakes a masked report for a complete one.

        .PARAMETER IncludeEvidence
        Also write a zip containing the reports, the matching text-log lines, and the
        scanned event channels as .evtx - the artifact to attach to a ticket. Combined
        with -Redact the channel exports are deliberately omitted, because .evtx is a
        binary format carrying the identifiers redaction strips out of the text.

        .PARAMETER AllowRawEvidence
        Explicitly authorize a forensic raw evidence bundle. Required with
        -IncludeEvidence when -Redact is not selected. Raw bundles are never described
        as sanitized and their privacy audit records any sensitive patterns found.

        .PARAMETER ProviderTemplatePath
        Optional validated provider message-template cache to include in an evidence
        bundle for offline review. The cache is written as PROVIDER-TEMPLATES.json.

        .EXAMPLE
        Invoke-LogVerdictScan | Export-LogVerdictReport

        .EXAMPLE
        Invoke-LogVerdictScan | Export-LogVerdictReport -Redact

        .EXAMPLE
        Invoke-LogVerdictScan | Export-LogVerdictReport -IncludeEvidence -AllowRawEvidence
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Result,
        [string]$OutputDir,
        [ValidateSet('Text', 'Json', 'Csv', 'Html', 'Markdown', 'TicketText', 'TicketHtml', 'All')][string[]]$Format = @('All'),
        [switch]$Redact,
        [switch]$IncludeEvidence,
        [switch]$AllowRawEvidence,
        [string]$ProviderTemplatePath
    )

    process {
        if ($IncludeEvidence -and -not $Redact -and -not $AllowRawEvidence) {
            throw 'Raw evidence packaging requires -AllowRawEvidence, or use -Redact for a shareable bundle.'
        }

        # Normalize legacy results and fail closed when a future writer's contract
        # cannot be understood by this reader.
        $Result = Resolve-LVScanInput -InputObject $Result -Role 'result'
        $Result = ConvertFrom-LVReportContract -InputObject $Result

        # Captured before redacting. The folder name keeps the real machine name because
        # the person running the scan has to find it on their own desktop - redaction is
        # about what leaves the machine, not about hiding the output from its author.
        $folderMachine = $Result.MachineName

        if ($Redact) {
            $Result = ConvertTo-LVRedactedResult -Result $Result
            Write-LVLog -Level info -Message 'Redacting account, machine and path identifiers from the written reports.'
        }
        $Result = ConvertTo-LVReportContract -Result $Result -Redacted:$Redact

        if (-not $OutputDir) {
            $desktop = [Environment]::GetFolderPath('Desktop')
            $stamp = '{0:yyyyMMdd-HHmmss}' -f $Result.ScanTime
            $name = 'LogVerdict_{0}_{1}' -f (ConvertTo-LVSafeName -Text $folderMachine), $stamp
            $OutputDir = Join-Path $desktop $name
        }

        if (-not (Test-Path -LiteralPath $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }

        $wantAll = $Format -contains 'All'
        $written = New-Object System.Collections.Generic.List[string]

        if ($wantAll -or $Format -contains 'Text') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.txt'
            Write-LVTextFile -Path $p -Content (ConvertTo-LVTextReport -Result $Result)
            $written.Add($p) | Out-Null
        }

        if ($wantAll -or $Format -contains 'Json') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.json'
            $jsonResult = ConvertTo-LVJsonSafeValue -Value $Result
            Write-LVTextFile -Path $p -Content ($jsonResult | ConvertTo-Json -Depth $script:LVJsonProjectionDepth)
            $written.Add($p) | Out-Null
        }

        if ($wantAll -or $Format -contains 'Csv') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.csv'
            Write-LVTextFile -Path $p -Content (ConvertTo-LVCsvReport -Result $Result)
            $written.Add($p) | Out-Null
        }

        if ($wantAll -or $Format -contains 'Html') {
            $p = Join-Path $OutputDir 'LogVerdict-Report.html'
            Write-LVTextFile -Path $p -Content (ConvertTo-LVHtmlReport -Result $Result)
            $written.Add($p) | Out-Null
        }

        $ticketFamily = $wantAll -or $Format -contains 'Markdown'
        if ($ticketFamily -or $Format -contains 'Markdown') {
            $p = Join-Path $OutputDir 'LogVerdict-Ticket-Summary.md'
            Write-LVTextFile -Path $p -Content (ConvertTo-LVTicketSummary -Result $Result)
            $written.Add($p) | Out-Null
        }
        if ($ticketFamily -or $Format -contains 'TicketText') {
            $p = Join-Path $OutputDir 'LogVerdict-Ticket-Summary.txt'
            $ticketModel = Get-LVTicketSummaryModel -Result $Result
            $ticketText = Limit-LVTicketText -Text (ConvertTo-LVTicketSummaryText -Model $ticketModel) `
                -Suffix 'Summary truncated; attach the full report for the complete list.'
            Write-LVTextFile -Path $p -Content $ticketText
            $written.Add($p) | Out-Null
        }
        if ($ticketFamily -or $Format -contains 'TicketHtml') {
            $p = Join-Path $OutputDir 'LogVerdict-Ticket-Summary.html'
            $ticketModel = if ($ticketModel) { $ticketModel } else { Get-LVTicketSummaryModel -Result $Result }
            $ticketHtml = Limit-LVTicketText -Text (ConvertTo-LVTicketSummaryHtml -Model $ticketModel) `
                -Suffix 'Summary truncated; attach the full report for the complete list.'
            Write-LVTextFile -Path $p -Content $ticketHtml
            $written.Add($p) | Out-Null
        }

        # The run transcript is a report artifact and has to be redacted with the rest.
        # It is built from log lines rather than from the result object, so redacting
        # the result does not touch it - and it names the machine on almost every line.
        $logPath = Join-Path $OutputDir 'LogVerdict-Run.log'
        $transcript = (Get-LVLogTranscript) -join [Environment]::NewLine
        if ($Redact) { $transcript = ConvertTo-LVRedactedText -Text $transcript -MachineName $folderMachine }
        Write-LVTextFile -Path $logPath -Content $transcript
        $written.Add($logPath) | Out-Null

        foreach ($w in $written) {
            Write-LVLog -Level ok -Message ('Wrote {0}' -f $w)
        }

        $bundle = $null
        $privacyAudit = $null
        $bundleStatus = [pscustomobject][ordered]@{
            State        = 'not-requested'
            Reason       = 'Evidence packaging was not requested.'
            Path         = $null
            ManifestPath = $null
        }
        if ($IncludeEvidence) {
            $bundle = New-LVEvidenceBundle -Result $Result -OutputDir $OutputDir `
                -ReportFile @($written.ToArray()) -Redact:$Redact -AllowRawEvidence:$AllowRawEvidence `
                -ProviderTemplatePath $ProviderTemplatePath `
                -OriginalMachineName $folderMachine -OriginalUserName $env:USERNAME -Audit ([ref]$privacyAudit) `
                -Status ([ref]$bundleStatus)
        }

        return [pscustomobject]@{
            OutputDir      = $OutputDir
            Files          = @($written.ToArray())
            EvidenceBundle = $bundle
            EvidenceBundleStatus = $bundleStatus
            EvidenceBundleManifest = $bundleStatus.ManifestPath
            PrivacyAudit   = $privacyAudit
        }
    }
}
