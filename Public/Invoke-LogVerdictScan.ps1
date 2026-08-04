function Invoke-LogVerdictScan {
    <#
        .SYNOPSIS
        Scan this PC's logs, deduplicate them, and rule on what is left.

        .DESCRIPTION
        Runs the full pipeline: collect -> reduce -> resolve. Read-only; nothing on the
        machine is modified. Returns a result object that Export-LogVerdictReport renders.
        Use Export-LogVerdictReport -Format Csv for one stable scalar row per finding.

        .PARAMETER DaysBack
        How far back to look, from 1 through 3650 days. Default 30.

        .PARAMETER Channel
        Event channels to read. Defaults to System and Application, which carry almost
        all client-troubleshooting signal.

        .PARAMETER AllChannels
        Sweep every channel on the machine that holds records. Much slower and much
        noisier; use when the default two come back empty but something is clearly wrong.

        .PARAMETER DiagnosticChannels
        Read System and Application plus six focused operational channels for storage,
        code integrity, device setup, packaged apps, memory pressure, and boot security.
        This is broader than the default scan without the noise and delay of AllChannels.

        .PARAMETER SkipTextLogs
        Skip CBS, DISM, SetupAPI and the other plain-text logs.

        .PARAMETER SkipReliability
        Skip Reliability Monitor. That source supplies the software install and removal
        history, which no error-level channel sweep can see.

        .PARAMETER PerformanceTelemetry
        Opt in to content-free source timing and bounded-count records in the result and
        reports. Telemetry contains no messages, paths, identifiers or signature data.

        .PARAMETER IncludeBenign
        Keep signatures ruled benign in the result. Off by default - the entire point
        is to remove them.

        .PARAMETER IncludeLowConfidence
        Keep curated low-confidence rulings in the result. Off by default so a weak
        ruling cannot crowd the report; unknown signatures remain visible.

        .PARAMETER SuppressionPath
        Optional operator-owned suppression expectation JSON. Without it, the
        per-user %LOCALAPPDATA%\LogVerdict\suppressions.json file is used when present.

        .PARAMETER SuppressedOnly
        Return the validated suppression set without collecting or scanning logs.

        .PARAMETER Redact
        Return a redacted result with account, machine, profile-path, SID, address,
        token, and secret identifiers masked. This applies to the result object itself;
        it also keeps any optional model prompt redaction enabled.

        .PARAMETER EvidencePath
        Analyze a LogVerdict evidence zip, extracted evidence directory, JSON report,
        one .evtx file, or a directory of .evtx files without reading any source on the
        reviewing PC. Captured report signatures preserve non-event evidence.

        .PARAMETER ExplainUnknown
        Opt in to asking a local Ollama model for a separately labelled, non-remedial
        draft explanation of signatures that have no curated rule. Known verdicts are
        never sent and never changed.

        .PARAMETER PromoteToRule
        Accept each safe model candidate into the local verdict file as an inactive
        review draft. Implies ExplainUnknown. Drafts cannot match until a human replaces
        both status unsupported and confidence draft.

        .PARAMETER LocalRulePath
        Override the local draft-rule destination. The default is Data\verdicts.local.json
        from source and verdicts.local.json beside a compiled executable.

        .PARAMETER HistoryPath
        Opt-in local JSON history for bounded per-signature trend analysis. History is
        never read for offline evidence scans and never changes a curated verdict.

        .PARAMETER HistoryWindowDays
        Number of days of prior local history eligible for comparison. Default 30.

        .PARAMETER AdvisoryPath
        Optional offline advisory-cache JSON. Supplying only this path inventories the
        cache; combine it with AdvisoryPackage and AdvisoryVersion to match a package.

        .PARAMETER AdvisoryPackage
        Package name to match in the optional advisory cache, such as PowerShell.

        .PARAMETER AdvisoryVersion
        Package version to test against the optional advisory cache's affected ranges.

        .PARAMETER CaseProfilePath
        Optional validated case profile to attach to the result. The profile records
        collection scope and operator choices for handoff; explicit scan parameters
        remain authoritative and the profile is not used as a verdict input.

        .PARAMETER ProviderPath
        One or more local provider manifests or provider directories. Providers are
        live-only, explicitly opt-in, and contribute redacted normalized evidence.

        .PARAMETER ProviderTemplatePath
        Optional operator-supplied provider message-template cache. The cache is
        validated for bounded size and license provenance; it is never downloaded by
        the scan. Offline evidence packages can carry the same file as
        PROVIDER-TEMPLATES.json.

        .PARAMETER AllowUntrustedProvider
        Explicitly approve execution of the pinned provider entrypoints named by
        ProviderPath. Providers are always marked untrusted and cannot supply verdicts.

        .EXAMPLE
        Invoke-LogVerdictScan -DaysBack 7

        .EXAMPLE
        Invoke-LogVerdictScan -AllChannels -IncludeBenign

        .EXAMPLE
        Invoke-LogVerdictScan -DiagnosticChannels
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 3650)][int]$DaysBack = 30,
        [string[]]$Channel,
        [switch]$AllChannels,
        [switch]$DiagnosticChannels,
        [switch]$SkipTextLogs,
        [switch]$SkipReliability,
        [switch]$PerformanceTelemetry,
        [switch]$IncludeBenign,
        [switch]$IncludeLowConfidence,
        [string]$SuppressionPath,
        [switch]$SuppressedOnly,
        [string]$DatabasePath,
        [string]$EvidencePath,
        [switch]$Redact,
        [switch]$ExplainUnknown,
        [string]$OllamaModel = 'llama3.2',
        [string]$OllamaEndpoint = 'http://127.0.0.1:11434',
        [switch]$PromoteToRule,
        [string]$LocalRulePath,
        [string]$HistoryPath,
        [ValidateRange(1, 3650)][int]$HistoryWindowDays = 30,
        [string]$AdvisoryPath,
        [string]$AdvisoryPackage,
        [string]$AdvisoryVersion,
        [string]$CaseProfilePath,
        [string[]]$ProviderPath,
        [string]$ProviderTemplatePath,
        [switch]$AllowUntrustedProvider,
        [ValidateRange(1, 8589934592)][long]$MaxCollectionBytes = 536870912,
        [ValidateRange(1, 10000000)][int]$MaxCollectionRecords = 100000,
        [ValidateRange(1, 86400)][int]$MaxCollectionSeconds = 600
    )

    if ($SuppressedOnly) {
        if ($EvidencePath) { throw '-SuppressedOnly cannot be combined with -EvidencePath.' }
        $set = Get-LogVerdictSuppression -Path $SuppressionPath
        return ConvertTo-LVArrayOutput -Value @($set.entries)
    }

    $collectionBudget = New-LVCollectionBudget -MaxBytes $MaxCollectionBytes -MaxRecords $MaxCollectionRecords -MaxSeconds $MaxCollectionSeconds
    $caseProfile = if ($CaseProfilePath) { Read-LVCaseProfile -Path $CaseProfilePath } else { $null }
    if ($EvidencePath) {
        if ($ProviderPath) { throw 'Provider extensions are live-only and cannot be combined with -EvidencePath.' }
        $offlineArgs = @{
            EvidencePath   = $EvidencePath
            Channel        = $Channel
            SkipTextLogs   = $SkipTextLogs
            SkipReliability = $SkipReliability
            PerformanceTelemetry = $PerformanceTelemetry
            IncludeBenign  = $IncludeBenign
            IncludeLowConfidence = $IncludeLowConfidence
            SuppressionPath = $SuppressionPath
            DatabasePath   = $DatabasePath
            Redact         = $Redact
            ExplainUnknown = $ExplainUnknown
            OllamaModel    = $OllamaModel
            OllamaEndpoint = $OllamaEndpoint
            PromoteToRule  = $PromoteToRule
            LocalRulePath  = $LocalRulePath
            ProviderTemplatePath = $ProviderTemplatePath
            CollectionBudget = $collectionBudget
        }
        if ($PSBoundParameters.ContainsKey('DaysBack')) { $offlineArgs['DaysBack'] = $DaysBack }
        $offlineResult = Invoke-LVOfflineScan @offlineArgs
        $offlineResult = Add-LVCaseProfileToResult -Result $offlineResult -Profile $caseProfile
        $offlineAdvisory = Get-LVAdvisoryScanContext -Path $AdvisoryPath -Package $AdvisoryPackage -Version $AdvisoryVersion
        $offlineResult = Add-LVAdvisoryContextToResult -Result $offlineResult -Context $offlineAdvisory
        if ($Redact) { $offlineResult = ConvertTo-LVRedactedResult -Result $offlineResult }
        return $offlineResult
    }

    return Invoke-LVLiveScan -DaysBack $DaysBack -Channel $Channel -AllChannels:$AllChannels `
        -DiagnosticChannels:$DiagnosticChannels -SkipTextLogs:$SkipTextLogs -SkipReliability:$SkipReliability `
        -PerformanceTelemetry:$PerformanceTelemetry -IncludeBenign:$IncludeBenign -IncludeLowConfidence:$IncludeLowConfidence `
        -SuppressionPath $SuppressionPath -DatabasePath $DatabasePath -Redact:$Redact -ExplainUnknown:$ExplainUnknown `
        -OllamaModel $OllamaModel -OllamaEndpoint $OllamaEndpoint -PromoteToRule:$PromoteToRule -LocalRulePath $LocalRulePath `
        -HistoryPath $HistoryPath -HistoryWindowDays $HistoryWindowDays -AdvisoryPath $AdvisoryPath `
        -AdvisoryPackage $AdvisoryPackage -AdvisoryVersion $AdvisoryVersion -ProviderPath $ProviderPath `
        -ProviderTemplatePath $ProviderTemplatePath -AllowUntrustedProvider:$AllowUntrustedProvider `
        -MaxCollectionBytes $MaxCollectionBytes -MaxCollectionRecords $MaxCollectionRecords -MaxCollectionSeconds $MaxCollectionSeconds `
        -CollectionBudget $collectionBudget -CaseProfile $caseProfile
}
