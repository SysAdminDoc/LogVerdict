@{
    RootModule        = 'LogVerdict.psm1'
    ModuleVersion     = '0.8.2'
    GUID              = '54d8b998-b5ce-40ec-8981-5525e95d4216'
    Author            = 'SysAdminDoc'
    CompanyName       = 'SysAdminDoc'
    Copyright         = '(c) 2026 SysAdminDoc. MIT License.'
    Description       = 'Scans a Windows PC log corpus, deduplicates it into signatures, and rules on each one in plain English.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FileList = @(
        'LogVerdict.psd1'
        'LogVerdict.psm1'
        'VERSION'
        'README.md'
        'CHANGELOG.md'
        'LICENSE'
        'NOTICE'
        'Private\00-LVCommon.ps1'
        'Private\10-LVCollectEvents.ps1'
        'Private\11-LVCollectTextLogs.ps1'
        'Private\12-LVScanPipeline.ps1'
        'Private\12-LVCollectReliability.ps1'
        'Private\13-LVCollectOffline.ps1'
        'Private\14-LVProviderTemplates.ps1'
        'Private\15-LVCollectHealth.ps1'
        'Private\16-LVLiveWatch.ps1'
        'Private\17-LVPrivacy.ps1'
        'Private\18-LVHistory.ps1'
        'Private\19-LVAdvisory.ps1'
        'Private\20-LVReduce.ps1'
        'Private\21-LVEventData.ps1'
        'Private\23-LVProvider.ps1'
        'Private\25-LVCorrelate.ps1'
        'Private\30-LVResolve.ps1'
        'Private\35-LVSuppression.ps1'
        'Private\31-LVFixture.ps1'
        'Private\32-LVErrorCatalog.ps1'
        'Private\40-LVReport.ps1'
        'Private\45-LVEvidence.ps1'
        'Private\46-LVCase.ps1'
        'Private\50-LVExplain.ps1'
        'Private\50-LVGuiXaml.ps1'
        'Private\51-LVGuiHost.ps1'
        'Private\51-LVGuiSession.ps1'
        'Private\52-LVGuiRender.ps1'
        'Private\53-LVGuiActions.ps1'
        'Private\54-LVGuiEvents.ps1'
        'Private\60-LVStandardExport.ps1'
        'Private\61-LVContract.ps1'
        'Private\62-LVReviewArtifact.ps1'
        'Public\Compare-LogVerdictScan.ps1'
        'Public\Export-LogVerdictHandoff.ps1'
        'Public\Export-LogVerdictReport.ps1'
        'Public\Export-LogVerdictStandard.ps1'
        'Public\Get-LogVerdictAdvisory.ps1'
        'Public\Get-LogVerdictAdvisoryStatus.ps1'
        'Public\Get-LogVerdictDatabase.ps1'
        'Public\Get-LogVerdictSuppression.ps1'
        'Public\Get-LogVerdictErrorCatalog.ps1'
        'Public\Get-LogVerdictProvider.ps1'
        'Public\Get-LogVerdictIntuneDigest.ps1'
        'Public\Invoke-LogVerdictProvider.ps1'
        'Public\Invoke-LogVerdictScan.ps1'
        'Public\New-LogVerdictCaseProfile.ps1'
        'Public\Show-LogVerdictGui.ps1'
        'Public\Show-LogVerdictReport.ps1'
        'Public\Test-LogVerdictAdvisoryDatabase.ps1'
        'Public\Test-LogVerdictCaseProfile.ps1'
        'Public\Test-LogVerdictDatabase.ps1'
        'Public\Test-LogVerdictProvider.ps1'
        'Public\Update-LogVerdictAdvisoryDatabase.ps1'
        'Public\Update-LogVerdictDatabase.ps1'
        'Public\Watch-LogVerdict.ps1'
        'Data\advisories.json'
        'Data\advisories.schema.json'
        'Data\build-dependencies.json'
        'Data\case-profile.schema.json'
        'Data\error-codes.json'
        'Data\error-codes.schema.json'
        'Data\evidence-contract.schema.json'
        'Data\export-templates.json'
        'Data\export-templates.schema.json'
        'Data\fixtures.schema.json'
        'Data\localization.json'
        'Data\provider.schema.json'
        'Data\provider-templates.schema.json'
        'Data\report-contract.schema.json'
        'Data\review-artifact.schema.json'
        'Data\suppressions.schema.json'
        'Data\windows-log-benchmark.json'
        'Data\windows-log-benchmark.schema.json'
        'Data\verdicts.json'
        'Data\verdicts.schema.json'
    )

    FunctionsToExport = @(
        'Compare-LogVerdictScan',
        'Invoke-LogVerdictScan',
        'Get-LogVerdictDatabase',
        'Get-LogVerdictSuppression',
        'Get-LogVerdictAdvisory',
        'Get-LogVerdictAdvisoryStatus',
        'Get-LogVerdictErrorCatalog',
        'Get-LogVerdictProvider',
        'Get-LogVerdictIntuneDigest',
        'Test-LogVerdictProvider',
        'Invoke-LogVerdictProvider',
        'New-LogVerdictCaseProfile',
        'Test-LogVerdictCaseProfile',
        'Export-LogVerdictHandoff',
        'Test-LogVerdictAdvisoryDatabase',
        'Update-LogVerdictDatabase',
        'Update-LogVerdictAdvisoryDatabase',
        'Test-LogVerdictDatabase',
        'Export-LogVerdictReport',
        'Export-LogVerdictStandard',
        'Watch-LogVerdict',
        'Show-LogVerdictReport',
        'Show-LogVerdictGui'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Windows', 'EventLog', 'Troubleshooting', 'Diagnostics', 'SysAdmin', 'Forensics', 'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri = 'https://github.com/SysAdminDoc/LogVerdict/blob/main/LICENSE'
            ProjectUri = 'https://github.com/SysAdminDoc/LogVerdict'
            ReleaseNotes = 'See CHANGELOG.md for the 0.8.2 release notes and the complete history.'
        }
    }
}
