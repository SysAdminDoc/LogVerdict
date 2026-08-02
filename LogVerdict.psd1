@{
    RootModule        = 'LogVerdict.psm1'
    ModuleVersion     = '0.8.1'
    GUID              = '54d8b998-b5ce-40ec-8981-5525e95d4216'
    Author            = 'SysAdminDoc'
    CompanyName       = 'SysAdminDoc'
    Copyright         = '(c) 2026 SysAdminDoc. MIT License.'
    Description       = 'Scans a Windows PC log corpus, deduplicates it into signatures, and rules on each one in plain English.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Compare-LogVerdictScan',
        'Invoke-LogVerdictScan',
        'Get-LogVerdictDatabase',
        'Get-LogVerdictAdvisory',
        'Get-LogVerdictAdvisoryStatus',
        'Get-LogVerdictErrorCatalog',
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
            Tags       = @('Windows', 'EventLog', 'Troubleshooting', 'Diagnostics', 'SysAdmin', 'Forensics')
            LicenseUri = 'https://github.com/SysAdminDoc/LogVerdict/blob/main/LICENSE'
            ProjectUri = 'https://github.com/SysAdminDoc/LogVerdict'
        }
    }
}
