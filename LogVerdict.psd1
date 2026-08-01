@{
    RootModule        = 'LogVerdict.psm1'
    ModuleVersion     = '0.6.0'
    GUID              = '54d8b998-b5ce-40ec-8981-5525e95d4216'
    Author            = 'SysAdminDoc'
    CompanyName       = 'SysAdminDoc'
    Copyright         = '(c) 2026 SysAdminDoc. MIT License.'
    Description       = 'Scans a Windows PC log corpus, deduplicates it into signatures, and rules on each one in plain English.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-LogVerdictScan',
        'Get-LogVerdictDatabase',
        'Test-LogVerdictDatabase',
        'Export-LogVerdictReport',
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
