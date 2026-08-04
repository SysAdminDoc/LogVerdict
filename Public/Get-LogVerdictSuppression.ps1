function Get-LogVerdictSuppression {
    <#
        .SYNOPSIS
        Read and validate the local suppression expectation set.

        .DESCRIPTION
        Suppressions are operator-owned, scoped expectations. This command does not
        change the file and returns the normalized set so it can be reviewed or piped
        to ConvertTo-Json. A missing default file is an empty set; an explicitly named
        file that is missing or malformed is an error.

        .PARAMETER Path
        Optional suppression JSON path. Without it, %LOCALAPPDATA%\LogVerdict\suppressions.json
        is used when present.
    #>
    [CmdletBinding()]
    param([string]$Path)

    $set = Import-LVSuppressionSet -Path $Path
    return [pscustomobject][ordered]@{
        schemaVersion = $script:LVSuppressionSchemaVersion
        name = 'LogVerdict.Suppressions'
        path = $set.Path
        status = $set.Status
        entries = @($set.Entries)
    }
}
