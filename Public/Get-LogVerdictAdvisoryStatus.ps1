function Get-LogVerdictAdvisoryStatus {
    <#
        .SYNOPSIS
        Return freshness and supported-runtime status for the offline advisory cache.

        .DESCRIPTION
        This is metadata only. A stale or unavailable advisory cache never becomes
        an event finding and cannot change a scan verdict or exit code.

        .PARAMETER Path
        Advisory cache JSON. Defaults to the optional local override and then the
        shipped cache.
    #>
    [CmdletBinding()]
    param([string]$Path)

    try {
        $database = Get-LVAdvisoryDatabase -Path $Path
        return [pscustomobject][ordered]@{
            Status      = $database.freshness.Status
            Reason      = $database.freshness.Reason
            Freshness   = $database.freshness
            Coverage    = $database.coverage
            Updated     = $database.updated
            Source      = $database.source
            SourceHash  = $database.sourceHash
            EntryCount  = @($database.advisories).Count
            PathName    = Split-Path -Leaf $database.sourceLabel
        }
    } catch {
        return [pscustomobject][ordered]@{
            Status      = 'unavailable'
            Reason      = $_.Exception.Message
            Freshness   = $null
            Coverage    = $null
            Updated     = $null
            Source      = $null
            SourceHash  = $null
            EntryCount  = 0
            PathName    = if ($Path) { Split-Path -Leaf $Path } else { 'advisories.json' }
        }
    }
}
