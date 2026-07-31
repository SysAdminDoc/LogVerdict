# Collection layer: pull raw records out of the Windows event channels.
# Read-only. Nothing in this file interprets anything - that is the reducer's job.

function Get-LVDefaultChannel {
    # The two channels that carry almost all client-troubleshooting signal.
    return @('System', 'Application')
}

function Get-LVPopulatedChannel {
    <#
        .SYNOPSIS
        Every channel on this machine that actually holds records.
        .DESCRIPTION
        A stock Windows 11 install exposes roughly a thousand channel definitions but
        only a fraction are enabled and non-empty. Enumerating first avoids hundreds of
        "no events found" round trips.
    #>
    [CmdletBinding()]
    param([int]$MinimumRecords = 1)

    $logs = @()
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordCount -ge $MinimumRecords }
    } catch {
        Write-LVLog -Level warn -Message ("Channel enumeration failed: {0}" -f $_.Exception.Message)
        return @()
    }
    return @($logs | Sort-Object -Property RecordCount -Descending | Select-Object -ExpandProperty LogName)
}

function Get-LVEventRecord {
    <#
        .SYNOPSIS
        Normalized event records from the requested channels.
        .OUTPUTS
        PSCustomObject with Source='event' plus Channel/Provider/Id/Level/TimeCreated/Message.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Channel = (Get-LVDefaultChannel),
        [int]$DaysBack = 30,
        [int[]]$Level = @(1, 2, 3),
        [int]$MaxPerChannel = 20000
    )

    $since = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $records = New-Object System.Collections.Generic.List[object]
    $denied = New-Object System.Collections.Generic.List[string]

    foreach ($ch in $Channel) {
        $filter = @{ LogName = $ch; StartTime = $since }
        if ($Level -and $Level.Count -gt 0) { $filter['Level'] = $Level }

        $events = $null
        try {
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxPerChannel -ErrorAction Stop
        } catch {
            $msg = $_.Exception.Message
            # "No events were found" is the normal empty case, not a failure.
            if ($msg -match 'No events were found') { continue }
            if ($msg -match 'Attempted to perform an unauthorized operation|Access is denied') {
                $denied.Add($ch) | Out-Null
                continue
            }
            Write-LVLog -Level warn -Message ("Channel '{0}' unreadable: {1}" -f $ch, $msg)
            continue
        }

        foreach ($e in $events) {
            $message = $e.Message
            if ([string]::IsNullOrWhiteSpace($message)) {
                # Provider metadata missing (uninstalled software, or an offline copy).
                # Keep the record - the signature is still valid, the prose just is not.
                $message = '(no message template registered for this provider on this machine)'
            }

            $records.Add([pscustomobject]@{
                Source       = 'event'
                Channel      = $ch
                Provider     = $e.ProviderName
                Id           = [int]$e.Id
                Level        = [int]$e.Level
                LevelName    = $e.LevelDisplayName
                TimeCreated  = $e.TimeCreated
                MachineName  = $e.MachineName
                RecordId     = $e.RecordId
                Message      = $message.Trim()
            }) | Out-Null
        }
    }

    if ($denied.Count -gt 0) {
        Write-LVLog -Level warn -Message ("Access denied on {0} channel(s): {1}. Re-run elevated for full coverage." -f $denied.Count, ($denied -join ', '))
    }

    return ConvertTo-LVArrayOutput -Value @($records.ToArray())
}

function Get-LVChannelHorizon {
    <#
        .SYNOPSIS
        Oldest record still held in a channel.
        .DESCRIPTION
        Guards the single most dangerous false negative this tool can produce. An
        in-place Windows upgrade wipes the event channels, so "no errors found" can
        mean "the evidence was destroyed" rather than "the machine is healthy".
        The report states the horizon so a clean result can be trusted or discounted.
    #>
    [CmdletBinding()]
    param([string[]]$Channel = (Get-LVDefaultChannel))

    $result = @{}
    foreach ($ch in $Channel) {
        try {
            $oldest = Get-WinEvent -LogName $ch -Oldest -MaxEvents 1 -ErrorAction Stop
            if ($oldest) { $result[$ch] = $oldest.TimeCreated }
        } catch {
            continue
        }
    }
    return $result
}
