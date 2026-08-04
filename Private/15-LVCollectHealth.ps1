# Read-only provider and configuration health profiles.
# These profiles describe whether the evidence sources were configured to produce
# useful data. They are advisory coverage facts, never verdicts about maliciousness.

function New-LVHealthProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Alias('Profile')][string]$ProfileName,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Status,
        [AllowNull()][string]$RequiredConfiguration,
        [AllowNull()][string]$ObservedConfiguration,
        [AllowNull()][string[]]$EnabledEventIds,
        [AllowNull()][string[]]$FilteredEventIds,
        [AllowNull()][string]$Provider,
        [AllowNull()][string]$ProviderId,
        [AllowNull()][string]$Channel,
        [AllowNull()][string[]]$EventIds,
        [AllowNull()][string[]]$EventVersions,
        [AllowNull()][string]$MetadataStatus,
        [AllowNull()][Nullable[bool]]$ReadExistingEvents,
        [AllowNull()][int]$HeartbeatIntervalSeconds,
        [AllowNull()][string]$BookmarkState,
        [AllowNull()][string]$RetentionMode,
        [AllowNull()][int64]$RecordCount,
        [AllowNull()][datetime]$OldestRecord,
        [AllowNull()][int64]$MaximumSizeBytes,
        [AllowNull()][int]$ClockOffsetMinutes,
        [AllowNull()][string]$Reason,
        [AllowNull()][string]$Advice,
        [AllowNull()][string]$Path,
        [string]$Origin = 'live'
    )

    return [pscustomobject][ordered]@{
        Profile                    = $ProfileName
        Source                     = $Source
        Name                       = $Name
        Status                     = $Status
        RequiredConfiguration      = $RequiredConfiguration
        ObservedConfiguration      = $ObservedConfiguration
        EnabledEventIds            = @($EnabledEventIds)
        FilteredEventIds           = @($FilteredEventIds)
        Provider                   = $Provider
        ProviderId                 = $ProviderId
        Channel                    = $Channel
        EventIds                   = @($EventIds)
        EventVersions              = @($EventVersions)
        MetadataStatus             = $MetadataStatus
        ReadExistingEvents         = $ReadExistingEvents
        HeartbeatIntervalSeconds   = $HeartbeatIntervalSeconds
        BookmarkState              = $BookmarkState
        RetentionMode              = $RetentionMode
        RecordCount                = $RecordCount
        OldestRecord               = $OldestRecord
        MaximumSizeBytes           = $MaximumSizeBytes
        ClockOffsetMinutes         = $ClockOffsetMinutes
        Reason                     = $Reason
        Advice                     = $Advice
        Path                       = $Path
        Origin                     = $Origin
    }
}

function Get-LVHealthValueText {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Array]) { return (@($Value | ForEach-Object { [string]$_ }) -join ', ') }
    return [string]$Value
}

function Get-LVProviderHealthProfile {
    <#
        Provider manifests are queried only for providers actually observed in the
        requested event records. The result carries observed EventID/version pairs
        even when a provider's localized manifest is unavailable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$EventRecord,
        [Parameter(Mandatory)][hashtable]$ChannelStatus
    )

    $profiles = New-Object System.Collections.Generic.List[object]
    $eventRecords = @($EventRecord | Where-Object { $_ -and $_.Source -eq 'event' })
    $channels = @($ChannelStatus.Keys | Sort-Object)
    foreach ($channel in $channels) {
        $channelRecords = @($eventRecords | Where-Object { [string]$_.Channel -eq [string]$channel })
        $channelState = $ChannelStatus[$channel]
        $channelDisabled = $channelState.PSObject.Properties['IsEnabled'] -and $channelState.IsEnabled -eq $false
        if ($channelRecords.Count -eq 0) {
            $status = if ($channelDisabled) { 'disabled' } elseif ($channelState.Access -in @('denied', 'missing', 'unreadable')) { 'not-observed' } else { 'empty' }
            $reason = switch ([string]$channelState.Access) {
                'denied'     { 'The channel was denied before provider metadata could be observed.'; break }
                'missing'    { 'The channel does not exist on this machine.'; break }
                'unreadable' { 'The channel could not be read, so provider metadata was not observed.'; break }
                default      { if ($channelDisabled) { 'Event logging is disabled for this channel, so provider metadata was not observed.' } else { 'No event in the requested window identified a provider manifest.' } }
            }
            $profiles.Add((New-LVHealthProfile -Profile 'provider-metadata' -Source 'event' `
                -Name ([string]$channel) -Status $status -RequiredConfiguration `
                'The provider manifest, message resources, and channel should be present for the selected event source.' `
                -ObservedConfiguration 'No provider metadata was observed in the requested window.' `
                -MetadataStatus 'not-observed' -Channel ([string]$channel) -Reason $reason `
                -Advice 'Treat this source as a coverage gap; an empty result is not proof that the provider is healthy.' -Origin 'live')) | Out-Null
            continue
        }

        foreach ($group in @($channelRecords | Group-Object Provider)) {
            $provider = [string]$group.Name
            if ([string]::IsNullOrWhiteSpace($provider)) { $provider = '<unknown provider>' }
            $groupRecords = @($group.Group)
            $eventIds = @($groupRecords | Where-Object { $null -ne $_.Id } | ForEach-Object { [string]$_.Id } | Sort-Object -Unique)
            $versions = @($groupRecords | Where-Object { $null -ne $_.Version } | ForEach-Object {
                    '{0}={1}' -f $_.Id, $_.Version
                } | Sort-Object -Unique)
            $providerId = @($groupRecords | Where-Object { $_.ProviderId } | Select-Object -ExpandProperty ProviderId -First 1)
            $manifest = $null
            $metadataStatus = 'unreadable'
            $metadataReason = $null
            $definitionCount = $null
            try {
                $manifest = @(Get-WinEvent -ListProvider $provider -ErrorAction Stop | Select-Object -First 1)
                if ($manifest.Count -gt 0) {
                    $metadataStatus = 'readable'
                    if ($manifest[0].PSObject.Properties['Events']) {
                        $definitionCount = @($manifest[0].Events).Count
                    }
                } else {
                    $metadataReason = 'The provider manifest returned no metadata.'
                }
            } catch {
                $metadataReason = $_.Exception.Message
            }
            $observed = 'Observed EventID(s): {0}' -f $(if ($eventIds.Count -gt 0) { $eventIds -join ', ' } else { 'none' })
            if ($versions.Count -gt 0) { $observed += '; versions: ' + ($versions -join ', ') }
            if ($null -ne $definitionCount) { $observed += '; provider manifest definitions: ' + $definitionCount }
            $profiles.Add((New-LVHealthProfile -Profile 'provider-metadata' -Source 'event' `
                -Name $provider -Status 'readable' -RequiredConfiguration `
                'The provider manifest, message resources, and channel should be present for the selected event source.' `
                -ObservedConfiguration $observed -Provider $provider -Channel ([string]$channel) `
                -ProviderId ([string]$providerId) -EventIds $eventIds -EventVersions $versions -MetadataStatus $metadataStatus `
                -Reason $metadataReason -Advice $(if ($metadataStatus -eq 'readable') { $null } else { 'The event was read, but provider definitions or localized message resources were unavailable.' }) `
                -Origin 'live')) | Out-Null
        }
    }
    return @($profiles.ToArray())
}

function Get-LVRetentionHealthProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$ChannelStatus,
        [Parameter(Mandatory)][datetime]$WindowStart,
        [Parameter(Mandatory)][datetime]$WindowEnd
    )

    $profiles = New-Object System.Collections.Generic.List[object]
    $offset = [int][DateTimeOffset]::Now.Offset.TotalMinutes
    foreach ($channel in @($ChannelStatus.Keys | Sort-Object)) {
        $entry = $ChannelStatus[$channel]
        $channelDisabled = $entry.PSObject.Properties['IsEnabled'] -and $entry.IsEnabled -eq $false
        $status = if ($channelDisabled) { 'disabled' } elseif ($entry.Access -in @('denied', 'missing', 'unreadable')) { 'not-observed' } else { 'readable' }
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($property in @('RecordCount', 'LogMode', 'IsEnabled', 'MaximumSizeInBytes')) {
            if ($entry.PSObject.Properties[$property] -and $null -ne $entry.$property) {
                $parts.Add(('{0}={1}' -f $property, $entry.$property)) | Out-Null
            }
        }
        if ($entry.Oldest) { $parts.Add(('OldestRecord={0:o}' -f $entry.Oldest)) | Out-Null }
        if ($parts.Count -eq 0) { $parts.Add(('Access={0}' -f $entry.Access)) | Out-Null }
        $reason = $null
        if ($channelDisabled) { $reason = 'Event logging is disabled for this channel; retention does not provide event coverage.' }
        elseif ($entry.Access -ne 'readable') { $reason = 'Channel retention metadata was not observed because the channel is not readable.' }
        $profiles.Add((New-LVHealthProfile -Profile 'retention-and-clock' -Source 'event' -Name ([string]$channel) `
            -Status $status -RequiredConfiguration ('The channel should retain records from {0:o} through {1:o}; event timestamps are interpreted with a local clock offset of {2} minutes.' -f $WindowStart, $WindowEnd, $offset) `
            -ObservedConfiguration ($parts -join '; ') -RetentionMode $(if ($entry.PSObject.Properties['LogMode']) { [string]$entry.LogMode } else { $null }) `
            -RecordCount $(if ($entry.PSObject.Properties['RecordCount']) { $entry.RecordCount } else { $null }) `
            -OldestRecord $entry.Oldest -MaximumSizeBytes $(if ($entry.PSObject.Properties['MaximumSizeInBytes']) { $entry.MaximumSizeInBytes } else { $null }) `
            -ClockOffsetMinutes $offset -Channel ([string]$channel) -Reason $reason `
            -Advice 'Retention depth, filtering, log rollover, clock skew, and concurrent writers can all create gaps; do not treat this profile as a tamper verdict.' -Origin 'live')) | Out-Null
    }
    return @($profiles.ToArray())
}

function Get-LVPowerShellLoggingHealthProfile {
    $profiles = New-Object System.Collections.Generic.List[object]
    $settings = @(
        @{ Name = 'PowerShell script block logging'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Value = 'EnableScriptBlockLogging'; EventIds = @('4104') }
        @{ Name = 'PowerShell module logging'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Value = 'EnableModuleLogging'; EventIds = @('4103') }
        @{ Name = 'PowerShell transcription'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Value = 'EnableTranscripting'; EventIds = @('4105', '4106') }
    )
    foreach ($setting in $settings) {
        $status = 'not-observed'
        $observed = 'Policy registry value was not present.'
        $reason = $null
        try {
            $property = Get-ItemProperty -LiteralPath $setting.Path -Name $setting.Value -ErrorAction Stop
            $value = $property.($setting.Value)
            if ([int]$value -eq 1) {
                $status = 'enabled'
                $observed = '{0}=1' -f $setting.Value
            } else {
                $status = 'disabled'
                $observed = '{0}={1}' -f $setting.Value, $value
            }
        } catch [System.Management.Automation.ItemNotFoundException] {
            # A missing policy is distinct from a failed registry read. It means the
            # effective Windows default is in force, not that logging is enabled.
            $observed = 'Policy registry value was not present; the effective Windows default is in force.'
        } catch {
            $status = 'unreadable'
            $reason = $_.Exception.Message
        }
        $profiles.Add((New-LVHealthProfile -Profile 'powershell-logging' -Source 'policy' -Name $setting.Name `
            -Status $status -RequiredConfiguration ('Enable the policy to retain event ID(s) {0} when this telemetry is required.' -f ($setting.EventIds -join ', ')) `
            -ObservedConfiguration $observed -EventIds $setting.EventIds -Reason $reason `
            -Advice 'This is configuration health only. Missing PowerShell logging reduces visibility but is not evidence of malicious activity.' -Origin 'live')) | Out-Null
    }
    return @($profiles.ToArray())
}

function Get-LVAuditPolicyHealthProfile {
    [CmdletBinding()]
    param()

    $auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
    if (-not (Test-Path -LiteralPath $auditpol -PathType Leaf)) {
        return New-LVHealthProfile -Profile 'advanced-audit-policy' -Source 'policy' -Name 'auditpol' -Status 'not-observed' `
            -RequiredConfiguration 'Advanced audit policy should enable the subcategories required by the selected event channels.' `
            -ObservedConfiguration 'auditpol.exe was not present.' -Reason 'The Windows audit policy command was unavailable.' `
            -Advice 'Review audit policy manually before treating missing Security events as absent.' -Origin 'live'
    }
    try {
        $output = @(& $auditpol /get /category:* /r 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
        $rows = @($output | Where-Object { $_ -and $_.Trim() -and $_ -notmatch '^Machine Name' -and $_ -notmatch '^Policy Target' })
        if ($code -ne 0 -or $rows.Count -eq 0) {
            return New-LVHealthProfile -Profile 'advanced-audit-policy' -Source 'policy' -Name 'auditpol' -Status 'unreadable' `
                -RequiredConfiguration 'Advanced audit policy should enable the subcategories required by the selected event channels.' `
                -ObservedConfiguration 'auditpol returned no readable policy rows.' -Reason (($output | Select-Object -Last 1) -join '') `
                -Advice 'Review audit policy manually before treating missing Security events as absent.' -Origin 'live'
        }
        return New-LVHealthProfile -Profile 'advanced-audit-policy' -Source 'policy' -Name 'auditpol' -Status 'readable' `
            -RequiredConfiguration 'Advanced audit policy should enable the subcategories required by the selected event channels.' `
            -ObservedConfiguration ('auditpol returned {0} policy row(s); localized policy names were intentionally not copied into the report.' -f $rows.Count) `
            -Reason $null -Advice 'Compare enabled subcategories with the event IDs required by the channels under review.' -Origin 'live'
    } catch {
        return New-LVHealthProfile -Profile 'advanced-audit-policy' -Source 'policy' -Name 'auditpol' -Status 'unreadable' `
            -RequiredConfiguration 'Advanced audit policy should enable the subcategories required by the selected event channels.' `
            -ObservedConfiguration 'auditpol could not be executed.' -Reason $_.Exception.Message `
            -Advice 'Review audit policy manually before treating missing Security events as absent.' -Origin 'live'
    }
}

function Get-LVDefenderHealthProfile {
    [CmdletBinding()]
    param()

    $command = Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return New-LVHealthProfile -Profile 'defender-configuration' -Source 'defender' -Name 'Microsoft Defender' -Status 'not-observed' `
            -RequiredConfiguration 'Defender antivirus and real-time protection should be enabled when Defender is the intended protection provider.' `
            -ObservedConfiguration 'Get-MpComputerStatus was not available.' -Reason 'The Defender PowerShell module is not installed or accessible.' `
            -Advice 'Check the active endpoint protection provider separately; this profile is not a malware verdict.' -Origin 'live'
    }
    try {
        $state = & $command.Name -ErrorAction Stop
        $antivirus = if ($state.PSObject.Properties['AntivirusEnabled']) { [bool]$state.AntivirusEnabled } else { $false }
        $realtime = if ($state.PSObject.Properties['RealTimeProtectionEnabled']) { [bool]$state.RealTimeProtectionEnabled } else { $false }
        $status = if ($antivirus -and $realtime) { 'enabled' } else { 'warning' }
        return New-LVHealthProfile -Profile 'defender-configuration' -Source 'defender' -Name 'Microsoft Defender' -Status $status `
            -RequiredConfiguration 'Defender antivirus and real-time protection should be enabled when Defender is the intended protection provider.' `
            -ObservedConfiguration ('AntivirusEnabled={0}; RealTimeProtectionEnabled={1}' -f $antivirus, $realtime) `
            -Advice 'A disabled or passive Defender state is configuration context only; it is not a malicious verdict.' -Origin 'live'
    } catch {
        return New-LVHealthProfile -Profile 'defender-configuration' -Source 'defender' -Name 'Microsoft Defender' -Status 'unreadable' `
            -RequiredConfiguration 'Defender antivirus and real-time protection should be enabled when Defender is the intended protection provider.' `
            -ObservedConfiguration 'Defender status could not be read.' -Reason $_.Exception.Message `
            -Advice 'Check the active endpoint protection provider separately; this profile is not a malware verdict.' -Origin 'live'
    }
}

function Get-LVSysmonHealthProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$EventRecord,
        [Parameter(Mandatory)][hashtable]$ChannelStatus
    )

    $channel = 'Microsoft-Windows-Sysmon/Operational'
    $state = if ($ChannelStatus.ContainsKey($channel)) { $ChannelStatus[$channel] } else { $null }
    if ($null -eq $state) {
        return New-LVHealthProfile -Profile 'sysmon-configuration' -Source 'sysmon' -Name 'Sysmon' -Status 'not-observed' `
            -RequiredConfiguration 'Sysmon should be installed with an intentional EventFiltering configuration when Sysmon telemetry is required.' `
            -ObservedConfiguration 'The Sysmon operational channel was not requested.' -Reason 'The selected scan tier did not include the Sysmon channel.' `
            -Advice 'Use -DiagnosticChannels or an explicit Sysmon channel when this telemetry is in scope.' -Origin 'live'
    }
    $records = @($EventRecord | Where-Object { $_ -and $_.Source -eq 'event' -and ([string]$_.Channel -eq $channel -or [string]$_.Provider -eq 'Microsoft-Windows-Sysmon') })
    $observed = @($records | Where-Object { $null -ne $_.Id } | ForEach-Object { [string]$_.Id } | Sort-Object -Unique)
    $configPath = $null
    $enabled = @()
    $filtered = @()
    $candidatePaths = @(
        (Join-Path $env:ProgramData 'Sysmon\config.xml')
        (Join-Path $env:ProgramFiles 'Sysmon\sysmonconfig.xml')
        (Join-Path $env:SystemRoot 'Sysmon.xml')
        (Join-Path $env:SystemRoot 'Sysmon64.xml')
    )
    foreach ($candidate in $candidatePaths) {
        if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            $xml = [xml](Get-Content -LiteralPath $candidate -Raw -ErrorAction Stop)
            $configPath = $candidate
            $map = @{
                ProcessCreate=1; FileCreateTime=2; NetworkConnect=3; ProcessTerminate=5; DriverLoad=6; ImageLoad=7
                CreateRemoteThread=8; RawAccessRead=9; ProcessAccess=10; FileCreate=11; RegistryEvent=12
                FileCreateStreamHash=15; PipeEvent=17; WmiEvent=19; DnsQuery=22; FileDelete=23
                ClipboardChange=24; ProcessTampering=25; SysmonError=255
            }
            $filter = $xml.SelectSingleNode("//*[local-name()='EventFiltering']")
            foreach ($node in @($filter.ChildNodes)) {
                if ($map.ContainsKey($node.LocalName)) {
                    $id = [string]$map[$node.LocalName]
                    $enabled += $id
                    if (@($node.ChildNodes).Count -gt 0) { $filtered += $id }
                }
            }
            break
        } catch {
            $configPath = $candidate
        }
    }
    $enabled = @($enabled | Sort-Object -Unique)
    $filtered = @($filtered | Sort-Object -Unique)
    $status = if ($state.Access -in @('denied', 'missing', 'unreadable')) { 'not-observed' } elseif ($configPath -and $enabled.Count -gt 0) { 'readable' } else { 'partial' }
    $observedText = 'Observed EventID(s): {0}' -f $(if ($observed.Count -gt 0) { $observed -join ', ' } else { 'none' })
    if ($enabled.Count -gt 0) { $observedText += '; configured IDs: ' + ($enabled -join ', ') }
    if ($filtered.Count -gt 0) { $observedText += '; IDs with filtering rules: ' + ($filtered -join ', ') }
    $reason = if ($state.Access -ne 'readable') { 'The Sysmon channel was not readable.' } elseif (-not $configPath) { 'No conventional Sysmon XML configuration path was readable; configured and filtered IDs remain unknown.' } else { $null }
    return New-LVHealthProfile -Profile 'sysmon-configuration' -Source 'sysmon' -Name 'Sysmon' -Status $status `
        -RequiredConfiguration 'Sysmon should be installed with an intentional EventFiltering configuration when Sysmon telemetry is required.' `
        -ObservedConfiguration $observedText -EnabledEventIds $enabled -FilteredEventIds $filtered `
        -EventIds $observed -Channel $channel -Path $configPath -Reason $reason `
        -Advice 'Observed Sysmon events are evidence of collection only; filtered or missing IDs are visibility context, never a malicious verdict.' -Origin 'live'
}

function Invoke-LVWecutil {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Argument
    )

    return @(& $Path @Argument 2>&1 | ForEach-Object { [string]$_ })
}

function Get-LVWEFHealthProfile {
    [CmdletBinding()]
    param([AllowNull()][string[]]$Subscription)

    $wecutil = Join-Path $env:SystemRoot 'System32\wecutil.exe'
    if (-not (Test-Path -LiteralPath $wecutil -PathType Leaf)) {
        return New-LVHealthProfile -Profile 'wef-subscriptions' -Source 'wef' -Name 'Windows Event Forwarding' -Status 'not-observed' `
            -RequiredConfiguration 'WEF subscriptions should declare read-existing behavior, a heartbeat, and a bookmark/runtime state when forwarding is in scope.' `
            -ObservedConfiguration 'wecutil.exe was not present.' -Reason 'Windows Event Collector tooling was unavailable.' `
            -Advice 'WEF health is outside a one-shot local scan unless subscriptions are configured on this machine.' -Origin 'live'
    }
    try {
        $names = if ($Subscription -and $Subscription.Count -gt 0) {
            @($Subscription | Where-Object { $_ -and $_.Trim() } | Select-Object -First 32)
        } else {
            @(Invoke-LVWecutil -Path $wecutil -Argument @('es') | Where-Object { $_ -and $_.Trim() -and $_ -notmatch '^\s*(ERROR|Error)\b' } | Select-Object -First 32)
        }
        if (-not ($Subscription -and $Subscription.Count -gt 0) -and @($names | Where-Object { $_ -match '(?i)failed to open subscription enumeration|RPC server is unavailable|NativeCommandError' }).Count -gt 0) {
            return New-LVHealthProfile -Profile 'wef-subscriptions' -Source 'wef' -Name 'Windows Event Forwarding' -Status 'unreadable' `
                -RequiredConfiguration 'WEF subscriptions should declare read-existing behavior, a heartbeat, and a bookmark/runtime state when forwarding is in scope.' `
                -ObservedConfiguration 'wecutil could not open subscription enumeration.' -Reason (($names | Select-Object -First 1) -as [string]) `
                -Advice 'Review the local Windows Event Collector service and subscription store; this is not a maliciousness signal.' -Origin 'live'
        }
        if ($names.Count -eq 0) {
            return New-LVHealthProfile -Profile 'wef-subscriptions' -Source 'wef' -Name 'Windows Event Forwarding' -Status 'empty' `
                -RequiredConfiguration 'WEF subscriptions should declare read-existing behavior, a heartbeat, and a bookmark/runtime state when forwarding is in scope.' `
                -ObservedConfiguration 'No WEF subscriptions were returned by wecutil.' -Reason 'No local subscriptions were observed.' `
                -Advice 'This source is empty, not proof that remote collection is healthy or unhealthy.' -Origin 'live'
        }
        $profiles = New-Object System.Collections.Generic.List[object]
        foreach ($name in @($names | Select-Object -First 32)) {
            $raw = (Invoke-LVWecutil -Path $wecutil -Argument @('gs', [string]$name, '/f:xml')) -join [Environment]::NewLine
            $runtime = (Invoke-LVWecutil -Path $wecutil -Argument @('rs', [string]$name)) -join [Environment]::NewLine
            $readExisting = $null
            $heartbeat = $null
            $bookmark = $null
            $runtimeStatus = $null
            $dropped = $null
            $runtimeError = $null
            try {
                $xml = [xml]$raw
                $readNode = $xml.SelectSingleNode("//*[local-name()='ReadExistingEvents']")
                $heartbeatNode = $xml.SelectSingleNode("//*[contains(translate(local-name(), 'HEARTBEAT', 'heartbeat'), 'heartbeat')]")
                $bookmarkNode = $xml.SelectSingleNode("//*[contains(translate(local-name(), 'BOOKMARKRUNTIME', 'bookmarkruntime'), 'bookmark')]")
                if ($readNode) { $readExisting = [bool]::Parse([string]$readNode.InnerText) }
                if ($heartbeatNode -and [int]::TryParse([string]$heartbeatNode.InnerText, [ref]$heartbeat)) { }
                if ($bookmarkNode) { $bookmark = [string]$bookmarkNode.InnerText }
            } catch {
                $bookmark = 'unreadable configuration XML'
            }
            if ($runtime -match '(?im)^\s*(?:RuntimeStatus|Status)\s*[:=]\s*(?<value>.+?)\s*$') { $runtimeStatus = $Matches['value'].Trim() }
            if ($runtime -match '(?im)^\s*(?:EventsDropped|DroppedEvents|EventsDroppedCount)\s*[:=]\s*(?<value>\d+)\s*$') { $dropped = [int64]$Matches['value'] }
            if ($runtime -match '(?im)^\s*(?:LastError|Error)\s*[:=]\s*(?<value>.+?)\s*$') { $runtimeError = $Matches['value'].Trim() }
            if (-not $bookmark -and $runtime -match '(?im)^\s*(?:Bookmark|BookmarkState)\s*[:=]\s*(?<value>.+?)\s*$') { $bookmark = $Matches['value'].Trim() }
            $status = if ($raw) { 'readable' } elseif ($runtime) { 'partial' } else { 'unreadable' }
            $observed = ('ReadExistingEvents={0}; HeartbeatIntervalSeconds={1}; BookmarkState={2}; RuntimeStatus={3}; DroppedEvents={4}' -f $readExisting, $heartbeat, $bookmark, $runtimeStatus, $dropped)
            $healthEntry = New-LVHealthProfile -Profile 'wef-subscription' -Source 'wef' -Name ([string]$name) -Status $status `
                -RequiredConfiguration 'WEF subscriptions should declare read-existing behavior, a heartbeat, and a bookmark/runtime state when forwarding is in scope.' `
                -ObservedConfiguration $observed -ReadExistingEvents $readExisting -HeartbeatIntervalSeconds $heartbeat -BookmarkState $bookmark `
                -Reason $(if ($status -eq 'unreadable') { 'wecutil could not return subscription configuration or runtime state.' } elseif ($runtimeError) { $runtimeError } else { $null }) `
                -Advice 'Read-existing, heartbeat, bookmark, reconnect, and drop values describe collection health only; they are not maliciousness signals.' -Origin 'live'
            $healthEntry | Add-Member -NotePropertyName RuntimeStatus -NotePropertyValue $runtimeStatus
            $healthEntry | Add-Member -NotePropertyName DroppedEvents -NotePropertyValue $dropped
            $profiles.Add($healthEntry) | Out-Null
        }
        return @($profiles.ToArray())
    } catch {
        return New-LVHealthProfile -Profile 'wef-subscriptions' -Source 'wef' -Name 'Windows Event Forwarding' -Status 'unreadable' `
            -RequiredConfiguration 'WEF subscriptions should declare read-existing behavior, a heartbeat, and a bookmark/runtime state when forwarding is in scope.' `
            -ObservedConfiguration 'wecutil could not enumerate subscriptions.' -Reason $_.Exception.Message `
            -Advice 'Review WEF subscription health separately; this is not a maliciousness signal.' -Origin 'live'
    }
}

function Get-LVHealthProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$EventRecord,
        [Parameter(Mandatory)][hashtable]$ChannelStatus,
        [Parameter(Mandatory)][datetime]$WindowStart,
        [Parameter(Mandatory)][datetime]$WindowEnd
    )

    $profiles = New-Object System.Collections.Generic.List[object]
    foreach ($healthRecord in @(Get-LVProviderHealthProfile -EventRecord $EventRecord -ChannelStatus $ChannelStatus)) { $profiles.Add($healthRecord) | Out-Null }
    foreach ($healthRecord in @(Get-LVRetentionHealthProfile -ChannelStatus $ChannelStatus -WindowStart $WindowStart -WindowEnd $WindowEnd)) { $profiles.Add($healthRecord) | Out-Null }
    foreach ($healthRecord in @(Get-LVPowerShellLoggingHealthProfile)) { $profiles.Add($healthRecord) | Out-Null }
    $profiles.Add((Get-LVAuditPolicyHealthProfile)) | Out-Null
    $profiles.Add((Get-LVDefenderHealthProfile)) | Out-Null
    $profiles.Add((Get-LVSysmonHealthProfile -EventRecord $EventRecord -ChannelStatus $ChannelStatus)) | Out-Null
    foreach ($healthRecord in @(Get-LVWEFHealthProfile)) { $profiles.Add($healthRecord) | Out-Null }
    return @($profiles.ToArray())
}
