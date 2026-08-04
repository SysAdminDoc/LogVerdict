# Provider message-template cache support. The cache is an operator-supplied,
# normalized export; the scan never downloads a provider database itself.

$script:LVProviderTemplateMissingMessage = '(no message template registered for this provider on this machine)'
$script:LVProviderTemplateAllowedLicenses = @('Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'CC-BY-4.0', 'MIT')
$script:LVProviderTemplateMaxFileBytes = 16777216
$script:LVProviderTemplateMaxEntries = 100000
$script:LVProviderTemplateMaxTextBytes = 32768
$script:LVProviderTemplateCoverage = @{ Cache = $null; LocalMissing = [int64]0; CacheResolved = [int64]0 }
$script:LVProviderTemplateCacheError = $null

function Get-LVProviderTemplateCachePath {
    [CmdletBinding()]
    param([AllowNull()][string]$Path)
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $candidate = [IO.Path]::GetFullPath($Path)
        if (Test-Path -LiteralPath $candidate -PathType Container) { return (Join-Path $candidate 'provider-templates.json') }
        return $candidate
    }
    $localApplicationData = [string]$env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($localApplicationData)) { $localApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData) }
    if ([string]::IsNullOrWhiteSpace($localApplicationData)) { return $null }
    return (Join-Path (Join-Path $localApplicationData 'LogVerdict') 'provider-templates.json')
}

function Get-LVProviderTemplateProperty {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string[]]$Name)
    if ($null -eq $InputObject) { return $null }
    foreach ($candidate in $Name) { $property = $InputObject.PSObject.Properties[$candidate]; if ($property) { return $property.Value } }
    return $null
}

function ConvertTo-LVProviderTemplateEventId {
    param([Parameter(Mandatory)][AllowNull()]$Value)
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'Provider template eventId is required.' }
    $number = 0
    try {
        if ($text -match '^(?i:0x)') { $number = [Convert]::ToInt32($text.Substring(2), 16) }
        elseif (-not [int]::TryParse($text, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { throw 'not an integer' }
    } catch { throw ("Provider template eventId '{0}' is not a valid integer." -f $text) }
    if ($number -lt 0 -or $number -gt 65535) { throw ("Provider template eventId '{0}' is outside the Windows Event ID range." -f $text) }
    return [int]$number
}

function Test-LVProviderTemplateMissingMessage {
    param([AllowNull()][string]$Message)
    return [string]::IsNullOrWhiteSpace($Message) -or $Message.Trim() -ieq $script:LVProviderTemplateMissingMessage
}

function Read-LVProviderTemplateCache {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path)
    $file = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if (-not $file -or $file.PSIsContainer -or [int64]$file.Length -gt [int64]$script:LVProviderTemplateMaxFileBytes) {
        throw ("Provider template cache exceeds the {0} byte safety limit or is not a file." -f $script:LVProviderTemplateMaxFileBytes)
    }
    try { $document = [IO.File]::ReadAllText($resolved, (New-Object Text.UTF8Encoding($false))) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw ("Provider template cache is not readable JSON: {0}" -f $_.Exception.Message) }
    if ($null -eq $document) { throw 'Provider template cache is empty.' }
    if ([int]$document.schemaVersion -ne 1) { throw 'Provider template cache schemaVersion must be 1.' }
    $documentName = [string](Get-LVProviderTemplateProperty -InputObject $document -Name @('name'))
    if ($documentName -ne 'LogVerdict.ProviderTemplates') { throw 'Provider template cache name must be LogVerdict.ProviderTemplates.' }
    if (-not $document.source) { throw 'Provider template cache source metadata is required.' }
    $sourceName = [string](Get-LVProviderTemplateProperty -InputObject $document.source -Name @('name', 'repository'))
    $license = [string](Get-LVProviderTemplateProperty -InputObject $document.source -Name @('license', 'licence'))
    $revision = [string](Get-LVProviderTemplateProperty -InputObject $document.source -Name @('revision', 'sourceRevision'))
    if ([string]::IsNullOrWhiteSpace($sourceName) -or $sourceName.Length -gt 256) { throw 'Provider template cache source.name is required and must be no longer than 256 characters.' }
    if ($script:LVProviderTemplateAllowedLicenses -notcontains $license) { throw ("Provider template cache license '{0}' is not permitted." -f $license) }
    if ([string]::IsNullOrWhiteSpace($revision) -or $revision.Length -gt 128) { throw 'Provider template cache source.revision is required and must be no longer than 128 characters.' }
    $sourceUri = [string](Get-LVProviderTemplateProperty -InputObject $document.source -Name @('uri', 'url', 'repositoryUri'))
    if (-not [string]::IsNullOrWhiteSpace($sourceUri) -and $sourceUri -notmatch '^https://') { throw 'Provider template cache source.uri must use HTTPS.' }
    $generatedAt = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse([string]$document.generatedAt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$generatedAt)) { throw 'Provider template cache generatedAt must be an ISO-8601 timestamp.' }
    if ($null -eq $document.PSObject.Properties['templates']) { throw 'Provider template cache templates are required.' }
    $entries = @($document.templates | Where-Object { $_ })
    if ($entries.Count -gt $script:LVProviderTemplateMaxEntries) { throw ("Provider template cache contains {0} entries; the safety limit is {1}." -f $entries.Count, $script:LVProviderTemplateMaxEntries) }
    $normalized = New-Object System.Collections.Generic.List[object]
    $keys = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $provider = ([string](Get-LVProviderTemplateProperty -InputObject $entry -Name @('provider', 'Provider', 'providerName', 'ProviderName'))).Trim()
        if ([string]::IsNullOrWhiteSpace($provider) -or $provider.Length -gt 260) { throw 'Every provider template needs a provider name no longer than 260 characters.' }
        $providerId = ([string](Get-LVProviderTemplateProperty -InputObject $entry -Name @('providerId', 'ProviderId', 'providerGuid', 'ProviderGuid'))).Trim()
        if ($providerId.Length -gt 128) { throw 'Provider template providerId is too long.' }
        $eventId = ConvertTo-LVProviderTemplateEventId -Value (Get-LVProviderTemplateProperty -InputObject $entry -Name @('eventId', 'EventId', 'id', 'Id', 'messageIdentifier', 'MessageIdentifier'))
        $locale = ([string](Get-LVProviderTemplateProperty -InputObject $entry -Name @('locale', 'Locale', 'language', 'Language'))).Trim()
        if ([string]::IsNullOrWhiteSpace($locale)) { $locale = 'en-US' }
        if ($locale.Length -gt 32 -or $locale -notmatch '^(?:\*|[A-Za-z]{2,8}(?:[-_][A-Za-z0-9]{2,8})*)$') { throw 'Provider template locale is invalid or too long.' }
        $template = ([string](Get-LVProviderTemplateProperty -InputObject $entry -Name @('template', 'Template', 'message', 'Message', 'messageString', 'MessageString'))).Trim()
        if ([string]::IsNullOrWhiteSpace($template) -or $template.Length -gt $script:LVProviderTemplateMaxTextBytes) { throw ("Provider template for {0}/{1} must contain text no longer than {2} characters." -f $provider, $eventId, $script:LVProviderTemplateMaxTextBytes) }
        if (Test-LVProviderTemplateMissingMessage -Message $template) { throw ("Provider template for {0}/{1} is the local-metadata placeholder, not vendor text." -f $provider, $eventId) }
        $versionValue = Get-LVProviderTemplateProperty -InputObject $entry -Name @('version', 'Version')
        $version = $null
        if ($null -ne $versionValue -and -not [string]::IsNullOrWhiteSpace([string]$versionValue)) {
            $version = ConvertTo-LVProviderTemplateEventId -Value $versionValue
        }
        $versionKey = if ($null -eq $version) { '*' } else { [string]$version }
        $key = '{0}|{1}|{2}|{3}|{4}' -f $provider.ToLowerInvariant(), $providerId.ToLowerInvariant(), $eventId, $versionKey, $locale.ToLowerInvariant()
        if (-not $keys.Add($key)) { throw ("Provider template cache contains a duplicate entry for {0}/{1}/{2}." -f $provider, $eventId, $locale) }
        $normalized.Add([pscustomobject][ordered]@{ Provider=$provider; ProviderId=if ([string]::IsNullOrWhiteSpace($providerId)) { $null } else { $providerId }; EventId=$eventId; Version=$version; Locale=$locale; Template=$template }) | Out-Null
    }
    return [pscustomobject][ordered]@{
        Path=$resolved; SchemaVersion=1
        Source=[pscustomobject][ordered]@{ Name=$sourceName; License=$license; Revision=$revision; Uri=$sourceUri }
        GeneratedAt=$generatedAt; Templates=@($normalized.ToArray())
    }
}

function Resolve-LVProviderTemplate {
    [CmdletBinding()]
    param(
        [AllowNull()]$Cache,
        [AllowNull()][string]$Provider,
        [AllowNull()][string]$ProviderId,
        [Parameter(Mandatory)][int]$EventId,
        [AllowNull()][Nullable[int]]$Version,
        [AllowNull()][string]$Locale
    )
    if ($null -eq $Cache) { return $null }
    $providerText=([string]$Provider).Trim(); $providerIdText=([string]$ProviderId).Trim(); $localeText=([string]$Locale).Trim()
    $language=if($localeText -match '-'){ $localeText.Split('-')[0] } else { $localeText }
    $best=$null; $bestRank=[int]::MaxValue
    foreach($entry in @($Cache.Templates | Where-Object { $_ })) {
        if([int]$entry.EventId -ne $EventId){continue}; $providerRank=[int]::MaxValue
        if($providerText -and [string]$entry.Provider -ieq $providerText){$providerRank=0}
        if($providerIdText -and $entry.ProviderId -and [string]$entry.ProviderId -ieq $providerIdText){$providerRank=[Math]::Min($providerRank,1)}
        if($providerRank -eq [int]::MaxValue){continue}; $entryLocale=([string]$entry.Locale).Trim(); $localeRank=4
        if($localeText -and $entryLocale -ieq $localeText){$localeRank=0}elseif($language -and $entryLocale -ieq $language){$localeRank=1}elseif($entryLocale -eq '*'){$localeRank=2}elseif($entryLocale -ieq 'en-US'){$localeRank=3}elseif([string]::IsNullOrWhiteSpace($entryLocale)){$localeRank=4}
        $versionRank=3
        if($null -eq $Version){if($null -eq $entry.Version){$versionRank=0}else{$versionRank=1}}
        elseif($null -eq $entry.Version){$versionRank=1}
        elseif([int]$entry.Version -eq [int]$Version){$versionRank=0}else{continue}
        $rank=($providerRank*100)+($versionRank*10)+$localeRank; if($rank -lt $bestRank){$best=$entry;$bestRank=$rank}
    }
    return $best
}

function ConvertTo-LVProviderTemplateMessage {
    param([Parameter(Mandatory)][string]$Template,[AllowNull()]$EventObject)
    if(-not $EventObject){return $Template}; $values=New-Object System.Collections.Generic.List[string]; $properties=$EventObject.PSObject.Properties['Properties']
    if($properties -and $properties.Value){foreach($property in @($properties.Value)){ $value=if($property.PSObject.Properties['Value']){$property.Value}else{$property};$values.Add([string]$value)|Out-Null }}
    $rendered=$Template; for($index=$values.Count-1;$index -ge 0;$index--){$rendered=$rendered.Replace(('%{0}' -f ($index+1)),$values[$index])}; return $rendered
}

function Initialize-LVProviderTemplateCache {
    [CmdletBinding()]
    param([AllowNull()][string]$Path)
    $script:LVProviderTemplateCoverage=[pscustomobject]@{Cache=$null;LocalMissing=[int64]0;CacheResolved=[int64]0}
    $script:LVProviderTemplateCacheError = $null
    $resolved=Get-LVProviderTemplateCachePath -Path $Path
    if([string]::IsNullOrWhiteSpace($resolved) -or -not(Test-Path -LiteralPath $resolved -PathType Leaf)){if(-not[string]::IsNullOrWhiteSpace($Path)){$script:LVProviderTemplateCacheError = "Provider template cache was not found: $resolved";Write-LVLog -Level warn -Message $script:LVProviderTemplateCacheError};return $null}
    try{$cache=Read-LVProviderTemplateCache -Path $resolved;$script:LVProviderTemplateCoverage.Cache=$cache;Write-LVLog -Level info -Message ('Loaded {0} provider message template(s) from {1} ({2}).' -f @($cache.Templates).Count,$cache.Source.Name,$cache.Source.Revision);return $cache}catch{$script:LVProviderTemplateCacheError=$_.Exception.Message;Write-LVLog -Level warn -Message ("Provider template cache was rejected and will not be used: {0}" -f $script:LVProviderTemplateCacheError);return $null}
}

function New-LVProviderTemplateCoverageRecord {
    [CmdletBinding()]
    param([AllowNull()]$Cache,[int64]$LocalMissing=0,[int64]$CacheResolved=0,[Parameter(Mandatory)][ValidateSet('live','offline')][string]$Origin,[AllowNull()]$CollectionBudget)
    if($null -eq $Cache -and $LocalMissing -eq 0){return $null};$name='provider message template cache';if($Cache -and $Cache.Source -and $Cache.Source.Name){$name=[string]$Cache.Source.Name}
    $reason=$null;if($LocalMissing -gt 0){$reason=('{0} record(s) had no provider message template registered locally; local provider metadata was absent.' -f $LocalMissing);if($CacheResolved -gt 0){$reason+=(' {0} record(s) were restored from the provider-template cache.' -f $CacheResolved)}elseif($Cache){$reason+=' No matching cache entry was available for those records.'}}elseif($Cache){$reason=('Loaded {0} provider message template(s); no local provider message gap was observed.' -f @($Cache.Templates).Count)}
    $status=if($Cache){'readable'}else{'not-observed'};return (New-LVCoverageRecord -Source 'provider-template' -Kind 'cache' -Name $name -Status $status -Reason $reason -ObservedRecords $CacheResolved -SkippedRecords $LocalMissing -Path $(if($Cache){$Cache.Path}else{$null}) -CollectionBudget $CollectionBudget -Origin $Origin)
}
