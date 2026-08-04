# Local, per-machine suppression expectations. These are an operator-owned baseline,
# not a verdict source: every matched entry remains present in the raw result and in
# corpus totals, while the reader-facing projection may hide or downgrade it.

$script:LVSuppressionSchemaVersion = 1
$script:LVSuppressionReviewDays = 90
$script:LVSuppressionActions = @('hide', 'downgrade')

function Get-LVSuppressionDefaultPath {
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { return $null }
    return Join-Path (Join-Path $env:LOCALAPPDATA 'LogVerdict') 'suppressions.json'
}

function Get-LVSuppressionSignatureHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Key)

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Key))
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $algorithm.Dispose()
    }
}

function ConvertTo-LVSuppressionDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Value -is [DateTimeOffset]) {
        return $Value.ToUniversalTime()
    }
    if ($Value -is [datetime]) {
        return ([DateTimeOffset]$Value).ToUniversalTime()
    }
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        throw ("Suppression field '{0}' must be an ISO-8601 date-time with a timezone." -f $Name)
    }
    $text = [string]$Value
    if ($text -notmatch 'T' -or $text -notmatch '(?i)(Z|[+-]\d{2}:\d{2})$') {
        throw ("Suppression field '{0}' must include a date, time, and timezone: {1}" -f $Name, $text)
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AllowWhiteSpaces
    if (-not [DateTimeOffset]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw ("Suppression field '{0}' is not a readable date-time: {1}" -f $Name, $text)
    }
    return $parsed.ToUniversalTime()
}

function ConvertTo-LVSuppressionDateText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][DateTimeOffset]$Value)

    # DateTime.ToString('o') includes the UTC designator when the value's Kind is
    # Utc. Appending another one would create a timestamp the report contract rejects.
    return $Value.UtcDateTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function Assert-LVSuppressionEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][DateTimeOffset]$AsOf
    )

    $allowed = @('id', 'scope', 'action', 'downgradeTo', 'statement', 'created', 'expiresOn')
    foreach ($property in @($Entry.PSObject.Properties)) {
        if ($allowed -notcontains $property.Name) {
            throw ("Suppression entry {0} contains unsupported field '{1}'." -f $Index, $property.Name)
        }
    }
    foreach ($required in @('id', 'scope', 'action', 'statement', 'created')) {
        if (-not $Entry.PSObject.Properties[$required]) {
            throw ("Suppression entry {0} is missing required field '{1}'." -f $Index, $required)
        }
    }

    $id = [string]$Entry.id
    if ($id -notmatch '^[A-Za-z][A-Za-z0-9._-]{0,63}$') {
        throw ("Suppression entry {0} has an invalid id '{1}'." -f $Index, $id)
    }
    if ($Entry.statement -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Entry.statement) -or ([string]$Entry.statement).Length -gt 4000) {
        throw ("Suppression entry '{0}' requires a non-empty statement of at most 4000 characters." -f $id)
    }
    $action = [string]$Entry.action
    if ($script:LVSuppressionActions -notcontains $action) {
        throw ("Suppression entry '{0}' has unsupported action '{1}'. Use hide or downgrade." -f $id, $action)
    }

    $scopeProperty = $Entry.PSObject.Properties['scope']
    if (-not $scopeProperty -or $null -eq $scopeProperty.Value -or $scopeProperty.Value -is [string]) {
        throw ("Suppression entry '{0}' requires an object-valued scope." -f $id)
    }
    $scope = $scopeProperty.Value
    foreach ($property in @($scope.PSObject.Properties)) {
        if (@('signatureHash', 'machine', 'windowsBuild', 'appVersion') -notcontains $property.Name) {
            throw ("Suppression entry '{0}' scope contains unsupported field '{1}'." -f $id, $property.Name)
        }
    }
    foreach ($required in @('signatureHash', 'machine')) {
        if (-not $scope.PSObject.Properties[$required] -or [string]::IsNullOrWhiteSpace([string]$scope.$required)) {
            throw ("Suppression entry '{0}' scope requires '{1}'." -f $id, $required)
        }
    }
    $signatureHash = [string]$scope.signatureHash
    if ($signatureHash -notmatch '^[0-9a-fA-F]{64}$') {
        throw ("Suppression entry '{0}' scope.signatureHash must be a 64-character SHA-256 value." -f $id)
    }
    if ([string]$scope.machine -match '[\r\n]' -or ([string]$scope.machine).Length -gt 255) {
        throw ("Suppression entry '{0}' scope.machine is invalid." -f $id)
    }
    $hasBuild = $scope.PSObject.Properties['windowsBuild'] -and -not [string]::IsNullOrWhiteSpace([string]$scope.windowsBuild)
    $hasVersion = $scope.PSObject.Properties['appVersion'] -and -not [string]::IsNullOrWhiteSpace([string]$scope.appVersion)
    if (-not $hasBuild -and -not $hasVersion) {
        throw ("Suppression entry '{0}' scope requires windowsBuild or appVersion." -f $id)
    }
    if ($hasBuild -and [string]$scope.windowsBuild -notmatch '^\d{1,10}$') {
        throw ("Suppression entry '{0}' scope.windowsBuild must be a numeric Windows build." -f $id)
    }
    $appVersionText = if ($hasVersion) { [string]$scope.appVersion } else { '' }
    if ($hasVersion -and ($appVersionText -match '[\r\n]' -or $appVersionText.Length -gt 64)) {
        throw ("Suppression entry '{0}' scope.appVersion is invalid." -f $id)
    }

    if ($action -eq 'hide' -and $Entry.PSObject.Properties['downgradeTo']) {
        throw ("Suppression entry '{0}' uses hide and cannot also declare downgradeTo." -f $id)
    }
    $downgradeTo = $null
    if ($action -eq 'downgrade') {
        if (-not $Entry.PSObject.Properties['downgradeTo'] -or [string]::IsNullOrWhiteSpace([string]$Entry.downgradeTo)) {
            throw ("Suppression entry '{0}' uses downgrade but has no downgradeTo verdict." -f $id)
        }
        $downgradeTo = [string]$Entry.downgradeTo
        if (-not $script:LVVerdictRank.ContainsKey($downgradeTo)) {
            throw ("Suppression entry '{0}' has an invalid downgradeTo verdict '{1}'." -f $id, $downgradeTo)
        }
    }

    $created = ConvertTo-LVSuppressionDate -Value $Entry.created -Name 'created'
    $expires = $null
    if ($Entry.PSObject.Properties['expiresOn']) {
        if ($null -eq $Entry.expiresOn) {
            throw ("Suppression entry '{0}' must omit expiresOn or provide a date-time; null is not valid." -f $id)
        }
        $expires = ConvertTo-LVSuppressionDate -Value $Entry.expiresOn -Name 'expiresOn'
        if ($expires -le $created) {
            throw ("Suppression entry '{0}' expiresOn must be later than created." -f $id)
        }
    }
    $reviewDue = if ($expires) { $expires } else { $created.AddDays($script:LVSuppressionReviewDays) }
    $status = if ($AsOf -ge $reviewDue) { 'expired' } else { 'active' }

    return [pscustomobject][ordered]@{
        id = $id
        scope = [pscustomobject][ordered]@{
            signatureHash = $signatureHash.ToLowerInvariant()
            machine = [string]$scope.machine
            windowsBuild = if ($hasBuild) { [string]$scope.windowsBuild } else { $null }
            appVersion = if ($hasVersion) { [string]$scope.appVersion } else { $null }
        }
        action = $action
        downgradeTo = $downgradeTo
        statement = [string]$Entry.statement
        created = ConvertTo-LVSuppressionDateText -Value $created
        expiresOn = if ($expires) { ConvertTo-LVSuppressionDateText -Value $expires } else { $null }
        reviewDueOn = ConvertTo-LVSuppressionDateText -Value $reviewDue
        status = $status
    }
}

function Import-LVSuppressionSet {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Path,
        [datetime]$AsOf = (Get-Date)
    )

    $explicit = -not [string]::IsNullOrWhiteSpace($Path)
    $resolved = if ($explicit) { $Path } else { Get-LVSuppressionDefaultPath }
    $base = [ordered]@{
        Path = $resolved
        Status = 'missing'
        SchemaVersion = $script:LVSuppressionSchemaVersion
        Entries = @()
        EntryCount = 0
        AsOf = ([DateTimeOffset]$AsOf).ToUniversalTime()
    }
    if ([string]::IsNullOrWhiteSpace($resolved) -or -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        if ($explicit) { throw ("Suppression file was not found: {0}" -f $resolved) }
        return [pscustomobject]$base
    }

    try {
        $json = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 -ErrorAction Stop
        # Windows PowerShell 5.1 eagerly materializes ISO-looking JSON strings as
        # DateTime values, losing whether the author supplied a timezone. Validate
        # the serialized date tokens first, then keep strings on newer runtimes too.
        foreach ($dateName in @('created', 'expiresOn')) {
            foreach ($dateMatch in [regex]::Matches($json, ('(?i)"{0}"\s*:\s*"([^"]*)"' -f $dateName))) {
                $dateText = $dateMatch.Groups[1].Value
                if ($dateText -notmatch 'T' -or $dateText -notmatch '(?i)(Z|[+-]\d{2}:\d{2})$') {
                    throw ("Suppression field '{0}' must include a date, time, and timezone: {1}" -f $dateName, $dateText)
                }
            }
        }
        $convertParameters = @{ InputObject = $json; ErrorAction = 'Stop' }
        if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
            $convertParameters.DateKind = 'String'
        }
        $document = ConvertFrom-Json @convertParameters
    } catch {
        throw ("Suppression file '{0}' is not readable JSON: {1}" -f $resolved, $_.Exception.Message)
    }
    foreach ($property in @($document.PSObject.Properties)) {
        if (@('schemaVersion', 'name', 'entries') -notcontains $property.Name) {
            throw ("Suppression document contains unsupported field '{0}'." -f $property.Name)
        }
    }
    if ([int]$document.schemaVersion -ne $script:LVSuppressionSchemaVersion) {
        throw ("Suppression document schemaVersion {0} is not supported." -f $document.schemaVersion)
    }
    if ([string]$document.name -ne 'LogVerdict.Suppressions') {
        throw "Suppression document name must be 'LogVerdict.Suppressions'."
    }
    if (-not $document.PSObject.Properties['entries'] -or $null -eq $document.entries -or $document.entries -is [string]) {
        throw 'Suppression document entries must be an array.'
    }

    $seenIds = @{}
    $seenScopes = @{}
    $entries = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($entry in @($document.entries | Where-Object { $_ })) {
        $normalized = Assert-LVSuppressionEntry -Entry $entry -Index $index -AsOf $base.AsOf
        $idKey = $normalized.id.ToLowerInvariant()
        if ($seenIds.ContainsKey($idKey)) { throw ("Suppression document contains duplicate id '{0}'." -f $normalized.id) }
        $seenIds[$idKey] = $true
        $scopeKey = '{0}|{1}|{2}|{3}' -f $normalized.scope.signatureHash, $normalized.scope.machine.ToLowerInvariant(), $normalized.scope.windowsBuild, $normalized.scope.appVersion
        if ($seenScopes.ContainsKey($scopeKey)) { throw ("Suppression document contains duplicate scope for ids '{0}' and '{1}'." -f $seenScopes[$scopeKey], $normalized.id) }
        $seenScopes[$scopeKey] = $normalized.id
        $entries.Add($normalized) | Out-Null
        $index++
    }
    $base.Status = 'loaded'
    $base.Entries = @($entries.ToArray())
    $base.EntryCount = $entries.Count
    return [pscustomobject]$base
}

function Test-LVSuppressionMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)]$Finding,
        [AllowNull()][string]$MachineName,
        [AllowNull()][string]$WindowsBuild,
        [AllowNull()][string]$AppVersion
    )

    if ([string]$Entry.status -ne 'active') { return $false }
    if ((Get-LVSuppressionSignatureHash -Key ([string]$Finding.Key)) -ine [string]$Entry.scope.signatureHash) { return $false }
    if ([string]$Entry.scope.machine -ine [string]$MachineName) { return $false }
    if ($Entry.scope.windowsBuild -and [string]$Entry.scope.windowsBuild -ne [string]$WindowsBuild) { return $false }
    if ($Entry.scope.appVersion -and [string]$Entry.scope.appVersion -ne [string]$AppVersion) { return $false }
    return $true
}

function Apply-LVSuppression {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Apply is the domain verb for attaching an operator expectation to each in-memory finding.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)]$SuppressionSet,
        [AllowNull()][string]$MachineName,
        [AllowNull()][string]$WindowsBuild,
        [AllowNull()][string]$AppVersion,
        [datetime]$AsOf = (Get-Date)
    )

    $matchedIds = New-Object 'System.Collections.Generic.HashSet[string]'
    $output = New-Object System.Collections.Generic.List[object]
    foreach ($source in @($Finding | Where-Object { $_ })) {
        $copy = [pscustomobject]@{}
        foreach ($property in @($source.PSObject.Properties)) {
            $copy | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
        }
        $copy | Add-Member -NotePropertyName 'Suppressed' -NotePropertyValue $false -Force
        $copy | Add-Member -NotePropertyName 'SuppressionAction' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'SuppressionId' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'SuppressionStatement' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'SuppressionCreated' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'SuppressionExpiresOn' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'SuppressionReviewDueOn' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'SuppressionStatus' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'SuppressionSignatureHash' -NotePropertyValue $null -Force
        $copy | Add-Member -NotePropertyName 'OriginalVerdict' -NotePropertyValue $null -Force

        $matchingEntries = @($SuppressionSet.Entries | Where-Object {
            Test-LVSuppressionMatch -Entry $_ -Finding $copy -MachineName $MachineName -WindowsBuild $WindowsBuild -AppVersion $AppVersion
        })
        if ($matchingEntries.Count -gt 1) {
            throw ("More than one active suppression matches signature '{0}'. Narrow the scope or remove the duplicate entries." -f $copy.Key)
        }
        if ($matchingEntries.Count -eq 1) {
            $entry = $matchingEntries[0]
            $matchedIds.Add([string]$entry.id) | Out-Null
            $copy.Suppressed = $true
            $copy.SuppressionAction = [string]$entry.action
            $copy.SuppressionId = [string]$entry.id
            $copy.SuppressionStatement = [string]$entry.statement
            $copy.SuppressionCreated = [string]$entry.created
            $copy.SuppressionExpiresOn = if ($entry.expiresOn) { [string]$entry.expiresOn } else { $null }
            $copy.SuppressionReviewDueOn = [string]$entry.reviewDueOn
            $copy.SuppressionStatus = 'active'
            $copy.SuppressionSignatureHash = [string]$entry.scope.signatureHash
            $copy.OriginalVerdict = [string]$copy.Verdict
            if ([string]$entry.action -eq 'downgrade') {
                $oldRank = Get-LVVerdictRank -Verdict $copy.OriginalVerdict
                $newRank = Get-LVVerdictRank -Verdict ([string]$entry.downgradeTo)
                if ($newRank -ge $oldRank) {
                    throw ("Suppression '{0}' is not a downgrade for signature '{1}': {2} -> {3}." -f $entry.id, $copy.Key, $copy.OriginalVerdict, $entry.downgradeTo)
                }
                $copy.Verdict = [string]$entry.downgradeTo
                $copy.Why = '{0} Suppression {1} downgraded this finding from {2} to {3}: {4}' -f $copy.Why, $entry.id, $copy.OriginalVerdict, $entry.downgradeTo, $entry.statement
            }
        }
        $output.Add($copy) | Out-Null
    }

    $matched = @($SuppressionSet.Entries | Where-Object { $matchedIds.Contains([string]$_.id) })
    $unmatched = @($SuppressionSet.Entries | Where-Object { $_.status -eq 'active' -and -not $matchedIds.Contains([string]$_.id) })
    $expired = @($SuppressionSet.Entries | Where-Object { $_.status -eq 'expired' })
    $summary = [pscustomobject][ordered]@{
        Path = $SuppressionSet.Path
        Status = $SuppressionSet.Status
        EntryCount = @($SuppressionSet.Entries).Count
        ActiveCount = @($SuppressionSet.Entries | Where-Object { $_.status -eq 'active' }).Count
        MatchedCount = $matched.Count
        UnmatchedCount = $unmatched.Count
        ExpiredCount = $expired.Count
        SuppressedFindingCount = @($output | Where-Object { $_.Suppressed }).Count
        Entries = @($SuppressionSet.Entries)
        Matched = $matched
        Unmatched = $unmatched
        Expired = $expired
        AsOf = ([DateTimeOffset]$AsOf).ToUniversalTime()
    }
    return [pscustomobject][ordered]@{
        Findings = @($output.ToArray())
        Summary = $summary
    }
}
