# Structured event fields. Windows renders Message from localized resources, while
# EventData/UserData values are the invariant fields that Sigma-style rules can inspect.
# This is intentionally a small, bounded subset: unsupported expressions stay review-only.

$script:LVStructuredDataMaxFields = 64
$script:LVStructuredDataMaxValuesPerField = 8
$script:LVStructuredDataMaxValueLength = 4096

function Add-LVStructuredDataValue {
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Name) -or $Map.Count -ge $script:LVStructuredDataMaxFields) { return }
    if ($null -eq $Value) { return }
    $text = [string]$Value
    if ($null -eq $text) { return }
    if ($text.Length -gt $script:LVStructuredDataMaxValueLength) {
        $text = $text.Substring(0, $script:LVStructuredDataMaxValueLength)
    }
    if (-not $Map.ContainsKey($Name)) {
        $Map[$Name] = $text
        return
    }
    $values = @($Map[$Name])
    if ($values -contains $text -or $values.Count -ge $script:LVStructuredDataMaxValuesPerField) { return }
    $Map[$Name] = @($values + $text)
}

function Add-LVStructuredDataObject {
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [Parameter(Mandatory)][string]$Prefix,
        [AllowNull()]$InputObject
    )

    if ($null -eq $InputObject) { return }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { Add-LVStructuredDataValue -Map $Map -Name ([string]$key) -Value $InputObject[$key] }
        return
    }
    if ($InputObject -is [string] -or $InputObject.GetType().IsPrimitive) {
        Add-LVStructuredDataValue -Map $Map -Name $Prefix -Value $InputObject
        return
    }
    $properties = @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -match 'Property|NoteProperty' })
    if ($properties.Count -eq 0) {
        Add-LVStructuredDataValue -Map $Map -Name $Prefix -Value $InputObject
        return
    }
    foreach ($property in $properties) {
        Add-LVStructuredDataValue -Map $Map -Name ([string]$property.Name) -Value $property.Value
    }
}

function ConvertTo-LVStructuredDataObject {
    param([AllowNull()]$InputObject)

    $accumulator = New-LVStructuredDataAccumulator
    if ($InputObject) {
        Add-LVEventStructuredDataToAccumulator -Accumulator $accumulator -Incoming $InputObject
    }
    return ConvertTo-LVStructuredDataProjection -Accumulator $accumulator
}

function New-LVStructuredDataAccumulator {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This creates an in-memory bounded accumulator and changes no external state.')]
    [CmdletBinding()]
    param()
    return [pscustomobject][ordered]@{
        EventData = @{}
        UserData  = @{}
    }
}

function Add-LVEventStructuredDataToAccumulator {
    param(
        [Parameter(Mandatory)]$Accumulator,
        [AllowNull()]$Incoming
    )

    if (-not $Incoming) { return }
    foreach ($section in @('EventData', 'UserData')) {
        $target = $Accumulator.$section
        if ($target.Count -ge $script:LVStructuredDataMaxFields) { continue }
        $incomingSection = $Incoming.PSObject.Properties[$section]
        if (-not $incomingSection -or -not $incomingSection.Value) { continue }
        foreach ($property in @($incomingSection.Value.PSObject.Properties)) {
            foreach ($value in @($property.Value)) {
                Add-LVStructuredDataValue -Map $target -Name ([string]$property.Name) -Value $value
                if ($target.Count -ge $script:LVStructuredDataMaxFields) { break }
            }
            if ($target.Count -ge $script:LVStructuredDataMaxFields) { break }
        }
    }
}

function ConvertTo-LVStructuredDataProjection {
    param([Parameter(Mandatory)]$Accumulator)

    $eventData = @{}
    $userData = @{}
    foreach ($property in @($Accumulator.EventData.Keys)) { $eventData[$property] = $Accumulator.EventData[$property] }
    foreach ($property in @($Accumulator.UserData.Keys)) { $userData[$property] = $Accumulator.UserData[$property] }
    return [pscustomobject][ordered]@{
        EventData = [pscustomobject]$eventData
        UserData  = [pscustomobject]$userData
    }
}

function Get-LVEventStructuredData {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$EventObject)

    $eventData = @{}
    $userData = @{}
    foreach ($section in @('EventData', 'UserData')) {
        $property = $EventObject.PSObject.Properties[$section]
        if ($property -and $property.Value) {
            $target = if ($section -eq 'EventData') { $eventData } else { $userData }
            Add-LVStructuredDataObject -Map $target -Prefix $section -InputObject $property.Value
        }
    }

    # Get-WinEvent exposes positional Properties even when provider metadata is
    # incomplete. Keep those as Data0/Data1 so a rule can still be explicit about
    # the positional fallback rather than silently treating the value as message text.
    $properties = $EventObject.PSObject.Properties['Properties']
    if ($properties -and $properties.Value) {
        $index = 0
        foreach ($propertyValue in @($properties.Value)) {
            $value = if ($propertyValue.PSObject.Properties['Value']) { $propertyValue.Value } else { $propertyValue }
            Add-LVStructuredDataValue -Map $eventData -Name ('Data{0}' -f $index) -Value $value
            $index++
        }
    }

    $xmlText = $null
    try {
        if ($EventObject.PSObject.Methods['ToXml']) { $xmlText = [string]$EventObject.ToXml() }
    } catch { Write-Verbose 'Event XML could not be read; positional fields remain available.' }
    if ($xmlText) {
        try {
            $xml = [xml]$xmlText
            $dataNodes = @($xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))
            $index = 0
            foreach ($node in $dataNodes) {
                $name = if ($node.Attributes['Name']) { [string]$node.Attributes['Name'].Value } else { 'Data{0}' -f $index }
                Add-LVStructuredDataValue -Map $eventData -Name $name -Value $node.InnerText
                $index++
            }
            $userNodes = @($xml.SelectNodes("//*[local-name()='UserData']//*[not(*)]"))
            foreach ($node in $userNodes) {
                Add-LVStructuredDataValue -Map $userData -Name ([string]$node.LocalName) -Value $node.InnerText
            }
        } catch { Write-Verbose 'Event XML did not contain parseable EventData/UserData nodes.' }
    }

    return [pscustomobject][ordered]@{
        EventData = [pscustomobject]$eventData
        UserData  = [pscustomobject]$userData
    }
}

function Merge-LVEventStructuredData {
    param(
        [AllowNull()]$Existing,
        [AllowNull()]$Incoming
    )

    $accumulator = New-LVStructuredDataAccumulator
    Add-LVEventStructuredDataToAccumulator -Accumulator $accumulator -Incoming $Existing
    Add-LVEventStructuredDataToAccumulator -Accumulator $accumulator -Incoming $Incoming
    return ConvertTo-LVStructuredDataProjection -Accumulator $accumulator
}

function Get-LVStructuredFieldValues {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The function returns all observed values for a structured field.')]
    param(
        [Parameter(Mandatory)]$Signature,
        [Parameter(Mandatory)][string]$Field
    )

    $data = $Signature.PSObject.Properties['StructuredData']
    if (-not $data -or -not $data.Value) { return @() }
    $sectionName = $null
    $fieldName = $Field
    if ($Field -match '^(?i:(EventData|UserData))\.(.+)$') {
        $sectionName = $Matches[1]
        $fieldName = $Matches[2]
    }
    $sections = if ($sectionName) { @($sectionName) } else { @('EventData', 'UserData') }
    $values = New-Object System.Collections.Generic.List[string]
    foreach ($section in $sections) {
        $sectionProperty = $data.Value.PSObject.Properties[$section]
        if (-not $sectionProperty -or -not $sectionProperty.Value) { continue }
        $property = $sectionProperty.Value.PSObject.Properties[$fieldName]
        if (-not $property) { continue }
        foreach ($value in @($property.Value)) { $values.Add([string]$value) | Out-Null }
    }
    return @($values.ToArray())
}

function Test-LVStructuredPredicate {
    param(
        [Parameter(Mandatory)]$Predicate,
        [Parameter(Mandatory)]$Signature,
        [AllowNull()][ref]$RegexFailure,
        [string]$RuleId
    )

    if (-not $Predicate.field) { return $false }
    $actual = @(Get-LVStructuredFieldValues -Signature $Signature -Field ([string]$Predicate.field))
    if ($actual.Count -eq 0) { return $false }
    foreach ($modifier in @('equals', 'contains', 'startswith', 'endswith', 'regex')) {
        $property = $Predicate.PSObject.Properties[$modifier]
        if (-not $property) { continue }
        foreach ($expected in @($property.Value)) {
            foreach ($observed in $actual) {
                switch ($modifier) {
                    'equals' { if ($observed -ieq [string]$expected) { return $true } }
                    'contains' { if ($observed.IndexOf([string]$expected, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
                    'startswith' { if ($observed.StartsWith([string]$expected, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
                    'endswith' { if ($observed.EndsWith([string]$expected, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
                    'regex' {
                        try {
                            $regex = Get-LVCompiledRegex -Pattern ([string]$expected)
                            if ($regex.IsMatch([string]$observed)) { return $true }
                        } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
                            if ($RegexFailure) { $RegexFailure.Value = $RuleId }
                            Write-LVLog -Level warn -Message ("Rule '{0}' structured regex timed out; signature will remain unknown." -f $RuleId)
                            return $false
                        } catch {
                            Write-LVLog -Level warn -Message ("Rule '{0}' structured regex could not be evaluated; signature will remain unknown." -f $RuleId)
                            return $false
                        }
                    }
                }
            }
        }
        return $false
    }
    return $false
}

function Test-LVStructuredCondition {
    param(
        [Parameter(Mandatory)]$Condition,
        [Parameter(Mandatory)]$Signature,
        [AllowNull()][ref]$RegexFailure,
        [string]$RuleId
    )

    if ($Condition.PSObject.Properties['all']) {
        $children = @($Condition.all)
        return ($children.Count -gt 0 -and (@($children | Where-Object {
            $childArgs = @{ Condition = $_; Signature = $Signature; RuleId = $RuleId }
            if ($RegexFailure) { $childArgs.RegexFailure = $RegexFailure }
            -not (Test-LVStructuredCondition @childArgs)
        }).Count -eq 0))
    }
    if ($Condition.PSObject.Properties['any']) {
        $children = @($Condition.any)
        return ($children.Count -gt 0 -and (@($children | Where-Object {
            $childArgs = @{ Condition = $_; Signature = $Signature; RuleId = $RuleId }
            if ($RegexFailure) { $childArgs.RegexFailure = $RegexFailure }
            Test-LVStructuredCondition @childArgs
        }).Count -gt 0))
    }
    if ($Condition.PSObject.Properties['not']) {
        $childArgs = @{ Condition = $Condition.not; Signature = $Signature; RuleId = $RuleId }
        if ($RegexFailure) { $childArgs.RegexFailure = $RegexFailure }
        return -not (Test-LVStructuredCondition @childArgs)
    }
    $predicateArgs = @{ Predicate = $Condition; Signature = $Signature; RuleId = $RuleId }
    if ($RegexFailure) { $predicateArgs.RegexFailure = $RegexFailure }
    return Test-LVStructuredPredicate @predicateArgs
}

function Get-LVStructuredConditionProblems {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'The function returns every validation problem in a condition tree.')]
    param(
        [AllowNull()]$Condition,
        [string]$Path = 'eventData',
        [int]$Depth = 0
    )

    $problems = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Condition) { $problems.Add("$Path is null") | Out-Null; return @($problems.ToArray()) }
    if ($Depth -gt 16) { $problems.Add("$Path exceeds the condition nesting limit") | Out-Null; return @($problems.ToArray()) }
    $properties = @($Condition.PSObject.Properties.Name)
    $operators = @($properties | Where-Object { $_ -in @('all', 'any', 'not') })
    if ($Condition.PSObject.Properties['field']) {
        if ($operators.Count -gt 0) { $problems.Add("$Path predicate cannot also contain a boolean operator") | Out-Null }
        if ($operators.Count -eq 0) {
            $modifiers = @($properties | Where-Object { $_ -in @('equals', 'contains', 'startswith', 'endswith', 'regex') })
            if ($modifiers.Count -ne 1) { $problems.Add("$Path predicate must contain exactly one supported modifier") | Out-Null }
            if ([string]::IsNullOrWhiteSpace([string]$Condition.field)) { $problems.Add("$Path.field is required") | Out-Null }
            foreach ($property in $properties) {
                if ($property -notin @('field', 'equals', 'contains', 'startswith', 'endswith', 'regex')) { $problems.Add("$Path has unsupported field '$property'") | Out-Null }
            }
        }
        return @($problems.ToArray())
    }
    if ($operators.Count -ne 1) { $problems.Add("$Path must contain exactly one of all, any, or not") | Out-Null; return @($problems.ToArray()) }
    foreach ($property in $properties) { if ($property -notin $operators) { $problems.Add("$Path has unsupported field '$property'") | Out-Null } }
    $operator = $operators[0]
    if ($operator -eq 'not') {
        foreach ($problem in @(Get-LVStructuredConditionProblems -Condition $Condition.not -Path "$Path.not" -Depth ($Depth + 1))) {
            $problems.Add([string]$problem) | Out-Null
        }
    } else {
        $children = @($Condition.$operator)
        if ($children.Count -eq 0) { $problems.Add("$Path.$operator must not be empty") | Out-Null }
        for ($i = 0; $i -lt $children.Count; $i++) {
            foreach ($problem in @(Get-LVStructuredConditionProblems -Condition $children[$i] -Path ("{0}.{1}[{2}]" -f $Path, $operator, $i) -Depth ($Depth + 1))) {
                $problems.Add([string]$problem) | Out-Null
            }
        }
    }
    return @($problems.ToArray())
}
