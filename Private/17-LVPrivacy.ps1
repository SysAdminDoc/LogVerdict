# Deterministic privacy audit for report and evidence artifacts.
#
# This is deliberately an artifact audit, not a claim that a log is anonymous. It
# checks the files LogVerdict is about to package, records only fingerprints and
# substitutions, and blocks a redacted bundle when a known sensitive shape remains.

$script:LVPrivacyPattern = @(
    [pscustomobject]@{
        Id = 'sid'; Category = 'SID'; Substitution = '<SID>'
        Regex = '(?<![\w])S-\d-\d+(?:-\d+){1,14}(?![-\d])'
    }
    [pscustomobject]@{
        Id = 'upn'; Category = 'account-or-mail'; Substitution = '<UPN>'
        Regex = '[\w.+-]+@[\w-]+\.[\w.-]+'
    }
    [pscustomobject]@{
        Id = 'profile-path'; Category = 'profile-path'; Substitution = 'C:\Users\<USER>'
        Regex = '(?i)[A-Z]:\\Users\\[^\\/:*?"<>|\r\n]+'
    }
    [pscustomobject]@{
        Id = 'credential'; Category = 'credential-or-secret'; Substitution = '<SECRET>'
        Regex = '(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]\s*["'']?(?!<[^>]+>)[^\s,;}'']+'
    }
    [pscustomobject]@{
        Id = 'bearer-token'; Category = 'bearer-token'; Substitution = '<TOKEN>'
        Regex = '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}'
    }
    [pscustomobject]@{
        Id = 'jwt'; Category = 'jwt'; Substitution = '<TOKEN>'
        Regex = '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
    }
    [pscustomobject]@{
        Id = 'aws-access-key'; Category = 'cloud-access-key'; Substitution = '<TOKEN>'
        Regex = '\bAKIA[0-9A-Z]{16}\b'
    }
    [pscustomobject]@{
        Id = 'github-token'; Category = 'github-token'; Substitution = '<TOKEN>'
        Regex = '\bgh[pousr]_[A-Za-z0-9]{20,}\b'
    }
    [pscustomobject]@{
        Id = 'script-block'; Category = 'PowerShell-script-block'; Substitution = '<SCRIPTBLOCK>'
        Regex = '(?i)(?:ScriptBlockText\s*[:=]|<ScriptBlock>|EncodedCommand\s*[:=]|FromBase64String\s*\()'
    }
)

function New-LVPrivacyFinding {
    param(
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Substitution,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][int[]]$Line
    )

    return [pscustomobject][ordered]@{
        Artifact      = $Artifact
        Category      = $Category
        Occurrences   = @($Line).Count
        Lines         = @($Line | Select-Object -Unique)
        Fingerprint   = Get-LVShortHash -Text $Value
        Substitution  = $Substitution
        Disposition   = $null
    }
}

function New-LVPrivacyAudit {
    <#
        .SYNOPSIS
        Audit the files staged for an evidence bundle without retaining secret values.

        .DESCRIPTION
        A redacted bundle is sanitized only when every staged text artifact passes the
        deterministic patterns and no raw binary evidence is present. A raw forensic
        bundle is intentionally not sanitized; it is allowed only when the caller has
        made the explicit raw-evidence choice and the audit records that override.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Path,
        [AllowNull()][string]$MachineName,
        [AllowNull()][string]$UserName = $env:USERNAME,
        [switch]$Redacted,
        [switch]$AllowRawEvidence
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $rawArtifacts = New-Object System.Collections.Generic.List[object]
    $filesScanned = New-Object System.Collections.Generic.List[string]
    $substitutionCounts = [ordered]@{}
    $binaryExtensions = @('.dmp', '.evtx', '.etl', '.pdb', '.zip', '.7z', '.cab', '.bin')

    $patterns = New-Object System.Collections.Generic.List[object]
    foreach ($pattern in $script:LVPrivacyPattern) { $patterns.Add($pattern) | Out-Null }
    if ($MachineName -and $MachineName -notmatch '^<[^>]+>$') {
        $patterns.Add([pscustomobject]@{
            Id = 'known-machine'; Category = 'machine-name'; Substitution = '<MACHINE>'
            Regex = '(?i)(?<![\p{L}\p{N}])' + [regex]::Escape($MachineName) + '(?![\p{L}\p{N}])'
        }) | Out-Null
    }
    if ($UserName -and $UserName -notmatch '^<[^>]+>$') {
        $patterns.Add([pscustomobject]@{
            Id = 'known-user'; Category = 'account-name'; Substitution = '<USER>'
            Regex = '(?i)(?<![\p{L}\p{N}])' + [regex]::Escape($UserName) + '(?![\p{L}\p{N}])'
        }) | Out-Null
    }

    foreach ($pathValue in @($Path | Where-Object { $_ })) {
        $file = Get-Item -LiteralPath $pathValue -ErrorAction SilentlyContinue
        if ($null -eq $file -or -not $file.PSIsContainer) {
            $leaf = Split-Path -Leaf $pathValue
        } else {
            continue
        }
        if ($null -eq $file) {
            $finding = [pscustomobject][ordered]@{
                Artifact = $leaf; Category = 'audit-unreadable'; Occurrences = 1; Lines = @()
                Fingerprint = $null; Substitution = $null; Disposition = $null
            }
            $findings.Add($finding) | Out-Null
            continue
        }

        $extension = [IO.Path]::GetExtension($file.Name).ToLowerInvariant()
        if ($binaryExtensions -contains $extension) {
            $raw = [pscustomobject][ordered]@{
                Artifact = $file.Name
                Extension = $extension
                Bytes = [int64]$file.Length
                AllowedByRawOverride = [bool]$AllowRawEvidence
            }
            $rawArtifacts.Add($raw) | Out-Null
            if ($Redacted) {
                $findings.Add([pscustomobject][ordered]@{
                    Artifact = $file.Name; Category = 'raw-binary-evidence'; Occurrences = 1; Lines = @()
                    Fingerprint = $null; Substitution = 'remove-artifact'; Disposition = 'blocked'
                }) | Out-Null
            }
            continue
        }

        try {
            $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
            $text = [IO.File]::ReadAllText($file.FullName, $utf8)
            $filesScanned.Add($file.Name) | Out-Null
        } catch {
            $findings.Add([pscustomobject][ordered]@{
                Artifact = $file.Name; Category = 'audit-unreadable'; Occurrences = 1; Lines = @()
                Fingerprint = $null; Substitution = $null; Disposition = $(if ($Redacted) { 'blocked' } else { 'warning' })
            }) | Out-Null
            continue
        }

        foreach ($pattern in $patterns) {
            $privacyMatches = @([regex]::Matches($text, [string]$pattern.Regex))
            if ($privacyMatches.Count -eq 0) { continue }
            $lineNumbers = New-Object System.Collections.Generic.List[int]
            foreach ($match in $privacyMatches) {
                $lineNumbers.Add((1 + @($text.Substring(0, $match.Index).Split("`n")).Count)) | Out-Null
            }
            $firstValue = [string]$privacyMatches[0].Value
            $finding = New-LVPrivacyFinding -Artifact $file.Name -Category $pattern.Category `
                -Substitution $pattern.Substitution -Value $firstValue -Line @($lineNumbers.ToArray())
            $finding.Disposition = if ($Redacted) { 'blocked' } else { 'allowed-by-raw-override' }
            $findings.Add($finding) | Out-Null
        }

        foreach ($placeholder in @('<USER>', '<MACHINE>', '<SID>', '<UPN>', '<SECRET>', '<TOKEN>', '<SCRIPTBLOCK>')) {
            $count = @([regex]::Matches($text, [regex]::Escape($placeholder))).Count
            if ($count -gt 0) { $substitutionCounts[$placeholder] = $count }
        }
    }

    $sanitized = [bool]($Redacted -and $findings.Count -eq 0 -and $rawArtifacts.Count -eq 0)
    $status = if (-not $Redacted) { 'raw-override-approved' } elseif ($sanitized) { 'passed' } else { 'blocked' }
    $findingDisposition = if ($Redacted) { 'blocked' } else { 'allowed-by-raw-override' }
    foreach ($finding in $findings) {
        if (-not $finding.Disposition) { $finding.Disposition = $findingDisposition }
    }

    return [pscustomobject][ordered]@{
        SchemaVersion             = 1
        Status                    = $status
        Redacted                  = [bool]$Redacted
        Sanitized                 = $sanitized
        RawEvidenceOverride       = [bool]$AllowRawEvidence
        FilesScanned              = @($filesScanned.ToArray())
        RawArtifacts              = @($rawArtifacts.ToArray())
        Findings                  = @($findings.ToArray())
        FindingCount              = $findings.Count
        Substitutions             = [pscustomobject]$substitutionCounts
        SubstitutionCount         = [int](($substitutionCounts.Values | Measure-Object -Sum).Sum)
        Explanation               = if ($sanitized) {
            'All staged text artifacts passed deterministic privacy checks and no raw binary artifact was present.'
        } elseif (-not $Redacted) {
            'This is a forensic raw bundle. Sensitive findings remain possible and are permitted only by the explicit raw-evidence override.'
        } else {
            'The bundle was not created because a staged artifact retained a sensitive pattern or could not be audited.'
        }
    }
}
