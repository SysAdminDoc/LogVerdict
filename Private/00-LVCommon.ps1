# Shared helpers. Loaded first (numeric filename prefix controls dot-source order).

# Verdict vocabulary, ordered least to most alarming. The rank drives report sorting
# and the exit code. "unknown" outranks "informational" on purpose: an unrecognized
# error is a lead, not background noise.
$script:LVVerdictRank = @{
    'benign'        = 0
    'informational' = 1
    'unknown'       = 2
    'investigate'   = 3
    'actionable'    = 4
    'critical'      = 5
}

$script:LVLogLines = New-Object System.Collections.Generic.List[string]

function Write-LVLog {
    <#
        .SYNOPSIS
        Console + in-memory diagnostic line. Never writes to the output stream,
        so callers capturing a function's return value do not swallow log text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('info', 'ok', 'warn', 'error', 'step')][string]$Level = 'info'
    )

    $marks = @{ info = '[ ]'; ok = '[+]'; warn = '[!]'; error = '[x]'; step = '==='; }
    $colors = @{ info = 'Gray'; ok = 'Green'; warn = 'Yellow'; error = 'Red'; step = 'Cyan'; }

    $line = '{0} {1}' -f $marks[$Level], $Message
    $script:LVLogLines.Add(('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $line))
    Write-Host $line -ForegroundColor $colors[$Level]
}

function ConvertTo-LVArrayOutput {
    <#
        .SYNOPSIS
        Return an array from a function without PowerShell unrolling it, and without
        the empty-collection trap.

        .DESCRIPTION
        The usual idiom `return , $array` keeps a populated array intact, but turns an
        EMPTY one into a single-element array whose only element is the empty array.
        Callers that foreach over the result then iterate once over a phantom item and
        add it to their own collection. Emitting nothing for the empty case is what
        every caller here actually expects.
    #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Value)

    if ($null -eq $Value -or $Value.Count -eq 0) { return @() }
    return , $Value
}

function Get-LVLogTranscript {
    return ConvertTo-LVArrayOutput -Value @($script:LVLogLines.ToArray())
}

function Test-LVElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LVVerdictRank {
    param([string]$Verdict)
    if ($script:LVVerdictRank.ContainsKey($Verdict)) { return $script:LVVerdictRank[$Verdict] }
    return $script:LVVerdictRank['unknown']
}

function ConvertTo-LVTemplate {
    <#
        .SYNOPSIS
        Collapses the variable parts of a log line so that repeated occurrences
        group into one signature. This is the same idea as Drain template mining,
        reduced to a masking pass that needs no dependencies.

        .DESCRIPTION
        Order matters: longer/more specific patterns are masked before shorter ones,
        otherwise the number mask eats the insides of GUIDs and paths.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $t = $Text
    $t = $t -replace '\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?', '<GUID>'
    $t = $t -replace '\b[A-Za-z]:\\[^\s,;"'')]*', '<PATH>'
    $t = $t -replace '\\\\[^\s,;"'')]+', '<UNC>'
    $t = $t -replace '\b\d{1,3}(\.\d{1,3}){3}\b', '<IP>'
    $t = $t -replace '\b0x[0-9A-Fa-f]+\b', '<HEX>'
    $t = $t -replace '\b[0-9A-Fa-f]{16,}\b', '<HEX>'
    $t = $t -replace '\b\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2}\S*)?', '<TIME>'
    $t = $t -replace '\b\d{2}:\d{2}:\d{2}(\.\d+)?\b', '<TIME>'
    $t = $t -replace '\b\d+\b', '<NUM>'
    $t = $t -replace '\s+', ' '
    return $t.Trim()
}

function Get-LVShortHash {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return (($bytes[0..5] | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-LVSafeName {
    param([Parameter(Mandatory)][string]$Text)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = '[{0}]' -f [regex]::Escape($invalid)
    return ($Text -replace $pattern, '_')
}

function ConvertTo-LVHtmlEncoded {
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    $t = $Text -replace '&', '&amp;'
    $t = $t -replace '<', '&lt;'
    $t = $t -replace '>', '&gt;'
    $t = $t -replace '"', '&quot;'
    return $t
}
