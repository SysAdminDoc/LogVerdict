<#
    .SYNOPSIS
    Build the LogVerdict executables - single, unsigned, self-contained.

    .DESCRIPTION
    Flattens the module into one script per target and compiles each with PS2EXE.

    Two artifacts, same scan engine:

      LogVerdict.exe      console. Prints a report, returns a meaningful exit code.
      LogVerdict-GUI.exe  windowed. The front end, with no console behind it.

    Everything either one needs is compiled in, including the verdict database, so the
    .exe is the whole product: copy it to a broken machine and run it. Nothing is
    installed, nothing is unpacked, and no PowerShell module import is involved.

    A verdicts.local.json placed beside the .exe is still merged, and still wins ties
    against the compiled-in rules, so a site can extend the build without rebuilding.

    The build is deliberately unsigned. SmartScreen will warn on first run; the answer
    is "More info" then "Run anyway".

    .PARAMETER OutputDir
    Where the executables land. Defaults to dist\ beside the repository.

    .PARAMETER Target
    Which executables to build. Default All.

    .PARAMETER KeepIntermediate
    Keep the generated standalone .ps1 files for inspection instead of deleting them.

    .EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\Build-LogVerdictExe.ps1

    .EXAMPLE
    .\Tools\Build-LogVerdictExe.ps1 -Target Gui -KeepIntermediate

    .NOTES
    The intermediate directory is obj\, deliberately NOT build\. Windows paths are
    case-insensitive, so a build\ intermediate collides with this script's own Tools\
    predecessor Build\ - and the clean step then deletes the build script itself.
    That happened once; hence the name and this note.

    The GUI is compiled -noConsole -noOutput -noError. -noOutput is not optional:
    PS2EXE's -noConsole host turns every Write-Host into a MessageBox (see its
    ps2exe.ps1, "called by Write-Host"), and the scan logs constantly. Without
    -noOutput a single run would fire a hundred modal dialogs.
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [ValidateSet('Console', 'Gui', 'All')][string]$Target = 'All',
    [switch]$KeepIntermediate
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDir) { $OutputDir = Join-Path $repoRoot 'dist' }
$objDir = Join-Path $repoRoot 'obj'

function Write-Step { param([string]$Message) Write-Host ("[build] {0}" -f $Message) -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host ("[  ok ] {0}" -f $Message) -ForegroundColor Green }
function Write-Bad  { param([string]$Message) Write-Host ("[fail ] {0}" -f $Message) -ForegroundColor Red }

# --- Clean -------------------------------------------------------------------
# Previous artifacts go first so a failed build cannot leave a stale exe looking
# like a fresh one. Both paths are asserted to be inside the repo and to not be a
# source directory, because this step deletes recursively.
Write-Step 'Cleaning previous build output'
foreach ($dir in @($OutputDir, $objDir)) {
    $leaf = Split-Path -Leaf $dir
    if ($leaf -in @('Tools', 'Private', 'Public', 'Data', 'Tests')) {
        throw ("Refusing to clean '{0}': that is a source directory." -f $dir)
    }
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# --- Preconditions -----------------------------------------------------------
if (-not (Get-Module -ListAvailable ps2exe)) {
    throw 'PS2EXE is not installed. Run: Install-Module ps2exe -Scope CurrentUser'
}

$manifest = Test-ModuleManifest -Path (Join-Path $repoRoot 'LogVerdict.psd1')
$version = (& (Join-Path $repoRoot 'Tools\Get-LogVerdictVersion.ps1')).Trim()
if ($manifest.Version.ToString() -ne $version) {
    throw ("LogVerdict.psd1 declares v{0}, but VERSION declares v{1}." -f $manifest.Version, $version)
}
Write-Ok ("Building LogVerdict v{0}" -f $version)

# --- Flatten the module ------------------------------------------------------
# Load order matters and matches LogVerdict.psm1: numeric-prefixed Private files
# first, then Public. Dot-sourcing is replaced by textual inclusion because a
# compiled binary has no files to dot-source.
Write-Step 'Flattening module sources'

$sourceFiles = @()
foreach ($scope in @('Private', 'Public')) {
    $sourceFiles += Get-ChildItem -LiteralPath (Join-Path $repoRoot $scope) -Filter '*.ps1' | Sort-Object Name
}
Write-Ok ("{0} source file(s)" -f $sourceFiles.Count)

$sourceBuilder = New-Object System.Text.StringBuilder
foreach ($file in $sourceFiles) {
    $null = $sourceBuilder.AppendLine(('#region {0}' -f $file.Name))
    $null = $sourceBuilder.AppendLine((Get-Content -LiteralPath $file.FullName -Raw))
    $null = $sourceBuilder.AppendLine('#endregion')
    $null = $sourceBuilder.AppendLine('')
}
$sourcesText = $sourceBuilder.ToString()

$verdictsPath = Join-Path $repoRoot 'Data\verdicts.json'
$verdictsRaw = Get-Content -LiteralPath $verdictsPath -Raw -Encoding UTF8
$ruleCount = @(($verdictsRaw | ConvertFrom-Json).rules).Count

$errorCatalogPath = Join-Path $repoRoot 'Data\error-codes.json'
$errorCatalogRaw = Get-Content -LiteralPath $errorCatalogPath -Raw -Encoding UTF8
$errorCatalogCount = @(($errorCatalogRaw | ConvertFrom-Json).entries).Count
$advisoryPath = Join-Path $repoRoot 'Data\advisories.json'
$advisoryRaw = Get-Content -LiteralPath $advisoryPath -Raw -Encoding UTF8
$advisoryCount = @(($advisoryRaw | ConvertFrom-Json).advisories).Count
$localizationPath = Join-Path $repoRoot 'Data\localization.json'
$localizationRaw = Get-Content -LiteralPath $localizationPath -Raw -Encoding UTF8
$localizationDocument = $localizationRaw | ConvertFrom-Json
if ($localizationDocument.schemaVersion -ne 1 -or -not $localizationDocument.locales.PSObject.Properties['en-US']) {
    throw 'Localization resource must expose schemaVersion 1 and an en-US fallback locale.'
}

# Base64 rather than a here-string: the database is arbitrary text and must not be
# able to terminate its own literal or pick up PowerShell escape semantics.
$verdictsB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($verdictsRaw))
Write-Ok ("Embedding verdict database: {0} rules, {1:N0} KB" -f $ruleCount, ($verdictsRaw.Length / 1KB))
$errorCatalogB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($errorCatalogRaw))
Write-Ok ("Embedding error catalog: {0} entries, {1:N0} KB" -f $errorCatalogCount, ($errorCatalogRaw.Length / 1KB))
$advisoryB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($advisoryRaw))
Write-Ok ("Embedding advisory cache: {0} entr{1}, {2:N0} KB" -f $advisoryCount, $(if ($advisoryCount -eq 1) { 'y' } else { 'ies' }), ($advisoryRaw.Length / 1KB))
$localizationB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($localizationRaw))
Write-Ok ("Embedding localization resources: {0} locale(s), {1:N0} KB" -f @($localizationDocument.locales.PSObject.Properties).Count, ($localizationRaw.Length / 1KB))

function ConvertTo-LVStandaloneScript {
    <#
        .SYNOPSIS
        Build one flattened script from an entry script plus the module sources.

        .PARAMETER EntryScript
        Path to the entry script whose param block and body are grafted on.

        .PARAMETER EmbedSource
        Also embed the module sources as base64. The GUI needs this: it runs the scan
        in a background runspace, and a fresh runspace inside a compiled binary has no
        .psd1 to import and no files to dot-source, so it reconstitutes LogVerdict from
        this string instead.
    #>
    param(
        [Parameter(Mandatory)][string]$EntryScript,
        [switch]$EmbedSource
    )

    $entryText = Get-Content -LiteralPath $EntryScript -Raw

    # Strip the entry script's comment-based help, param block and module import: the
    # bundle declares its own param block (which must be the first statement) and has
    # no module to import.
    $importMarker = 'Import-Module $modulePath -Force -ErrorAction Stop'
    $idx = $entryText.IndexOf($importMarker)
    if ($idx -lt 0) {
        throw ("Entry script '{0}' layout changed: could not find the module import to strip." -f $EntryScript)
    }
    $entryBody = $entryText.Substring($idx + $importMarker.Length)

    # The param block is EXTRACTED from the entry script, never retyped here. A
    # hand-copied duplicate silently drops any switch added later - which is exactly
    # how -Pause would have been missing from the compiled build.
    $cmdletIdx = $entryText.IndexOf('[CmdletBinding()]')
    # Single-quoted: a double-quoted literal would interpolate $ErrorActionPreference
    # to its current value and search for "Stop = 'Stop'", which never matches.
    $eapIdx = $entryText.IndexOf('$ErrorActionPreference = ''Stop''')
    if ($cmdletIdx -lt 0 -or $eapIdx -le $cmdletIdx) {
        throw ("Entry script '{0}' layout changed: could not extract the param block." -f $EntryScript)
    }
    $paramBlock = $entryText.Substring($cmdletIdx, $eapIdx - $cmdletIdx).TrimEnd()
    $paramCount = ([regex]::Matches($paramBlock, '(?m)^\s*\[[^\r\n]*\]\s*\$\w+')).Count
    Write-Ok ("{0}: extracted param block ({1} parameter(s))" -f (Split-Path -Leaf $EntryScript), $paramCount)

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("<#")
    $null = $sb.AppendLine("    LogVerdict $version - standalone build")
    $null = $sb.AppendLine("    GENERATED by Tools\Build-LogVerdictExe.ps1. Do not edit; edit the module instead.")
    $null = $sb.AppendLine("#>")
    $null = $sb.AppendLine($paramBlock)
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("`$ErrorActionPreference = 'Stop'")
    $null = $sb.AppendLine("`$script:LVVersion = '$version'")
    $null = $sb.AppendLine("`$script:LVModuleRoot = `$null")
    $null = $sb.AppendLine("")

    # Data dir points beside the executable, so dropping a real Data\verdicts.json next
    # to the .exe overrides the compiled-in copy without a rebuild.
    $null = $sb.AppendLine(@'
$script:LVDataDir = $null
try {
    $hostPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($hostPath) { $script:LVDataDir = Join-Path (Split-Path -Parent $hostPath) 'Data' }
} catch {
    $script:LVDataDir = Join-Path (Get-Location).Path 'Data'
}
if (-not $script:LVDataDir) { $script:LVDataDir = Join-Path (Get-Location).Path 'Data' }
'@)

    $null = $sb.AppendLine('$script:LVEmbeddedVerdictsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $verdictsB64 + '''))')
    $null = $sb.AppendLine('$script:LVEmbeddedErrorCatalogJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $errorCatalogB64 + '''))')
    $null = $sb.AppendLine('$script:LVEmbeddedAdvisoriesJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $advisoryB64 + '''))')
    $null = $sb.AppendLine('$script:LVEmbeddedLocalizationJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $localizationB64 + '''))')

    if ($EmbedSource) {
        # Deliberately the sources ONLY - not this generated wrapper. The verdict
        # database and the version travel to the runspace as arguments, so embedding
        # them a second time here would double the payload for nothing.
        $sourceB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sourcesText))
        $null = $sb.AppendLine('$script:LVEmbeddedSource = ''' + $sourceB64 + '''')
    }

    $null = $sb.AppendLine('')
    $null = $sb.Append($sourcesText)
    $null = $sb.AppendLine('#region entry')
    $null = $sb.AppendLine($entryBody)
    $null = $sb.AppendLine('#endregion')

    return $sb.ToString()
}

function Test-LVGeneratedScript {
    <#
        .SYNOPSIS
        Refuse to compile a bundle that Windows PowerShell 5.1 cannot read.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $nonAscii = ([System.IO.File]::ReadAllBytes($Path) | Where-Object { $_ -gt 127 }).Count
    if ($nonAscii -gt 0) {
        throw ("Generated script contains {0} non-ASCII byte(s); PS 5.1 will mis-parse it." -f $nonAscii)
    }

    $parseErrors = $null
    [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $Path -Raw), [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0) {
        foreach ($e in (@($parseErrors) | Select-Object -First 5)) {
            Write-Bad ("line {0}: {1}" -f $e.Token.StartLine, $e.Message)
        }
        throw 'Generated script does not parse.'
    }
}

# --- Compile -----------------------------------------------------------------
Import-Module ps2exe -Force

$targets = @()
if ($Target -in @('Console', 'All')) {
    $targets += [pscustomobject]@{
        Name        = 'LogVerdict.exe'
        Entry       = Join-Path $repoRoot 'Invoke-LogVerdict.ps1'
        Intermediate = 'LogVerdict.Standalone.ps1'
        EmbedSource = $false
        Description = 'Scans a Windows PC log corpus and rules on it in plain English'
        Ps2ExeArgs  = @{}
    }
}
if ($Target -in @('Gui', 'All')) {
    $targets += [pscustomobject]@{
        Name        = 'LogVerdict-GUI.exe'
        Entry       = Join-Path $repoRoot 'LogVerdict-GUI.ps1'
        Intermediate = 'LogVerdict.Gui.Standalone.ps1'
        EmbedSource = $true
        Description = 'Reads this PC log corpus and explains what is wrong, in plain English'
        # -STA because WPF refuses to start on any other apartment.
        # -noOutput/-noError because the -noConsole host renders host writes as modal
        # dialogs; see the .NOTES above.
        Ps2ExeArgs  = @{ noConsole = $true; noOutput = $true; noError = $true; STA = $true }
    }
}

$built = @()
foreach ($t in $targets) {
    Write-Step ("Building {0}" -f $t.Name)

    $standalone = Join-Path $objDir $t.Intermediate
    $text = ConvertTo-LVStandaloneScript -EntryScript $t.Entry -EmbedSource:$t.EmbedSource
    [System.IO.File]::WriteAllText($standalone, $text, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok ("Standalone script: {0:N0} KB" -f ((Get-Item $standalone).Length / 1KB))

    Test-LVGeneratedScript -Path $standalone
    Write-Ok 'Pure ASCII, parses clean'

    $exePath = Join-Path $OutputDir $t.Name
    $ps2exeArgs = @{
        inputFile   = $standalone
        outputFile  = $exePath
        title       = 'LogVerdict'
        description = $t.Description
        company     = 'SysAdminDoc'
        product     = 'LogVerdict'
        copyright   = '(c) 2026 SysAdminDoc. MIT License.'
        version     = $version
        x64         = $true
    }
    foreach ($k in $t.Ps2ExeArgs.Keys) { $ps2exeArgs[$k] = $t.Ps2ExeArgs[$k] }

    Invoke-ps2exe @ps2exeArgs | Out-Null

    if (-not (Test-Path -LiteralPath $exePath)) {
        throw ("PS2EXE produced no output for {0}." -f $t.Name)
    }
    $built += (Get-Item -LiteralPath $exePath)
}

if (-not $KeepIntermediate) { Remove-Item -LiteralPath $objDir -Recurse -Force }

Write-Host ''
foreach ($exe in $built) {
    Write-Ok ("{0} ({1:N0} KB)" -f $exe.FullName, ($exe.Length / 1KB))
}
Write-Host ''
Write-Host 'Unsigned by design. SmartScreen: More info -> Run anyway.' -ForegroundColor Yellow
