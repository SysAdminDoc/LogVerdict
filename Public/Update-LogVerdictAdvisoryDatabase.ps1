function Update-LogVerdictAdvisoryDatabase {
    <#
        .SYNOPSIS
        Install a hash-verified advisory cache from an explicit local file or URL.

        .DESCRIPTION
        The updater is opt-in. A local source is useful for air-gapped staging; both
        local and network sources require an independently supplied SHA-256 digest.
        The candidate is validated before atomic installation and the previous cache
        is retained with a .previous.json suffix.

        .PARAMETER Uri
        Explicit advisory-cache URL. No URL is contacted unless this is supplied.

        .PARAMETER SourcePath
        Already downloaded cache for offline staging.

        .PARAMETER TargetPath
        Installation destination. Defaults to advisories.local.json beside the module
        or compiled executable.

        .PARAMETER ExpectedSha256
        Required SHA-256 digest for the source bytes.

        .PARAMETER Rollback
        Restore the retained previous cache.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Uri,
        [string]$SourcePath,
        [string]$TargetPath,
        [ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSha256,
        [switch]$Rollback
    )

    if ($Uri -and $SourcePath) { throw 'Choose only one source: -Uri or -SourcePath.' }
    if (-not $Uri -and -not $SourcePath -and -not $Rollback) { throw 'Supply -Uri, -SourcePath, or -Rollback.' }
    if (($Uri -or $SourcePath) -and -not $ExpectedSha256) { throw '-ExpectedSha256 is required for advisory-cache installation.' }
    if ($SourcePath -and -not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) { throw ("Source cache not found at '{0}'." -f $SourcePath) }

    if (-not $TargetPath) {
        if ($script:LVModuleRoot) { $TargetPath = Join-Path $script:LVDataDir 'advisories.local.json' }
        else { $TargetPath = Join-Path (Get-LVHostDirectory) 'advisories.local.json' }
    }
    $TargetPath = [IO.Path]::GetFullPath($TargetPath)
    $backupPath = $TargetPath + '.previous.json'

    function Get-LVAdvisoryFileHash {
        param([Parameter(Mandatory)][string]$Path)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }

    function Write-LVAdvisoryAtomically {
        param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Backup, [Parameter(Mandatory)][string]$Content)
        $directory = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
        $temporary = Join-Path $directory ('.advisories-' + [guid]::NewGuid().ToString('N') + '.tmp')
        try {
            Write-LVTextFile -Path $temporary -Content $Content
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                try { [IO.File]::Replace($temporary, $Path, $Backup, $true) }
                catch { Move-Item -LiteralPath $temporary -Destination $Path -Force }
            } else { Move-Item -LiteralPath $temporary -Destination $Path -Force }
        } finally {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }

    if ($Rollback) {
        if ($Uri -or $SourcePath -or $ExpectedSha256) { throw '-Rollback cannot be combined with a source or digest.' }
        if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) { throw ("No previous advisory cache exists at '{0}'." -f $backupPath) }
        if (-not $PSCmdlet.ShouldProcess($TargetPath, 'restore the previous advisory cache')) { return }
        $content = [IO.File]::ReadAllText($backupPath)
        Write-LVAdvisoryAtomically -Path $TargetPath -Backup $backupPath -Content $content
        $verified = Get-LVAdvisoryDatabase -Path $TargetPath
        return [pscustomobject]@{ Action='rollback'; TargetPath=$TargetPath; BackupPath=$backupPath; Sha256=(Get-LVAdvisoryFileHash -Path $TargetPath); EntryCount=@($verified.advisories).Count }
    }

    $temporarySource = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-advisories-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        if ($SourcePath) { Copy-Item -LiteralPath $SourcePath -Destination $temporarySource -Force }
        else { Invoke-WebRequest -Uri $Uri -OutFile $temporarySource -UseBasicParsing | Out-Null }
        $actualHash = Get-LVAdvisoryFileHash -Path $temporarySource
        if ($actualHash -ine $ExpectedSha256) { throw ("SHA-256 mismatch for advisory cache. Expected {0}, got {1}." -f $ExpectedSha256.ToLowerInvariant(), $actualHash) }
        $candidate = Get-Content -LiteralPath $temporarySource -Raw -Encoding UTF8 | ConvertFrom-Json
        $problems = @(Get-LVAdvisoryDatabaseProblem -Database $candidate)
        if ($problems.Count -gt 0) { throw ('Advisory cache failed validation: ' + ($problems -join '; ')) }
        if (-not $PSCmdlet.ShouldProcess($TargetPath, 'install the advisory cache')) { return }
        Write-LVAdvisoryAtomically -Path $TargetPath -Backup $backupPath -Content ([IO.File]::ReadAllText($temporarySource))
        return [pscustomobject]@{ Action='update'; TargetPath=$TargetPath; BackupPath=if (Test-Path -LiteralPath $backupPath) { $backupPath } else { $null }; Sha256=$actualHash; EntryCount=@($candidate.advisories).Count; Updated=$candidate.updated }
    } finally {
        Remove-Item -LiteralPath $temporarySource -Force -ErrorAction SilentlyContinue
    }
}
