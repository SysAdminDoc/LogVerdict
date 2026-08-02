function Update-LogVerdictDatabase {
    <#
        .SYNOPSIS
        Opt in to a hash-verified verdict database update from a GitHub release.

        .DESCRIPTION
        Downloads only when this command is invoked. The release must expose a
        verdicts.json asset and GitHub's release API must provide its SHA-256 digest
        (or -ExpectedSha256 must be supplied explicitly). The downloaded database is
        validated before it is installed as verdicts.local.json, leaving the shipped
        database untouched. The previous local copy is retained beside it with a
        .previous.json suffix and can be restored with -Rollback.

        .PARAMETER ReleaseTag
        A GitHub release tag such as v0.8.1. Omit it to use the latest stable release.

        .PARAMETER TargetPath
        The local override to install. Defaults to Data\verdicts.local.json for the
        module and verdicts.local.json beside a compiled executable.

        .PARAMETER SourcePath
        An already downloaded asset. This is intended for air-gapped staging and tests;
        it still requires -ExpectedSha256 so the install is hash-verified.

        .PARAMETER ExpectedSha256
        The expected SHA-256 digest. GitHub release metadata supplies this by default.

        .PARAMETER Rollback
        Restore the retained .previous.json copy instead of downloading anything.

        .EXAMPLE
        Update-LogVerdictDatabase

        .EXAMPLE
        Update-LogVerdictDatabase -ReleaseTag v0.8.1

        .EXAMPLE
        Update-LogVerdictDatabase -Rollback
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
        [string]$Repository = 'SysAdminDoc/LogVerdict',

        [ValidatePattern('^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
        [string]$ReleaseTag,

        [string]$TargetPath,

        [string]$SourcePath,

        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedSha256,

        [switch]$Rollback
    )

    if (-not $TargetPath) {
        if ($script:LVModuleRoot) {
            $TargetPath = Join-Path $script:LVDataDir 'verdicts.local.json'
        } else {
            $TargetPath = Join-Path (Get-LVHostDirectory) 'verdicts.local.json'
        }
    }
    $TargetPath = [IO.Path]::GetFullPath($TargetPath)
    $backupPath = $TargetPath + '.previous.json'

    function Write-LVDatabaseAtomically {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][string]$Content
        )

        $directory = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $directory)) {
            $null = New-Item -ItemType Directory -Path $directory -Force
        }
        $temporary = Join-Path $directory ('.verdicts-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        try {
            [IO.File]::WriteAllText($temporary, $Content, (New-Object Text.UTF8Encoding($false)))
            if (Test-Path -LiteralPath $Path) {
                [IO.File]::Replace($temporary, $Path, $backupPath, $true)
            } else {
                Move-Item -LiteralPath $temporary -Destination $Path -Force
            }
        } finally {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }

    function Get-LVUpdateSha256 {
        param([Parameter(Mandatory)][string]$Path)
        $stream = [IO.File]::OpenRead($Path)
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToUpperInvariant()
        } finally {
            $algorithm.Dispose()
            $stream.Dispose()
        }
    }

    if ($Rollback) {
        if ($SourcePath -or $ReleaseTag -or $ExpectedSha256) {
            throw '-Rollback cannot be combined with a release, source, or digest parameter.'
        }
        if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
            throw ("No previous verdict database exists at '{0}'." -f $backupPath)
        }
        if (-not $PSCmdlet.ShouldProcess($TargetPath, 'restore the previous verdict database')) {
            return
        }
        $content = [IO.File]::ReadAllText($backupPath)
        Write-LVDatabaseAtomically -Path $TargetPath -Content $content
        $restored = Get-Content -LiteralPath $TargetPath -Raw -Encoding UTF8 | ConvertFrom-Json
        return [pscustomobject]@{
            Action      = 'rollback'
            TargetPath  = $TargetPath
            BackupPath  = $backupPath
            ReleaseTag  = $null
            Sha256      = Get-LVUpdateSha256 -Path $TargetPath
            RuleCount   = @($restored.rules).Count
            Updated     = $restored.updated
        }
    }

    if ($SourcePath -and -not $ExpectedSha256) {
        throw '-ExpectedSha256 is required when -SourcePath is used.'
    }
    if ($SourcePath -and -not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        throw ("Source database not found at '{0}'." -f $SourcePath)
    }

    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('LogVerdict-update-' + [Guid]::NewGuid().ToString('N') + '.json')
    $release = $null
    $tag = $ReleaseTag
    if ($tag -and $tag -notmatch '^v') { $tag = 'v' + $tag }

    try {
        if ($SourcePath) {
            Copy-Item -LiteralPath $SourcePath -Destination $temporary -Force
        } else {
            $apiUri = if ($tag) {
                'https://api.github.com/repos/{0}/releases/tags/{1}' -f $Repository, $tag
            } else {
                'https://api.github.com/repos/{0}/releases/latest' -f $Repository
            }
            $headers = @{ 'User-Agent' = 'LogVerdict-database-updater' }
            $release = Invoke-RestMethod -Uri $apiUri -Headers $headers
            if ($release.draft -or $release.prerelease) {
                throw 'GitHub returned a draft or prerelease; only published stable releases may update the database.'
            }
            if ($tag -and [string]$release.tag_name -ne $tag) {
                throw ("GitHub returned tag '{0}', expected '{1}'." -f $release.tag_name, $tag)
            }
            $tag = [string]$release.tag_name

            $assets = @($release.assets | Where-Object { $_.name -eq 'verdicts.json' })
            if ($assets.Count -ne 1) {
                throw ("Release {0} must contain exactly one verdicts.json asset; found {1}." -f $tag, $assets.Count)
            }
            $asset = $assets[0]
            if (-not $ExpectedSha256 -and $asset.digest -and [string]$asset.digest -match '^sha256:([0-9A-Fa-f]{64})$') {
                $ExpectedSha256 = $Matches[1]
            }
            if (-not $ExpectedSha256) {
                throw 'GitHub did not provide a SHA-256 digest for verdicts.json; pass -ExpectedSha256 after independently verifying the release asset.'
            }
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $temporary -Headers $headers -UseBasicParsing | Out-Null
        }

        $actualSha256 = Get-LVUpdateSha256 -Path $temporary
        if ($actualSha256 -ne $ExpectedSha256.ToUpperInvariant()) {
            throw ("SHA-256 mismatch for the downloaded verdict database. Expected {0}, got {1}." -f $ExpectedSha256.ToUpperInvariant(), $actualSha256)
        }

        $json = [IO.File]::ReadAllText($temporary)
        $candidate = $json | ConvertFrom-Json
        Assert-LVSchemaVersion -Database $candidate -Path $temporary
        if (@($candidate.rules).Count -eq 0) {
            throw 'The downloaded verdict database contains no rules.'
        }
        if (-not (Test-LogVerdictDatabase -Path $temporary -SkipFixture -Quiet)) {
            throw 'The downloaded verdict database failed structural validation and was not installed.'
        }

        if (-not $PSCmdlet.ShouldProcess($TargetPath, ('install verdict database {0}' -f $tag))) {
            return
        }
        Write-LVDatabaseAtomically -Path $TargetPath -Content $json
        return [pscustomobject]@{
            Action      = 'update'
            TargetPath  = $TargetPath
            BackupPath  = if (Test-Path -LiteralPath $backupPath) { $backupPath } else { $null }
            ReleaseTag  = $tag
            Sha256      = $actualSha256
            RuleCount   = @($candidate.rules).Count
            Updated     = $candidate.updated
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}
