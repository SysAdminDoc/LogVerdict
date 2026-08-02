#requires -Version 5.1

[CmdletBinding()]
param()

$versionPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'VERSION'
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
    throw ("Version source not found at '{0}'." -f $versionPath)
}

$version = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw ("Version source '{0}' contains invalid SemVer '{1}'." -f $versionPath, $version)
}
return $version
