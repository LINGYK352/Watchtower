param(
    [string]$Source = $PSScriptRoot,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Watchtower')
)
$ErrorActionPreference = 'Stop'
$setupPath = Join-Path $PSScriptRoot 'WatchtowerSetup.exe'
if (-not (Test-Path -LiteralPath $setupPath)) { throw '请保留安装器文件，或重新下载完整安装包。' }
& $setupPath --source $Source --root $InstallDir --launch
