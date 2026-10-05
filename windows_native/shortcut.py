"""Desktop entry and exact brand icon, independent from the installer UI."""
from pathlib import Path
import os,subprocess,tempfile

def create(destination):
    script='''$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Watchtower.lnk'))
$link.TargetPath = Join-Path $env:WATCHTOWER_SHORTCUT_ROOT 'WatchtowerNative.exe'
$pointer = Join-Path $env:WATCHTOWER_SHORTCUT_ROOT 'state/guardian/current.json'
if (Test-Path -LiteralPath $pointer) {
 $generation = (Get-Content -LiteralPath $pointer -Raw | ConvertFrom-Json).generation
 if ($generation -match '^[0-9a-f]{16}$') {
  $guardian = Join-Path $env:WATCHTOWER_SHORTCUT_ROOT ('state/guardian/generations/' + $generation + '/WatchtowerNative.exe')
  if (Test-Path -LiteralPath $guardian) { $link.TargetPath = $guardian; $link.Arguments = '--root "' + $env:WATCHTOWER_SHORTCUT_ROOT + '"' }
 }
}
$link.WorkingDirectory = $env:WATCHTOWER_SHORTCUT_ROOT
$link.IconLocation = $link.TargetPath
$icon = Join-Path $env:WATCHTOWER_SHORTCUT_ROOT 'app/docker/frontend/native-icon.ico'
if (Test-Path -LiteralPath $icon) { $link.IconLocation = $icon }
if ($guardian) {
 $guardIcon = Join-Path (Split-Path $guardian) 'native-icon.ico'
 if (Test-Path -LiteralPath $guardIcon) { $link.IconLocation = $guardIcon }
}
$link.Save()
'''
    env=dict(os.environ,WATCHTOWER_SHORTCUT_ROOT=str(Path(destination).resolve()))
    with tempfile.TemporaryDirectory(prefix='watchtower-shortcut-') as folder:
        path=Path(folder)/'shortcut.ps1';path.write_text(script,encoding='utf-8-sig')
        subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(path)],env=env,check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
