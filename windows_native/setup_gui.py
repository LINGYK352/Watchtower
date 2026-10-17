"""Per-user native installer. No Python, Docker, WSL or manual account file required."""
from pathlib import Path
import os,sys,threading,queue,subprocess,json,tempfile
from windows_native.setup import install
from windows_native.startup_diagnostics import StartupDiagnostics,redact

_diagnostic=None

TEXT={
 'zh-CN':{'title':'Watchtower 安装','folder':'安装目录','browse':'浏览…','choose':'选择安装目录','user':'管理员账号','password':'管理员密码（至少6位）','start':'开始安装','launch':'打开 Watchtower','done':'安装完成。打开后可注册并激活。','error':'安装失败','confirm':'请填写目录、账号和至少6位密码。','busy':'正在验证并安装…'},
 'en-US':{'title':'Install Watchtower','folder':'Installation folder','browse':'Browse…','choose':'Choose installation folder','user':'Administrator account','password':'Administrator password (at least 6 characters)','start':'Install','launch':'Open Watchtower','done':'Installed. Open Watchtower to register and activate.','error':'Installation failed','confirm':'Enter a folder, account, and password of at least 6 characters.','busy':'Verifying and installing…'}
}

TEXT['zh-CN'].update(new_install='全新安装',repair_install='修复现有安装',repair_start='开始修复安装',repair_note='保留账号、激活、配置和业务数据。验证安装包后关闭此安装的程序，修复缺失或损坏的文件；无需填写管理员账号。',new_note='选择空目录安装，并设置新的管理员账号。',choose_existing='请选择已有Watchtower安装目录进行修复。',repaired='修复完成，原账号、激活、配置及业务数据已保留。')
TEXT['en-US'].update(new_install='New installation',repair_install='Repair existing installation',repair_start='Repair installation',repair_note='Keep accounts, activation, configuration and business data. After verifying the package, close this installation and repair its files. No administrator details are required.',new_note='Choose an empty folder and create an administrator account.',choose_existing='Choose an existing Watchtower installation to repair.',repaired='Repair completed. Accounts, activation, configuration and business data were retained.')

def shortcut(destination):
 from windows_native.shortcut import create
 return create(destination)
 # Environment arguments keep the PowerShell source fixed, even for quoted paths.
 script="""$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Watchtower.lnk'))
$link.TargetPath = Join-Path $env:WATCHTOWER_SETUP_DEST 'WatchtowerNative.exe'
$link.WorkingDirectory = $env:WATCHTOWER_SETUP_DEST
$link.IconLocation = $link.TargetPath
$brandIcon = Join-Path $env:WATCHTOWER_SETUP_DEST 'app/docker/frontend/native-icon.ico'
if (Test-Path -LiteralPath $brandIcon) { $link.IconLocation = $brandIcon }
$link.Save()
"""
 env=os.environ.copy();env['WATCHTOWER_SETUP_DEST']=str(destination)
 with tempfile.TemporaryDirectory(prefix='watchtower-shortcut-') as folder:
  path=Path(folder)/'shortcut.ps1';path.write_text(script,encoding='utf-8-sig')
  subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(path)],env=env,check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)

def main():
 global _diagnostic
 folder=Path(os.environ.get('LOCALAPPDATA') or tempfile.gettempdir())/'Watchtower'/'diagnostics'/'installer'
 _diagnostic=StartupDiagnostics(folder)
 try:return _main()
 except Exception as exc:
  _diagnostic.failed(exc)
  if '--install-cli' not in sys.argv:
   try:
    from windows_native.diagnostic_dialog import show
    show(_diagnostic,phase='install')
   except Exception:pass
  return 1

def _main():
 if '--install-cli' in sys.argv:
  import argparse,json
  parser=argparse.ArgumentParser();parser.add_argument('--install-cli',action='store_true');parser.add_argument('--repair',action='store_true');parser.add_argument('--source',type=Path);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--account-file',type=Path);parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
  try:
   from windows_native.embedded_install import detect
   source=args.source or detect(sys.executable) or Path(sys.executable).parent
   result=install(source,args.root,json.loads(args.account_file.read_text(encoding='utf-8')) if args.account_file else {},progress=lambda value:None,mode='repair' if args.repair else 'auto')
   shortcut(args.root)
   result['desktop_shortcut']=True
  except Exception as exc:
   _diagnostic.failed(exc);result={'ok':False,'error':redact(exc),'diagnostic':_diagnostic.public()}
  args.report.write_text(json.dumps(result),encoding='utf-8');return 0 if result['ok'] else 1
 from windows_native.embedded_install import detect
 source=detect(sys.executable) if getattr(sys,'frozen',False) else None
 source=source or (Path(sys.argv[sys.argv.index('--source')+1]).resolve() if '--source' in sys.argv else Path(sys.executable).parent)
 root=Path(sys.argv[sys.argv.index('--root')+1]).resolve() if '--root' in sys.argv else None
 from windows_native import maintenance
 if '--uninstall' in sys.argv and root is not None and maintenance.handoff(root):return 0
 from windows_native.installer_ui import show
 return show(source,_diagnostic,root=root,uninstall_only='--uninstall' in sys.argv)

if __name__=='__main__':raise SystemExit(main())
