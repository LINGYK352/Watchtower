"""Per-user native installer. No Python, Docker, WSL or manual account file required."""
from pathlib import Path
import os,sys,threading,queue,subprocess,json,tempfile
from windows_native.setup import install

TEXT={
 'zh-CN':{'title':'Watchtower 安装','folder':'安装目录','browse':'浏览…','choose':'选择安装目录','user':'管理员账号','password':'管理员密码（至少6位）','start':'开始安装','launch':'打开 Watchtower','done':'安装完成。打开后可注册并激活。','error':'安装失败','confirm':'请填写目录、账号和至少6位密码。','busy':'正在验证并安装…'},
 'en-US':{'title':'Install Watchtower','folder':'Installation folder','browse':'Browse…','choose':'Choose installation folder','user':'Administrator account','password':'Administrator password (at least 6 characters)','start':'Install','launch':'Open Watchtower','done':'Installed. Open Watchtower to register and activate.','error':'Installation failed','confirm':'Enter a folder, account, and password of at least 6 characters.','busy':'Verifying and installing…'}
}

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
 if '--install-cli' in sys.argv:
  import argparse,json
  parser=argparse.ArgumentParser();parser.add_argument('--install-cli',action='store_true');parser.add_argument('--source',type=Path);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--account-file',type=Path);parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
  try:
   from windows_native.embedded_install import detect
   source=args.source or detect(sys.executable) or Path(sys.executable).parent
   result=install(source,args.root,json.loads(args.account_file.read_text(encoding='utf-8')) if args.account_file else {},progress=lambda value:None)
   shortcut(args.root)
   result['desktop_shortcut']=True
  except Exception as exc:result={'ok':False,'error':str(exc)[:240]}
  args.report.write_text(json.dumps(result),encoding='utf-8');return 0 if result['ok'] else 1
 import tkinter as tk
 from tkinter import ttk,messagebox,filedialog
 source=Path(sys.executable).parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parent
 if getattr(sys,'frozen',False):
  from windows_native.embedded_install import detect
  source=detect(sys.executable) or source
 if '--source' in sys.argv:source=Path(sys.argv[sys.argv.index('--source')+1]).resolve()
 window=tk.Tk();window.geometry('640x430');window.resizable(False,False)
 locale=tk.StringVar(value='zh-CN');destination=tk.StringVar(value=str(Path(os.environ['LOCALAPPDATA'])/'Watchtower'));username=tk.StringVar();password=tk.StringVar();events=queue.Queue();installed=None;running=False
 frame=ttk.Frame(window,padding=24);frame.pack(fill='both',expand=True)
 picker=ttk.Combobox(frame,textvariable=locale,values=['zh-CN','en-US'],state='readonly',width=12);picker.pack(anchor='e')
 labels=[];entries=[];browse_button=None
 def browse():
  if running or installed:return
  initial=Path(destination.get()).expanduser()
  while not initial.is_dir() and initial!=initial.parent:initial=initial.parent
  chosen=filedialog.askdirectory(parent=window,title=TEXT[locale.get()]['choose'],initialdir=str(initial),mustexist=True)
  if chosen:destination.set(str(Path(chosen)))
 for field,var,hidden in [('folder',destination,False),('user',username,False),('password',password,True)]:
  label=ttk.Label(frame);label.pack(anchor='w',pady=(12,4));labels.append((field,label))
  container=ttk.Frame(frame) if field=='folder' else frame
  if field=='folder':container.pack(fill='x')
  entry=ttk.Entry(container,textvariable=var,show='*' if hidden else '');entries.append(entry)
  if field=='folder':
   entry.pack(side='left',fill='x',expand=True);browse_button=ttk.Button(container,command=browse);browse_button.pack(side='right',padx=(8,0))
  else:entry.pack(fill='x')
 status=ttk.Label(frame,wraplength=590);status.pack(anchor='w',pady=14)
 progress=ttk.Progressbar(frame,mode='indeterminate');progress.pack(fill='x')
 def launch():
  subprocess.Popen([str(installed/'WatchtowerNative.exe')],cwd=installed,creationflags=subprocess.CREATE_NO_WINDOW)
  window.destroy()
 def start():
  nonlocal running
  if installed:return launch()
  if running:return
  existing=Path(destination.get())/'state/native-release-receipt.json'
  if not destination.get().strip() or not existing.is_file() and (not username.get().strip() or len(password.get())<6):
   messagebox.showerror(TEXT[locale.get()]['error'],TEXT[locale.get()]['confirm']);return
  running=True;button.configure(state='disabled');picker.configure(state='disabled');progress.start();status.configure(text=TEXT[locale.get()]['busy'])
  for entry in entries:entry.configure(state='disabled')
  browse_button.configure(state='disabled')
  target=Path(destination.get()).resolve();account={'username':username.get().strip(),'password':password.get()}
  def work():
   try:
    install(source,target,account,progress=lambda text:events.put(('progress',text)))
    warning=''
    try:shortcut(target)
    except Exception:warning=' Desktop shortcut could not be created.'
    events.put(('done',(target,warning)))
   except Exception as exc:events.put(('error',str(exc)[:240]))
  threading.Thread(target=work,daemon=True).start()
 button=ttk.Button(frame,command=start);button.pack(anchor='e',pady=14)
 def language(*args):
  text=TEXT[locale.get()];window.title(text['title'])
  for name,label in labels:label.configure(text=text[name])
  browse_button.configure(text=text['browse'])
  button.configure(text=text['launch' if installed else 'start'])
 locale.trace_add('write',language);language()
 def poll():
  nonlocal installed,running
  while not events.empty():
   kind,value=events.get()
   if kind=='progress':status.configure(text=value)
   elif kind=='done':
    installed,warning=value;running=False;password.set('');progress.stop();button.configure(state='normal');status.configure(text=TEXT[locale.get()]['done']+warning);language()
   else:
    running=False;progress.stop();button.configure(state='normal');picker.configure(state='readonly');status.configure(text=value);messagebox.showerror(TEXT[locale.get()]['error'],value)
    for entry in entries:entry.configure(state='normal')
    browse_button.configure(state='normal')
  window.after(100,poll)
 window.protocol('WM_DELETE_WINDOW',lambda:None if running else window.destroy())
 poll();window.mainloop()

if __name__=='__main__':raise SystemExit(main())
