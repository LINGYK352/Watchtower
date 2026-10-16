"""User-level signed setup; no Python/Docker/WSL installation on Windows."""
from pathlib import Path
import argparse,base64,ctypes,json,os,platform,queue,re,shutil,subprocess,sys,threading,time,uuid,zipfile
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from windows_preview._trust import PUBLIC_KEY
from windows_preview.signed_download import signed_manifest,asset_source,download,safe_resource,validate_url

PRODUCT='watchtower-windows-preview-install'
HIDDEN=getattr(subprocess,'CREATE_NO_WINDOW',0)


def private_directory(path):
    path=Path(path);path.mkdir(parents=True,exist_ok=True)
    if os.name=='nt':
        import csv,io
        r=subprocess.run(['whoami.exe','/user','/fo','csv','/nh'],capture_output=True,check=True,creationflags=HIDDEN)
        sid=next(csv.reader(io.StringIO(r.stdout.decode('utf-8','replace'))))[1]
        subprocess.run(['icacls.exe',str(path),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F'],capture_output=True,check=True,creationflags=HIDDEN)


def webview2_present():
    if os.name!='nt':return False
    import winreg
    key=r'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    for hive in [winreg.HKEY_CURRENT_USER,winreg.HKEY_LOCAL_MACHINE]:
        for flags in [winreg.KEY_READ|winreg.KEY_WOW64_32KEY,winreg.KEY_READ|winreg.KEY_WOW64_64KEY]:
            try:
                with winreg.OpenKey(hive,key,0,flags) as k:value=winreg.QueryValueEx(k,'pv')[0]
                if value and value!='0.0.0.0':return True
            except OSError:pass
    return False


def powershell_literal(value):return "'"+str(value).replace("'","''")+"'"


def ensure_webview2(cache,progress):
    if webview2_present():progress('已检测到 WebView2');return
    # The Microsoft bootstrapper is intentionally validated by publisher signature,
    # because its official redirect points to a continually updated binary.
    from windows_preview.signed_download import OPENER
    cache=Path(cache);target=cache/'MicrosoftEdgeWebview2Setup.exe'
    progress('正在准备微软 WebView2 运行库')
    with OPENER.open(validate_url('https://go.microsoft.com/fwlink/p/?LinkId=2124703'),timeout=30) as response,target.open('wb') as out:
        shutil.copyfileobj(response,out)
    script='$s=Get-AuthenticodeSignature -LiteralPath '+powershell_literal(target)+'; if($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch "(?:^|,\s*)O=Microsoft Corporation(?:,|$)"){exit 1}'
    checked=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,creationflags=HIDDEN)
    if checked.returncode:raise ValueError('微软运行库发布者签名检查失败')
    result=subprocess.run([str(target),'/silent','/install'],timeout=300,creationflags=HIDDEN)
    if result.returncode:raise RuntimeError('WebView2 安装未完成')
    for _ in range(60):
        if webview2_present():return
        time.sleep(1)
    raise RuntimeError('WebView2 安装后检测未通过，请查看运行库安装结果')


def install_name(name):
    safe_resource(name)
    top=name.split('/')[0]
    if top not in ('engine','runtime','versions','Watchtower.exe','brand.png','active.json','update-channel.json','测试说明.md'):raise ValueError('安装组件包含禁止目录或文件')
    if any(part.split('.')[0].upper() in ['CON','PRN','AUX','NUL']+[f'COM{i}' for i in range(1,10)]+[f'LPT{i}' for i in range(1,10)] for part in name.split('/')):raise ValueError('Windows 保留文件名')
    return name


def extract_component(archive,stage,seen):
    with zipfile.ZipFile(archive) as z:
        if sum(i.file_size for i in z.infolist())>2*1024**3:raise ValueError('安装压缩组件展开超过大小限制')
        if len(z.infolist())>10000:raise ValueError('安装文件数量超过限制')
        for info in z.infolist():
            name=info.filename.rstrip('/')
            if not name:continue
            install_name(name)
            if (info.external_attr>>16)&0o170000==0o120000:raise ValueError('安装包禁止链接')
            path=stage/name;path.resolve().relative_to(stage.resolve())
            if info.is_dir():path.mkdir(parents=True,exist_ok=True);continue
            if name.casefold() in seen:raise ValueError('安装包存在重复文件')
            seen.add(name.casefold());path.parent.mkdir(parents=True,exist_ok=True)
            with z.open(info) as source,path.open('wb') as output:shutil.copyfileobj(source,output)


def create_shortcut(root,directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    link=directory/'Watchtower.lnk'
    script='$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut('+powershell_literal(link)+'); $s.TargetPath='+powershell_literal(root/'Watchtower.exe')+'; $s.WorkingDirectory='+powershell_literal(root)+'; $s.IconLocation='+powershell_literal(root/'Watchtower.exe')+'; $s.Save()'
    subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],check=True,capture_output=True,creationflags=HIDDEN)


def install(source,destination,admin,progress=lambda text:None,launch=False,shortcut_dir=None,cancel=None):
    root=Path(destination).resolve()
    if os.name!='nt' or platform.machine().lower() not in ('amd64','x86_64'):raise RuntimeError('此测试安装包仅支持 64 位 Windows')
    if root.exists() and any(root.iterdir()):raise ValueError('安装目录已有文件，请选择新目录；已有程序通过内置更新升级')
    manifest=signed_manifest(source,base64.b64decode(PUBLIC_KEY),PRODUCT)
    channel=manifest.get('channel','testing')
    username=str(admin.get('username','')).strip();password=str(admin.get('password',''))
    min_length=6 if channel=='testing' and admin.get('testing') is True else 12
    if not username or len(username)>64 or any(ord(c)<32 for c in username) or len(password)<min_length:raise ValueError('请设置有效账号和符合长度要求的密码')
    class Memory(ctypes.Structure):
        _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(name,ctypes.c_ulonglong) for name in ['total','available','total_page','available_page','total_virtual','available_virtual','extended']]
    memory=Memory();memory.length=ctypes.sizeof(memory);ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory))
    if memory.total<manifest.get('min_ram_bytes',12*1024**3):raise RuntimeError('当前8GiB客体配置需要至少12GiB物理内存；低配模式尚待专项评估')
    assets=manifest.get('assets',[])
    if not assets or len(assets)>12:raise ValueError('安装组件清单无效')
    root.parent.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(root.parent).free<max(24*1024**3,manifest.get('min_disk_bytes',0)):raise RuntimeError('安装目录剩余空间不足（本地完整版建议至少24GiB可用空间，含下载、运行磁盘与安全余量）')
    cache=root.parent/'.watchtower-install-cache';private_directory(cache)
    stage=root.parent/('.watchtower-install-'+uuid.uuid4().hex);stage.mkdir();private_directory(stage)
    try:
        ensure_webview2(cache,progress)
        seen=set()
        for index,item in enumerate(assets):
            if cancel and cancel.is_set():raise InterruptedError('安装已取消')
            file=safe_resource(item['file'])
            def display(done,size):progress('准备组件 '+str(index+1)+'/'+str(len(assets))+' · '+str(round(done*100/size))+'%')
            downloaded=download(asset_source(source,file),cache,item['sha256'],item['bytes'],display,cancel)
            if item['kind']=='zip':extract_component(downloaded,stage,seen)
            elif item['kind']=='file':
                name=install_name(item['target'])
                if name.casefold() in seen:raise ValueError('安装组件目标重复')
                seen.add(name.casefold());target=stage/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(downloaded,target)
            else:raise ValueError('安装组件类型无效')
        pointer=json.loads((stage/'active.json').read_text(encoding='utf-8'))['version']
        if pointer!=manifest['version'] or not re.fullmatch(r'v\d+\.\d+\.\d+(?:-\d+)?-build\d+',pointer):raise ValueError('安装入口版本与签名清单不一致')
        private_directory(stage/'state')
        (stage/'state/admin-init.json').write_text(json.dumps({'username':username,'password':password},ensure_ascii=False),encoding='utf-8')
        (stage/'update-channel.json').write_text(json.dumps({'channel':channel,'source':manifest.get('update_source','')},ensure_ascii=False),encoding='utf-8')
        if manifest.get('update_source'):validate_url(manifest['update_source'])
        receipt={'schema':1,'product':PRODUCT,'version':pointer,'runtime_abi':manifest['runtime_abi'],'channel':channel}
        (stage/'installation.json').write_text(json.dumps(receipt),encoding='utf-8')
        progress('正在检查桌面程序和配套组件')
        report=stage/'state/setup-health.json'
        result=subprocess.run([str(stage/'versions'/pointer/'WatchtowerDesktop.exe'),'--health-check','--report',str(report)],cwd=stage,timeout=45,creationflags=HIDDEN)
        if result.returncode or not report.is_file() or not json.loads(report.read_text(encoding='utf-8')).get('ok'):raise RuntimeError('安装后的程序健康检查未通过')
        if cancel and cancel.is_set():raise InterruptedError('安装已取消')
        if root.exists():root.rmdir()
        os.replace(stage,root)
        if shortcut_dir:create_shortcut(root,shortcut_dir)
        for item in assets:
            cached=cache/(item['sha256']+'.asset')
            try:
                if cached.is_file():cached.unlink()
            except OSError:pass
        progress('安装完成；首次启动将在窗口内加载运行资源')
        if launch and not (cancel and cancel.is_set()):subprocess.Popen([str(root/'Watchtower.exe')],cwd=root,creationflags=HIDDEN)
        return receipt
    except Exception:
        # Never delete user data: only this newly generated, contained staging folder.
        if stage.exists():stage.resolve().relative_to(root.parent.resolve());shutil.rmtree(stage)
        raise


class SetupWindow:
    def __init__(self,source,destination,launch=True):
        self.source=source;self.launch=launch;self.events=queue.Queue();self.cancel_event=threading.Event();self.busy=False;self.window=tk.Tk();self.window.title('Watchtower · 安装本地测试版');self.window.geometry('700x490')
        self.target=tk.StringVar(value=str(destination));self.username=tk.StringVar(value='admin');self.password=tk.StringVar();self.status=tk.StringVar(value='独立桌面工作台 · 自动准备运行环境')
        frame=ttk.Frame(self.window,padding=28);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='安装瞭望塔 Watchtower',font=('Microsoft YaHei UI',19,'bold')).pack(anchor='w',pady=(0,18))
        for label,value in [('安装目录',self.target),('管理员账号',self.username),('管理员密码（至少12位）',self.password)]:
            ttk.Label(frame,text=label).pack(anchor='w',pady=(8,4));ttk.Entry(frame,textvariable=value,show='•' if value is self.password else '').pack(fill='x')
        self.button=ttk.Button(frame,text='安装并启动',command=self.begin);self.button.pack(anchor='e',pady=20)
        ttk.Label(frame,textvariable=self.status,wraplength=630).pack(anchor='w')
        self.window.protocol('WM_DELETE_WINDOW',self.close)
        self.window.after(100,self.pump)
    def begin(self):
        self.busy=True;self.cancel_event.clear();self.button.state(['disabled']);target=self.target.get();admin={'username':self.username.get(),'password':self.password.get()}
        def worker():
            try:
                install(self.source,target,admin,lambda text:self.events.put(('status',text)),self.launch,Path(target)/'快捷方式',self.cancel_event)
                self.events.put(('done','安装完成'))
            except Exception as e:self.events.put(('error',str(e)[:300]))
        threading.Thread(target=worker,daemon=True).start()
    def close(self):
        if self.busy:self.cancel_event.set();self.status.set('正在取消并清理本次暂存文件…')
        else:self.window.destroy()
    def pump(self):
        while not self.events.empty():
            kind,text=self.events.get_nowait();self.status.set(text)
            if kind in ('error','done'):self.busy=False
            if self.cancel_event.is_set() and kind in ('error','done'):self.window.destroy();return
            if kind=='error':self.button.state(['!disabled']);messagebox.showerror('安装未完成',text,parent=self.window)
            if kind=='done':self.button.configure(text='安装完成');self.password.set('')
        self.window.after(100,self.pump)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source');parser.add_argument('--root');parser.add_argument('--install',action='store_true');parser.add_argument('--admin-file');parser.add_argument('--launch',action='store_true');parser.add_argument('--report');parser.add_argument('--shortcut-dir');parser.add_argument('--health-check',action='store_true')
    args=parser.parse_args()
    if args.health_check:
        r=tk.Tk();r.withdraw();r.destroy();Path(args.report).write_text(json.dumps({'ok':True}));return 0
    source=args.source or str(Path(sys.executable).parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[2]/'安装包/v1.21.167-11')
    root=Path(args.root) if args.root else Path(os.environ['LOCALAPPDATA'])/'Watchtower'
    if args.install and args.admin_file:
        try:
            receipt=install(source,root,json.loads(Path(args.admin_file).read_text(encoding='utf-8')),launch=args.launch,shortcut_dir=args.shortcut_dir)
            if args.report:Path(args.report).write_text(json.dumps({'ok':True,**receipt}))
            return 0
        except Exception as e:
            if args.report:Path(args.report).write_text(json.dumps({'ok':False,'error':str(e)[:300]}))
            return 1
    SetupWindow(source,root).window.mainloop();return 0

if __name__=='__main__':raise SystemExit(main())
