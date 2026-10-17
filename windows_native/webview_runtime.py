"""Offline WebView2 provisioning from the verified complete installer payload."""
from pathlib import Path
import os,subprocess,time,hashlib,tempfile,zipfile
MEMBER='__installer__/MicrosoftEdgeWebView2RuntimeInstallerX64.exe'
def _loader_path():
    import importlib.util,sys
    spec=importlib.util.find_spec('webview')
    if spec is None:return None
    base=Path(spec.origin).parent
    candidates=[base/'lib/runtimes/win-x64/native/WebView2Loader.dll',base/'lib/x64/WebView2Loader.dll']
    if hasattr(sys,'_MEIPASS'):
        frozen=Path(sys._MEIPASS);candidates += [frozen/'win-x64/WebView2Loader.dll',frozen/'WebView2Loader.dll',frozen/'webview/lib/runtimes/win-x64/native/WebView2Loader.dll']
    return next((p for p in candidates if p.is_file()),None)

def loader_version(folder=None):
    import ctypes
    loader=_loader_path()
    if loader is None:return None
    pointer=ctypes.c_void_p()
    try:
        dll=ctypes.WinDLL(str(loader));fn=dll.GetAvailableCoreWebView2BrowserVersionString
        fn.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_void_p)];fn.restype=ctypes.c_long
        result=fn(str(folder) if folder else None,ctypes.byref(pointer))
        return ctypes.wstring_at(pointer.value) if result>=0 and pointer.value else ''
    except OSError:return ''
    finally:
        if pointer.value:
            free=ctypes.windll.ole32.CoTaskMemFree;free.argtypes=[ctypes.c_void_p];free(pointer)

def installed_folders():
    if os.name!='nt':return []
    import winreg
    key=r'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    locations=[Path(os.environ[name])/'Microsoft/EdgeWebView/Application' for name in ('LOCALAPPDATA','PROGRAMFILES(X86)','PROGRAMFILES') if os.environ.get(name)]
    folders=[]
    for hive in (winreg.HKEY_CURRENT_USER,winreg.HKEY_LOCAL_MACHINE):
        for flags in (winreg.KEY_READ|winreg.KEY_WOW64_32KEY,winreg.KEY_READ|winreg.KEY_WOW64_64KEY):
            try:
                with winreg.OpenKey(hive,key,0,flags) as handle:version=str(winreg.QueryValueEx(handle,'pv')[0])
                if version and version!='0.0.0.0' and all(p.isdigit() for p in version.split('.')):
                    for base in locations:
                        folder=base/version
                        if (folder/'msedgewebview2.exe').is_file() and folder not in folders:folders.append(folder)
            except OSError:pass
    return folders

def present():
    if os.name!='nt':return False
    version=loader_version()
    if version is not None:return bool(version)
    # Installer-only bootstrap has no GUI Loader. The actual frozen GUI health
    # process still verifies that Loader and WebView2 can really initialize.
    return bool(installed_folders())

def loader_available():return present()

def configure_runtime(webview,diagnostic):
    from windows_native.startup_diagnostics import redact
    override=os.environ.get('WEBVIEW2_BROWSER_EXECUTABLE_FOLDER','').strip()
    if override and not (Path(override)/'msedgewebview2.exe').is_file():
        os.environ.pop('WEBVIEW2_BROWSER_EXECUTABLE_FOLDER',None)
        diagnostic._write({'event':'webview_runtime_override','message':redact('Ignored unavailable process runtime folder: '+override)})
        override=''
    # The platform owns a per-install profile. Ambient process overrides must
    # not redirect separate installations to an unrelated/locked data folder.
    profile=os.environ.pop('WEBVIEW2_USER_DATA_FOLDER',None)
    if profile:diagnostic._write({'event':'webview_profile_override','message':redact('Using application profile instead of process override: '+profile)})
    if override:
        override=str(Path(override).resolve());os.environ['WEBVIEW2_BROWSER_EXECUTABLE_FOLDER']=override
    available=loader_version(override) if override else loader_version()
    if not available:raise RuntimeError('WebView2实际运行检测失败：Loader未找到可用引擎，请使用完整安装器修复 / WebView2 Loader did not find a usable runtime')
    folder=Path(override) if override else next((p for p in installed_folders() if loader_version(p)==available),None)
    if folder is not None:webview.settings['WEBVIEW2_RUNTIME_PATH']=str(folder)
    diagnostic._write({'event':'webview_runtime_selection','message':redact('version='+available+'; folder='+str(folder or 'Microsoft Loader automatic selection')+'; loader='+str(_loader_path()))})

def verify_publisher(path):
    literal="'"+str(path).replace("'","''")+"'"
    # A parent PowerShell7 module path cannot be consumed by Windows PowerShell5.
    # Load only the native host modules, retaining the normal Authenticode policy.
    script="$ErrorActionPreference='Stop'; $env:PSModulePath=Join-Path $PSHOME 'Modules'; "+'$s=Get-AuthenticodeSignature -LiteralPath '+literal+'; if($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch "(?:^|,\\s*)O=Microsoft Corporation(?:,|$)"){exit 1}'
    host=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    result=subprocess.run([str(host),'-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=45,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:raise ValueError('内置依赖的微软发布者签名验证失败 / Bundled Microsoft publisher verification failed')

def ensure_webview2(cache,progress,source=None,manifest=None):
    ensure_dotnet(source,manifest,progress)
    if present():progress('已检测到 WebView2 运行库');return
    metadata=(manifest or getattr(source,'manifest',{})).get('prerequisites',{}).get('webview2',{})
    if metadata.get('member')!=MEMBER or not isinstance(metadata.get('bytes'),int) or not 50*1024**2<metadata['bytes']<512*1024**2:raise RuntimeError('安装包未包含WebView2离线运行库，请下载178完整安装器 / Download the complete178 installer with offline WebView2')
    progress('正在验证内置 WebView2 离线运行库（无需联网下载）')
    from windows_native.embedded_install import Source
    with tempfile.TemporaryDirectory(prefix='Watchtower-WebView2-',ignore_cleanup_errors=True) as folder:
        target=Path(folder)/'MicrosoftEdgeWebView2RuntimeInstallerX64.exe';payload=source.payload() if isinstance(source,Source) else Path(source)/(manifest or {})['file']
        with zipfile.ZipFile(payload) as archive:
            info=archive.getinfo(MEMBER)
            if info.file_size!=metadata['bytes']:raise ValueError('WebView2 component size mismatch')
            digest=hashlib.sha256()
            with archive.open(info) as inp,target.open('xb') as out:
                for raw in iter(lambda:inp.read(1024**2),b''):digest.update(raw);out.write(raw)
            if digest.hexdigest()!=metadata.get('sha256'):raise ValueError('WebView2 component checksum mismatch')
        verify_publisher(target);progress('正在安装内置 WebView2 运行库，请稍候…')
        result=subprocess.run([str(target),'/silent','/install'],timeout=600,capture_output=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode not in (0,3010):raise RuntimeError('WebView2离线安装失败，代码 '+str(result.returncode)+' / Offline runtime installation failed')
        for _ in range(60):
            if present():progress('WebView2 运行库已就绪');return
            time.sleep(.5)
        raise RuntimeError('WebView2已执行安装但尚未就绪；请检查系统安装策略或重启Windows后重试 / Runtime not ready after offline installation')

def dotnet_present():
    if os.name!='nt':return False
    import winreg
    for flags in (winreg.KEY_READ|winreg.KEY_WOW64_32KEY,winreg.KEY_READ|winreg.KEY_WOW64_64KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full',0,flags) as key:
                if int(winreg.QueryValueEx(key,'Release')[0])>=394802:return True
        except (OSError,ValueError):pass
    return False

def ensure_dotnet(source,manifest,progress):
    if dotnet_present():return
    member='__installer__/NDP48-x86-x64-AllOS-ENU.exe';metadata=(manifest or getattr(source,'manifest',{})).get('prerequisites',{}).get('dotnet',{})
    if metadata.get('member')!=member:raise RuntimeError('缺少.NET窗口组件，请使用178完整离线安装器修复 / Required .NET component missing; use the complete178 installer')
    from windows_native.embedded_install import Source
    import ctypes
    progress('正在准备内置.NET离线窗口组件；系统需要时会请求管理员允许…')
    with tempfile.TemporaryDirectory(prefix='Watchtower-DotNet-',ignore_cleanup_errors=True) as folder:
        target=Path(folder)/'NDP48-x86-x64-AllOS-ENU.exe';payload=source.payload() if isinstance(source,Source) else Path(source)/(manifest or {})['file']
        with zipfile.ZipFile(payload) as archive:
            info=archive.getinfo(member)
            if not isinstance(metadata.get('bytes'),int) or not 50*1024**2<info.file_size<256*1024**2 or info.file_size!=metadata['bytes']:raise ValueError('.NET component size mismatch')
            digest=hashlib.sha256()
            with archive.open(info) as inp,target.open('xb') as out:
                for raw in iter(lambda:inp.read(1024**2),b''):digest.update(raw);out.write(raw)
            if digest.hexdigest()!=metadata.get('sha256'):raise ValueError('.NET component checksum mismatch')
        verify_publisher(target)
        hidden=getattr(subprocess,'CREATE_NO_WINDOW',0)
        if ctypes.windll.shell32.IsUserAnAdmin():result=subprocess.run([str(target),'/q','/norestart'],timeout=900,creationflags=hidden)
        else:
            literal="'"+str(target).replace("'","''")+"'"
            script="$ErrorActionPreference='Stop'; $p=Start-Process -FilePath "+literal+" -ArgumentList '/q','/norestart' -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],timeout=900,capture_output=True,creationflags=hidden)
        if result.returncode in (3010,1641):raise RuntimeError('.NET依赖已安装，请重启Windows后重新运行安装器，原资料保留 / .NET installed; restart Windows and rerun setup')
        if result.returncode or not dotnet_present():raise RuntimeError('Windows未能完成.NET离线组件安装，请检查管理员授权或系统安装策略 / Windows could not install the bundled .NET component')
