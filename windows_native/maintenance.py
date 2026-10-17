"""Per-user Windows registration and receipt-scoped, data-preserving uninstall."""
from pathlib import Path
import os,sys,json,hashlib,subprocess,shutil,tempfile,uuid,time
from windows_native import update_state
from windows_native.update_channel import name,long_path
PREFIX=r'Software\Microsoft\Windows\CurrentVersion\Uninstall'
def key_name(root):return PREFIX+'\\Watchtower-'+hashlib.sha256(os.path.normcase(str(Path(root).resolve())).encode()).hexdigest()[:16]
def register(root):
    import winreg
    root=Path(root).resolve();maintenance=root/'runtime/maintenance/WatchtowerMaintenance.exe'
    if not maintenance.is_file():return
    receipt=update_state.read(root/'state/native-release-receipt.json')
    from windows_native.guardian import display_version
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,key_name(root)) as key:
        values={'DisplayName':'瞭望塔 Watchtower','DisplayVersion':display_version(receipt['version']),'Publisher':'Watchtower','InstallLocation':str(root),'DisplayIcon':str(root/'WatchtowerNative.exe'),'UninstallString':subprocess.list2cmdline([str(maintenance),'--uninstall','--root',str(root)]),'URLInfoAbout':'https://watchtowers.info/'}
        for label,value in values.items():winreg.SetValueEx(key,label,0,winreg.REG_SZ,value)
        winreg.SetValueEx(key,'NoRepair',0,winreg.REG_DWORD,1);winreg.SetValueEx(key,'NoModify',0,winreg.REG_DWORD,1);winreg.SetValueEx(key,'EstimatedSize',0,winreg.REG_DWORD,min(2**32-1,receipt.get('installed_kib',1600000)))
def unregister(root):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,key_name(root)) as key:
            if os.path.normcase(winreg.QueryValueEx(key,'InstallLocation')[0])!=os.path.normcase(str(Path(root).resolve())):raise ValueError('Windows installation registration belongs to another folder')
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER,key_name(root))
    except FileNotFoundError:pass
def handoff(root):
    """Show maintenance from a temporary copy, so its installed EXE can be removed."""
    root=Path(root).resolve();exe=Path(sys.executable).resolve()
    if not getattr(sys,'frozen',False) or root not in exe.parents:return False
    folder=Path(tempfile.mkdtemp(prefix='Watchtower-maintenance-'));target=folder/'WatchtowerMaintenance.exe';shutil.copy2(exe,target)
    update_state.write(folder/'owned-maintenance.json',{'product':'watchtower-maintenance','parent_pid':os.getpid(),'created':time.time()})
    subprocess.Popen([str(target),'--uninstall','--root',str(root)],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));return True
def uninstall(root,remove_data=False,progress=print):
    from windows_native.repair_install import recognized,close_owned
    from windows_native import update_transaction
    root=Path(root).resolve()
    if not recognized(root):raise ValueError('请选择已安装的Watchtower目录 / Choose an existing Watchtower installation')
    receipt=update_state.read(root/'state/native-release-receipt.json');files=receipt.get('files')
    if not isinstance(files,dict) or not files or len(files)>20000:raise ValueError('安装清单无效，未删除任何数据 / Invalid receipt; nothing removed')
    paths=[update_transaction._inside(root,name(n)) for n in files]
    if any(p.is_dir() for p in paths):raise ValueError('程序清单类型冲突，未删除任何数据 / Invalid receipt member type')
    state=root/'state';state.resolve().relative_to(root)
    progress('正在关闭此安装的程序…');close_owned(root)
    with update_state.lock(root):
        if update_state.read(state/'native-release-receipt.json')!=receipt:raise ValueError('安装信息已变化，请重新打开卸载 / Installation changed; reopen maintenance')
        update_state.write(state/'native-uninstall.json',{'phase':'removing_program','version':receipt['version'],'remove_data':bool(remove_data)})
        progress('正在卸载程序文件…')
        for path in sorted(paths,key=lambda p:len(p.parts),reverse=True):
            p=Path(long_path(path));p.unlink(missing_ok=True)
        parents={p.parent for p in paths}
        for parent in sorted(parents,key=lambda p:len(p.parts),reverse=True):
            while parent!=root:
                try:parent.rmdir()
                except OSError:break
                parent=parent.parent
        # Guardian contains executable controller copies, never business records.
        guardian=state/'guardian'
        if guardian.exists():
            guardian.resolve().relative_to(state.resolve())
            if guardian.is_symlink() or getattr(guardian.lstat(),'st_file_attributes',0)&0x400:raise ValueError('Unsafe guardian path')
            shutil.rmtree(long_path(guardian))
        from windows_native.shortcut import remove
        remove(root)
        unregister(root);update_state.write(state/'native-uninstall.json',{'phase':'done','version':receipt['version'],'user_data_retained':not remove_data})
    if remove_data:
        # The lock is closed before removing this explicitly selected data folder.
        state.resolve().relative_to(root)
        if state.is_symlink() or getattr(state.lstat(),'st_file_attributes',0)&0x400:raise ValueError('Unsafe data directory; data was retained')
        progress('正在删除已明确勾选的此安装个人数据…');shutil.rmtree(long_path(state))
    try:root.rmdir()
    except OSError:pass
    return {'ok':True,'uninstalled':True,'root':str(root),'user_data_retained':not remove_data,'shared_webview2_retained':True}
