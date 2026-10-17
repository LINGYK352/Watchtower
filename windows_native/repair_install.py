"""Commit an already verified offline install program without replacing user state."""
from pathlib import Path
import json,os,shutil,sys,time,uuid
import psutil
from windows_native import update_state,update_transaction as transaction
from windows_native.update_channel import sha256,link,long_path
from windows_native.guardian import display_version

def recognized(root):
    root=Path(root)
    try:
        old=update_state.read(root/'state/native-release-receipt.json')
        from windows_native.update_channel import version,name
        version(old['version']);files=old['files']
        if not isinstance(files,dict) or not {'WatchtowerNative.exe','app/version.txt','runtime/service/NativeService.exe'}<=set(files) or len(files)>20000:return False
        import re
        for key,digest in files.items():
            name(key)
            if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):return False
        return (root/'app/version.txt').is_file() or ((root/'state/runtime.json').is_file() and (root/'state/config.yaml').is_file())
    except (OSError,ValueError,KeyError,TypeError):return False

def close_owned(root,timeout=35):
    """User-selected repair closes only this installation; never force-kill data writers."""
    import ctypes,subprocess
    from ctypes import wintypes
    root=Path(root).resolve()
    with update_state.lock(root):pass
    def processes():
        output=[]
        for process in psutil.process_iter(['pid','exe']):
            try:
                if process.pid!=os.getpid() and process.info['exe']:
                    exe=Path(process.info['exe']).resolve()
                    if root in exe.parents:output.append((process,exe))
            except psutil.NoSuchProcess:pass
        return output
    owned=processes()
    if not owned:return
    guis={p.pid for p,exe in owned if exe.name.casefold()=='watchtowernative.exe'}
    if guis:
        api=ctypes.WinDLL('user32',use_last_error=True);callback=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HWND,wintypes.LPARAM)
        api.EnumWindows.argtypes=[callback,wintypes.LPARAM];api.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)];api.PostMessageW.argtypes=[wintypes.HWND,wintypes.UINT,wintypes.WPARAM,wintypes.LPARAM]
        def close(handle,_):
            pid=wintypes.DWORD();api.GetWindowThreadProcessId(handle,ctypes.byref(pid))
            if pid.value in guis:api.PostMessageW(handle,0x10,0,0)
            return True
        api.EnumWindows(callback(close),0)
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if not processes():return
        time.sleep(.2)
    raise ValueError('请关闭该安装目录的Watchtower后再次修复；账号和资料保留 / Close this installation before retrying repair; user data is retained')

def commit(root,stage,manifest,progress=print):
    root,stage=Path(root).resolve(),Path(stage).resolve()
    if not recognized(root):
        raise ValueError('Existing folder is not a recognized Watchtower installation')
    for p in psutil.process_iter(['exe']):
        try:
            if p.info['exe'] and root in Path(p.info['exe']).resolve().parents:
                raise ValueError('Close Watchtower and its owned processes before repairing; user data will be retained')
        except (psutil.NoSuchProcess,psutil.AccessDenied):continue
    with update_state.lock(root):
        # A verified complete installer supersedes an interrupted software
        # transaction. Its temporary rollback files may already be missing;
        # archive the old intent and snapshot current files instead of depending
        # on that obsolete rollback before repairing the program.
        prior_journal=root/'state/native-update-journal.json'
        prior_journal_bytes=prior_journal.read_bytes() if prior_journal.is_file() else None
        old=update_state.read(root/'state/native-release-receipt.json');files=manifest['files']
        changed=[n for n,h in files.items() if not transaction._inside(root,n).is_file() or sha256(transaction._inside(root,n))!=h]
        removed=[n for n in old.get('files',{}) if n not in files]
        backup=Path(long_path(root/'state/update-backups'))/('repair-'+uuid.uuid4().hex[:12]);backup.mkdir(parents=True)
        if prior_journal_bytes is not None:
            prior=backup/'previous-intents';prior.mkdir();(prior/'native-update-journal.json').write_bytes(prior_journal_bytes)
        journal={'phase':'preparing','base':old.get('version'),'target':manifest['version'],'backup':str(backup),
                 'operations':{},'receipt':old,'owner_pid':os.getpid(),'helper_exe':sys.executable,'repair_install':True}
        marker=root/'state/native-update-journal.json'
        helper=root/'state'/('.update-helper-repair-'+uuid.uuid4().hex[:12])
        # A cold restart can recover even if the setup EXE was killed mid-commit.
        shutil.copytree(stage/'runtime/service',helper,copy_function=link)
        update_state.write(helper/'helper.json',{'created':time.time(),'product':'watchtower-native-update-helper'})
        try:
            for n in changed+removed:
                p=transaction._inside(root,n);exists=p.is_file();journal['operations'][n]=exists
                if exists:
                    saved=backup/'program'/n;saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,saved)
            journal['phase']='committing';update_state.write(marker,journal)
            for n in sorted(changed,key=lambda n:(n=='app/docker/frontend/index.html',n=='app/version.txt',n)):
                target=transaction._inside(root,n);target.parent.mkdir(parents=True,exist_ok=True)
                os.replace(long_path(stage/n),str(target))
            for n in removed:transaction._inside(root,n).unlink(missing_ok=True)
            for n,h in files.items():
                if sha256(transaction._inside(root,n))!=h:raise ValueError('Repaired program member mismatch: '+n)
            update_state.write(root/'state/native-release-receipt.json',{'version':manifest['version'],'files':files,'base_install':display_version(manifest['version'])})
            for name in ['native-update-chain.json','native-update-command.json','native-update-active.json','native-update-progress.json']:
                path=root/'state'/name
                if path.is_file():
                    dest=backup/'previous-intents'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest);path.unlink()
            from windows_native import guardian
            guardian.install(root)
            journal['phase']='done';update_state.write(marker,journal)
            update_state.progress(root,phase='done',target=manifest['version'],msg='Windows修复安装完成，账号/配置/任务与浏览器数据保留，旧更新计划已归档',terminal=True)
            progress('Repair installation completed; existing user state retained')
            return {'ok':True,'version':manifest['version'],'root':str(root),'repair':True,'user_state_retained':True,'backup':str(backup)}
        except Exception:
            if journal['phase']=='committing':transaction._restore(root,journal)
            prior=backup/'previous-intents'
            if prior.exists():
                for p in prior.iterdir():
                    if p.name!='native-update-journal.json':shutil.copy2(p,root/'state'/p.name)
            journal['phase']='rolled_back';update_state.write(marker,journal);raise
