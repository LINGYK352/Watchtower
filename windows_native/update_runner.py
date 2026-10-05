"""An owned helper survives the GUI exit so executable files can be updated."""
from pathlib import Path
import ctypes,json,os,subprocess,time,uuid,shutil
from ctypes import wintypes
from windows_native import update_state,update_transaction

def launch(root,request):
    root=Path(root).resolve();request_file=root/'state/native-update-active.json'
    helper=root/'state'/('.update-helper-'+uuid.uuid4().hex[:12]);helper.mkdir()
    # Hardlinks share unchanged DLLs and keep the helper outside managed program paths.
    from windows_native.update_channel import link
    from windows_native.guardian import service
    shutil.copytree(service(root),helper,dirs_exist_ok=True,copy_function=link)
    update_state.write(helper/'helper.json',{'created':time.time(),'product':'watchtower-native-update-helper'})
    update_state.write(request_file,request)
    command=[str(helper/'NativeService.exe'),'--root',str(root),'--boot',uuid.uuid4().hex,'--update-request',str(request_file)]
    environment=os.environ.copy();environment.pop('PYTHONHOME',None);environment.pop('PYTHONPATH',None)
    with (root/'state/native-update-helper.log').open('ab') as log:
        process=subprocess.Popen(command,stdout=log,stderr=log,cwd=root,env=environment,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
    update_state.progress(root,phase='checking',request_id=request['id'],target=request['target'],owner_pid=process.pid,helper_exe=command[0],msg='正在检查 Windows 更新')
    return process

def recover_launch(root):
    root=Path(root).resolve();candidates=[]
    for path in (root/'state').glob('.update-helper-*'):
        try:
            path.resolve().relative_to((root/'state').resolve());marker=json.loads((path/'helper.json').read_text(encoding='utf-8'))
            if marker.get('product')=='watchtower-native-update-helper':candidates.append((marker['created'],path))
        except (OSError,ValueError,KeyError):continue
    if not candidates:raise RuntimeError('Interrupted update helper is missing')
    helper=max(candidates,key=lambda item:item[0])[1]
    with (root/'state/native-update-helper.log').open('ab') as log:
        return subprocess.Popen([str(helper/'NativeService.exe'),'--root',str(root),'--boot',uuid.uuid4().hex,'--recover-update'],stdout=log,stderr=log,cwd=root,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)

def cleanup_helpers(root):
    import psutil
    state=(Path(root)/'state').resolve();active=[]
    for process in psutil.process_iter(['exe']):
        if process.info['exe']:active.append(Path(process.info['exe']).resolve())
    for path in state.glob('.update-helper-*'):
        if any(path in executable.parents for executable in active):continue
        try:
            path.resolve().relative_to(state);marker=json.loads((path/'helper.json').read_text(encoding='utf-8'))
            if marker.get('product')=='watchtower-native-update-helper' and not path.is_symlink():shutil.rmtree(path)
        except (OSError,ValueError):continue

def recover_progress(root):
    import psutil
    root=Path(root).resolve();progress=update_state.get_progress(root)
    if (root/'state/native-update-command.json').exists() or progress.get('phase') not in update_state.ACTIVE:return
    try:
        if Path(psutil.Process(progress['owner_pid']).exe()).resolve()==Path(progress['helper_exe']).resolve():return
    except (KeyError,psutil.Error):pass
    update_state.progress(root,phase='error',msg='上次更新已中断，原程序和下载缓存保留，可重新更新',error='Interrupted update before commit',terminal=True)
    (root/'state/native-update-active.json').unlink(missing_ok=True)
    for stage in (root/'state').glob('.wu-*'):
        try:
            stage.resolve().relative_to((root/'state').resolve());marker=json.loads((stage/'transaction.json').read_text(encoding='utf-8'))
            if marker.get('product')=='watchtower-native-update-stage' and not stage.is_symlink():
                from windows_native.update_channel import long_path
                shutil.rmtree(long_path(stage))
        except (OSError,ValueError):continue

def claim(root):
    with update_state.lock(root):
        path=Path(root)/'state/native-update-command.json'
        if not path.exists():return None
        request=update_state.read(path)
        if request.get('action') not in ('apply','rollback') or not isinstance(request.get('id'),str):raise ValueError('Invalid native update intent')
        path.unlink();return request

def run(root,request_file=None):
    import psutil
    root=Path(root).resolve();recover_only=request_file is None
    if not recover_only:
        request_file=Path(request_file).resolve();request_file.relative_to((root/'state').resolve())
        request=update_state.read(request_file)
    from windows_native.update_channel import version
    if not recover_only:
        import sys
        version(request['target'])
        update_state.progress(root,phase='checking',request_id=request['id'],target=request['target'],owner_pid=os.getpid(),helper_exe=sys.executable,msg='正在检查 Windows 更新')
    settings=update_state.read(root/'state/runtime.json')
    from windows_native.guardian import gui as guardian_gui
    gui=guardian_gui(root).resolve();active_gui=None
    def managed_processes():
        matches=[]
        for process in psutil.process_iter(['pid','exe']):
            try:
                exe=Path(process.info['exe']).resolve() if process.info['exe'] else None
                if exe in {gui,(root/'WatchtowerNative.exe').resolve()} or exe and (root/'runtime').resolve() in exe.parents:matches.append(process)
            except (psutil.Error,OSError):continue
        return matches
    def stop():
        user32=ctypes.WinDLL('user32',use_last_error=True)
        callback_type=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HWND,wintypes.LPARAM)
        user32.EnumWindows.argtypes=[callback_type,wintypes.LPARAM];user32.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
        user32.PostMessageW.argtypes=[wintypes.HWND,wintypes.UINT,wintypes.WPARAM,wintypes.LPARAM]
        pids={process.pid for process in managed_processes() if Path(process.exe()).resolve() in {gui,(root/'WatchtowerNative.exe').resolve()}}
        def close_window(handle,_):
            pid=wintypes.DWORD();user32.GetWindowThreadProcessId(handle,ctypes.byref(pid))
            if pid.value in pids:user32.PostMessageW(handle,0x10,0,0)
            return True
        user32.EnumWindows(callback_type(close_window),0)
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            if not managed_processes():return
            time.sleep(.1)
        raise RuntimeError('The owned application did not finish graceful shutdown')
    def start():
        nonlocal active_gui
        from urllib.request import Request,urlopen
        from windows_native import guardian
        guardian.install(root)
        launch_gui=guardian.gui(root)
        active_gui=subprocess.Popen([str(launch_gui),'--root',str(root)],cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            if active_gui.poll() is not None:return False
            try:
                request=Request('http://127.0.0.1:'+str(settings['web_port'])+'/__native_ready',headers={'X-Native-Control':settings['control_token']})
                with urlopen(request,timeout=1) as response:
                    status=json.load(response)
                    if status.get('ready') and status.get('version')==(root/'app/version.txt').read_text().strip():return True
            except (OSError,ValueError):pass
            time.sleep(.2)
        return False
    def health(candidate,release):
        report=root/'state'/('update-health-'+uuid.uuid4().hex+'.json')
        service=candidate/'runtime/service/NativeService.exe'
        command=[str(service),'--root',str(root),'--boot',uuid.uuid4().hex,'--probe-core',str(candidate/'app'),'--probe-runtime',str(candidate/'runtime'),'--report',str(report)]
        result=subprocess.run(command,capture_output=True,timeout=45,creationflags=subprocess.CREATE_NO_WINDOW)
        try:checked=json.loads(report.read_text(encoding='utf-8'))
        except (OSError,ValueError):return False
        finally:report.unlink(missing_ok=True)
        return result.returncode==0 and checked.get('ok') and checked.get('core_version')==release['version']
    try:
        if recover_only:
            stop();update_transaction.recover(root)
            if not start():raise RuntimeError('Recovered native application did not start')
            return 0
        update_transaction.apply(root,request['target'],health,start,stop,full=bool(request.get('full')))
        from windows_native.update_chain import success
        success(root,request)
        return 0
    except Exception as exc:
        if not recover_only and request.get('chain_id'):
            from windows_native.update_chain import failed
            failed(root,str(exc))
        update_state.progress(root,phase='error',msg='Windows 更新失败，请查看更新状态',error=type(exc).__name__+': '+str(exc)[:180],terminal=True)
        return 1
    finally:
        if request_file:request_file.unlink(missing_ok=True)
