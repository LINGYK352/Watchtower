"""Shared durable update intent/progress; no in-process boolean owns a transaction."""
from pathlib import Path
from contextlib import contextmanager
import json,os,uuid,time
ACTIVE={'checking','downloading','validating','applying','restarting'}
class UpdateBusyError(RuntimeError):pass

def open_read(path):
    """Read a stable file snapshot without blocking another process's rename.

    Windows's default CRT reader omits FILE_SHARE_DELETE. Atomic os.replace
    therefore fails while even a read-only UI poll holds the destination open.
    The handle owns the old snapshot; subsequent readers see the replacement.
    """
    path=Path(path)
    if os.name!='nt':return path.open('r',encoding='utf-8')
    import ctypes,msvcrt
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE];kernel.CloseHandle.restype=wintypes.BOOL
    # Do not resolve the file's identity before opening its pathname. On Windows,
    # realpath/GetFinalPathNameByHandle can return the previous temporary name
    # if a concurrent rename changes that object between the two operations.
    handle=kernel.CreateFileW(str(path.absolute()),0x80000000,0x1|0x2|0x4,None,3,0x80,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
    except Exception:kernel.CloseHandle(handle);raise
    return os.fdopen(fd,'r',encoding='utf-8')

def read(path):
    with open_read(path) as handle:return json.load(handle)

def _replace(source,target):
    if os.name!='nt':os.replace(source,target);return
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.SetFileInformationByHandle.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.CreateFileW(str(source.absolute()),0x10000,7,None,3,0x80,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    # One namespace operation: MoveFileEx refuses an open destination and
    # ReplaceFile briefly removes its name. POSIX rename retains old handles
    # and makes every new open see either the old or new complete snapshot.
    name=str(target.absolute()).encode('utf-16-le')
    class Rename(ctypes.Structure):
        _fields_=[('Flags',wintypes.DWORD),('RootDirectory',wintypes.HANDLE),('FileNameLength',wintypes.DWORD),('FileName',wintypes.WCHAR*(len(name)//2+1))]
    info=Rename();info.Flags=3;info.FileNameLength=len(name)
    ctypes.memmove(ctypes.byref(info,Rename.FileName.offset),name,len(name))
    try:
        if not kernel.SetFileInformationByHandle(handle,22,ctypes.byref(info),ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:kernel.CloseHandle(handle)

def write(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        with temporary.open('x',encoding='utf-8') as handle:
            json.dump(data,handle,ensure_ascii=False);handle.flush();os.fsync(handle.fileno())
        _replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)

def progress(root,**data):
    previous=get_progress(root)
    if data.get('phase') in ACTIVE:
        for key in ('owner_pid','helper_exe'):
            if key in previous:data.setdefault(key,previous[key])
    data.setdefault('ts',time.time());data.setdefault('terminal',data.get('phase') in {'done','error'})
    try:chain=read(Path(root)/'state/native-update-chain.json')
    except (OSError,ValueError):chain={}
    if chain.get('id'):
        data.update(current_version=(Path(root)/'app/version.txt').read_text().strip(),target_version=chain['target'],
                    hop_version=chain['steps'][chain['cursor']] if chain['cursor']<len(chain['steps']) else chain['target'],
                    hop=min(chain['cursor']+1,len(chain['steps'])),hops=len(chain['steps']),completed=chain['completed'],
                    resumable=chain['cursor']<len(chain['steps']),chain_active=chain.get('active',False),run_id=chain['id'])
        if data['phase']=='done' and chain.get('active'):
            data.update(phase='checking',terminal=False,msg='本级更新完成，正在确认运行并准备下一级')
    write(Path(root)/'state/native-update-progress.json',data)

def get_progress(root):
    try:return read(Path(root)/'state/native-update-progress.json')
    except (OSError,ValueError):return {'phase':'idle','total':0,'done':0,'terminal':True}

@contextmanager
def lock(root):
    path=Path(root)/'state/native-update.lock';path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+b') as handle:
        handle.write(b'0');handle.flush();handle.seek(0)
        if os.name=='nt':
            import msvcrt
            try:msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            except OSError as exc:raise UpdateBusyError('Another native update transaction is active') from exc
        else:
            import fcntl
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:yield
        finally:
            handle.seek(0)
            if os.name=='nt':msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(handle,fcntl.LOCK_UN)

def _enqueue(root,action,target,full=False):
    with lock(root):
        current=get_progress(root);command=Path(root)/'state/native-update-command.json'
        if current.get('phase') in ACTIVE or command.exists():return {'started':False,'msg':'更新正在进行中'}
        request={'id':uuid.uuid4().hex,'action':action,'target':target,'full':bool(full),'created':time.time()}
        write(command,request);progress(root,phase='checking',total=0,done=0,msg='正在启动原生更新',request_id=request['id'])
        return {'started':True,'request_id':request['id'],'target_version':target}

def enqueue(root,action,target,full=False):
    try:return _enqueue(root,action,target,full)
    except UpdateBusyError:return {'started':False,'msg':'更新仍在收尾，请稍后重试'}
