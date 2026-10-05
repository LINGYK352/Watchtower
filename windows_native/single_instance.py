"""One interactive Watchtower client in the current Windows session."""
import ctypes,os
from ctypes import wintypes as w
kernel=ctypes.WinDLL('kernel32',use_last_error=True);user=ctypes.WinDLL('user32',use_last_error=True)
kernel.CreateMutexW.argtypes=[ctypes.c_void_p,w.BOOL,w.LPCWSTR];kernel.CreateMutexW.restype=w.HANDLE
kernel.CloseHandle.argtypes=[w.HANDLE];kernel.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)]
callback_type=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
user.EnumWindows.argtypes=[callback_type,w.LPARAM];user.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
user.IsWindowVisible.argtypes=[w.HWND];user.IsIconic.argtypes=[w.HWND];user.ShowWindow.argtypes=[w.HWND,ctypes.c_int];user.SetForegroundWindow.argtypes=[w.HWND]

def focus_existing():
    import psutil
    current=w.DWORD();kernel.ProcessIdToSessionId(os.getpid(),ctypes.byref(current));pids=set()
    for process in psutil.process_iter(['pid','name']):
        if process.pid==os.getpid() or (process.info['name'] or '').casefold()!='watchtowernative.exe':continue
        session=w.DWORD()
        if kernel.ProcessIdToSessionId(process.pid,ctypes.byref(session)) and session.value==current.value:pids.add(process.pid)
    found=[]
    def focus(handle,_):
        pid=w.DWORD();user.GetWindowThreadProcessId(handle,ctypes.byref(pid))
        if pid.value in pids and user.IsWindowVisible(handle):
            if user.IsIconic(handle):user.ShowWindow(handle,9)
            user.SetForegroundWindow(handle);found.append(handle)
        return True
    user.EnumWindows(callback_type(focus),0)
    return bool(found)

def acquire():
    handle=kernel.CreateMutexW(None,True,'Local\\WatchtowerNative.Interactive')
    if not handle:raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error()==183:
        kernel.CloseHandle(handle);focus_existing();return None
    # Earlier private test versions used a per-directory lock. Activate their
    # existing window too, instead of starting another backend during migration.
    if focus_existing():kernel.CloseHandle(handle);return None
    return handle

def release(handle):
    if handle:kernel.CloseHandle(handle)
