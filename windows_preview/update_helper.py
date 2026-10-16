from pathlib import Path
import argparse, base64, ctypes, json, os, re, subprocess, time, uuid
from windows_preview.desktop_update import apply, UpdateError, atomic_json
from windows_preview._trust import PUBLIC_KEY


def wait_for_parent(pid, expected):
    if not pid:return
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.restype=ctypes.c_void_p
    handle=kernel.OpenProcess(0x1000|0x100000,False,pid)
    if not handle:return
    try:
        buffer=ctypes.create_unicode_buffer(32768);length=ctypes.c_ulong(len(buffer))
        kernel.QueryFullProcessImageNameW.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_ulong)]
        if not kernel.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(length)):
            raise UpdateError('无法核对需要退出的 Windows 程序')
        if Path(buffer.value).resolve()!=expected.resolve():raise UpdateError('退出进程与当前程序不一致')
        # Request closure only for windows belonging to the verified application PID.
        user=ctypes.WinDLL('user32',use_last_error=True)
        callback_type=ctypes.WINFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p)
        user.GetWindowThreadProcessId.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
        user.PostMessageW.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p]
        def close_own_window(window,context):
            owner=ctypes.c_ulong()
            user.GetWindowThreadProcessId(window,ctypes.byref(owner))
            if owner.value==pid:user.PostMessageW(window,0x0010,None,None)
            return True
        callback=callback_type(close_own_window)
        user.EnumWindows.argtypes=[callback_type,ctypes.c_void_p]
        user.EnumWindows(callback,None)
        kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong]
        if kernel.WaitForSingleObject(handle,60000)!=0:raise UpdateError('Windows 界面尚未退出，本次更新已保留')
    finally:
        kernel.CloseHandle.argtypes=[ctypes.c_void_p];kernel.CloseHandle(handle)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);parser.add_argument('--bundle',required=True)
    parser.add_argument('--pid',type=int,default=0);parser.add_argument('--launch',action='store_true');parser.add_argument('--job',default=uuid.uuid4().hex)
    args=parser.parse_args();root=Path(args.root).resolve()
    if not re.fullmatch('[0-9a-f]{32}',args.job):raise UpdateError('更新请求标识无效')
    status=root/'state'/('desktop-update-'+args.job+'.json')
    def prepared(manifest):
        atomic_json(status,{'phase':'prepared','job':args.job})
        expected=root/'versions'/manifest['base']/'WatchtowerDesktop.exe'
        wait_for_parent(args.pid,expected)
    def healthy(target,manifest):
        report=root/'state/new-desktop-health.json'
        if report.exists():report.unlink()
        result=subprocess.run([str(target/'WatchtowerDesktop.exe'),'--health-check','--report',str(report)],
                   cwd=target,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode or not report.exists():return False
        actual=json.loads(report.read_text(encoding='utf-8'))
        return actual.get('ok') is True and actual.get('version')==manifest['app_version'] and actual.get('build')==manifest['build']
    try:
        apply(root,args.bundle,base64.b64decode(PUBLIC_KEY),healthy,prepared)
        atomic_json(status,{'phase':'done','job':args.job})
        if args.launch:subprocess.Popen([str(root/'Watchtower.exe')],cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as exc:
        atomic_json(status,{'phase':'error','job':args.job,'error':str(exc)[:400]})
        if args.launch:subprocess.Popen([str(root/'Watchtower.exe')],cwd=root,creationflags=subprocess.CREATE_NO_WINDOW)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
