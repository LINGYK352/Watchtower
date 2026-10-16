"""Embedded Windows workbench. Native menus never expose privileged JS APIs."""
from pathlib import Path
import argparse
import base64
import ctypes
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
import urllib.request

import webview
from webview.menu import Menu, MenuAction, MenuSeparator
from windows_preview.portable_runtime import PortableRuntime, APP_VERSION, HOST, WEB_PORT, hidden_flags, protect_state
from windows_preview.desktop_version import DESKTOP_VERSION
from windows_preview.desktop_update import atomic_json
from windows_preview.frontend_update import apply_to_guest, validate_bundle
from windows_preview import core_delivery, online_update
from windows_preview.client_bridge import ClientBridge
from windows_preview.bootstrap_entry import ensure as ensure_entry

WORKSPACE = 'http://' + HOST + ':' + str(WEB_PORT) + '/'


def package_root():
    return Path(sys.executable).resolve().parents[2] if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]


def desktop_directory():
    return Path(sys.executable).parent if getattr(sys, 'frozen', False) else package_root()/'versions'/(DESKTOP_VERSION+'-build1')


def desktop_meta():
    return json.loads((desktop_directory()/'desktop.json').read_text(encoding='utf-8'))


def loading_html(root):
    logo = root/'brand.png'
    image = '<img alt="" src="data:image/png;base64,'+base64.b64encode(logo.read_bytes()).decode()+'">' if logo.is_file() else ''
    return """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Watchtower</title><style>
    *{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e7edf9;font:15px 'Segoe UI','Microsoft YaHei UI',sans-serif}
    main{height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(ellipse at 50% 38%,#14263f,transparent 65%)}
    section{width:460px;padding:48px;text-align:center}img{width:72px;height:72px;margin-bottom:16px}h1{font-size:30px;letter-spacing:2px;margin:0 0 12px}
    .tag{font-size:12px;letter-spacing:3px;color:#7794bd}#status{font-size:17px;margin-top:42px}#detail{color:#8fa5c4;line-height:1.8;white-space:pre-wrap;overflow-wrap:anywhere}
    .bar{height:3px;overflow:hidden;background:#1b304c;margin:28px auto;width:180px;border-radius:3px}.bar i{display:block;width:45%;height:100%;background:#67bcff;animation:slide 1.5s infinite}
    @keyframes slide{from{transform:translateX(-100%)}to{transform:translateX(330%)}}footer{color:#527093;font-size:12px;margin-top:35px}
    </style><main><section>"""+image+"""<h1>WATCHTOWER</h1><div class="tag">瞭望塔 · WINDOWS</div><div class="bar"><i></i></div>
    <p id="status">正在准备工作台</p><p id="detail">首次启动需要准备运行环境，请稍候。</p><footer>"""+DESKTOP_VERSION+""" · 本机测试版</footer></section></main></html>"""


class DesktopInstance:
    """One desktop per install directory; hold the handle for the process lifetime."""
    def __init__(self, root):
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        name = 'Local\\WatchtowerDesktop-' + hashlib.sha256(str(root).casefold().encode()).hexdigest()[:24]
        self.handle = kernel.CreateMutexW(None, False, name)
        if not self.handle: raise ctypes.WinError(ctypes.get_last_error())
        self.existing = ctypes.get_last_error() == 183
        self.kernel = kernel
        if self.existing:
            self.focus_existing(root)

    def focus_existing(self, root):
        try:
            pid = int(json.loads((root/'state/desktop-session.json').read_text())['pid'])
            kernel = self.kernel
            kernel.OpenProcess.restype = ctypes.c_void_p
            handle = kernel.OpenProcess(0x1000, False, pid)
            if not handle: return
            try:
                size = ctypes.c_ulong(32768); image = ctypes.create_unicode_buffer(size.value)
                kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
                if not kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)): return
                if Path(image.value).resolve() != desktop_directory().resolve()/'WatchtowerDesktop.exe': return
                user = ctypes.WinDLL('user32')
                user.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
                user.IsWindowVisible.argtypes = [ctypes.c_void_p]
                user.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
                user.SetForegroundWindow.argtypes = [ctypes.c_void_p]
                callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
                def focus(hwnd, _):
                    owner = ctypes.c_ulong(); user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
                    if owner.value == pid and user.IsWindowVisible(hwnd):
                        user.ShowWindow(hwnd, 9); user.SetForegroundWindow(hwnd)
                    return True
                user.EnumWindows(callback_type(focus), None)
            finally:
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]; kernel.CloseHandle(handle)
        except (OSError, ValueError, KeyError): pass

    def close(self):
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle(self.handle)


class PreviewApp:
    def __init__(self, root):
        self.root = Path(root).resolve(); self.runtime = PortableRuntime(self.root); self.workspace = 'http://'+HOST+':'+str(self.runtime.web_port)+'/'
        self.closed = threading.Event(); self.operation = threading.Lock(); self.showing_workspace = False; self.core_version = APP_VERSION; self.initial_load = True; self._checked_online = False; self._online_lock = threading.Lock()
        menu = [Menu('应用', [MenuAction('重新连接工作台', self.start), MenuSeparator(),
                 MenuAction('检查程序更新…', self.check_online_update), MenuAction('安装本地更新包…', self.import_update),
                 MenuAction('查看测试说明', self.open_records), MenuSeparator(),
                 MenuAction('停止后台并退出', self.stop), MenuAction('关闭窗口（保留后台任务）', self.close)])]
        self.window = webview.create_window('瞭望塔 Watchtower · '+DESKTOP_VERSION,
            html=loading_html(self.root), js_api=ClientBridge(self,DESKTOP_VERSION), width=1320, height=900, min_size=(960, 640), maximized=True,
            background_color='#0b1220', text_select=True, zoomable=True, menu=menu)
        self.window.events.closed += self.closed.set
        self.window.events.loaded += self.on_loaded
        atomic_json(self.root/'state/desktop-session.json', {'pid':os.getpid(), 'version':DESKTOP_VERSION, 'build':desktop_meta()['build'], 'renderer':'edgechromium'})

    def on_loaded(self):
        if self.closed.is_set(): return
        url = self.window.get_current_url() or ''
        if not url.startswith(self.workspace): return
        # HTTP 200 and NavigationCompleted do not prove the Vue route mounted.
        deadline = time.monotonic()+20
        while not self.closed.is_set() and time.monotonic() < deadline:
            try:
                if not (self.window.get_current_url() or '').startswith(self.workspace): return
                mounted = self.window.evaluate_js('Boolean(document.querySelector(".ant-layout-sider") || document.querySelector("form input[type=password]"))')
                if mounted:
                    self.showing_workspace = True
                    atomic_json(self.root/'state/desktop-window.json', {'version':DESKTOP_VERSION, 'core_version':self.core_version, 'payload_version':APP_VERSION, 'renderer':'edgechromium', 'workspace_loaded':True, 'pid':os.getpid()})
                    if not self._checked_online:
                        self._checked_online = True
                        self.check_online_update(silent=True)
                    return
            except Exception: pass
            self.closed.wait(.25)
        if not self.closed.is_set():
            self.showing_workspace = False
            logging.error('Workbench document loaded but Vue did not mount')
            self.window.load_html(loading_html(self.root))
            self.status('工作台资源未能加载', '请从顶部应用菜单重新连接工作台，后台任务继续保留。')

    def status(self, title, detail):
        if self.closed.is_set() or self.showing_workspace: return
        try:
            self.window.evaluate_js('document.getElementById("status").textContent='+json.dumps(title)+';document.getElementById("detail").textContent='+json.dumps(detail)+';')
        except Exception: pass

    def start(self):
        if not self.operation.acquire(False): return
        def worker():
            try:
                self.showing_workspace = False
                if self.initial_load:
                    self.initial_load = False
                else:
                    self.window.load_html(loading_html(self.root))
                if not self.window.events.loaded.wait(30): raise RuntimeError('桌面渲染初始化超时')
                ensure_entry(self.root,desktop_directory())
                self.status('正在启动本机后台', '准备完成后将自动进入工作台。')
                if not self.runtime.is_running(): self.runtime.start()
                deadline = time.monotonic()+240
                while not self.closed.is_set() and time.monotonic() < deadline:
                    try:
                        client = self.runtime.connect(8); break
                    except Exception:
                        self.closed.wait(2)
                else:
                    if self.closed.is_set(): return
                    raise RuntimeError('运行环境启动超时，请从应用菜单重试，或查看 state/serial.log。')
                try:
                    _, out, _ = client.exec_command('test -f /opt/watchtower-preview/ready && echo ready', timeout=10)
                    if out.read().strip() != b'ready':
                        bootstrap=desktop_directory()/'bootstrap.sh'
                        if __import__('hashlib').sha256(bootstrap.read_bytes()).hexdigest()!=desktop_meta().get('bootstrap_sha256'):raise RuntimeError('初始化脚本校验失败')
                        self.runtime.provision(client,bootstrap)
                        self.status('正在准备本机服务', '首次安装资源准备完成后将自动更新工作台。')
                        deadline = time.monotonic()+900
                        while not self.closed.is_set() and time.monotonic() < deadline:
                            _, out, _ = client.exec_command('if test -f /opt/watchtower-preview/ready; then echo ready; elif test -f /opt/watchtower-preview/error; then echo failed; fi', timeout=10)
                            state = out.read().strip()
                            if state == b'ready': break
                            if state == b'failed': raise RuntimeError('首次初始化失败，请查看后台准备记录后重试。')
                            self.closed.wait(2)
                        else:
                            if self.closed.is_set(): return
                            raise RuntimeError('本机初始化尚未完成，请稍后重新连接。')
                    self.status('正在更新本机工作台', '校验并同步当前桌面版本的界面。')
                    core_delivery.apply_to_guest(client, desktop_directory())
                    updated = apply_to_guest(client, desktop_directory())
                    if updated: self.core_version = updated['version']
                finally: client.close()
                self.status('正在加载工作台', '首次准备可能需要数分钟，后台会继续完成初始化。')
                deadline = time.monotonic()+900
                while not self.closed.is_set() and time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(self.workspace, timeout=4) as response:
                            ready = response.status == 200
                        if ready:
                            if not self.closed.is_set(): self.window.load_url(self.workspace)
                            return
                    except (OSError, TimeoutError): pass
                    self.closed.wait(2)
                if not self.closed.is_set(): raise RuntimeError('应用服务未就绪，请查看 state/serial.log 和后台初始化记录。')
            except Exception as exc:
                self.status('暂时无法进入工作台', str(exc)[:400]+'\n可使用顶部「应用 → 重新连接工作台」重试。')
                logging.exception('Desktop startup failed')
            finally: self.operation.release()
        threading.Thread(target=worker, daemon=True).start()

    def stop(self):
        if not self.window.create_confirmation_dialog('停止后台', '将停止本测试实例中的任务并释放后台资源。确认停止并退出？'): return
        if not self.operation.acquire(False): return
        try:
            self.runtime.stop(); self.close()
        except Exception as exc:
            self.window.create_confirmation_dialog('停止未完成', str(exc)[:300])
        finally: self.operation.release()

    def open_records(self):
        path = self.root/'测试说明.md'
        if path.is_file(): os.startfile(path)

    def check_online_update(self,silent=False):
        if getattr(self,'update_dialog',None) and not self.update_dialog._cancel.is_set():return
        if not self._online_lock.acquire(False):return
        def work():
            try:
                offer=online_update.check(self.root)
                if self.closed.is_set():return
                if not offer:
                    if silent:return
                    self.window.create_confirmation_dialog('程序更新', '此本机测试安装尚未配置在线发布源。可安装本地签名更新包。');return
                if not offer['available']:
                    if silent:return
                    self.window.create_confirmation_dialog('程序更新', '当前程序已是此渠道可用的最新版本。');return
                from windows_preview.update_dialog import UpdateDialog
                self.update_dialog=UpdateDialog(self,offer)
            except Exception as exc:
                if not self.closed.is_set() and not silent:self.window.create_confirmation_dialog('更新检查未完成',str(exc)[:300])
            finally:self._online_lock.release()
        threading.Thread(target=work,daemon=True).start()

    def import_update(self):
        paths=self.window.create_file_dialog(webview.FileDialog.OPEN,file_types=('Windows 更新包 (*.zip)',))
        if paths:self.launch_update(paths[0])

    def launch_update(self,bundle):
        if not self.operation.acquire(False):raise RuntimeError('程序正在准备后台，请稍后再更新')
        try:
            helper=desktop_directory()/'UpdateHelper.exe'
            if not helper.is_file():raise RuntimeError('独立更新器缺失')
            job=uuid.uuid4().hex
            subprocess.Popen([str(helper),'--root',str(self.root),'--bundle',str(bundle),'--pid',str(os.getpid()),'--job',job,'--launch'],cwd=self.root,creationflags=hidden_flags())
        except Exception:
            self.operation.release();raise
        def watch():
            try:
                while not self.closed.wait(.3):
                    try:
                        state=json.loads((self.root/'state'/('desktop-update-'+job+'.json')).read_text())
                        if state.get('phase')=='prepared':self.close();return
                        if state.get('phase')=='error':self.window.create_confirmation_dialog('更新未应用',state.get('error','更新失败'));return
                    except (OSError,ValueError):pass
            finally:self.operation.release()
        threading.Thread(target=watch,daemon=True).start()

    def close(self):
        self.closed.set(); self.window.destroy()


def health_check(root, report_path):
    """Update admission verifies a real WebView2 renderer, without touching the guest."""
    meta = desktop_meta(); validate_bundle(desktop_directory()); core_delivery.validate(desktop_directory()); report = {'ok':False, 'version':DESKTOP_VERSION, 'build':meta['build'], 'renderer':'edgechromium'}
    window = webview.create_window('Watchtower renderer check', html='<div id="health">watchtower-webview-ready</div>', hidden=True)
    finished = threading.Event()
    def verify():
        try:
            report['ok'] = meta['version'] == DESKTOP_VERSION and window.evaluate_js('document.getElementById("health").textContent') == 'watchtower-webview-ready'
            atomic_json(report_path, report)
        finally: finished.set(); window.destroy()
    window.events.loaded += verify
    def timeout():
        if not finished.wait(20):
            report['error'] = 'WebView2 initialization timed out'
            atomic_json(report_path, report); window.destroy()
    webview.start(timeout, gui='edgechromium', storage_path=str(root/'state'/('health-'+uuid.uuid4().hex)), private_mode=True)
    return 0 if report['ok'] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--health-check', action='store_true'); parser.add_argument('--report')
    parser.add_argument('--diagnostic-port', type=int, help='Opt-in local UI verification; disabled during normal launch')
    args = parser.parse_args(); root = package_root()
    protect_state(root/'state')
    logging.basicConfig(filename=str(root/'state/desktop.log'), level=logging.WARNING)
    webview.settings['ALLOW_DOWNLOADS'] = True
    webview.settings['ALLOW_FILE_URLS'] = False
    webview.settings['OPEN_EXTERNAL_LINKS_IN_BROWSER'] = False
    if args.health_check:
        if not args.report: parser.error('--report is required')
        return health_check(root, Path(args.report))
    if args.diagnostic_port:
        if not 1024 <= args.diagnostic_port <= 65535: parser.error('invalid diagnostic port')
        webview.settings['REMOTE_DEBUGGING_PORT'] = args.diagnostic_port
    instance = DesktopInstance(root)
    try:
        if instance.existing: return 0
        app = PreviewApp(root)
        webview.start(app.start, gui='edgechromium', storage_path=str(root/'state/webview'), private_mode=False)
        return 0
    finally: instance.close()


if __name__ == '__main__': raise SystemExit(main())
