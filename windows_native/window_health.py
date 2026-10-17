"""Bounded shell recovery and native diagnostics, independent of a healthy webpage."""
from pathlib import Path
import os,json,time,threading,secrets
from windows_native import update_state
def configure_renderer(root,safe=False):
    try:
        preference=update_state.read(Path(root)/'state/native-renderer.json');safe=safe or isinstance(preference,dict) and preference.get('software') is True
    except (OSError,ValueError):pass
    if safe:
        args=os.environ.get('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS','')
        if '--disable-gpu' not in args.split():os.environ['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS']=(args+' --disable-gpu').strip()
    return safe
class WindowHealth:
    def __init__(self,window,root,diagnostic,closed,alert=None,clock=time.monotonic,on_ready=None):
        self.window=window;self.root=Path(root);self.diagnostic=diagnostic;self.closed=closed;self.clock=clock;self.url='';self.deadline=clock()+90;self.ready=threading.Event();self.reported=threading.Event();self.reloaded=False;self.lock=threading.RLock();self.alert=alert;self.hooks=False;self.splash_loaded=False;self.monitor=None;self.on_ready=on_ready;self.engine={};self.snapshot={};self.last_note={};self.dialog_lock=threading.Lock()
    def start(self):threading.Thread(target=self._watch,daemon=True,name='watchtower-window-health').start()
    def navigating(self,url):
        with self.lock:self.url=url.rstrip('/');self.deadline=self.clock()+45;self.ready.clear()
    def mounted(self):
        with self.lock:
            if self.closed.is_set() or self.reported.is_set() or self.ready.is_set():return
            self.ready.set()
        if self.on_ready:
            def notify():
                try:self.on_ready(self.snapshot)
                except Exception as exc:self.note('interface_ready_record',str(exc))
            threading.Thread(target=notify,daemon=True).start()
    def note(self,event,message):
        from windows_native.startup_diagnostics import redact
        message=redact(message)
        if self.last_note.get(event)==message:return
        self.last_note[event]=message
        self.diagnostic._write({'event':event,'message':message})
    def observe(self,value):
        self.snapshot=value
        if value.get('ready') is True:self.mounted()
    def navigation_failed(self,status):
        state=update_state.get_progress(self.root)
        try:restarting=state.get('phase') in ('applying','restarting') and time.time()-float(state.get('ts',0))<90
        except (TypeError,ValueError):restarting=False
        if restarting:self.ready.clear();self.deadline=self.clock()+30;return
        self.note('interface_navigation_failed',status)

    def fail(self,error,software=False,stage='interface'):
        with self.lock:
            if self.reported.is_set() or self.closed.is_set():return
            self.reported.set()
        if software:
            try:update_state.write(self.root/'state/native-renderer.json',{'software':True,'reason':'webview_process_failure'})
            except (OSError,ValueError):pass  # A diagnostic must still appear on a read-only/damaged installation.
        self.diagnostic.stage(stage);self.diagnostic.failed(error)
        self.review()
    def review(self):
        if self.closed.is_set() or not self.dialog_lock.acquire(blocking=False):return
        def notify():
            try:
                if self.closed.is_set():return
                if self.alert:self.alert(self.diagnostic);return
                from windows_native.diagnostic_dialog import show
                from windows_native.splash import locale
                show(self.diagnostic,locale=locale(self.root))
            except Exception:
                import ctypes
                ctypes.windll.user32.MessageBoxW(None,'Watchtower界面未能加载。错误已记录，请重新打开或使用完整安装器修复；账号与资料未删除。','Watchtower · 界面加载失败',0x10|0x10000)
            finally:self.dialog_lock.release()
        threading.Thread(target=notify,daemon=True,name='watchtower-native-diagnostic').start()
    def tick(self):
        if self.closed.is_set() or self.reported.is_set() or self.ready.is_set() or self.clock()<self.deadline:return
        if not self.url and self.splash_loaded:return  # Backend startup owns its own deadlines; a visible splash is healthy.
        with self.lock:
            if self.closed.is_set() or self.reported.is_set() or self.ready.is_set():return
            # Give the final asynchronous UI probe a bounded two seconds at the
            # exact deadline. A newly queued probe must not race its own result.
            if self.monitor and self.monitor.bound and self.monitor.last_completed<self.deadline and self.clock()-self.deadline<2:return
            if self.url and not self.reloaded:
                self.reloaded=True;self.deadline=self.clock()+30;target=self.url+'/?native_reload='+secrets.token_hex(6)
                self.diagnostic.stage('interface_reload')
                def reload():
                    try:
                        if self.monitor and self.monitor.bound:self.monitor.reload(target)
                        else:self.window.load_url(target)
                    except Exception as exc:self.fail(exc)
                threading.Thread(target=reload,daemon=True,name='watchtower-ui-reload').start();return
            self.note('interface_state',json.dumps({'engine':self.engine,'page':self.snapshot},ensure_ascii=False))
            self.fail(RuntimeError('工作台界面未完成加载，已尝试自动重载并启用下次启动的兼容显示。可重新打开或使用完整安装器修复，原资料保留 / Workspace interface did not become ready after bounded reload'),software=True)
    def _watch(self):
        while not self.closed.wait(.5):
            try:
                self.attach()
                if self.monitor:self.monitor.probe()
            except Exception as exc:self.note('webview_monitor',type(exc).__name__+': '+str(exc)[:200])
            self.tick()
    def attach(self):
        if self.closed.is_set():return
        if self.monitor is None:
            from windows_native.native_webview_monitor import NativeMonitor
            self.monitor=NativeMonitor(self)
        self.monitor.attach()
