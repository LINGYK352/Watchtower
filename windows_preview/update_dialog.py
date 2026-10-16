"""A trusted, isolated update window. Its bridge accepts no paths or commands."""
import json,threading
import webview
from windows_preview.online_update import fetch

class UpdateDialog:
    def __init__(self,app,offer):
        self._app=app;self._offer=offer;self._cancel=threading.Event();self._lock=threading.Lock();self._started=False
        target=offer['release']['target']
        html='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>Watchtower 程序更新</title><style>body{margin:0;padding:36px;background:#101b2b;color:#e8f1ff;font:15px "Segoe UI","Microsoft YaHei UI",sans-serif}h2{font-size:24px}p{color:#9bb0d0;line-height:1.7}button{border:0;border-radius:8px;padding:12px 22px;color:white;background:#187cec;margin:14px 12px 0 0;cursor:pointer}#bar{height:5px;background:#243a58;margin:24px 0}#fill{height:100%;width:0;background:#48c9ff}</style><h2>有新的程序版本</h2><p id="version"></p><p>更新将在后台校验签名和文件。程序窗口会重新打开，本机后台与数据继续保留。</p><div id="bar"><div id="fill"></div></div><p id="status">可以开始下载并安装。</p><button id="install" disabled onclick="this.disabled=true;window.pywebview.api.install()">下载并安装</button><button onclick="window.pywebview.api.cancel()">取消</button><script>window.addEventListener("pywebviewready",()=>document.getElementById("install").disabled=false)</script></html>'
        self._window=webview.create_window('Watchtower 程序更新',html=html,js_api=self,width=620,height=390,min_size=(560,350),background_color='#101b2b')
        self._window.events.closed += self._cancel.set
        self._window.events.loaded += lambda:self._window.evaluate_js('document.getElementById("version").textContent='+json.dumps('当前 '+offer['current']+' → '+target))
    def install(self):
        with self._lock:
            if self._started:return
            self._started=True
        def work():
            try:
                def progress(done,size):
                    if self._cancel.is_set():return
                    value=round(done*100/size)
                    self._window.evaluate_js('document.getElementById("fill").style.width="'+str(value)+'%";document.getElementById("status").textContent='+json.dumps('正在下载 '+str(value)+'%'))
                bundle=fetch(self._app.root,self._offer,progress,self._cancel)
                if self._cancel.is_set():return
                self._window.evaluate_js('document.getElementById("status").textContent="下载校验完成，正在应用更新…"')
                self._app.launch_update(bundle)
            except Exception as exc:
                if not self._cancel.is_set():self._window.evaluate_js('document.getElementById("status").textContent='+json.dumps(str(exc)[:250]))
                with self._lock:self._started=False
                if not self._cancel.is_set():self._window.evaluate_js('document.getElementById("install").disabled=false')
        threading.Thread(target=work,daemon=True).start()
    def cancel(self):
        self._cancel.set();self._window.destroy()
