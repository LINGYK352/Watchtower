"""Nonblocking WebView2 probes independent of pywebview's one-shot loaded bridge."""
from pathlib import Path
from urllib.parse import urlsplit
import json,threading,time

BOOT_SCRIPT=r'''(()=>{if(window.__wtNativeBoot)return;const errors=[];window.__wtNativeBoot={errors};
const path=s=>{try{const u=new URL(s,location.href);return u.origin+u.pathname}catch{return ''}};
const push=s=>{if(errors.length<6)errors.push(String(s).slice(0,240))};
addEventListener('error',e=>{const t=e.target;if(t&&t!==window&&(t.tagName==='SCRIPT'||t.tagName==='LINK'))push('resource: '+path(t.src||t.href));else if(e.message)push(e.message)},true);
addEventListener('unhandledrejection',e=>push(e.reason?.message||String(e.reason)));
})()'''
PROBE_SCRIPT=r'''(()=>{const a=document.getElementById('app'),s=a?getComputedStyle(a):null,r=a?a.getBoundingClientRect():null;
return {origin:location.origin,path:location.pathname,state:document.readyState,
ready:!!(window.__watchtowerAppReady!==false&&a&&a.childElementCount&&a.innerText.trim()&&s.display!=='none'&&s.visibility!=='hidden'&&r.width&&r.height),
app_children:a?.childElementCount||0,app_text:a?.innerText?.length||0,errors:window.__wtNativeBoot?.errors||[]}})()'''

class NativeMonitor:
    def __init__(self,health):
        self.health=health;self.view=None;self.bound=False;self.initialization_hooked=False;self.binding=False;self.pending=None;self.generation=0;self.lock=threading.RLock();self.handlers=[];self.last_completed=float("-inf");self.last_review=float("-inf");self.bundle=None;self.resource_noted=False
    def same_origin(self,value):
        try:return bool(self.health.url) and urlsplit(value).scheme==urlsplit(self.health.url).scheme and urlsplit(value).netloc==urlsplit(self.health.url).netloc
        except (TypeError,ValueError):return False
    def attach(self):
        if self.bound or self.binding or self.health.closed.is_set():return
        native=getattr(self.health.window,'native',None)
        if native is None:return
        import System
        self.binding=True
        def bind():
            try:
                self.view=native.browser.webview
                if not self.initialization_hooked:
                    self.view.CoreWebView2InitializationCompleted+=self.initialized;self.handlers.append(self.initialized);self.initialization_hooked=True
                if self.view.CoreWebView2 is not None:self.bind_core(self.view.CoreWebView2)
            except Exception as exc:self.health.note('webview_bind',str(exc))
            finally:self.binding=False
        try:native.BeginInvoke(System.Action(bind))
        except Exception:self.binding=False
    def initialized(self,sender,args):
        if not args.IsSuccess:
            self.health.fail(RuntimeError('WebView2初始化失败 / WebView2 initialization failed: '+str(args.InitializationException)[:350]),stage='webview');return
        self.bind_core(sender.CoreWebView2)
    def bind_core(self,core):
        if self.bound:return
        self.bound=True;self.health.hooks=True
        info={}
        try:
            import psutil
            info={'version':str(core.Environment.BrowserVersionString),'executable':psutil.Process(int(core.BrowserProcessId)).exe(),'profile':str(core.Environment.UserDataFolder)}
        except Exception as exc:info['probe_error']=type(exc).__name__
        self.health.engine=info;self.health.note('webview_runtime',json.dumps(info,ensure_ascii=False))
        from windows_native.ui_resources import Bundle
        try:
            self.bundle=Bundle(self.health.root)
            self.health.note('program_identity',json.dumps(self.bundle.identity(),ensure_ascii=False))
        except Exception as exc:
            self.health.fail(RuntimeError('界面安装收据无法读取，请修复安装 / UI installation receipt is unreadable: '+type(exc).__name__),stage='interface');return
        from Microsoft.Web.WebView2.Core import CoreWebView2WebResourceContext
        core.AddWebResourceRequestedFilter('*',CoreWebView2WebResourceContext.All)
        core.WebResourceRequested+=self.resource_requested
        # This dedicated local shell must not reuse rejected module MIME headers
        # from an earlier installation. It does not change the system browser.
        try:core.CallDevToolsProtocolMethodAsync('Network.setCacheDisabled','{"cacheDisabled":true}')
        except Exception as exc:self.health.note('ui_cache_control_unavailable',type(exc).__name__)
        self.requests={};self.network_receivers=[]
        try:
            for event,handler in [('Network.requestWillBeSent',self.network_request),('Network.loadingFailed',self.network_failure)]:
                receiver=core.GetDevToolsProtocolEventReceiver(event);receiver.DevToolsProtocolEventReceived+=handler;self.network_receivers.append(receiver);self.handlers.append(handler)
            core.CallDevToolsProtocolMethodAsync('Network.enable','{}')
        except Exception as exc:self.health.note('network_diagnostics_unavailable',type(exc).__name__)
        core.ProcessFailed+=self.process_failed;core.NavigationStarting+=self.navigation_start;core.NavigationCompleted+=self.navigation_completed;core.WebResourceResponseReceived+=self.resource_received;core.WebMessageReceived+=self.web_message
        self.handlers.extend([self.resource_requested,self.process_failed,self.navigation_start,self.navigation_completed,self.resource_received,self.web_message])
        core.AddScriptToExecuteOnDocumentCreatedAsync(BOOT_SCRIPT);core.ExecuteScriptAsync(BOOT_SCRIPT)
    def resource_requested(self,sender,args):
        uri=str(args.Request.Uri)
        if not self.same_origin(uri):return
        path=urlsplit(uri).path
        try:
            value=self.bundle.respond(path,str(args.Request.Method))
            if value is None:return
            status,headers,data=value
            failure=self.bundle.last_failure
            import System
            from System.IO import MemoryStream
            # The COM response owns the managed stream until WebView finishes
            # reading it. Do not close it on ResponseReceived (headers only).
            stream=MemoryStream(System.Array[System.Byte](data))
            args.Response=sender.Environment.CreateWebResourceResponse(stream,status,'OK' if status==200 else 'UI resource failure','\r\n'.join(k+': '+v for k,v in headers.items()))
            if failure:
                detail={k:v for k,v in failure.items() if k not in ('expected_sha256','actual_sha256')}
                self.health.note('ui_resource_failure',json.dumps(detail,ensure_ascii=False,separators=(',',':')))
                for key,event in [('expected_sha256','ui_resource_expected'),('actual_sha256','ui_resource_actual')]:
                    if key in failure:self.health.note(event,json.dumps({'path':failure['path'],key:failure[key]},ensure_ascii=False,separators=(',',':')))
                if path.endswith(('.js','.css')) or path in ('/','/index.html'):
                    try:raise RuntimeError('界面资源失败 / UI resource failure: '+path[:180]+'; HTTP '+str(status)+'; '+failure['reason'])
                    except RuntimeError as exc:self.health.fail(exc,stage='interface')
            if status!=200 or (path.endswith('.js') and not self.resource_noted):
                self.resource_noted=True;self.health.note('native_resource','HTTP '+str(status)+' '+path[:180]+'; '+headers['Content-Type']+'; '+headers['X-Watchtower-Resource-Status'])
        except Exception as exc:
            self.health.note('native_resource_error',type(exc).__name__+': '+str(exc)[:240])
    def network_request(self,sender,args):
        try:
            value=json.loads(str(args.ParameterObjectAsJson));uri=value.get('request',{}).get('url','');path=urlsplit(uri).path
            if self.same_origin(uri) and (path.startswith('/assets/') or value.get('type')=='Document'):
                if len(self.requests)>=128:self.requests.pop(next(iter(self.requests)))
                self.requests[value['requestId']]={'path':path[:180],'resource_type':value.get('type'),'started':time.monotonic()}
        except Exception:pass
    def network_failure(self,sender,args):
        try:
            value=json.loads(str(args.ParameterObjectAsJson));request=self.requests.pop(value.get('requestId'),None)
            if request:
                detail={k:v for k,v in request.items() if k!='started'};detail.update(error=value.get('errorText'),blocked_reason=value.get('blockedReason'),canceled=value.get('canceled',False),elapsed_ms=round((time.monotonic()-request['started'])*1000))
                self.health.note('webview_network_failure',json.dumps(detail,ensure_ascii=False,separators=(',',':')))
                if not detail['canceled'] and not self.health.ready.is_set() and request.get('resource_type') in ('Script','Stylesheet'):
                    try:raise RuntimeError('界面请求失败 / UI request failed: '+request['path']+'; '+str(detail['error'])+'; blocked='+str(detail['blocked_reason']))
                    except RuntimeError as exc:self.health.fail(exc,stage='interface')
        except Exception:pass
    def navigation_start(self,sender,args):
        if not self.same_origin(str(args.Uri)):return
        with self.lock:self.generation+=1;self.pending=None
        if self.health.ready.is_set():
            self.health.ready.clear();self.health.reloaded=False;self.health.deadline=self.health.clock()+45
    def navigation_completed(self,sender,args):
        self.health.note('webview_navigation','success='+str(args.IsSuccess)+'; status='+str(args.WebErrorStatus))
        if not args.IsSuccess and str(args.WebErrorStatus) not in ('OperationCanceled','Unknown'):
            self.health.navigation_failed(str(args.WebErrorStatus))
    def process_failed(self,sender,args):
        kind=str(args.ProcessFailedKind);self.health.note('webview_process',kind)
        if kind in ('RenderProcessExited','BrowserProcessExited','RenderProcessUnresponsive'):self.health.fail(RuntimeError('WebView2界面进程异常：'+kind),software=True)
        elif kind=='GpuProcessExited':
            from windows_native import update_state
            try:update_state.write(self.health.root/'state/native-renderer.json',{'software':True,'reason':'gpu_process_exited'})
            except OSError:pass
    def resource_received(self,sender,args):
        try:
            uri=str(args.Request.Uri);status=int(args.Response.StatusCode);path=urlsplit(uri).path
            if status>=400 and self.same_origin(uri) and (path.endswith(('.js','.css')) or path=='/'):
                headers=args.Response.Headers;detail={'path':path[:180],'status':status}
                for key in ('Content-Type','X-Watchtower-Resource-Status','X-Watchtower-Resource-Source'):
                    if headers.Contains(key):detail[key]=str(headers.GetHeader(key))[:120]
                self.health.note('webview_resource',json.dumps(detail,ensure_ascii=False,separators=(',',':')))
        except Exception:pass
    def web_message(self,sender,args):
        # The native channel is independent of pywebview's JS bridge. It can
        # only open a consent-based diagnostic review, never upload by itself.
        try:
            if not self.same_origin(str(args.Source)):return
            raw=str(args.WebMessageAsJson)
            if len(raw)>4096:return
            value=json.loads(raw)
            if not isinstance(value,dict) or value.get('type')!='watchtower-startup-diagnostic' or value.get('action')!='review':return
            if self.health.ready.is_set() or self.health.clock()-self.last_review<2:return
            from windows_native.diagnostic_report import redact
            reason=redact(str(value.get('reason','Interface resource failed'))[:600])
            detail=redact(str(value.get('detail',''))[:900])
            self.last_review=self.health.clock()
            self.health.note('interface_resource_detail',detail)
            self.health.diagnostic.stage('interface')
            self.health.diagnostic.failed(RuntimeError(reason+(': '+detail if detail else '')))
            self.health.review()
        except Exception as exc:self.health.note('interface_report_error',str(exc))
    def probe(self):
        if not self.bound or not self.health.url or self.health.ready.is_set() or self.health.reported.is_set():return
        with self.lock:
            if self.pending is not None:return
            token=(self.generation,time.monotonic());self.pending=token
        import System
        from System.Threading.Tasks import Task
        def complete(task):
            try:
                if task.IsFaulted or task.IsCanceled:return
                value=json.loads(str(task.Result))
                if isinstance(value,str):value=json.loads(value)
                with self.lock:
                    if token!=self.pending or token[0]!=self.generation:return
                if isinstance(value,dict) and self.same_origin(value.get('origin','')):self.health.observe(value)
            except Exception as exc:self.health.note('webview_probe',type(exc).__name__+': '+str(exc)[:180])
            finally:
                with self.lock:
                    if self.pending==token:self.pending=None;self.last_completed=self.health.clock()
        def query():
            try:self.view.CoreWebView2.ExecuteScriptAsync(PROBE_SCRIPT).ContinueWith(System.Action[Task[System.String]](complete))
            except Exception as exc:
                with self.lock:
                    if self.pending==token:self.pending=None
                self.health.note('webview_probe',str(exc))
        try:self.view.BeginInvoke(System.Action(query))
        except Exception:
            with self.lock:
                if self.pending==token:self.pending=None
    def reload(self,target):
        import System
        from System.Threading.Tasks import Task
        def navigate():
            try:
                core=self.view.CoreWebView2
                def cleared(task):
                    # Completion returns to the UI dispatcher; no Result/Wait on that thread.
                    try:self.view.BeginInvoke(System.Action(lambda:core.Navigate(target)))
                    except Exception as exc:self.health.fail(exc)
                core.CallDevToolsProtocolMethodAsync('Network.clearBrowserCache','{}').ContinueWith(System.Action[Task[System.String]](cleared))
            except Exception:
                try:self.view.CoreWebView2.Navigate(target)
                except Exception as exc:self.health.fail(exc)
        self.view.BeginInvoke(System.Action(navigate))
