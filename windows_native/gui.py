from pathlib import Path
import argparse,sys,os,ctypes,hashlib,json,threading,time
from windows_native.paths import configure

def main():
 p=argparse.ArgumentParser();p.add_argument('--root');p.add_argument('--connect-existing',action='store_true');p.add_argument('--diagnostic-port',type=int);p.add_argument('--health-check',action='store_true');p.add_argument('--safe-renderer',action='store_true');p.add_argument('--report');p.add_argument('--recover-update',action='store_true');a=p.parse_args()
 if a.recover_update:
  from windows_native.update_runner import run as recover_update
  return recover_update(configure(a.root,optional=True))
 from windows_native.startup_diagnostics import StartupDiagnostics
 candidate=a.root or (Path(sys.executable).parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[2]/'native-test')
 diagnostic=StartupDiagnostics(candidate)
 try:return run(a,diagnostic,candidate)
 except Exception as exc:
  diagnostic.failed(exc)
  if a.health_check:
   from windows_native.update_state import write
   if a.report:write(Path(a.report),{'ok':False,'phase':diagnostic.stage_name,'error_type':type(exc).__name__,'error':str(exc)[:600]})
   return 1  # A hidden installer probe must never open a blocking error dialog.
  info=diagnostic.public()
  try:
   from windows_native.diagnostic_dialog import show
   from windows_native.splash import locale
   show(diagnostic,locale=locale(candidate));return 1
  except Exception:pass
  try:
   from windows_native import splash
   text=splash.messages(candidate)['startup'];stage=text.get(info['stage'],info['stage'])
   detail=text['failureLog'].replace('{stage}',stage).replace('{path}',info['log_path']) if info['log_path'] else text['failureNoLog']
   ctypes.windll.user32.MessageBoxW(None,text['failed']+'\n'+detail,'Watchtower',0x10)
  except Exception:pass
  return 1

def run(a,diagnostic,candidate):
 from windows_native import update_runner,update_state
 from windows_native.single_instance import acquire,release
 mutex=None if a.health_check else acquire()
 if not a.health_check and mutex is None:diagnostic.complete();return 0
 diagnostic.stage('configuration',5)
 root=configure(candidate)
 from windows_native.update_recovery import required
 interrupted=required(root)
 if interrupted:update_runner.recover_launch(root);release(mutex);return 0
 update_runner.recover_progress(root)
 update_runner.cleanup_helpers(root)
 from windows_native.window_health import configure_renderer
 configure_renderer(root,safe=getattr(a,'safe_renderer',False))
 if a.health_check:
  diagnostic.stage('webview')
  from windows_native.update_state import write
  write(Path(a.report),{'ok':False,'phase':'loading_webview'})
  import webview
  from windows_native.webview_runtime import configure_runtime
  configure_runtime(webview,diagnostic)
  result={'ok':False};w=webview.create_window('Native install check',html='<div id="native">native-runtime-ok</div>',hidden=True)
  def ready():
   try:result.update(ok=w.evaluate_js('document.getElementById("native").textContent')=='native-runtime-ok',phase='complete')
   except Exception as exc:result.update(ok=False,phase='webview_script',error_type=type(exc).__name__,error=str(exc)[:400])
   write(Path(a.report),result);w.destroy()
  w.events.loaded+=ready;webview.start(gui='edgechromium',private_mode=True,storage_path=str(root/'state/health-webview'));return 0 if result['ok'] else 1
 from windows_native.guardian import install as install_guardian,display_version
 diagnostic.stage('guardian',10)
 install_guardian(root)
 from windows_native.runtime import Runtime
 diagnostic.stage('runtime',15)
 rt=Runtime(root,backend=root/'runtime/service/NativeService.exe' if getattr(sys,'frozen',False) else None);closed=threading.Event();ready=False
 diagnostic.stage('webview',20)
 import webview
 from windows_native.webview_runtime import configure_runtime
 configure_runtime(webview,diagnostic)
 # Downloads are client actions; the node package's Linux target does not restrict Windows clients.
 webview.settings['ALLOW_DOWNLOADS']=True
 if a.diagnostic_port:webview.settings['REMOTE_DEBUGGING_PORT']=a.diagnostic_port
 from windows_native import splash
 text=splash.messages(root)
 window=webview.create_window(text.get('windowTitle','瞭望塔 Watchtower · Windows 原生版')+' '+display_version((root/'app/version.txt').read_text(encoding='utf-8').strip()),html=splash.render(root),maximized=True,min_size=(1100,760),background_color='#0c1422',js_api=splash.Api(root,diagnostic=diagnostic),text_select=True)
 window.events.closed+=closed.set
 from windows_native.window_health import WindowHealth
 def interface_ready(snapshot):
  diagnostic.complete()
  update_state.write(root/'state/native-window.json',{'pid':os.getpid(),'version':(root/'app/version.txt').read_text().strip(),'mounted':True,'url':str(snapshot.get('origin',''))+str(snapshot.get('path','')),'engine':health.engine})
 health=WindowHealth(window,root,diagnostic,closed,on_ready=interface_ready);health.start()
 def start():
  try:
   def progress(stage,percent):
    diagnostic.stage(stage,percent)
    if not closed.is_set():
     def paint():
      try:window.evaluate_js('window.watchtowerStartup && window.watchtowerStartup('+json.dumps(text['startup'][stage])+','+str(percent)+')')
      except Exception:pass
     threading.Thread(target=paint,daemon=True).start()  # Backend startup must not wait for an unhealthy renderer.
   if not a.connect_existing:rt.start(progress=progress)
   if not closed.is_set():
    progress('workspace',95)
    import secrets
    health.navigating(rt.url);window.load_url(rt.url+'/?native_boot='+secrets.token_hex(8))
   failures=0;update_helper=None
   while not closed.wait(.5):
    # Native service owns its workers. A failed worker exits the service; the
    # supervisor restarts it only after the complete old Job tree has closed.
    if a.connect_existing or (root/'state/shutdown').exists():continue
    if update_helper is not None:
     if update_helper.poll() is None:continue
     update_helper=None
    from windows_native import update_runner,update_state
    from windows_native.update_chain import tick
    tick(root)
    if (root/'state/native-update-command.json').exists():
     try:
      request=update_runner.claim(root)
      if request:update_helper=update_runner.launch(root,request)
     except Exception as exc:update_state.progress(root,phase='error',msg='原生更新启动失败',error=type(exc).__name__+': '+str(exc)[:150],terminal=True)
     continue
    if rt.service is not None and rt.service.poll() is not None:
     diagnostic.stage('service',60)
     failures+=1
     if failures>3:raise RuntimeError('Native service repeatedly exited; inspect state/service.log')
     from sentinel_platform.core import process_control
     process_control.close(rt.service)
     rt.start_service()
  except Exception as e:
   health.fail(e,stage=diagnostic.stage_name)
   if not closed.is_set():
    threading.Thread(target=lambda:window.load_html(splash.render(root,failed=True,diagnostic=diagnostic.public())),daemon=True).start()
 def loaded():
  health.splash_loaded=True;health.attach()
  # Preferences are optional; a failed or late JS bridge cannot gate readiness.
  try:
   from windows_native.browser_preferences import apply
   apply(window,root)
  except Exception as exc:health.note('browser_preferences',type(exc).__name__+': '+str(exc)[:200])
 window.events.shown+=health.attach
 window.events.loaded+=loaded
 try:webview.start(start,gui='edgechromium',storage_path=str(root/'state/webview'),private_mode=False)
 finally:
  if a.connect_existing:(root/'state/host-stop').touch()
  else:rt.stop()
  release(mutex)
 return 0
if __name__=='__main__':raise SystemExit(main())
