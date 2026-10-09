from pathlib import Path
import argparse,sys,os,ctypes,hashlib,json,threading,time
from windows_native.paths import configure

def main():
 p=argparse.ArgumentParser();p.add_argument('--root');p.add_argument('--connect-existing',action='store_true');p.add_argument('--diagnostic-port',type=int);p.add_argument('--health-check',action='store_true');p.add_argument('--report');a=p.parse_args()
 from windows_native import update_runner,update_state
 from windows_native.single_instance import acquire,release
 mutex=None if a.health_check else acquire()
 if not a.health_check and mutex is None:return 0
 root=configure(a.root or (Path(sys.executable).parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[2]/'native-test'))
 try:
  journal=update_state.read(root/'state/native-update-journal.json');interrupted=journal.get('phase')=='committing'
  if interrupted:
   import psutil
   try:interrupted=Path(psutil.Process(journal['owner_pid']).exe()).resolve()!=Path(journal['helper_exe']).resolve()
   except (psutil.Error,KeyError):pass
 except (OSError,ValueError):interrupted=False
 if interrupted:update_runner.recover_launch(root);release(mutex);return 0
 update_runner.recover_progress(root)
 update_runner.cleanup_helpers(root)
 if a.health_check:
  import webview
  result={'ok':False};w=webview.create_window('Native install check',html='<div id="native">native-runtime-ok</div>',hidden=True)
  def ready():
   result['ok']=w.evaluate_js('document.getElementById("native").textContent')=='native-runtime-ok';Path(a.report).write_text(json.dumps(result),encoding='utf-8');w.destroy()
  w.events.loaded+=ready;webview.start(gui='edgechromium',private_mode=True,storage_path=str(root/'state/health-webview'));return 0 if result['ok'] else 1
 from windows_native.guardian import install as install_guardian
 install_guardian(root)
 from windows_native.runtime import Runtime
 import webview
 rt=Runtime(root,backend=root/'runtime/service/NativeService.exe' if getattr(sys,'frozen',False) else None);closed=threading.Event();ready=False
 if a.diagnostic_port:webview.settings['REMOTE_DEBUGGING_PORT']=a.diagnostic_port
 from windows_native import splash
 text=splash.messages(root)
 window=webview.create_window(text.get('windowTitle','瞭望塔 Watchtower · Windows 原生版')+' '+(root/'app/version.txt').read_text(encoding='utf-8').strip(),html=splash.render(root),maximized=True,min_size=(1100,760),background_color='#0c1422',js_api=splash.Api(root),text_select=True)
 window.events.closed+=closed.set
 def start():
  try:
   def progress(stage,percent):
    if not closed.is_set():window.evaluate_js('window.watchtowerStartup && window.watchtowerStartup('+json.dumps(text['startup'][stage])+','+str(percent)+')')
   if not a.connect_existing:rt.start(progress=progress)
   if not closed.is_set():
    progress('workspace',95)
    window.load_url(rt.url+'/')
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
     failures+=1
     if failures>3:raise RuntimeError('Native service repeatedly exited; inspect state/service.log')
     from sentinel_platform.core import process_control
     process_control.close(rt.service)
     rt.start_service()
  except Exception as e:
   if not closed.is_set():window.load_html(splash.render(root,failed=True))
 def mounted():
  if not (window.get_current_url() or '').startswith(rt.url+'/'):return
  try:
   from windows_native.browser_preferences import apply
   apply(window,root)
  except Exception as exc:
   update_state.write(root/'state/browser-preferences-error.json',{'error':type(exc).__name__,'details':str(exc)[:200]})
  for _ in range(80):
   if closed.is_set():return
   if window.evaluate_js('Boolean(document.querySelector(".ant-layout-sider") || document.querySelector("form input[type=password]"))'):
    update_state.write(root/'state/native-window.json',{'pid':os.getpid(),'version':(root/'app/version.txt').read_text().strip(),'mounted':True,'url':window.get_current_url()});return
   closed.wait(.25)
 window.events.loaded+=mounted
 try:webview.start(start,gui='edgechromium',storage_path=str(root/'state/webview'),private_mode=False)
 finally:
  if a.connect_existing:(root/'state/host-stop').touch()
  else:rt.stop()
  release(mutex)
 return 0
if __name__=='__main__':raise SystemExit(main())
