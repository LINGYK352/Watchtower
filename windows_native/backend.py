from pathlib import Path
import argparse,os,sys,json,time,uuid,threading,subprocess
from windows_native.paths import configure

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--boot',required=True);p.add_argument('--worker',action='store_true');p.add_argument('--scheduler',action='store_true');p.add_argument('--browser-service',action='store_true');p.add_argument('--browser-cli',choices=['probe','screenshot']);p.add_argument('--url');p.add_argument('--image');p.add_argument('--browser-timeout',type=int,default=30);p.add_argument('--qa-tree',action='store_true');p.add_argument('--qa-sleep',action='store_true');p.add_argument('--probe-core');p.add_argument('--probe-runtime');p.add_argument('--update-request');p.add_argument('--recover-update',action='store_true');p.add_argument('--report');a=p.parse_args();root=configure(a.root,core=a.probe_core,optional=True,runtime=a.probe_runtime);os.environ['WATCHTOWER_NATIVE_PREVIEW']='1'
 if a.update_request:
  from windows_native.update_runner import run
  return run(root,a.update_request)
 if a.recover_update:
  from windows_native.update_runner import run
  return run(root)
 if a.browser_cli:
  if a.browser_cli=='probe':
   from sentinel_platform.modules.ai_pentest import _browser
   return 0 if _browser.available() else 1
  from windows_native.browser_service import screenshot
  screenshot(root,a.url,a.image,a.browser_timeout);return 0
 if a.qa_tree or a.qa_sleep:
  import yaml
  if not yaml.safe_load((root/'state/config.yaml').read_text(encoding='utf-8'))['NATIVE']['TEST']:raise RuntimeError('QA process mode unavailable')
  if a.qa_tree:
   child=subprocess.Popen([sys.executable,'--root',str(root),'--boot',a.boot,'--qa-sleep'],creationflags=subprocess.CREATE_NO_WINDOW)
   (root/'state/qa-child.pid').write_text(str(child.pid))
  time.sleep(60);return 0
 from sentinel_platform.core import get_repo
 from sentinel_platform import bootstrap
 from sentinel_platform.modules.kernel import orchestration as tasks
 from sentinel_platform.core import process_control as process
 from windows_native.dispatch import deliver,consume,recover
 from windows_native.extension_host import run as native_extension
 from sentinel_platform.modules.ai_pentest._extension_runtime import install_native_executor
 install_native_executor(native_extension)
 bootstrap.bootstrap(with_indexes=False);tasks.set_delivery(deliver)
 from windows_native.browser_service import serve as serve_browsers,install_client
 boot_version=(root/'app/version.txt').read_text(encoding='utf-8').strip()
 if a.browser_service:serve_browsers(root);return 0
 if a.probe_core:
  from sentinel_platform.router import create_app
  app=create_app();get_repo()._db().command('ping')
  Path(a.report).write_text(json.dumps({'ok':len(list(app.url_map.iter_rules()))>=330,'core_version':(Path(a.probe_core)/'version.txt').read_text().strip()}),encoding='utf-8');return 0
 install_client(root)
 if a.worker:
  # QA handler is loaded only from this deliberately isolated test runtime.
  from windows_native.qa_fixture import register
  register(root)
  consume(root,a.boot)
  return 0
 if a.scheduler:
  from sentinel_platform import scheduler
  interval=max(1,scheduler._tick_seconds())
  while not (root/'state/shutdown').exists():
   scheduler.tick()
   for _ in range(interval*4):
    if (root/'state/shutdown').exists():break
    time.sleep(.25)
  return 0
 # All previous workers belong to the closed, owned supervisor tree. Preserve stop intent.
 recover(a.boot)
 from sentinel_platform.modules.about import _updater
 _updater.PROGRESS_FILE=str(root/'state/core-update-progress.json')
 from windows_native import update_state
 app=bootstrap.create_app();settings=update_state.read(root/'state/runtime.json')
 from flask import request,send_from_directory,abort,jsonify
 from windows_native.update_api import install as install_update_api
 install_update_api(app,root)
 @app.route('/__native_ready')
 def ready():
  if request.headers.get('X-Native-Control')!=settings['control_token']:abort(403)
  get_repo()._db().command('ping');return jsonify(ready=bool(children) and all(child.poll() is None for child in children),version=boot_version,route_count=len(list(app.url_map.iter_rules())))
 @app.route('/',defaults={'path':''})
 @app.route('/<path:path>')
 def frontend(path):
  if path.startswith(('api/','__native')):abort(404)
  folder=root/'app/docker/frontend';candidate=(folder/path).resolve()
  try:candidate.relative_to(folder.resolve())
  except ValueError:abort(404)
  return send_from_directory(folder,path if path and candidate.is_file() else 'index.html')
 from waitress import create_server
 server=create_server(app,host='127.0.0.1',port=settings['web_port'],threads=12)
 worker_command=[sys.executable,'--root',str(root),'--boot',a.boot,'--worker'] if getattr(sys,'frozen',False) else [sys.executable,'-m','windows_native.backend','--root',str(root),'--boot',a.boot,'--worker']
 from sentinel_platform.core import get_config
 concurrency=int(get_config().section('NATIVE','WORKERS',default=4) or 4)
 if not 1<=concurrency<=32:raise ValueError('Invalid native worker count')
 children=[]
 browser_command=[sys.executable,'--root',str(root),'--boot',a.boot,'--browser-service'] if getattr(sys,'frozen',False) else [sys.executable,'-m','windows_native.backend','--root',str(root),'--boot',a.boot,'--browser-service']
 with (root/'state/browser-service.log').open('ab') as log:children.append(process.popen(browser_command,stdout=log,stderr=log))
 from windows_native.browser_service import client as browser_client
 for attempt in range(100):
  if browser_client(root)('ready','',{}).get('ok'):break
  if children[0].poll() is not None:raise RuntimeError('Native browser service exited')
  time.sleep(.1)
 else:raise RuntimeError('Native browser service did not start')
 for index in range(concurrency):
  with (root/'state'/('worker-'+str(index)+'.log')).open('ab') as log:children.append(process.popen(worker_command,stdout=log,stderr=log))
 scheduler_command=[sys.executable,'--root',str(root),'--boot',a.boot,'--scheduler'] if getattr(sys,'frozen',False) else [sys.executable,'-m','windows_native.backend','--root',str(root),'--boot',a.boot,'--scheduler']
 with (root/'state/scheduler.log').open('ab') as log:children.append(process.popen(scheduler_command,stdout=log,stderr=log))
 threading.Thread(target=server.run,daemon=True).start()
 try:
  while not (root/'state/shutdown').exists():
   if any(child.poll() is not None for child in children):raise RuntimeError('Native worker or scheduler exited')
   time.sleep(.25)
 finally:
  server.close()
  for child in children:
   try:child.wait(timeout=5)
   except subprocess.TimeoutExpired:process.terminate_tree(child)
   process.close(child)
 return 0
if __name__=='__main__':raise SystemExit(main())
