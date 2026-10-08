"""One owned browser process serves API and all native workers over loopback RPC."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.request import Request,urlopen
import json,threading,time,hmac

def client(root):
    settings=json.loads((Path(root)/'state/runtime.json').read_text(encoding='utf-8'))
    url='http://127.0.0.1:'+str(settings['browser_port'])+'/browser'
    def call(action,sid,payload):
        data=json.dumps({'action':action,'session_id':sid,'payload':payload},ensure_ascii=False).encode('utf-8')
        request=Request(url,data=data,headers={'Content-Type':'application/json','X-Native-Control':settings['control_token']})
        try:
            with urlopen(request,timeout=100) as response:return json.load(response)
        except Exception as exc:return {'error':'Native browser service unavailable: '+type(exc).__name__}
    return call

def install_client(root):
    from sentinel_platform.modules.ai_pentest import _browser_session
    _browser_session.install_transport(client(root))

def serve(root,on_ready=None):
    root=Path(root);settings=json.loads((root/'state/runtime.json').read_text(encoding='utf-8'))
    from sentinel_platform.modules.ai_pentest import _browser_session as browser
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def reply(self,status,payload):
            data=json.dumps(payload,ensure_ascii=False).encode('utf-8');self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def do_POST(self):
            if self.path!='/browser' or not hmac.compare_digest(self.headers.get('X-Native-Control',''),settings['control_token']):return self.reply(403,{'error':'Control authentication required'})
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=4*1024**2:raise ValueError('Invalid browser command size')
                body=json.loads(self.rfile.read(length));action=body['action'];sid=body.get('session_id','');payload=body.get('payload') or {}
                if action=='open':result=browser.open_session(sid,**payload)
                elif action=='operation':result=browser.op_session(sid,payload['op'],payload.get('args'))
                elif action=='state':result=browser.session_state(sid)
                elif action=='close':result=browser.close_session(sid,**payload)
                elif action=='close_all':browser.close_all();result={'ok':True}
                elif action=='ready':result={'ok':True}
                else:raise ValueError('Unknown browser operation')
                self.reply(200,result)
            except (ValueError,KeyError,TypeError):self.reply(400,{'error':'Invalid browser operation'})
            except Exception as exc:self.reply(500,{'error':type(exc).__name__})
    server=ThreadingHTTPServer(('127.0.0.1',settings['browser_port']),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        if on_ready:on_ready()
        while not (root/'state/shutdown').exists():time.sleep(.2)
    finally:
        browser.close_all();server.shutdown();server.server_close()

def screenshot(root,url,output,timeout):
    from pathlib import Path
    from playwright.sync_api import sync_playwright
    from sentinel_platform.core.browser_runtime import executable
    from sentinel_platform.core import image_dir
    target=Path(output).resolve();target.relative_to(Path(image_dir()).resolve())
    if not url.startswith(('https://','http://')):raise ValueError('Screenshot requires HTTP(S)')
    target.parent.mkdir(parents=True,exist_ok=True)
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=executable(),headless=True)
        try:
            page=browser.new_page(viewport={'width':1440,'height':900},ignore_https_errors=True)
            page.goto(url,wait_until='domcontentloaded',timeout=timeout*1000);page.wait_for_timeout(1500);page.screenshot(path=str(target))
        finally:browser.close()
