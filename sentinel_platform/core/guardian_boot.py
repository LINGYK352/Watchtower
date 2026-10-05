"""Signed persistent updater import hook; executed through a read-only .pth."""
from pathlib import Path
import hashlib,importlib.abc,importlib.machinery,importlib.util,json,os,sys,time
HOME=Path(__file__).resolve().parent.parent
ROOT=HOME.parents[1]
pointer=json.loads((HOME/'current.json').read_text(encoding='utf-8'))['generation']
if not isinstance(pointer,str) or len(pointer)!=16 or any(c not in '0123456789abcdef' for c in pointer):raise ValueError('Invalid guardian generation')
ENGINE=HOME/'generations'/pointer
sys.path.insert(0,str(ROOT))

def valid():
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        envelope=json.loads((ENGINE/'manifest.json').read_text(encoding='utf-8'));data=envelope['descriptor']
        canonical=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
        Ed25519PublicKey.from_public_bytes(base64.b64decode('REbZ+VtgBKKmbIwUb6vnIaYWOe8LecIKpUxUKV/qW00=')).verify(base64.b64decode(envelope['signature'],validate=True),canonical)
        return all(hashlib.sha256((ENGINE/name).read_bytes()).hexdigest()==digest for name,digest in data['files'].items())
    except Exception:return False

ALIASES={'sentinel_platform.core.'+name:'core/'+name+'.py' for name in ('update_bundle','update_commit','update_platform','update_policy','persistent_guardian')}
ALIASES.update({'sentinel_platform.modules.about.'+name:'about/'+name+'.py' for name in ('_updater','_update_chain')})

class RouterLoader:
    def __init__(self,loader):self.loader=loader
    def create_module(self,spec):return self.loader.create_module(spec) if hasattr(self.loader,'create_module') else None
    def exec_module(self,module):
        self.loader.exec_module(module);original=module.create_app
        def create_app(*args,**kwargs):
            app=original(*args,**kwargs)
            from sentinel_platform.modules.about import _updater as updater,_update_chain as chain
            from flask import request,jsonify
            version=(ROOT/'version.txt').read_text(encoding='utf-8').strip()
            chain.runtime_ready(ROOT,version)
            def readiness():
                if request.path=='/api/meta/health/update-ready':return jsonify(code=200,message='success',data=chain.ready_status(ROOT,version))
            app.before_request_funcs.setdefault(None,[]).insert(0,readiness)
            chain.pending(updater,str(ROOT))
            return app
        module.create_app=create_app

class Finder(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname in ALIASES:return importlib.util.spec_from_file_location(fullname,str(ENGINE/ALIASES[fullname]))
        if fullname in ('sentinel_platform.router','sentinel_platform.celery_app','sentinel_platform.scheduler'):
            spec=importlib.machinery.PathFinder.find_spec(fullname,path)
            if spec and spec.loader:spec.loader=RouterLoader(spec.loader) if fullname.endswith('.router') else BackgroundLoader(spec.loader)
            return spec
        return None

def background_ready():
    role=os.environ.get('SENTINEL_BACKGROUND_ROLE','')
    if role not in ('worker','scheduler'):return
    from sentinel_platform.core.update_commit import write
    write(ROOT/'.update_stage/background-ready'/(role+'-ack.json'),
          {'version':os.environ['SENTINEL_BACKGROUND_VERSION'],'nonce':os.environ['SENTINEL_BACKGROUND_NONCE']})

class BackgroundLoader:
    def __init__(self,loader):self.loader=loader
    def create_module(self,spec):return self.loader.create_module(spec) if hasattr(self.loader,'create_module') else None
    def exec_module(self,module):
        self.loader.exec_module(module)
        if module.__name__.endswith('.celery_app'):
            from celery.signals import worker_ready
            worker_ready.connect(lambda **kwargs:background_ready(),weak=False)
        else:
            original=module._install_celery_delivery
            def install():
                result=original();background_ready();return result
            module._install_celery_delivery=install
            if os.environ.get('SENTINEL_WARM_RELOAD')=='1':
                # Worker TERM drains live jobs; a scheduler-only restart is
                # not evidence that those jobs died. Periodic lease recovery stays active.
                module._reclaim_on_startup=lambda:None

if valid():
    os.environ['SENTINEL_GUARDIAN_ROOT']=str(ROOT)
    os.environ['SENTINEL_PERSISTENT_GUARDIAN']='1'
    os.environ['SENTINEL_GUARDIAN_GENERATION']=pointer
    sys.meta_path.insert(0,Finder())
    # Recover or wait out a commit BEFORE old business modules can be imported.
    from sentinel_platform.core import update_commit
    from sentinel_platform.modules.about import _updater
    journal=ROOT/'.update_stage/.commit.json';deadline=time.monotonic()+180
    while journal.exists() and json.loads(journal.read_text(encoding='utf-8')).get('phase')=='committing':
        with _updater._apply_lock(str(ROOT)) as acquired:
            if acquired:update_commit.recover(ROOT);break
        if time.monotonic()>deadline:raise RuntimeError('Persistent guardian is waiting for an unfinished commit')
        time.sleep(.05)
