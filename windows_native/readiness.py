"""Native readiness proves initialized roles in the current boot, not just PIDs."""
from pathlib import Path
import os,time,json,psutil
from windows_native.update_state import write

def acknowledge(root,boot,version,role):
    process=psutil.Process()
    write(Path(root)/'state/native-ready'/('%s-%s.json' % (boot,process.pid)),
          {'boot':boot,'pid':process.pid,'started':process.create_time(),'version':version,'role':role,'ready':True})

def status(root,boot,version,children):
    phases={};ready=bool(children)
    for child in children:
        try:
            if child.poll() is not None:phases[str(child.pid)]='exited';ready=False;continue
            row=json.loads((Path(root)/'state/native-ready'/('%s-%s.json' % (boot,child.pid))).read_text(encoding='utf-8'))
            current=psutil.Process(child.pid)
            valid=row.get('boot')==boot and row.get('version')==version and row.get('pid')==child.pid and abs(row.get('started',0)-current.create_time())<.01 and row.get('ready') is True
            phases[str(child.pid)]='ready' if valid else 'stale';ready=ready and valid
        except (OSError,ValueError,psutil.Error):phases[str(child.pid)]='starting';ready=False
    return {'ready':ready,'version':version,'background':phases}

def running_version(root,expected):
    """A persisted version marker alone cannot advance an interrupted update hop."""
    from urllib.request import Request,build_opener,ProxyHandler
    from windows_native.update_state import read
    try:
        setting=read(Path(root)/'state/runtime.json')
        request=Request('http://127.0.0.1:%s/__native_ready' % setting['web_port'],headers={'X-Native-Control':setting['control_token']})
        with build_opener(ProxyHandler({})).open(request,timeout=3) as response:state=json.load(response)
        return state.get('ready') is True and state.get('version')==expected
    except (OSError,ValueError,KeyError):return False
