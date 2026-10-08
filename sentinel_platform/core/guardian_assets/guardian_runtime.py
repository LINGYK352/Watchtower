"""Persistent background-process supervisor; warm reload without container restart."""
from pathlib import Path
import json,os,signal,subprocess,sys,time,uuid
ROOT=Path(__file__).resolve().parents[3]
HOME=ROOT/'.update_stage/background-ready'
def write(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_name(path.name+'.'+uuid.uuid4().hex)
 with temporary.open('w',encoding='utf-8') as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
 os.replace(temporary,path)
def version():return (ROOT/'version.txt').read_text(encoding='utf-8').strip()
def main():
 role=sys.argv[1];command=sys.argv[2:]
 if role not in ('worker','scheduler') or not command:raise ValueError('Invalid guardian process role')
 # Import hooks wrap scheduler startup before run_forever. runpy's -m path
 # bypasses exec_module, so use normal import for the standard Compose entry.
 if role=='scheduler' and len(command)==3 and command[1:]==['-m','sentinel_platform.scheduler']:
  command=[command[0],'-c','from sentinel_platform.scheduler import run_forever;run_forever()']
 child=None;stopping=False;warm=False;boot='';nonce='';reload_sent=False
 def stop(*args):
  nonlocal stopping
  stopping=True
  if child and child.poll() is None:os.kill(child.pid,signal.SIGTERM)
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
 while True:
  desired=version();journal=ROOT/'.update_stage/.commit.json'
  committing=journal.exists() and json.loads(journal.read_text()).get('phase')=='committing'
  if child is None or child.poll() is not None:
   if stopping:break
   if committing:time.sleep(.2);continue
   boot=desired;nonce=uuid.uuid4().hex;reload_sent=False
   env=dict(os.environ,SENTINEL_BACKGROUND_ROLE=role,SENTINEL_BACKGROUND_NONCE=nonce,
            SENTINEL_BACKGROUND_VERSION=boot,SENTINEL_WARM_RELOAD='1' if warm else '0')
   child=subprocess.Popen(command,env=env,start_new_session=True);started=time.monotonic()
  if not committing and desired!=boot and not reload_sent:
   warm=True;reload_sent=True;os.kill(child.pid,signal.SIGTERM)
  ready=False
  try:
   ack=json.loads((HOME/(role+'-ack.json')).read_text());ready=ack['nonce']==nonce and ack['version']==boot
  except (OSError,ValueError,KeyError):pass
  write(HOME/(role+'.json'),{'role':role,'version':boot,'nonce':nonce,'ready':ready and not reload_sent,
        'phase':'draining' if reload_sent else ('ready' if ready else 'starting'),'heartbeat':time.time()})
  if child.poll() is not None and not reload_sent and time.monotonic()-started<2:time.sleep(2)
  time.sleep(.3)
if __name__=='__main__':main()
