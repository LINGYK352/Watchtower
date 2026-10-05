"""Signed core transaction for the same business source; native runtime ABI is pinned."""
from pathlib import Path
import os,json,hashlib,base64,zipfile,shutil,uuid,py_compile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from windows_preview.signed_download import canonical,sha256,safe_resource
PRODUCT='watchtower-native-core';ABI='windows-amd64-py311-v1'
ALLOWED=('sentinel_platform/','docker/frontend/','dicts/')
EXACT={'version.txt','changelog.json','runtime-contract.json','.deployment-profile.json'}

def name(value):
 safe_resource(value)
 if value not in EXACT and not value.startswith(ALLOWED):raise ValueError('Core update path is outside distributed source')
 if any(part.split('.')[0].upper() in ['CON','PRN','AUX','NUL']+[f'COM{i}' for i in range(1,10)]+[f'LPT{i}' for i in range(1,10)] for part in value.split('/')):raise ValueError('Reserved Windows filename')
 return value

def journal(root,data):
 path=Path(root)/'state/native-core-update.json';pending=path.with_suffix('.pending');pending.write_bytes(canonical(data));os.replace(pending,path)

def prepare(root,bundle,public):
 root=Path(root).resolve();app=root/'app';base=(app/'version.txt').read_text(encoding='utf-8').strip();stage=root/'state'/('core-stage-'+uuid.uuid4().hex);stage.mkdir()
 try:
  with zipfile.ZipFile(bundle) as z:
   entries=z.namelist()
   if len(entries)!=len(set(entries)) or len(entries)>5000 or sum(v.file_size for v in z.infolist())>250*1024**2:raise ValueError('Core archive exceeds limits or repeats entries')
   data=json.loads(z.read('manifest.json'));Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(z.read('manifest.sig'),validate=True),canonical(data))
   if data.get('product')!=PRODUCT or data.get('schema')!=1 or data.get('runtime_abi')!=ABI:raise ValueError('Core product or runtime ABI mismatch')
   if data.get('base')!=base:raise ValueError('Core update baseline mismatch')
   if not __import__('re').fullmatch(r'v\d+\.\d+\.\d+-\d+',data.get('target','')) or data['target']==base:raise ValueError('Expected a distinct testing version')
   files=data['files'];changes=data['changes']
   if not __import__('re').fullmatch(r'v\d+\.\d+\.\d+-\d+',base):raise ValueError('Invalid baseline')
   if len({n.casefold() for n in files})!=len(files):raise ValueError('Case-insensitive duplicate file paths')
   if not files or set(changes)-set(files) or set(entries)!={'manifest.json','manifest.sig'}|{'files/'+n for n in changes}:raise ValueError('Incomplete core update file set')
   for n,h in files.items():
    name(n)
    if not __import__('re').fullmatch('[0-9a-f]{64}',h):raise ValueError('Invalid core digest')
    (app/n).resolve().relative_to(app.resolve())
    if (app/n).is_symlink():raise ValueError('Core destination may not be a link')
    if n not in changes and (not (app/n).is_file() or sha256(app/n)!=h):raise ValueError('Unchanged baseline mismatch: '+n)
   for n,h in changes.items():
    if h!=files[n]:raise ValueError('Changed digest not in target manifest')
    info=z.getinfo('files/'+n)
    if (info.external_attr>>16)&0o170000==0o120000:raise ValueError('Core update may not contain links')
    path=stage/'changes'/name(n);path.parent.mkdir(parents=True,exist_ok=True)
    with z.open(info) as src,path.open('wb') as out:shutil.copyfileobj(src,out)
    if sha256(path)!=h:raise ValueError('Core payload checksum mismatch')
    if n.endswith('.py'):compile(path.read_bytes(),n,'exec')
   if 'version.txt' not in changes or (stage/'changes/version.txt').read_text(encoding='utf-8').strip()!=data['target']:raise ValueError('Core version payload mismatch')
   for required in ['sentinel_platform/core/deployment_profile.py','sentinel_platform/modules/about/_updater.py','runtime-contract.json','.deployment-profile.json']:
    if required not in files:raise ValueError('Missing deployment compatibility contract')
  # Health candidate carries only code, never state/config/keys/extension data.
  candidate=stage/'candidate'
  for n in files:
   dest=candidate/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(stage/'changes'/n if n in changes else app/n,dest)
  # The sample config is a read-only initial-install template required by the common core.
  if (app/'config/config.yaml.example').exists():dest=candidate/'config/config.yaml.example';dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(app/'config/config.yaml.example',dest)
  return data,stage
 except Exception:
  stage.resolve().relative_to((root/'state').resolve());shutil.rmtree(stage);raise

def apply(root,bundle,public,health,stop,start):
 root=Path(root).resolve();state=root/'state';lock=state/'native-core.lock';committed=[];stopped=False;app=root/'app'
 with lock.open('a+b') as handle:
  handle.write(b'0');handle.flush();handle.seek(0)
  import msvcrt
  try:msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
  except OSError:raise RuntimeError('Another native core update is active')
  stage=None
  try:
   data,stage=prepare(root,bundle,public);journal(root,{'phase':'checking','base':data['base'],'target':data['target']})
   if not health(stage/'candidate',data):raise ValueError('Candidate core health check failed')
   stop();stopped=True;backup=state/'core-backups'/data['base'];backup.mkdir(parents=True,exist_ok=True)
   for n in sorted(data['changes'],key=lambda n:(n=='docker/frontend/index.html',n=='version.txt',n)):
    target=app/n;old=backup/n;exists=target.exists()
    if exists:old.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(target,old)
    target.parent.mkdir(parents=True,exist_ok=True);os.replace(stage/'changes'/n,target);committed.append((target,old,exists))
   start()
   journal(root,{'phase':'done','base':data['base'],'target':data['target'],'changed_files':len(committed),'data_preserved':True})
   return data
  except Exception as exc:
   for target,old,exists in reversed(committed):
    if exists:shutil.copy2(old,target)
    else:target.unlink(missing_ok=True)
   if stopped:
    try:start()
    except Exception:pass
   journal(root,{'phase':'error','error_type':type(exc).__name__,'message':str(exc)[:200],'rolled_back':bool(committed)})
   raise
  finally:
   if stage:stage.resolve().relative_to(state.resolve());shutil.rmtree(stage)
   handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
