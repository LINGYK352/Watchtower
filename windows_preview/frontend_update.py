"""Deliver the bundled frontend to existing and newly initialized local guests."""
from pathlib import Path
import hashlib
import json
import shlex
import uuid


def validate_bundle(directory):
    meta = json.loads((Path(directory)/'desktop.json').read_text(encoding='utf-8'))
    descriptor = meta.get('frontend')
    if not descriptor: return None  # Older desktop versions carry no frontend patch.
    if descriptor.get('file') != 'frontend-update.tar.gz': raise ValueError('Unexpected frontend bundle path')
    bundle = Path(directory)/descriptor['file']
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    if digest != descriptor['sha256']: raise ValueError('Frontend bundle hash mismatch')
    if descriptor['version'] != meta['version']: raise ValueError('Frontend and desktop version mismatch')
    return bundle, descriptor


APPLY_SCRIPT = r"""
from pathlib import Path, PurePosixPath
import fcntl, hashlib, json, os, re, shutil, tarfile, time
root=Path('/opt/sentinel/sentinel').resolve()
state=Path('/opt/watchtower-preview');state.mkdir(exist_ok=True)
bundle=Path(__file__).parent/'frontend-update.tar.gz'
expected=EXPECTED
if hashlib.sha256(bundle.read_bytes()).hexdigest()!=expected['sha256']:raise RuntimeError('Transferred frontend bundle hash mismatch')
def version_key(text):
 m=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-(\d+))?',text.strip())
 if not m:raise RuntimeError('Invalid local core version')
 return tuple(int(x) for x in m.groups()[:3])+(1 if m[4] is None else 0,int(m[4] or 0))
lock_dir=root/'.deployment-state';lock_dir.mkdir(exist_ok=True)
with (lock_dir/'update.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 current=(root/'version.txt').read_text().strip()
 if version_key(current)>version_key(expected['version']):
  print(json.dumps({'version':current,'status':'newer-core-preserved'}));raise SystemExit(0)
 with tarfile.open(bundle,'r:gz') as archive:
  members=archive.getmembers()
  if len(members)>3000 or sum(m.size for m in members)>200*1024*1024:raise RuntimeError('Frontend bundle exceeds limits')
  names=[m.name for m in members]
  if len(set(names))!=len(names):raise RuntimeError('Duplicate frontend bundle members')
  manifest=json.load(archive.extractfile('frontend-manifest.json'))
  if manifest.get('version')!=expected['version']:raise RuntimeError('Frontend manifest version mismatch')
  files=manifest['files']
  changes=manifest['changes']
  if not set(changes)<=set(files) or any(files[n]!=changes[n] for n in changes):raise RuntimeError('Frontend change set mismatch')
  if set(names)!=set(changes)|{'frontend-manifest.json'}:raise RuntimeError('Frontend bundle file set mismatch')
  for name in files:
   parts=PurePosixPath(name).parts
   if not parts or PurePosixPath(name).is_absolute() or '..' in parts or '\\' in name or ':' in name:raise RuntimeError('Invalid frontend manifest path')
   if name not in ('version.txt','changelog.json') and not name.startswith('docker/frontend/'):raise RuntimeError('Non-frontend manifest path')
   (root/name).resolve().relative_to(root)
   if (root/name).is_symlink():raise RuntimeError('Symlink frontend destination')
   if name not in changes and (not (root/name).is_file() or hashlib.sha256((root/name).read_bytes()).hexdigest()!=files[name]):raise RuntimeError('Unchanged frontend baseline file mismatch')
  payload={}
  for member in members:
   if not member.isfile():raise RuntimeError('Non-regular frontend bundle entry')
   if member.name=='frontend-manifest.json':continue
   name=member.name;parts=PurePosixPath(name).parts
   if not parts or PurePosixPath(name).is_absolute() or any(x in ('.','..') for x in parts) or '\\' in name or ':' in name:raise RuntimeError('Invalid frontend path')
   if name not in ('version.txt','changelog.json') and not name.startswith('docker/frontend/'):raise RuntimeError('Frontend bundle attempted to change non-frontend code or configuration')
   target=root/name;target.resolve().relative_to(root)
   if target.is_symlink():raise RuntimeError('Symlink frontend destination')
   data=archive.extractfile(member).read()
   if hashlib.sha256(data).hexdigest()!=files[name]:raise RuntimeError('Frontend member hash mismatch')
   payload[name]=data
  if payload['version.txt'].decode().strip()!=expected['version'] or 'docker/frontend/index.html' not in payload:raise RuntimeError('Missing frontend entry or version')
  marker=state/'desktop-frontend.json'
  if all((root/name).is_file() and hashlib.sha256((root/name).read_bytes()).hexdigest()==files[name] for name in files):
   print(json.dumps({'version':expected['version'],'status':'current'}));raise SystemExit(0)
  backup=root/'.update_backup'/('desktop-frontend-'+expected['version']+'-'+str(time.time_ns()))
  backup.mkdir(parents=True)
  # Preserve old hashed chunks for already open pages. Publish index.html last,
  # and write files in place through atomic replacements: no bind-mount swap.
  ordered=sorted(payload,key=lambda name:(name=='docker/frontend/index.html',name=='version.txt',name))
  for name in ordered:
   target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
   if target.exists():
    saved=backup/name;saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(target,saved)
   pending=target.with_name(target.name+'.desktop-pending')
   with pending.open('wb') as stream:stream.write(payload[name]);stream.flush();os.fsync(stream.fileno())
   os.chmod(pending,0o644);os.replace(pending,target)
  receipt={'version':expected['version'],'sha256':expected['sha256'],'previous':current,'backup':str(backup)}
  pending=marker.with_suffix('.pending');pending.write_text(json.dumps(receipt));os.replace(pending,marker)
  print(json.dumps({'version':expected['version'],'status':'applied','backup':str(backup)}))
"""


def apply_to_guest(client, directory):
    validated = validate_bundle(directory)
    if not validated: return None
    bundle, descriptor = validated
    # Guest application takes a shared file lock and verifies real files afresh.
    stage = '/tmp/watchtower-desktop-frontend-' + uuid.uuid4().hex
    _, output, error = client.exec_command('mkdir -m 700 '+shlex.quote(stage), timeout=10)
    if output.channel.recv_exit_status(): raise RuntimeError('Cannot prepare local guest frontend update')
    sftp = client.open_sftp()
    try:
        sftp.put(str(bundle), stage+'/frontend-update.tar.gz')
        script = APPLY_SCRIPT.replace('expected=EXPECTED', 'expected='+repr(descriptor), 1)
        with sftp.open(stage+'/apply.py', 'w') as stream: stream.write(script)
        _, output, error = client.exec_command('sudo python3 '+shlex.quote(stage+'/apply.py'), timeout=120)
        result=output.read().decode();errors=error.read().decode()
        if output.channel.recv_exit_status(): raise RuntimeError('Local frontend update failed: '+errors[-500:])
        return json.loads(result.strip().splitlines()[-1])
    finally:
        sftp.close()
        # This is a generated, fixed-format owned directory; no caller path is deleted.
        client.exec_command('rm -f '+shlex.quote(stage+'/apply.py')+' '+shlex.quote(stage+'/frontend-update.tar.gz')+'; rmdir '+shlex.quote(stage), timeout=10)
