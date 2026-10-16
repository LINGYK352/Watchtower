"""Install the same shared core update contract into an existing managed guest."""
from pathlib import Path
import hashlib,json,shlex,uuid
from windows_preview.signed_download import sha256


def validate(directory):
    meta=json.loads((Path(directory)/'desktop.json').read_text(encoding='utf-8'))
    item=meta.get('core')
    if not item:return None
    if item.get('file')!='core-update.tar.gz':raise ValueError('核心配套包路径无效')
    path=Path(directory)/item['file']
    if sha256(path)!=item['sha256']:raise ValueError('核心配套包摘要无效')
    return path,item


SCRIPT=r"""
from pathlib import Path
import fcntl,hashlib,json,os,tarfile,py_compile,shutil,time,re
root=Path('/opt/sentinel/sentinel').resolve();state=root/'.deployment-state';state.mkdir(exist_ok=True)
expected=EXPECTED
bundle=Path(__file__).parent/'core-update.tar.gz'
if hashlib.sha256(bundle.read_bytes()).hexdigest()!=expected['sha256']:raise RuntimeError('Core transfer checksum mismatch')
def version(text):
 m=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-(\d+))?',text.strip())
 if not m:raise RuntimeError('Invalid core version')
 return tuple(map(int,m.groups()[:3]))+(1 if m[4] is None else 0,int(m[4] or 0))
with (state/'update.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 if version((root/'version.txt').read_text(encoding='utf-8'))>version(expected['version']):
  if not (root/'sentinel_platform/core/deployment_profile.py').is_file():raise RuntimeError('Newer core lacks the common deployment contract')
 else:
  with tarfile.open(bundle,'r:gz') as archive:
   manifest=json.load(archive.extractfile('core-manifest.json'))
   allowed={'sentinel_platform/core/deployment_profile.py','sentinel_platform/modules/about/_updater.py','runtime-contract.json'}
   if set(manifest['files'])!=allowed or len(archive.getmembers())!=len(allowed)+1:raise RuntimeError('Invalid common core file set')
   updates={}
   for name in allowed:
    member=archive.getmember(name)
    if not member.isfile():raise RuntimeError('Invalid core file type')
    data=archive.extractfile(member).read()
    if hashlib.sha256(data).hexdigest()!=manifest['files'][name]:raise RuntimeError('Core member hash mismatch')
    if name.endswith('.py'):compile(data,name,'exec')
    else:json.loads(data)
    updates[name]=data
   backup=root/'.update_backup'/('common-deployment-'+str(time.time_ns()))
   for name,data in updates.items():
    target=root/name;target.resolve().relative_to(root)
    if target.is_symlink():raise RuntimeError('Symlink core destination')
    if target.is_file() and target.read_bytes()==data:continue
    if target.exists():
     old=backup/name;old.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(target,old)
    target.parent.mkdir(parents=True,exist_ok=True);pending=target.with_suffix('.delivery-pending');pending.write_bytes(data);os.chmod(pending,0o644);os.replace(pending,target)
 import yaml
 compose=yaml.safe_load((root/'docker/docker-compose.yml').read_text(encoding='utf-8'))
 paths=[]
 for service in ['web','worker','scheduler','mihomo']:
  if service in compose['services']:paths.extend([['services',service,'image'],['services',service,'volumes']])
 for service in ['mongo','rabbitmq']:
  paths.append(['services',service,'volumes'])
 for key in ['RABBITMQ_DEFAULT_USER','RABBITMQ_DEFAULT_PASS','RABBITMQ_DEFAULT_VHOST']:paths.append(['services','rabbitmq','environment',key])
 profile={'schema':1,'contract':1,'runtime_abi':'linux-amd64-py311-v1','preserve_compose_paths':paths}
 profile_path=root/'.deployment-profile.json'
 if not profile_path.exists():
  pending=profile_path.with_suffix('.pending');pending.write_text(json.dumps(profile));os.chmod(pending,0o644);os.replace(pending,profile_path)
 marker=state/'managed.json';marker.write_text(json.dumps({'managed':True,'runtime_abi':profile['runtime_abi']}))
 print(json.dumps({'contract':1,'runtime_abi':profile['runtime_abi']}))
"""


def apply_to_guest(client,directory):
    checked=validate(directory)
    if not checked:return
    bundle,item=checked;stage='/tmp/watchtower-common-core-'+uuid.uuid4().hex
    _,out,_=client.exec_command('mkdir -m 700 '+stage,timeout=10)
    if out.channel.recv_exit_status():raise RuntimeError('Cannot prepare shared core delivery')
    s=client.open_sftp()
    try:
        s.put(str(bundle),stage+'/core-update.tar.gz')
        with s.open(stage+'/apply.py','w') as f:f.write(SCRIPT.replace('expected=EXPECTED','expected='+repr(item),1))
        _,out,err=client.exec_command('sudo python3 '+shlex.quote(stage+'/apply.py'),timeout=90)
        result=out.read().decode();errors=err.read().decode()
        if out.channel.recv_exit_status():raise RuntimeError('共用核心契约同步失败: '+errors[-400:])
        return json.loads(result.strip())
    finally:
        s.close();client.exec_command('rm -f '+stage+'/apply.py '+stage+'/core-update.tar.gz; rmdir '+stage,timeout=10)
