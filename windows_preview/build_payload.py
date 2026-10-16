"""Offline initialization media with the same shared core used by Web deployments."""
# Build paths resolve from this source checkout, never from cwd.
from pathlib import Path as _BuildPath
import sys as _BuildSys
_BuildSource = _BuildPath(__file__).resolve().parents[1]
_BuildSys.path.insert(0, str(_BuildSource))
from release_tools.workspace_paths import development_paths
_BuildPaths = development_paths(_BuildSource)
WIN_SOURCE = _BuildPaths['source']
WIN_QA = _BuildPaths['validation']
WIN_NATIVE = _BuildPaths['native']
WIN_LEGACY = _BuildPaths['legacy']
WIN_RELEASES = _BuildPaths['releases']
if not WIN_LEGACY.is_dir():
    raise SystemExit('The obsolete Linux VM packaging flow was removed. Use windows_native/build.py for the current native client.')
from pathlib import Path
import subprocess,tarfile,hashlib,json,io,yaml,pycdlib
import sys
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root));package=WIN_LEGACY
components=WIN_QA / 'components';core=components/'install-core.tar.gz'
files=[n for n in subprocess.check_output(['git','ls-files','-z','sentinel_platform','dicts','config/config.yaml.example'],cwd=root).decode().split('\0') if n and 'tests' not in Path(n).parts]
files=list(dict.fromkeys(files+['sentinel_platform/core/deployment_profile.py','version.txt','changelog.json','docker/nginx.conf','runtime-contract.json']))
with tarfile.open(core,'w:gz') as archive:
    for name in files:archive.add(root/name,arcname=name,recursive=False)
    archive.add(root/'docker/frontend',arcname='docker/frontend')
    compose=yaml.safe_load((root/'docker/docker-compose.yml').read_text(encoding='utf-8'))
    compose['services']['rabbitmq']['environment']['RABBITMQ_DEFAULT_PASS']='${WT_BROKER_PASSWORD}'
    for service in ['web','worker','scheduler','mihomo']:compose['services'][service]['image']='sentinel:runtime-v1'
    encoded=yaml.safe_dump(compose,allow_unicode=True,sort_keys=False).encode();info=tarfile.TarInfo('docker/docker-compose.yml');info.size=len(encoded);info.mode=0o644;archive.addfile(info,io.BytesIO(encoded))
    paths=[]
    for service in ['web','worker','scheduler','mihomo']:paths.extend([['services',service,'image'],['services',service,'volumes']])
    for service in ['mongo','rabbitmq']:paths.append(['services',service,'volumes'])
    for name in ['RABBITMQ_DEFAULT_USER','RABBITMQ_DEFAULT_PASS','RABBITMQ_DEFAULT_VHOST']:paths.append(['services','rabbitmq','environment',name])
    profile=json.dumps({'schema':1,'contract':1,'runtime_abi':'linux-amd64-py311-v1','preserve_compose_paths':paths}).encode();info=tarfile.TarInfo('.deployment-profile.json');info.size=len(profile);info.mode=0o644;archive.addfile(info,io.BytesIO(profile))
items={'images.tar.gz':components/'images.tar.gz','source.tar.gz':components/'source.tar.gz','core.tar.gz':core,'docker-compose':components/'docker-compose','bootstrap.sh':root/'windows_preview/bootstrap.sh','make_config.py':root/'windows_preview/make_config.py','Dockerfile.runtime':root/'docker/Dockerfile.runtime'}
from windows_preview.signed_download import sha256
checks=components/'install-payload.sha256';checks.write_text('\n'.join(sha256(path)+'  '+name for name,path in items.items())+'\n');items['payload.sha256']=checks
version=(root/'version.txt').read_text(encoding='utf-8').strip();target=package/'runtime'/('payload-'+version+'.iso');pending=target.with_suffix('.pending')
iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='WATCHTOWER')
for index,(name,path) in enumerate(items.items()):iso.add_file(str(path),iso_path='/FILE%04d.;1'%index,joliet_path='/'+name,rr_name=name)
iso.write(str(pending));iso.close();pending.replace(target)
print(json.dumps({'payload_version':version,'bytes':target.stat().st_size,'shared_core':True}))
