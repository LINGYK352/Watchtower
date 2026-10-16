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
import sys, subprocess, json, base64, shutil, zipfile, tarfile, io
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
root=Path(__file__).resolve().parents[1];package=WIN_LEGACY
sys.path.insert(0,str(root))
from windows_preview.desktop_update import canonical,digest,PRODUCT

private_path=WIN_QA / 'update-signing.key'
if private_path.exists():
    private=serialization.load_pem_private_key(private_path.read_bytes(),password=None)
else:
    private=Ed25519PrivateKey.generate()
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
(root/'windows_preview/_trust.py').write_text('PUBLIC_KEY = '+repr(base64.b64encode(public).decode())+'\n')
from windows_preview.desktop_version import DESKTOP_VERSION
app_version=DESKTOP_VERSION
build=int(sys.argv[sys.argv.index('--build')+1]) if '--build' in sys.argv else 1
if build<1:raise ValueError('Build number must be positive')
version=app_version+'-build'+str(build)
if (root/'version.txt').read_text().strip()!=app_version:raise RuntimeError('Desktop and frontend build versions must match')
initial=not (package/'active.json').exists()
destination=(package/'versions'/version) if initial else WIN_QA / 'candidate'/version
destination.mkdir(parents=True,exist_ok=True)
work=WIN_QA / 'build';dist=WIN_QA / 'dist';spec=WIN_QA / 'spec';spec.mkdir(exist_ok=True)
for name,source in [('WatchtowerDesktop','launcher.py'),('UpdateHelper','update_helper.py'),('Watchtower','entry.py')]:
    command=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onefile','--windowed',
             '--name',name,'--icon',str(root/'frontend/public/favicon.ico'),'--paths',str(root),
             '--distpath',str(dist),'--workpath',str(work/name),'--specpath',str(spec),
             str(root/'windows_preview'/source)]
    if '--reuse-exes' not in sys.argv:
        result=subprocess.run(command,cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        if result.returncode:
            print(result.stderr.decode('utf-8','replace')[-6000:],flush=True)
            result.check_returncode()
    target=(package if name=='Watchtower' else destination)/(name+'.exe')
    if name!='Watchtower' or not target.exists():shutil.copy2(dist/(name+'.exe'),target)
    if name=='Watchtower':shutil.copy2(dist/(name+'.exe'),destination/'WatchtowerEntry.exe')
    print(json.dumps({'built':name,'bytes':target.stat().st_size}),flush=True)
frontend_files={str(path.relative_to(root).as_posix()):digest(path) for path in (root/'docker/frontend').rglob('*') if path.is_file()}
for name in ['version.txt','changelog.json']:frontend_files[name]=digest(root/name)
# Compare against the retained base payload so fresh installs and existing
# instances share one compatible patch, without retransmitting unchanged images.
PAYLOAD_VERSION='v1.21.167-8'
import pycdlib
baseline=WIN_QA / 'components/desktop-frontend-base.tar.gz'
if not baseline.exists():
    baseline.parent.mkdir(parents=True,exist_ok=True)
    iso=pycdlib.PyCdlib();iso.open(str(package/'runtime'/('payload-'+PAYLOAD_VERSION+'.iso')))
    try:
        with baseline.open('wb') as stream:iso.get_file_from_iso_fp(stream,rr_path='/core.tar.gz')
    finally:iso.close()
with tarfile.open(baseline,'r:gz') as archive:
    if archive.extractfile('version.txt').read().decode().strip()!=PAYLOAD_VERSION:raise RuntimeError('Retained frontend baseline version mismatch')
    import hashlib
    baseline_hashes={member.name:hashlib.sha256(archive.extractfile(member).read()).hexdigest() for member in archive.getmembers() if member.isfile() and member.name in frontend_files}
frontend_changes={name:sha for name,sha in frontend_files.items() if baseline_hashes.get(name)!=sha}
frontend_bundle=destination/'frontend-update.tar.gz'
with tarfile.open(frontend_bundle,'w:gz') as archive:
    data=canonical({'version':app_version,'base':PAYLOAD_VERSION,'files':frontend_files,'changes':frontend_changes})
    info=tarfile.TarInfo('frontend-manifest.json');info.size=len(data);info.mode=0o644
    archive.addfile(info,io.BytesIO(data))
    for name in sorted(frontend_changes):archive.add(root/name,arcname=name,recursive=False)
(destination/'desktop.json').write_bytes(canonical({'version':app_version,'build':build,'frontend':{'file':frontend_bundle.name,'sha256':digest(frontend_bundle),'version':app_version}}))
core_files=['sentinel_platform/core/deployment_profile.py','sentinel_platform/modules/about/_updater.py','runtime-contract.json']
core_bundle=destination/'core-update.tar.gz'
with tarfile.open(core_bundle,'w:gz') as archive:
    data=canonical({'version':app_version,'files':{name:digest(root/name) for name in core_files}})
    info=tarfile.TarInfo('core-manifest.json');info.size=len(data);info.mode=0o644;archive.addfile(info,io.BytesIO(data))
    for name in core_files:archive.add(root/name,arcname=name,recursive=False)
meta=json.loads((destination/'desktop.json').read_text());meta['core']={'file':core_bundle.name,'sha256':digest(core_bundle),'version':app_version};meta['runtime_abi']='linux-amd64-py311-v1';meta['entry_sha256']=digest(destination/'WatchtowerEntry.exe')
shutil.copy2(root/'windows_preview/bootstrap.sh',destination/'bootstrap.sh');meta['bootstrap_sha256']=digest(destination/'bootstrap.sh')
(destination/'desktop.json').write_bytes(canonical(meta))
if initial:(package/'active.json').write_bytes(canonical({'version':version}))
shutil.copy2(root/'windows_preview/assets/brand.png',package/'brand.png')
complete={p.relative_to(destination).as_posix():digest(p) for p in destination.rglob('*') if p.is_file()}
base=json.loads((package/'active.json').read_text())['version']
base_folder=package/'versions'/base
changes={name:sha for name,sha in complete.items() if not (base_folder/name).exists() or digest(base_folder/name)!=sha}
manifest={'schema':1,'product':PRODUCT,'base':base,'target':version,
          'app_version':app_version,'build':build,'files':complete,'changes':changes}
samples=package/'测试更新包';samples.mkdir(exist_ok=True)
bundle=samples/(app_version+'.zip')
with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as archive:
    archive.writestr('manifest.json',canonical(manifest));archive.writestr('manifest.sig',base64.b64encode(private.sign(canonical(manifest))))
    for name in changes:archive.write(destination/name,'files/'+name)
print(json.dumps({'signed_incremental_test_bundle_bytes':bundle.stat().st_size,'base':base,'target':version}))
