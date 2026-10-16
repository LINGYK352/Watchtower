"""Build a clean signed install kit, never package the development directory."""
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
import base64,json,shutil,subprocess,sys,zipfile
from cryptography.hazmat.primitives import serialization
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from windows_preview.signed_download import canonical,sha256
root=Path(__file__).resolve().parents[1];package=WIN_LEGACY
version=(root/'version.txt').read_text(encoding='utf-8').strip();build=int(sys.argv[sys.argv.index('--desktop-build')+1]) if '--desktop-build' in sys.argv else 1
current=version+'-build'+str(build);candidate=WIN_QA / 'candidate'/current
kit=package/'安装包'/version;kit.mkdir(parents=True,exist_ok=True)
work=WIN_QA / 'build/WatchtowerSetup';dist=WIN_QA / 'dist';spec=WIN_QA / 'spec'
if '--reuse-setup' not in sys.argv:
 command=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onefile','--windowed','--name','WatchtowerSetup','--icon',str(root/'frontend/public/favicon.ico'),'--paths',str(root),'--distpath',str(dist),'--workpath',str(work),'--specpath',str(spec),str(root/'windows_preview/setup.py')]
 result=subprocess.run(command,cwd=root,capture_output=True)
 if result.returncode:print(result.stderr.decode('utf-8','replace')[-5000:]);result.check_returncode()
shutil.copy2(dist/'WatchtowerSetup.exe',kit/'WatchtowerSetup.exe');shutil.copy2(root/'windows_preview/Install-Watchtower.ps1',kit/'Install-Watchtower.ps1')
assets=[]
def add_asset(path,kind,target=None):
 entry={'file':path.name,'kind':kind,'bytes':path.stat().st_size,'sha256':sha256(path)}
 if target:entry['target']=target
 assets.append(entry)
app_zip=kit/'application.zip'
with zipfile.ZipFile(app_zip,'w',zipfile.ZIP_DEFLATED) as archive:
 archive.write(candidate/'WatchtowerEntry.exe','Watchtower.exe');archive.write(package/'brand.png','brand.png')
 for path in candidate.rglob('*'):
  if path.is_file():archive.write(path,'versions/'+current+'/'+path.relative_to(candidate).as_posix())
 archive.writestr('active.json',canonical({'version':current}))
 base=json.loads((package/'runtime/preinstalled-base.json').read_text(encoding='utf-8'));base.update(payload_version=version,preinstalled=True)
 archive.writestr('runtime/base.json',canonical(base))
 archive.writestr('测试说明.md','# Watchtower Windows 本地测试安装\n\n双击 Watchtower.exe，自动准备后台并打开最大化工作台。首次账号由安装器设置，协议/激活需本人操作。\n\n本地完整版使用软件仿真，不启用WSL/Hyper-V，不重启Windows；性能与特殊网络仍有边界。程序更新通过顶部应用菜单。\n')
add_asset(app_zip,'zip')
engine_zip=kit/'engine.zip'
with zipfile.ZipFile(engine_zip,'w',zipfile.ZIP_DEFLATED) as archive:
 for path in (package/'engine').rglob('*'):
  if path.is_file():archive.write(path,'engine/'+path.relative_to(package/'engine').as_posix())
add_asset(engine_zip,'zip')
for filename in ['debian-preinstalled.qcow2','payload-'+version+'.iso']:
 target=kit/filename
 if not target.exists() or sha256(target)!=sha256(package/'runtime'/filename):pending=target.with_name(target.name+'.pending');shutil.copy2(package/'runtime'/filename,pending);pending.replace(target)
 add_asset(target,'file','runtime/'+filename)
manifest={'schema':1,'product':'watchtower-windows-preview-install','version':current,'channel':'testing','runtime_abi':'linux-amd64-py311-v1','update_source':'','min_ram_bytes':12*1024**3,'min_disk_bytes':24*1024**3,'assets':assets}
private=serialization.load_pem_private_key((WIN_QA / 'update-signing.key').read_bytes(),None)
(kit/'manifest.json').write_bytes(canonical(manifest));(kit/'manifest.json.sig').write_bytes(base64.b64encode(private.sign(canonical(manifest))))
print(json.dumps({'kit':str(kit),'version':current,'installer_bytes':(kit/'WatchtowerSetup.exe').stat().st_size,'resource_bytes':sum(a['bytes'] for a in assets),'excluded_private_state':True}))
