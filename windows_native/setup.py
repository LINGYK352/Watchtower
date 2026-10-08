from pathlib import Path
import argparse,json,zipfile,os,uuid,shutil,subprocess,base64
from windows_preview._trust import PUBLIC_KEY
from windows_preview.signed_download import signed_manifest,canonical,sha256
from windows_native.webview_runtime import ensure_webview2
from windows_native.runtime import private
PRODUCT='watchtower-native-install'

def install(source,destination,account,progress=print):
 root=Path(destination).resolve()
 repair=root.exists() and any(root.iterdir())
 if repair and (not (root/'app/version.txt').is_file() or not (root/'state/native-release-receipt.json').is_file()):raise ValueError('Nonempty destination is not a recognized Watchtower installation')
 from windows_native.embedded_install import Source
 embedded=isinstance(source,Source)
 manifest=source.manifest if embedded else signed_manifest(source,base64.b64decode(PUBLIC_KEY),PRODUCT)
 if manifest.get('runtime_abi')!='windows-amd64-py311-v1':raise ValueError('Native runtime ABI mismatch')
 if os.name!='nt' or __import__('platform').machine().lower() not in ('amd64','x86_64'):raise ValueError('This native package requires 64-bit Windows on x64')
 if len(str(root/'state/browser-profiles'/('0'*24)).encode('utf-16-le'))//2>180:raise ValueError('Installation folder is too long for reliable browser profiles; choose a shorter folder')
 if not repair and (len(account.get('password',''))<6 or not account.get('username')):raise ValueError('Missing account information')
 root.parent.mkdir(parents=True,exist_ok=True)
 if shutil.disk_usage(root.parent).free<2*1024**3:raise ValueError('Native installation needs2GiB free for staging/data headroom')
 if embedded:source.verify_payload();asset=source.payload()
 else:
  asset=Path(source)/manifest['file']
  if asset.stat().st_size!=manifest['bytes'] or sha256(asset)!=manifest['sha256']:raise ValueError('Native component checksum mismatch')
 # Keep the transaction directory short on Windows: report libraries contain
 # deeply nested resources. The long former prefix exceeded MAX_PATH before
 # first boot even when the selected final installation folder was usable.
 stage=root.parent/('.wt-'+uuid.uuid4().hex[:12]);stage.mkdir()
 try:
  ensure_webview2(stage,progress)
  with zipfile.ZipFile(asset) as z:
   expanded=sum(v.file_size for v in z.infolist())
   if expanded>2*1024**3 or len(z.infolist())>20000:raise ValueError('Native installation archive exceeds safety budget')
   if shutil.disk_usage(stage).free<expanded*2+512*1024**2:raise ValueError('Insufficient space for installation staging and rollback')
   seen=set()
   for info in z.infolist():
    n=info.filename.rstrip('/')
    if not n:continue
    if n.startswith(('state/','validation/','source/','Watchtower-engineering/','Watchtower-distribution/')) or ':' in n or '\\' in n or '..' in n.split('/'):raise ValueError('Private or invalid installation path')
    if n.casefold() in seen:raise ValueError('Duplicate native file');
    seen.add(n.casefold())
    if (info.external_attr>>16)&0o170000==0o120000:raise ValueError('Links are not allowed')
    dest=stage/n;dest.resolve().relative_to(stage.resolve())
    if info.is_dir():dest.mkdir(parents=True,exist_ok=True);continue
    dest.parent.mkdir(parents=True,exist_ok=True)
    with z.open(info) as f,dest.open('wb') as out:shutil.copyfileobj(f,out)
  for n,h in manifest['files'].items():
   if sha256(stage/n)!=h:raise ValueError('Native installed member mismatch')
  private(stage/'state')
  if not repair:(stage/'state/install-account.json').write_text(json.dumps(account),encoding='utf-8')
  (stage/'state/native-release-receipt.json').write_text(json.dumps({'version':manifest['version'],'files':manifest['files']}),encoding='utf-8')
  report=stage/'state/setup-health.json'
  # The WebView health process has browser children. Own the whole tree so its
  # profile handles cannot keep the verified staging directory locked afterward.
  import importlib.util
  spec=importlib.util.spec_from_file_location('watchtower_setup_process',stage/'app/sentinel_platform/core/process_control.py')
  owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
  completed=owned.run([str(stage/'WatchtowerNative.exe'),'--health-check','--report',str(report)],timeout=35,capture_output=True)
  if completed.returncode or not json.loads(report.read_text(encoding='utf-8')).get('ok'):raise ValueError('Native installation health failed')
  if repair:
   from windows_native.repair_install import commit
   result=commit(root,stage,manifest,progress);stage.resolve().relative_to(root.parent);shutil.rmtree(stage);return result
  if root.exists():root.rmdir()
  os.replace(stage,root);progress('Native installation completed');return {'ok':True,'version':manifest['version'],'root':str(root)}
 except Exception:
  if stage.exists():stage.resolve().relative_to(root.parent);shutil.rmtree(stage)
  raise

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--root',required=True);p.add_argument('--account-file',required=True);p.add_argument('--report');a=p.parse_args()
 try:result=install(a.source,a.root,json.loads(Path(a.account_file).read_text(encoding='utf-8')))
 except Exception as e:result={'ok':False,'error_type':type(e).__name__,'message':str(e)[:150]}
 if a.report:Path(a.report).write_text(json.dumps(result),encoding='utf-8')
 return 0 if result['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
