from pathlib import Path
import argparse,json,zipfile,os,uuid,shutil,subprocess,base64
from windows_preview._trust import PUBLIC_KEY
from windows_preview.signed_download import signed_manifest,canonical,sha256
from windows_native.webview_runtime import ensure_webview2
from windows_native.runtime import private
PRODUCT='watchtower-native-install'

def install(source,destination,account,progress=print,mode='auto'):
 root=Path(destination).resolve()
 from windows_native.repair_install import recognized
 if mode not in ('auto','install','repair'):raise ValueError('Invalid installation mode')
 occupied=root.exists() and any(root.iterdir());existing=recognized(root)
 if mode=='repair' and not existing:raise ValueError('请选择已有Watchtower安装目录 / Choose an existing Watchtower installation')
 if mode=='install' and occupied:raise ValueError('目录已有文件，请选择修复安装或空目录 / Choose Repair installation or an empty folder')
 repair=mode=='repair' or mode=='auto' and bool(occupied)
 if repair and not existing:raise ValueError('Nonempty destination is not a recognized Watchtower installation')
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
  ensure_webview2(stage,progress,source=source,manifest=manifest)
  with zipfile.ZipFile(asset) as z:
   expanded=sum(v.file_size for v in z.infolist())
   if expanded>2*1024**3 or len(z.infolist())>20000:raise ValueError('Native installation archive exceeds safety budget')
   if shutil.disk_usage(stage).free<expanded*2+512*1024**2:raise ValueError('Insufficient space for installation staging and rollback')
   seen=set();private_members={row['member'] for row in manifest.get('prerequisites',{}).values()}
   for info in z.infolist():
    n=info.filename.rstrip('/')
    if not n:continue
    if n.startswith(('state/','validation/','source/','Watchtower-engineering/','Watchtower-distribution/')) or ':' in n or '\\' in n or '..' in n.split('/'):raise ValueError('Private or invalid installation path')
    if n.casefold() in seen:raise ValueError('Duplicate native file');
    seen.add(n.casefold())
    if n.startswith('__installer__/'):
     if n not in private_members:raise ValueError('Undeclared installer dependency')
     continue
    if not info.is_dir() and n not in manifest['files']:raise ValueError('Untracked installation member')
    if (info.external_attr>>16)&0o170000==0o120000:raise ValueError('Links are not allowed')
    dest=stage/n;dest.resolve().relative_to(stage.resolve())
    if info.is_dir():dest.mkdir(parents=True,exist_ok=True);continue
    dest.parent.mkdir(parents=True,exist_ok=True)
    with z.open(info) as f,dest.open('wb') as out:shutil.copyfileobj(f,out)
  for n,h in manifest['files'].items():
   if sha256(stage/n)!=h:raise ValueError('Native installed member mismatch')
  private(stage/'state')
  if not repair:(stage/'state/install-account.json').write_text(json.dumps(account),encoding='utf-8')
  from windows_native.guardian import display_version
  (stage/'state/native-release-receipt.json').write_text(json.dumps({'version':manifest['version'],'base_install':display_version(manifest['version']),'files':manifest['files']}),encoding='utf-8')
  report=stage/'state/setup-health.json'
  # The WebView health process has browser children. Own the whole tree so its
  # profile handles cannot keep the verified staging directory locked afterward.
  import importlib.util
  spec=importlib.util.spec_from_file_location('watchtower_setup_process',stage/'app/sentinel_platform/core/process_control.py')
  owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
  progress('正在检查窗口组件，首次加载可能需要稍候…')
  compatible=False;last_error=''
  for safe in (False,True):
   report.unlink(missing_ok=True)
   args=[str(stage/'WatchtowerNative.exe'),'--root',str(stage),'--health-check','--report',str(report)]+(['--safe-renderer'] if safe else [])
   try:
    completed=owned.run(args,timeout=120,capture_output=True)
    detail=json.loads(report.read_text(encoding='utf-8')) if report.is_file() else {}
    if completed.returncode==0 and detail.get('ok'):
     compatible=safe;break
    last_error=str(detail.get('error') or ('窗口组件未完成初始化（阶段：'+str(detail.get('phase','unknown'))+'，退出码：'+str(completed.returncode)+'）'))
   except subprocess.TimeoutExpired:
    try:detail=json.loads(report.read_text(encoding='utf-8'))
    except (OSError,ValueError):detail={}
    last_error='窗口组件自检超时（'+str(detail.get('phase','initializing'))+'）；'+str(detail.get('error',''))
   if not safe:progress('正在使用兼容显示方式重新检查窗口组件…')
  else:raise RuntimeError(last_error[:600]+' / Window component check failed; local diagnostics retained')
  if compatible:
   from windows_native.update_state import write
   write(stage/'state/native-renderer.json',{'software':True,'reason':'installer_health_compatibility'})

  if repair:
   from windows_native.repair_install import commit,close_owned
   progress('Closing this Watchtower installation for preserving repair');close_owned(root)
   result=commit(root,stage,manifest,progress)
   if compatible:
    from windows_native.update_state import write
    write(root/'state/native-renderer.json',{'software':True,'reason':'installer_health_compatibility'})
   cleanup_stage(stage,root,progress);return result
  if root.exists():root.rmdir()
  os.replace(stage,root);progress('Native installation completed');return {'ok':True,'version':manifest['version'],'root':str(root)}
 except Exception:
  if stage.exists():cleanup_stage(stage,root,progress)
  raise

def cleanup_stage(stage,root,progress):
 stage,root=Path(stage),Path(root)
 stage.resolve().relative_to(root.parent.resolve())
 if stage.resolve().parent!=root.parent.resolve() or not __import__('re').fullmatch(r'\.wt-[0-9a-f]{12}',stage.name) or stage.is_symlink():raise ValueError('Unsafe installer staging path')
 try:
  from windows_native.update_channel import long_path
  shutil.rmtree(long_path(stage))
 except FileNotFoundError:pass
 except OSError:progress('临时文件仍被系统占用，可稍后清理；程序与个人资料保持 / Temporary cleanup deferred; program and data retained')

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--root',required=True);p.add_argument('--account-file',required=True);p.add_argument('--report');a=p.parse_args()
 try:result=install(a.source,a.root,json.loads(Path(a.account_file).read_text(encoding='utf-8')))
 except Exception as e:result={'ok':False,'error_type':type(e).__name__,'message':str(e)[:150]}
 if a.report:Path(a.report).write_text(json.dumps(result),encoding='utf-8')
 return 0 if result['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
