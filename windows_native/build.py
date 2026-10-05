from pathlib import Path
import sys,subprocess,shutil,json
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
from release_tools.workspace_paths import development_paths
paths=development_paths(root);package=paths['native'];work=paths['validation']/'native-build';dist=paths['validation']/'native-dist';spec=paths['validation']/'native-spec'
if '--paths-only' in sys.argv:
 print(json.dumps({key:str(value) for key,value in {'source':root,'package':package,'work':work,'dist':dist,'spec':spec}.items()},ensure_ascii=False));raise SystemExit()
spec.mkdir(parents=True,exist_ok=True)
for name,source,mode in [('NativeService','backend.py','--onedir'),('WatchtowerNative','gui.py','--onefile'),('WatchtowerSetup','setup_gui.py','--onefile')]:
 if '--service-only' in sys.argv and name!='NativeService':continue
 if '--gui-only' in sys.argv and name!='WatchtowerNative':continue
 if '--setup-only' in sys.argv and name!='WatchtowerSetup':continue
 command=[sys.executable,'-m','PyInstaller','--noconfirm','--clean',mode,'--name',name,'--icon',str(root/'windows_native/assets/watchtower.ico'),'--add-data',str(root/'windows_native/assets')+';windows_native/assets','--paths',str(root),'--exclude-module','sentinel_platform','--distpath',str(dist),'--workpath',str(work/name),'--specpath',str(spec)]
 for module in ['torch','torchvision','onnxruntime','scipy','numpy','pandas','sympy','matplotlib','IPython','networkx','fsspec','botocore','boto3','tensorflow']:command+=['--exclude-module',module]
 for module in ['playwright','greenlet','pyee']:command+=['--exclude-module',module]
 if name=='NativeService':command+=['--collect-all','flask_restx','--hidden-import','requests','--hidden-import','yaml','--hidden-import','pymongo','--hidden-import','psutil','--hidden-import','waitress','--hidden-import','jinja2.meta','--hidden-import','win32com.client','--hidden-import','pythoncom']
 else:command+=['--windowed']
 command+=[str(root/'windows_native'/source)]
 result=subprocess.run(command,cwd=root,capture_output=True)
 if result.returncode:print(result.stderr.decode('utf-8','replace')[-4500:],flush=True);result.check_returncode()
 if '--stage-only' in sys.argv:
  print(json.dumps({'built':name,'staged_only':True,'path':str(dist/name if name=='NativeService' else dist/(name+'.exe'))}),flush=True)
  continue
 if name=='NativeService':
  size=sum(p.stat().st_size for p in (dist/name).rglob('*') if p.is_file())
  if size>250*1024**2:raise RuntimeError('Native basic service exceeded component budget')
  shutil.copytree(dist/name,package/'runtime/service')
 elif name=='WatchtowerNative':shutil.copy2(dist/(name+'.exe'),package/(name+'.exe'))
 else:shutil.copy2(dist/(name+'.exe'),paths['validation']/(name+'.exe'))
 print(json.dumps({'built':name,'bytes':sum(p.stat().st_size for p in (dist/name).rglob('*') if p.is_file()) if name=='NativeService' else (dist/(name+'.exe')).stat().st_size}),flush=True)
