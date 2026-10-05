from pathlib import Path
import uuid,time,hashlib,json
from windows_native.appcontainer import execute

def run(root,manifest,args,ctx,workspace_root):
 from sentinel_platform.modules.ai_pentest._extension_runtime import build_argv,redacted_argv,ExtensionRuntimeError
 if manifest['entry']['type'] not in ('binary','launcher','python'):raise ExtensionRuntimeError('Windows扩展入口类型不支持')
 entry=(Path(root)/manifest['entry']['path']).resolve();entry.relative_to(Path(root).resolve())
 permissions=manifest.get('permissions',{})
 if permissions.get('raw_socket'):raise ExtensionRuntimeError('Windows隔离扩展不提供原始套接字权限')
 if permissions.get('secrets'):raise ExtensionRuntimeError('Windows隔离扩展不能访问平台密钥；请使用显式非敏感参数')
 if manifest['entry']['type']!='python' and entry.read_bytes()[:2]!=b'MZ':raise ExtensionRuntimeError('当前系统不能运行该扩展二进制格式')
 argv=build_argv(root,manifest,args);run_id=uuid.uuid4().hex;work=Path(workspace_root)/run_id;started=time.monotonic();max_bytes=int(manifest.get('output',{}).get('max_bytes',262144))
 read_roots=[]
 if manifest['entry']['type']=='python':
  import os
  runtime=Path(os.environ.get('SENTINEL_NATIVE_ROOT',''))/'runtime/python'
  # Console Python fails before main inside a no-console AppContainer. The
  # packaged GUI-subsystem interpreter honors our redirected standard handles.
  if not (runtime/'pythonw.exe').is_file():raise ExtensionRuntimeError('打包Python运行时缺失，请修复Windows安装')
  argv=[str(runtime/'pythonw.exe'),'-I','-S',str(entry)]+argv[2:];read_roots=[runtime]
 result=execute(argv,root,work,timeout=int(manifest.get('timeout',120)),max_bytes=max_bytes,
                network=bool(permissions.get('network')),read_roots=read_roots,
                allow_process=bool(permissions.get('process')),cancel_check=ctx.get('cancel_check') if isinstance(ctx,dict) else getattr(ctx,'cancel_check',None),proxy_url=ctx.get('proxy_url','') if isinstance(ctx,dict) else '')
 text=result['stdout'];value=text
 if manifest.get('output',{}).get('format','json')=='json':
  try:value=json.loads(text)
  except ValueError:value={'text':text,'parse_error':'invalid json'}
 return {'ok':result['code']==0,'extension_id':manifest['extension_id'],'version':manifest['version'],'run_id':run_id,'exit_code':result['code'],'duration_ms':int((time.monotonic()-started)*1000),'result':value,'stderr':result['stderr'][:max_bytes],'stdout_truncated':result['stdout_truncated'],'stderr_truncated':result['stderr_truncated'],'output_hash':hashlib.sha256(text.encode()).hexdigest(),'argv_redacted':redacted_argv(argv,args),'workspace':str(work),'isolation':'windows-appcontainer','network_enabled':result['network']}
