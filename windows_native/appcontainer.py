"""Windows AppContainer boundary; only explicit package/workspace grants."""
import ctypes,subprocess,os,msvcrt,time,uuid
from pathlib import Path
from ctypes import wintypes as w
k=ctypes.WinDLL('kernel32',use_last_error=True);u=ctypes.WinDLL('userenv',use_last_error=True);a=ctypes.WinDLL('advapi32',use_last_error=True)
class CAPS(ctypes.Structure):_fields_=[('sid',ctypes.c_void_p),('capabilities',ctypes.c_void_p),('count',w.DWORD),('reserved',w.DWORD)]
class START(ctypes.Structure):
 _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR)]+[(n,w.DWORD) for n in ['x','y','xsize','ysize','xchars','ychars','fill','flags']]+[('show',w.WORD),('reserved2size',w.WORD),('reserved2',ctypes.c_void_p),('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]
class STARTEX(ctypes.Structure):_fields_=[('start',START),('attributes',ctypes.c_void_p)]
class INFO(ctypes.Structure):_fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]
class SIDATTR(ctypes.Structure):_fields_=[('sid',ctypes.c_void_p),('attributes',w.DWORD)]
for lib,name,args,result in [(u,'CreateAppContainerProfile',[w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,ctypes.c_void_p,w.DWORD,ctypes.POINTER(ctypes.c_void_p)],ctypes.c_long),(u,'DeleteAppContainerProfile',[w.LPCWSTR],ctypes.c_long),(a,'ConvertSidToStringSidW',[ctypes.c_void_p,ctypes.POINTER(w.LPWSTR)],w.BOOL),(a,'FreeSid',[ctypes.c_void_p],ctypes.c_void_p),(k,'LocalFree',[ctypes.c_void_p],ctypes.c_void_p),(k,'InitializeProcThreadAttributeList',[ctypes.c_void_p,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.c_size_t)],w.BOOL),(k,'UpdateProcThreadAttribute',[ctypes.c_void_p,w.DWORD,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p],w.BOOL),(k,'DeleteProcThreadAttributeList',[ctypes.c_void_p],None),(k,'CreateProcessW',[w.LPCWSTR,w.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,w.BOOL,w.DWORD,ctypes.c_void_p,w.LPCWSTR,ctypes.c_void_p,ctypes.POINTER(INFO)],w.BOOL),(k,'WaitForSingleObject',[w.HANDLE,w.DWORD],w.DWORD),(k,'GetExitCodeProcess',[w.HANDLE,ctypes.POINTER(w.DWORD)],w.BOOL),(k,'CloseHandle',[w.HANDLE],w.BOOL),(k,'ResumeThread',[w.HANDLE],w.DWORD)]:
 f=getattr(lib,name);f.argtypes=args;f.restype=result

def check(value):
 if not value:raise ctypes.WinError(ctypes.get_last_error())
 return value

def offline_network_ready():
 """Firewall-disabled profiles bypass capability filtering: refuse offline runs."""
 import pythoncom,win32com.client
 policy=None
 pythoncom.CoInitialize()
 try:
  policy=win32com.client.Dispatch('HNetCfg.FwPolicy2')
  return all(bool(policy.FirewallEnabled(profile)) for profile in (1,2,4))
 finally:
  policy=None
  pythoncom.CoUninitialize()

def execute(argv,package,workspace,timeout=10,max_bytes=262144,memory_bytes=1024**3,
            network=False,read_roots=(),allow_process=False,cancel_check=None,proxy_url=''):
 from sentinel_platform.core.process_control import Job
 if not network:
  try:isolated=offline_network_ready()
  except Exception:isolated=False
  if not isolated:raise RuntimeError('无法确保离线扩展的网络隔离：Windows防火墙部分配置未启用或不可读取，已拒绝执行该扩展')
 name='Watchtower.Extension.'+uuid.uuid4().hex;sid=ctypes.c_void_p();hr=u.CreateAppContainerProfile(name,name,'Watchtower isolated extension',None,0,ctypes.byref(sid))
 if hr<0:raise OSError('AppContainer profile HRESULT '+hex(hr&0xffffffff))
 string=w.LPWSTR();check(a.ConvertSidToStringSidW(sid,ctypes.byref(string)));sid_text=string.value;k.LocalFree(string)
 package=Path(package).resolve();workspace=Path(workspace).resolve();workspace.mkdir(parents=True,exist_ok=True);job=None;info=INFO();attributes=None;files=[];cap_sids=[]
 grants=[(package,'RX'),(workspace,'M')]+[(Path(folder).resolve(),'RX') for folder in read_roots]
 try:
  # Windows' executable/DLL loader needs the packaged immutable interpreter
  # visible to ALL APPLICATION PACKAGES, in addition to this run's SID. Only
  # explicit trusted runtime roots receive RX; state/config/package do not.
  for folder in read_roots:
   subprocess.run(['icacls',str(Path(folder).resolve()),'/grant','*S-1-15-2-1:(OI)(CI)RX','/T'],check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
  for folder,rights in grants:
   if not folder.is_dir():raise ValueError('AppContainer grant directory does not exist')
   subprocess.run(['icacls',str(folder),'/grant','*'+sid_text+':(OI)(CI)'+rights,'/T'],check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
  subprocess.run(['icacls',str(workspace),'/setintegritylevel','(OI)(CI)L'],check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
  for file in ['stdin','stdout','stderr']:
   handle=(workspace/file).open('w+b');files.append(handle);os.set_handle_inheritable(msvcrt.get_osfhandle(handle.fileno()),True)
  size=ctypes.c_size_t();k.InitializeProcThreadAttributeList(None,3,0,ctypes.byref(size));storage=ctypes.create_string_buffer(size.value);attributes=ctypes.cast(storage,ctypes.c_void_p);check(k.InitializeProcThreadAttributeList(attributes,3,0,ctypes.byref(size)))
  capability_array=None
  if network:
   convert=a.ConvertStringSidToSidW;convert.argtypes=[w.LPCWSTR,ctypes.POINTER(ctypes.c_void_p)];convert.restype=w.BOOL
   # Outbound Internet plus the OS's private-network capability. No loopback
   # exemption, raw-socket privileges or host firewall rules are installed.
   for value in ['S-1-15-3-1','S-1-15-3-3']:
    pointer=ctypes.c_void_p();check(convert(value,ctypes.byref(pointer)));cap_sids.append(pointer)
   capability_array=(SIDATTR*len(cap_sids))(*[SIDATTR(pointer,4) for pointer in cap_sids])
  caps=CAPS(sid,ctypes.cast(capability_array,ctypes.c_void_p) if capability_array is not None else None,len(cap_sids),0);check(k.UpdateProcThreadAttribute(attributes,0,0x20009,ctypes.byref(caps),ctypes.sizeof(caps),None,None))
  child_policy=w.DWORD(0 if allow_process else 1);check(k.UpdateProcThreadAttribute(attributes,0,0x2000E,ctypes.byref(child_policy),ctypes.sizeof(child_policy),None,None))
  inherited=(w.HANDLE*3)(*[msvcrt.get_osfhandle(f.fileno()) for f in files]);check(k.UpdateProcThreadAttribute(attributes,0,0x20002,inherited,ctypes.sizeof(inherited),None,None))
  start=STARTEX();start.start.cb=ctypes.sizeof(start);start.start.flags=0x100;start.start.stdin,start.start.stdout,start.start.stderr=inherited;start.attributes=attributes
  env={'SystemRoot':os.environ['SystemRoot'],'WINDIR':os.environ['WINDIR'],'PATH':str(package)+';'+os.environ['SystemRoot']+'\\System32','TEMP':str(workspace),'TMP':str(workspace),'USERPROFILE':str(workspace),'APPDATA':str(workspace),'LOCALAPPDATA':str(workspace),'PYTHONUTF8':'1'}
  if network and proxy_url:env.update({key:str(proxy_url) for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')})
  block=ctypes.create_unicode_buffer(''.join(key+'='+value+'\0' for key,value in sorted(env.items()))+'\0');command=ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
  check(k.CreateProcessW(str(argv[0]),command,None,None,True,0x80000|0x08000000|0x400|0x4,block,str(workspace),ctypes.byref(start),ctypes.byref(info)));job=Job()
  from sentinel_platform.core.process_control import EXTENDED
  limit=EXTENDED();limit.basic.flags=0x2000|0x200|0x8|0x2;limit.job_memory=memory_bytes;limit.basic.active=32;limit.basic.process_time=int(timeout+2)*10000000
  check(k.SetInformationJobObject(job.handle,9,ctypes.byref(limit),ctypes.sizeof(limit)));job.attach(info.pid)
  if k.ResumeThread(info.thread)==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
  deadline=time.monotonic()+timeout;waited=258
  while time.monotonic()<deadline:
   if callable(cancel_check) and cancel_check():
    job.terminate();k.WaitForSingleObject(info.process,3000);raise InterruptedError('Extension execution cancelled')
   waited=k.WaitForSingleObject(info.process,50)
   if waited==0:break
   if sum(f.stat().st_size for f in workspace.rglob('*') if f.is_file())>max_bytes*4:
    job.terminate();raise RuntimeError('Extension workspace quota exceeded')
  if waited!=0:job.terminate();k.WaitForSingleObject(info.process,3000);raise TimeoutError('AppContainer execution timed out')
  code=w.DWORD();check(k.GetExitCodeProcess(info.process,ctypes.byref(code)));out=[]
  for file in files[1:]:file.seek(0);out.append(file.read(max_bytes+1))
  return {'code':code.value,'stdout':out[0][:max_bytes].decode('utf-8','replace'),'stderr':out[1][:max_bytes].decode('utf-8','replace'),
          'stdout_truncated':len(out[0])>max_bytes,'stderr_truncated':len(out[1])>max_bytes,'network':bool(network)}
 finally:
  if job:job.close()
  elif info.process:
   k.TerminateProcess.argtypes=[w.HANDLE,w.UINT];k.TerminateProcess.restype=w.BOOL;k.TerminateProcess(info.process,1)
  if info.thread:k.CloseHandle(info.thread)
  if info.process:k.CloseHandle(info.process)
  if attributes:k.DeleteProcThreadAttributeList(attributes)
  for f in files:f.close()
  for folder,_ in grants:subprocess.run(['icacls',str(folder),'/remove:g','*'+sid_text,'/T'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
  for pointer in cap_sids:k.LocalFree(pointer)
  a.FreeSid(sid);u.DeleteAppContainerProfile(name)
