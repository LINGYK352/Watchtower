"""Owned tool process trees: POSIX groups and Windows Job Objects."""
import os,subprocess

if os.name=='nt':
 import ctypes
 from ctypes import wintypes as w
 kernel=ctypes.WinDLL('kernel32',use_last_error=True)
 class BASIC(ctypes.Structure):
  _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',w.DWORD),('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),('active',w.DWORD),('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
 class IO(ctypes.Structure):_fields_=[(n,ctypes.c_ulonglong) for n in ['read_count','write_count','other_count','read_bytes','write_bytes','other_bytes']]
 class EXTENDED(ctypes.Structure):_fields_=[('basic',BASIC),('io',IO)]+[(n,ctypes.c_size_t) for n in ['process_memory','job_memory','peak_process','peak_job']]
 class THREAD(ctypes.Structure):_fields_=[('size',w.DWORD),('usage',w.DWORD),('tid',w.DWORD),('pid',w.DWORD),('base_priority',w.LONG),('delta',w.LONG),('flags',w.DWORD)]
 for name,args,result in [('CreateJobObjectW',[ctypes.c_void_p,w.LPCWSTR],w.HANDLE),('SetInformationJobObject',[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD],w.BOOL),('AssignProcessToJobObject',[w.HANDLE,w.HANDLE],w.BOOL),('TerminateJobObject',[w.HANDLE,w.UINT],w.BOOL),('CloseHandle',[w.HANDLE],w.BOOL),('OpenProcess',[w.DWORD,w.BOOL,w.DWORD],w.HANDLE),('CreateToolhelp32Snapshot',[w.DWORD,w.DWORD],w.HANDLE),('Thread32First',[w.HANDLE,ctypes.POINTER(THREAD)],w.BOOL),('Thread32Next',[w.HANDLE,ctypes.POINTER(THREAD)],w.BOOL),('OpenThread',[w.DWORD,w.BOOL,w.DWORD],w.HANDLE),('ResumeThread',[w.HANDLE],w.DWORD)]:
  f=getattr(kernel,name);f.argtypes=args;f.restype=result
 def checked(value):
  if not value:raise ctypes.WinError(ctypes.get_last_error())
  return value
 class Job:
  def __init__(self):
   self.handle=checked(kernel.CreateJobObjectW(None,None));info=EXTENDED();info.basic.flags=0x2000
   try:checked(kernel.SetInformationJobObject(self.handle,9,ctypes.byref(info),ctypes.sizeof(info)))
   except Exception:self.close();raise
  def attach(self,pid):
   handle=checked(kernel.OpenProcess(0x0101,False,pid))
   try:checked(kernel.AssignProcessToJobObject(self.handle,handle))
   finally:kernel.CloseHandle(handle)
  def terminate(self):
   if self.handle:checked(kernel.TerminateJobObject(self.handle,1))
  def close(self):
   if self.handle:kernel.CloseHandle(self.handle);self.handle=None
  def __del__(self):
   if getattr(self,'handle',None):self.close()
 def resume(pid):
  snapshot=kernel.CreateToolhelp32Snapshot(4,0)
  if snapshot==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
  try:
   entry=THREAD();entry.size=ctypes.sizeof(entry);ok=kernel.Thread32First(snapshot,ctypes.byref(entry))
   while ok:
    if entry.pid==pid:
     handle=checked(kernel.OpenThread(2,False,entry.tid))
     try:
      if kernel.ResumeThread(handle)==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
     finally:kernel.CloseHandle(handle)
     return
    ok=kernel.Thread32Next(snapshot,ctypes.byref(entry))
   raise RuntimeError('New suspended process thread not found')
  finally:kernel.CloseHandle(snapshot)

def popen(*args,**kwargs):
 if os.name!='nt':
  proc=subprocess.Popen(*args,**kwargs);proc._watchtower_own_group=bool(kwargs.get('start_new_session'));return proc
 kwargs.pop('start_new_session',None);kwargs['creationflags']=kwargs.get('creationflags',0)|0x4|subprocess.CREATE_NO_WINDOW
 job=Job();proc=None
 try:
  proc=subprocess.Popen(*args,**kwargs);job.attach(proc.pid);proc._watchtower_job=job;resume(proc.pid);return proc
 except Exception:
  if proc is not None:proc.kill();proc.wait(timeout=5)
  job.close();raise

def close(proc):
 job=getattr(proc,'_watchtower_job',None)
 if job:job.close();proc._watchtower_job=None

def terminate_tree(proc):
 if os.name=='nt':
  job=getattr(proc,'_watchtower_job',None)
  if job:job.terminate();close(proc)
  else:
   try:
    import psutil
    children=psutil.Process(proc.pid).children(recursive=True)
    for child in reversed(children):
     try:child.kill()
     except psutil.NoSuchProcess:pass
   except Exception as exc:
    if not isinstance(exc,(ImportError,OSError)) and exc.__class__.__name__ not in ("NoSuchProcess","AccessDenied"):raise
   if proc.poll() is None:proc.kill()
 else:
  try:
   group=proc.pid if getattr(proc,'_watchtower_own_group',False) else os.getpgid(proc.pid)
   if group==proc.pid:os.killpg(group,9)
   elif proc.poll() is None:proc.kill()
  except ProcessLookupError:pass
  except OSError:
   if proc.poll() is None:proc.kill()
 try:proc.wait(timeout=5)
 finally:close(proc)


def run(argv, input=None, timeout=None, **kwargs):
    if os.name != 'nt':return subprocess.run(argv,input=input,timeout=timeout,**kwargs)
    capture=kwargs.pop('capture_output',False)
    if capture:kwargs['stdout']=subprocess.PIPE;kwargs['stderr']=subprocess.PIPE
    if input is not None:kwargs['stdin']=subprocess.PIPE
    proc=popen(argv,**kwargs)
    try:
        out,err=proc.communicate(input=input,timeout=timeout)
        return subprocess.CompletedProcess(argv,proc.returncode,out,err)
    except subprocess.TimeoutExpired:
        terminate_tree(proc);proc.communicate();raise
    finally:close(proc)
