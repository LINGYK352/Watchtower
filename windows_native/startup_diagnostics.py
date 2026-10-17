"""Durable startup diagnostics exist before Mongo or the platform service starts."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib,json,os,re,threading,traceback,uuid

MAX_BYTES=1024*1024

def frame_file(filename):
    parts=Path(filename).parts
    for name in ('windows_native','sentinel_platform','windows_preview'):
        if name in parts:return '/'.join(parts[parts.index(name):])
    return Path(filename).name

def redact(value):
    try:lines=str(value).splitlines();text=lines[0][:1200] if lines else ''
    except Exception:text=type(value).__name__
    text=re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[redacted-token]',text)
    text=re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@',r'\1[redacted]@',text)
    text=re.sub(r'(?i)(https?://[^\s?]+)\?[^\s]+',r'\1?[redacted]',text)
    text=re.sub(r'(?i)\b(bearer|basic)\s+[^\s,;]+',r'\1 [redacted]',text)
    text=re.sub(r'''(?ix)(["']?(?:password|passwd|pwd|api[-_ ]?key|access[-_ ]?token|control[-_ ]?token|token|secret|authorization)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)''',r'\1[redacted]',text)
    return text[:600]

class StartupDiagnostics:
    def __init__(self,root):
        self.root=Path(root).resolve();self.path=None;self.stage_name='checking';self.error_type='';self.lock=threading.RLock();self.run_id=uuid.uuid4().hex
        fallback=os.environ.get('LOCALAPPDATA')
        folders=[self.root/'state']
        if fallback:folders.append(Path(fallback)/'Watchtower'/'diagnostics'/hashlib.sha256(str(self.root).encode()).hexdigest()[:16])
        for folder in folders:
            try:
                folder.mkdir(parents=True,exist_ok=True,mode=0o700)
                candidate=folder/'startup.log'
                if candidate.is_symlink():continue
                with candidate.open('a',encoding='utf-8'):pass
                self.path=candidate
                if self._write({'event':'begin'}):
                    self._write({'event':'component_revision','message':'native-shell=20261017-r8; ui=native-verified-file'})
                    break
            except OSError:pass
            self.path=None
    def _write(self,value):
        if self.path is None:return False
        with self.lock:
            try:
                if self.path.stat().st_size>=MAX_BYTES:
                    oldest=self.path.with_name('startup.log.2');oldest.unlink(missing_ok=True)
                    previous=self.path.with_name('startup.log.1')
                    if previous.exists():os.replace(previous,oldest)
                    os.replace(self.path,previous)
                row={'time':datetime.now(timezone.utc).isoformat(),'run_id':self.run_id,'stage':self.stage_name,**value}
                with self.path.open('a',encoding='utf-8') as stream:
                    stream.write(json.dumps(row,ensure_ascii=False)+'\n');stream.flush();os.fsync(stream.fileno())
                return True
            except OSError:
                self.path=None
                return False
    def stage(self,name,percent=None):
        self.stage_name=str(name)
        self._write({'event':'stage','percent':percent})
    def failed(self,exc):
        self.error_type=type(exc).__name__
        errors=[];seen=set();current=exc
        while current is not None and id(current) not in seen and len(errors)<4:
            seen.add(id(current));errors.append({'type':type(current).__name__,'errno':getattr(current,'errno',None),'winerror':getattr(current,'winerror',None),'message':redact(current),'frames':[{'file':frame_file(frame.filename),'line':frame.lineno,'function':frame.name} for frame in traceback.extract_tb(current.__traceback__)[-16:]]});current=current.__cause__ or (None if current.__suppress_context__ else current.__context__)
        self._write({'event':'failed','errors':errors})
    def complete(self):self._write({'event':'ready'})
    def public(self):
        return {'stage':self.stage_name,'error_type':self.error_type,'log_path':str(self.path) if self.path and self.path.is_file() else ''}
