"""A previewable opt-in report independent of the platform service and activation."""
from pathlib import Path
import hashlib,json,os,re,platform,urllib.request,urllib.error,uuid
from windows_native.startup_diagnostics import redact as first_line_redact

DESTINATION='https://watchtowers.info/native/diagnostics'
MAX_LOG=48*1024

def redact(value):
    text=first_line_redact(value)
    text=re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[redacted-token]',text)
    text=re.sub(r'(?i)([a-z]:[\\/]+users[\\/]+)[^\\/\s]+',r'\1[user]',text)
    text=re.sub(r'''(?ix)(["']?(?:cookie|set-cookie)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)''',r'\1[redacted]',text)
    return text[:600]

def windows_label():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
            build=int(winreg.QueryValueEx(key,'CurrentBuildNumber')[0])
            return 'Windows '+('11' if build>=22000 else '10' if build>=10240 else platform.release())+' (build '+str(build)+')'
    except (OSError,ValueError):return 'Windows '+platform.release()

def create(diagnostic,phase='startup'):
    if phase not in ('startup','install'):raise ValueError('Invalid diagnostic phase')
    info=diagnostic.public();events=[]
    path=diagnostic.path
    if path and path.is_file() and not path.is_symlink():
        with path.open('rb') as stream:
            stream.seek(max(0,path.stat().st_size-96*1024));raw=stream.read(96*1024).decode('utf-8','replace')
        for line in raw.splitlines():
            try:row=json.loads(line)
            except ValueError:continue
            if row.get('run_id')!=diagnostic.run_id:continue
            event={k:redact(row[k]) for k in ('time','stage','event','message') if k in row}
            if isinstance(row.get('errors'),list):
                event['errors']=[]
                for error in row['errors'][:4]:
                    item={k:redact(error[k]) for k in ('type','errno','winerror','message') if k in error}
                    item['frames']=[{k:redact(frame.get(k,'')) for k in ('file','line','function')} for frame in error.get('frames',[])[:16] if isinstance(frame,dict)]
                    event['errors'].append(item)
            events.append(event)
    try:version=(diagnostic.root/'app/version.txt').read_text(encoding='utf-8').strip()
    except OSError:
        try:version=json.loads(Path(__file__).with_name('assets').joinpath('release.json').read_text(encoding='utf-8'))['version']
        except (OSError,ValueError,KeyError):version='v1.21.177'
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-\d+)?',version):version='v1.21.177'
    # Preserve installation identity and the first concrete resource error even
    # when repeated browser probes produce many later events.
    pinned=[e for e in events if e.get('event') in ('component_revision','program_identity','ui_resource_failure','ui_resource_expected','ui_resource_actual')][:12]
    remaining=[e for e in events if e not in pinned]
    value={'schema':1,'report_id':diagnostic.run_id,'version':version,'phase':phase,'stage':redact(info['stage']),'error_type':redact(info['error_type']),'summary':redact(next((e['errors'][0].get('message','') for e in reversed(events) if e.get('errors')),info['error_type'])),'os':windows_label(),'events':pinned+remaining[-(60-len(pinned)):]}
    while len(encode(value))>MAX_LOG and value['events']:
        value['events'].pop(len(pinned) if len(value['events'])>len(pinned) else 0)
    value['report_id']=hashlib.sha256(encode(value)).hexdigest()[:32]
    return value

def encode(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2).encode('utf-8')

def send(value,confirmed=False):
    if confirmed is not True:raise ValueError('Explicit diagnostic upload consent required')
    body=encode(value)
    if len(body)>MAX_LOG:raise ValueError('Diagnostic report exceeds limit')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):return None
    opener=urllib.request.build_opener(NoRedirect())
    request=urllib.request.Request(DESTINATION,data=body,headers={'Content-Type':'application/json','User-Agent':'Watchtower-Windows-Diagnostics/'+value['version']},method='POST')
    try:
        with opener.open(request,timeout=12) as response:
            raw=response.read(4097)
            if len(raw)>4096:raise ValueError('Invalid diagnostic receipt')
            result=json.loads(raw)
            if result.get('ok') is not True or result.get('report_id')!=value['report_id']:raise ValueError('Invalid diagnostic receipt')
            return result
    except urllib.error.HTTPError as error:
        if error.code==429:raise RuntimeError('Upload limit reached. The local report has been retained.') from None
        raise RuntimeError('Diagnostic upload failed (HTTP '+str(error.code)+'). The local report has been retained.') from None
    except Exception as error:raise RuntimeError('Diagnostic upload unavailable: '+redact(error)+'. The local report has been retained.') from None
