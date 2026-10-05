"""Signed Windows release catalog and per-file transport; never a Linux manifest."""
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.parse import urljoin,urlsplit
import os,json,base64,hashlib,re,shutil,zlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from windows_preview.signed_download import canonical,validate_url,safe_resource,sha256
from windows_preview._trust import PUBLIC_KEY

ABI='windows-amd64-py311-v1';CATALOG='watchtower-native-updates';RELEASE='watchtower-native-release'
ROOT_FILES={'WatchtowerNative.exe','WatchtowerSetup.exe','LICENSE','NOTICE','README.md'}
APP_EXACT={'app/version.txt','app/changelog.json','app/config/config.yaml.example','app/runtime-contract.json','app/.deployment-profile.json'}
APP_PREFIXES=('app/sentinel_platform/','app/docker/frontend/','app/dicts/')

def long_path(path):
    value=str(Path(path).resolve())
    if os.name!='nt' or value.startswith('\\\\?\\'):return value
    return '\\\\?\\UNC\\'+value[2:] if value.startswith('\\\\') else '\\\\?\\'+value

def link(source,destination):
    os.link(long_path(source),long_path(destination))
def name(value):
    safe_resource(value)
    if any(ord(character)<32 for character in value):raise ValueError('Control characters in update path')
    if value not in ROOT_FILES and not value.startswith(('app/','runtime/')):raise ValueError('Release may not write user state')
    if value.startswith('app/') and value not in APP_EXACT and not value.startswith(APP_PREFIXES):raise ValueError('Release app path is not distributed business source')
    for part in value.split('/'):
        if part.upper().split('.')[0] in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}:raise ValueError('Reserved Windows path')
        private=part.casefold()
        if private in {'config.yaml','install-account.json','runtime.json','.app_platform_key'} or private.startswith(('.activation','.disclaimer')):raise ValueError('Release may not contain private configuration')
    return value

def version(value):
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-\d+)?',value or ''):raise ValueError('Invalid release version')
    return value

class OriginRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,url):
        validate_url(url)
        if (urlsplit(url).scheme,urlsplit(url).netloc)!=(urlsplit(req.full_url).scheme,urlsplit(req.full_url).netloc):raise ValueError('Authenticated update redirect changes origin')
        return super().redirect_request(req,fp,code,msg,headers,url)
OPENER=build_opener(OriginRedirect())

def source(root):
    root=Path(root)
    try:
        value=json.loads((root/'state/native-update-source.json').read_text(encoding='utf-8'))['url']
    except (OSError,ValueError,KeyError):
        from sentinel_platform.core import get_config
        value=get_config().section('NATIVE','UPDATE_URL',default='') or 'https://watchtowers.info/native/windows/x64'
    return validate_url(str(value).rstrip('/'))

def key():
    from sentinel_platform.modules.system import activation
    return activation.read_key()

def headers(root=None):
    from sentinel_platform.core.update_platform import request_headers
    result=request_headers('windows-native',ABI)
    result.update({'Accept-Encoding':'identity','Cache-Control':'no-cache'})
    credential=key()
    if credential:result['X-Update-Key']=credential
    if root:
        try:result['X-Client-Version']=(Path(root)/'app/version.txt').read_text(encoding='utf-8').strip()
        except OSError:pass
    return result

def chain(root,target=''):
    from urllib.parse import urlencode
    from sentinel_platform.core import update_policy
    url=source(root)+'/chain'+('?' + urlencode({'target':target}) if target else '')
    with OPENER.open(Request(url,headers=headers(root)),timeout=30) as response:raw=response.read(1024**2+1)
    if len(raw)>1024**2:raise ValueError('Native chain metadata too large')
    plan=json.loads(raw);current=headers(root).get('X-Client-Version','')
    if plan.get('schema')!=1 or plan.get('policy')!='mandatory-chain' or plan.get('current')!=current:raise ValueError('Native chain baseline mismatch')
    guardian=plan['guardian']
    if update_policy.key(guardian)[:3]!=update_policy.key(update_policy.GUARDIAN)[:3] or '-' in guardian and '-' not in current:raise ValueError('Invalid native guardian')
    previous=current;seen=set()
    rollback=plan.get('direction')=='rollback'
    for step in plan['steps']:
        if step in seen:raise ValueError('Native update chain loops')
        seen.add(step)
        bootstrap=(not previous or update_policy.key(previous)<update_policy.key(guardian)) and step==guardian
        neighbor=update_policy.adjacent(step,previous) if rollback else update_policy.adjacent(previous,step)
        if not bootstrap and not neighbor:raise ValueError('Native update chain skips a version')
        previous=step
    if plan['steps'] and (plan['steps'][-1]!=plan['target'] or plan['next']!=plan['steps'][0]):raise ValueError('Native chain endpoints mismatch')
    return plan

def fetch(source_url,path,limit=4*1024**2,root=None):
    safe_resource(path);url=validate_url(urljoin(source_url+'/',path))
    with OPENER.open(Request(url,headers=headers(root)),timeout=25) as response:data=response.read(limit+1)
    if len(data)>limit:raise ValueError('Update metadata exceeds safety budget')
    return data

def signed(source_url,path,product,root=None):
    payload=json.loads(fetch(source_url,path,root=root));signature=base64.b64decode(fetch(source_url,path+'.sig',4096,root),validate=True)
    Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY)).verify(signature,canonical(payload))
    if payload.get('schema')!=1 or payload.get('product')!=product or payload.get('runtime_abi')!=ABI:raise ValueError('Windows update product/runtime ABI mismatch')
    return payload

def catalog(root):
    from urllib.error import HTTPError
    try:paired=json.loads(fetch(source(root),'release-index',root=root))
    except HTTPError as exc:
        if exc.code!=404:raise
        paired=None
    if paired:
        from sentinel_platform.core import update_policy
        data=paired['descriptor']
        Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY)).verify(base64.b64decode(paired['signature'],validate=True),canonical(data))
        if data.get('schema')!=1 or data.get('product')!='watchtower-dual-release-index' or data.get('status')!='ACTIVE':raise ValueError('Invalid paired native index')
        releases=[]
        floor=data.get('minimum_rollback',{}).get('windows-amd64',data.get('guardian','v1.21.171'))
        update_policy.key(floor)
        for record in data['releases']:
            version(record['version'])
            if record.get('products')!=['web-linux-amd64','windows-amd64']:raise ValueError('Index does not contain both platforms')
            if update_policy.key(record['version'])>=update_policy.key(floor):releases.append(dict(record,manifest=record['version']+'.json',files=record.get('file_counts',{}).get('windows-amd64',0)))
        if data['latest'] not in {r['version'] for r in releases}:raise ValueError('Native latest missing from paired index')
        return {'schema':1,'product':CATALOG,'runtime_abi':ABI,'channel':data['channel'],'latest':data['latest'],'releases':releases,'minimum_rollback':floor,'paired':True}
    data=signed(source(root),'catalog.json',CATALOG,root)
    releases=data.get('releases')
    if not isinstance(releases,list) or len({r.get('version') for r in releases})!=len(releases):raise ValueError('Invalid release catalog')
    for item in releases:version(item['version']);safe_resource(item['manifest'])
    if data.get('latest') not in {r['version'] for r in releases}:raise ValueError('Latest Windows version is missing')
    return data

def manifest(root,target,full=False):
    version(target)
    from sentinel_platform.core import update_bundle,update_policy
    request_headers=headers(root);base=request_headers.get('X-Client-Version','')
    policy=chain(root,target if base and update_policy.key(target)<update_policy.key(base) else '')
    update_policy.allow(base,target,policy)
    packaged=update_policy.uses_packages(base,target)
    paired=update_bundle.fetch_plan(source(root),request_headers,'windows-amd64',target,base,lambda p,h:name(p),full) if packaged else None
    if paired:
        return {'schema':1,'product':RELEASE,'runtime_abi':ABI,'version':target,'channel':'paired',
                'files':{p:{'sha256':h,'bytes':paired['inventory_bytes'][p]} for p,h in paired['inventory'].items()},'bundle':paired}
    if packaged:raise ValueError('公共包与Windows专属包未准备，禁止退回逐文件模式')
    cat=catalog(root);entry=next((r for r in cat['releases'] if r['version']==target),None)
    if not entry:raise ValueError('Target release unavailable for this Windows channel')
    data=signed(source(root),entry['manifest'],RELEASE,root)
    if data.get('version')!=target or data.get('channel')!=cat.get('channel'):raise ValueError('Release catalog and manifest do not match')
    files=data.get('files')
    if not isinstance(files,dict) or not files or len({n.casefold() for n in files})!=len(files):raise ValueError('Invalid release inventory')
    for path,item in files.items():
        name(path)
        if not isinstance(item,dict) or not re.fullmatch('[0-9a-f]{64}',item.get('sha256','')) or not re.fullmatch('[0-9a-f]{64}',item.get('compressed_sha256','')):raise ValueError('Invalid release digest')
        safe_resource(item['object'])
        if type(item.get('bytes')) is not int or type(item.get('compressed_bytes')) is not int or min(item['bytes'],item['compressed_bytes'])<0:raise ValueError('Invalid release byte count')
    if 'app/version.txt' not in files:raise ValueError('Release has no version marker')
    return data

def download(root,item,progress=None):
    cache=Path(root)/'state/update-cache';cache.mkdir(parents=True,exist_ok=True)
    expected=item['compressed_sha256'];target=cache/(expected+'.z');part=cache/(expected+'.part');size=item['compressed_bytes']
    for path in [target,part]:
        if path.is_symlink():raise ValueError('Update cache may not be a link')
    if target.is_file() and target.stat().st_size==size and sha256(target)==expected:return target
    offset=part.stat().st_size if part.exists() else 0
    if offset>=size:
        if offset==size and sha256(part)==expected:part.replace(target);return target
        part.unlink();offset=0
    request_headers=headers(root)
    if offset:request_headers['Range']='bytes='+str(offset)+'-'
    url=validate_url(urljoin(source(root)+'/',item['object']))
    with OPENER.open(Request(url,headers=request_headers),timeout=30) as response:
        if response.status==206:
            matched=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',response.headers.get('Content-Range',''))
            if not matched or int(matched[1])!=offset or int(matched[3])!=size:raise ValueError('Resume response range does not match signed inventory')
            mode='ab'
        elif response.status==200:offset=0;mode='wb'
        else:raise ValueError('Invalid update object response')
        with part.open(mode) as out:
            while True:
                chunk=response.read(min(1024*1024,size-offset+1))
                if not chunk:break
                if offset+len(chunk)>size:raise ValueError('Update object exceeds signed byte count')
                out.write(chunk);offset+=len(chunk)
                if progress:progress(offset,size)
            out.flush();os.fsync(out.fileno())
    if offset!=size:raise ConnectionError('Update download interrupted; next attempt resumes')
    if sha256(part)!=expected:part.unlink();raise ValueError('Update object digest mismatch')
    part.replace(target);return target

def unpack(blob,destination,item):
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True);decoder=zlib.decompressobj();count=0;digest=hashlib.sha256()
    with Path(blob).open('rb') as source_file,destination.open('wb') as out:
        while True:
            chunk=source_file.read(1024*1024)
            if not chunk:break
            while chunk:
                data=decoder.decompress(chunk,min(1024*1024,item['bytes']-count+1));chunk=decoder.unconsumed_tail
                count+=len(data)
                if count>item['bytes']:raise ValueError('Expanded update exceeds signed byte count')
                out.write(data);digest.update(data)
        rest=decoder.flush();count+=len(rest)
        if count>item['bytes']:raise ValueError('Expanded update exceeds signed byte count')
        out.write(rest);digest.update(rest)
    if not decoder.eof or decoder.unused_data or count!=item['bytes'] or digest.hexdigest()!=item['sha256']:raise ValueError('Expanded update content mismatch')
