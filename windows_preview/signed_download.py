"""Signed distribution transport shared by the setup program and desktop updater."""
from pathlib import Path
import base64, hashlib, ipaddress, json, os, re, socket
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_METADATA = 1024*1024


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def validate_url(value):
    if any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('分发地址包含控制字符')
    u=urlsplit(value)
    if not u.hostname or u.username or u.password or u.fragment: raise ValueError('分发地址无效')
    if u.port is not None and not 1<=u.port<=65535:raise ValueError('分发端口无效')
    if u.scheme=='https': return value
    if u.scheme!='http': raise ValueError('外部分发地址必须使用 HTTPS')
    try: local=ipaddress.ip_address(u.hostname).is_loopback
    except ValueError: local=u.hostname.lower()=='localhost' and all(ipaddress.ip_address(a[4][0]).is_loopback for a in socket.getaddrinfo(u.hostname,u.port or 80,type=socket.SOCK_STREAM))
    if not local: raise ValueError('HTTP 仅用于本机测试源')
    return value


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        validate_url(newurl)
        if urlsplit(req.full_url).scheme=='https' and urlsplit(newurl).scheme!='https': raise ValueError('拒绝 HTTPS 分发降级重定向')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


OPENER=build_opener(SafeRedirect())


def safe_resource(name):
    if not isinstance(name,str) or not name or name.startswith('/') or '\\' in name or ':' in name or any(p in ('','..','.') or p.endswith((' ','.')) for p in name.split('/')): raise ValueError('分发资源路径无效')
    return name


def read_resource(source,name,limit=MAX_METADATA):
    safe_resource(name)
    if isinstance(source,Path) or not str(source).startswith(('https://','http://')):
        base=Path(source).resolve();path=(base/name).resolve();path.relative_to(base)
        with path.open('rb') as f: value=f.read(limit+1)
    else:
        url=validate_url(urljoin(str(source).rstrip('/')+'/',name))
        with OPENER.open(Request(url,headers={'Cache-Control':'no-cache'}),timeout=20) as f:value=f.read(limit+1)
    if len(value)>limit:raise ValueError('分发元数据超过大小限制')
    return value


def signed_manifest(source,public_key,product,name='manifest.json'):
    raw=read_resource(source,name)
    payload=json.loads(raw)
    signature=base64.b64decode(read_resource(source,name+'.sig'),validate=True)
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature,canonical(payload))
    if payload.get('schema')!=1 or payload.get('product')!=product:raise ValueError('分发产品或协议不匹配')
    return payload


def asset_source(source,name):
    safe_resource(name)
    if str(source).startswith(('https://','http://')):return validate_url(urljoin(str(source).rstrip('/')+'/',name))
    base=Path(source).resolve();result=(base/name).resolve();result.relative_to(base);return result


def sha256(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def download(source,cache,expected_hash,size,progress=None,cancel=None):
    if not isinstance(size,int) or isinstance(size,bool) or not 0<size<=8*1024**3 or not re.fullmatch('[0-9a-f]{64}',expected_hash):raise ValueError('资源大小或摘要无效')
    cache=Path(cache);cache.mkdir(parents=True,exist_ok=True)
    target=cache/(expected_hash+'.asset');part=cache/(expected_hash+'.part')
    if target.is_symlink() or part.is_symlink():raise ValueError('下载缓存禁止链接')
    if target.is_file() and target.stat().st_size==size and sha256(target)==expected_hash:return target
    offset=part.stat().st_size if part.exists() else 0
    if offset>size:part.unlink();offset=0
    if offset==size:
        if sha256(part)==expected_hash:os.replace(part,target);return target
        part.unlink();offset=0
    if isinstance(source,Path):
        stream=source.open('rb');stream.seek(offset);mode='ab' if offset else 'wb'
    else:
        headers={'Accept-Encoding':'identity'}
        if offset:headers['Range']='bytes='+str(offset)+'-'
        stream=OPENER.open(Request(validate_url(source),headers=headers),timeout=30)
        if stream.status==206:
            m=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',stream.headers.get('Content-Range',''))
            if not m or int(m[1])!=offset or int(m[3])!=size or not int(m[1])<=int(m[2])<size:stream.close();raise ValueError('断点响应范围不匹配')
            mode='ab' if offset else 'wb'
        elif stream.status==200:offset=0;mode='wb'
        else:stream.close();raise ValueError('资源下载响应无效')
    done=offset
    try:
        with stream,part.open(mode) as f:
            while True:
                if cancel and cancel.is_set():raise InterruptedError('下载已取消，可继续断点下载')
                block=stream.read(min(1024*1024,size-done+1))
                if not block:break
                if done+len(block)>size:raise ValueError('下载内容超过清单大小')
                f.write(block);done+=len(block)
                if progress:progress(done,size)
            f.flush();os.fsync(f.fileno())
    except Exception:raise
    if done!=size:raise ConnectionError('资源尚未下载完整，重试将继续断点')
    if sha256(part)!=expected_hash:part.unlink();raise ValueError('资源 SHA256 校验失败')
    os.replace(part,target);return target
