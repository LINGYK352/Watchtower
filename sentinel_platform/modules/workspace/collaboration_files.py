"""Opaque chat attachments use the existing encrypted package delivery, never extraction."""
from __future__ import annotations
import hashlib,io,json,re,unicodedata,zipfile
from sentinel_platform.contracts import Collections
from .control_sync.security import ControlSyncError
from .collaboration_cache.policy import archive_manifest

MAX_ATTACHMENT=20*1024*1024-65536

def safe_filename(value):
    if not isinstance(value,str) or not value or len(value)>180:raise ControlSyncError('附件名称无效 / Invalid attachment filename')
    value=unicodedata.normalize('NFC',value)
    if value in ('.','..') or value!=value.strip() or value.endswith('.') or any(ch in '/'+chr(92) or unicodedata.category(ch) in ('Cc','Cf','Cs') for ch in value):raise ControlSyncError('附件名称含路径或隐藏字符 / Filename contains a path or hidden characters')
    value=re.sub(r'[<>:"|?*]','_',value)
    if len(value.encode('utf-16-le'))>360:raise ControlSyncError('附件名称过长 / Attachment filename is too long')
    if value.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}:value='file-'+value
    return value

def make_package(name,raw):
    name=safe_filename(name)
    if not isinstance(raw,bytes) or len(raw)>MAX_ATTACHMENT:raise ControlSyncError('单个附件需小于20MiB / Attachment must be under20MiB',413)
    meta={'name':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()};stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as archive:
        for member,data in [('data.json',json.dumps({'schema':1,'kind':'file','file':meta},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()),('payload.bin',raw)]:
            info=zipfile.ZipInfo(member,(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_STORED;info.create_system=3;info.external_attr=(0o100600<<16);archive.writestr(info,data)
    packed=stream.getvalue();archive_manifest(packed);return packed,meta

def inspect_package(raw):
    archive_manifest(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist())!=2 or set(archive.namelist())!={'data.json','payload.bin'} or archive.getinfo('data.json').file_size>4096 or archive.getinfo('payload.bin').file_size>MAX_ATTACHMENT:raise ControlSyncError('附件包格式无效 / Invalid attachment package')
        try:doc=json.loads(archive.read('data.json').decode('utf-8'))
        except (UnicodeError,ValueError):raise ControlSyncError('附件说明无效 / Invalid attachment metadata') from None
        if not isinstance(doc,dict) or set(doc)!={'schema','kind','file'} or type(doc.get('schema')) is not int or doc['schema']!=1 or doc.get('kind')!='file' or not isinstance(doc.get('file'),dict):raise ControlSyncError('附件契约无效 / Invalid attachment contract')
        meta=doc['file']
        if set(meta)!={'name','size','sha256'} or safe_filename(meta.get('name'))!=meta.get('name') or isinstance(meta.get('size'),bool) or not isinstance(meta.get('size'),int) or not 0<=meta['size']<=MAX_ATTACHMENT or not isinstance(meta.get('sha256'),str) or not re.fullmatch('[0-9a-f]{64}',meta['sha256']):raise ControlSyncError('附件说明无效 / Invalid attachment metadata')
        payload=archive.read('payload.bin')
    if len(payload)!=meta['size'] or hashlib.sha256(payload).hexdigest()!=meta['sha256']:raise ControlSyncError('附件完整性校验失败 / Attachment integrity failed',409)
    return meta,payload

class CollaborationFiles:
    def attachment_permission(self,gid,user):
        owner=user.get('username') if isinstance(user,dict) else None
        if not isinstance(owner,str) or not owner:raise ControlSyncError('附件需要有效用户 / Valid attachment user required',401)
        account=self.repo.collection(Collections.USER).find_one({'username':owner},{'disabled':1})
        if not account or account.get('disabled'):raise ControlSyncError('用户已失效 / User unavailable',403)
        self._access(gid,user)

    def share_attachment(self,gid,user,body,name,raw):
        self.attachment_permission(gid,user)
        snapshot=self.cache.workspace(gid,user)
        if snapshot['group'].get('crypto_format')!=1:raise ControlSyncError('请先升级工作区加密协议 / Upgrade workspace encryption before sending attachments',409)
        nonce=body.get('nonce')
        if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce):raise ControlSyncError('附件发送凭据无效 / Invalid attachment send nonce')
        packed,meta=make_package(name,raw)
        values={**body,'title':meta['name'][:100]}
        summary={'file_name':meta['name'],'file_bytes':meta['size'],'file_sha256':meta['sha256'],'client_nonce':nonce}
        return self.cache.queue(gid,user,values,'file',packed,summary)

    def attachment_data(self,gid,iid,user):
        self.attachment_permission(gid,user)
        item,raw=self.cache.fetch_package(gid,iid,user)
        if item.get('kind')!='file':raise ControlSyncError('此对象不是附件 / This object is not an attachment')
        meta,payload=inspect_package(raw);summary=item.get('summary') or {}
        if summary.get('file_name')!=meta['name'] or summary.get('file_bytes')!=meta['size'] or summary.get('file_sha256')!=meta['sha256']:raise ControlSyncError('附件摘要与正文不一致 / Attachment caption does not match payload',409)
        self.attachment_permission(gid,user)
        return meta,payload
