"""Creator-moderated cross-instance workgroups with isolated shared packages and provenance."""
from __future__ import annotations
from pathlib import Path
from datetime import datetime,timezone
import hashlib,io,json,os,secrets,time,zipfile,tempfile,threading
from bson import ObjectId,json_util
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from sentinel_platform.contracts import Collections,ROLE,get_registry
from .control_sync.security import ControlSyncError,text,ttl,digest,encode_peer,decode_peer,b64,unb64,normalize_target
from .control_sync.pairing import transport
from .collaboration_rooms import CollaborationRooms
from .collaboration_files import CollaborationFiles,inspect_package
from . import collaboration_profiles as profiles
from . import preferences
from . import collaboration_keys as invitation_keys
from . import collaboration_join as durable_join
from .collaboration_invites import invitation_settings, admit, admission
from .control_sync.peer_poll import refresh_peer
from .collaboration_cache.service import CacheService
from .collaboration_cache.policy import CacheError, normalize as cache_policy, archive_manifest
from .collaboration_cache import crypto as cache_crypto

CHUNK=2*1024*1024
MAX_PACKAGE=64*1024*1024

def oid(value):
    try:return ObjectId(value)
    except Exception:return value

def hex_id(value):
    value=text(value,32)
    if len(value)!=32 or any(c not in '0123456789abcdef' for c in value):raise ControlSyncError('工作组对象标识无效 / Invalid workgroup object id')
    return value

def atomic_file(path,raw):
    """Publish a complete file; distinct temporary names work across workers."""
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=str(path.parent),prefix='.upload-',delete=False) as handle:
            temporary=Path(handle.name);os.chmod(str(temporary),0o600)
            handle.write(raw);handle.flush();os.fsync(handle.fileno())
        os.replace(str(temporary),str(path))
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()

class CollaborationService(CollaborationFiles,CollaborationRooms):
    def __init__(self,repo,control,directory=None,clock=time.time,send=None):
        self.repo,self.control,self.clock=repo,control,clock
        self.directory=Path(directory or control.directory.parent/'collaboration');self.directory.mkdir(parents=True,exist_ok=True)
        self.groups=repo.collection('collaboration_groups');self.members=repo.collection('collaboration_members')
        self.members.create_index([('group_id',1),('state',1),('expires_at',1)])
        self.members.create_index([('group_id',1),('alias_id',1)],unique=True,partialFilterExpression={'alias_id':{'$type':'string'}})
        self.members.create_index([('group_id',1),('name_key',1)],unique=True,partialFilterExpression={'name_key':{'$type':'string'}})
        self.links=repo.collection('collaboration_links');self.items=repo.collection('collaboration_items');self.uploads=repo.collection('collaboration_uploads')
        self.items.create_index([('group_id',1),('audience',1),('participants',1),('published_revision',1)])
        self.items.create_index([('group_id',1),('state',1),('published',1)])
        self.parts=repo.collection('collaboration_parts')
        self.nonces=repo.collection('collaboration_nonces');self.nonces.create_index('expires',expireAfterSeconds=0)
        self.send=send or (lambda target,action,packet:transport(target,action,packet,prefix='/api/collaboration/peer/',timeout_override=2 if action=='leave' else None))
        self._default_send=self.send if send is None else None
        self.cache=CacheService(self)

    def identity(self,user):
        return {**self.control.pairing.identity(),'member':user['username'],**self.cache.identity(user)}

    def direct_send(self,target,action,packet,seconds=None):
        if seconds is not None and self.send is self._default_send:
            return transport(target,action,packet,prefix='/api/collaboration/peer/',timeout_override=seconds)
        return self.send(target,action,packet)

    def deliver(self,link,action,packet,user,seconds=None):
        try:return self.cache.transport(link,action,packet,user,seconds=seconds)
        except CacheError as exc:raise ControlSyncError(str(exc),exc.status) from None

    def _group(self,gid):
        doc=self.groups.find_one({'_id':hex_id(gid),'enabled':True})
        if not doc:raise ControlSyncError('工作组不存在或已关闭 / Workgroup unavailable',404)
        creator=self.repo.collection(Collections.USER).find_one({'username':doc['owner']},{'disabled':1})
        if not creator or creator.get('disabled'):raise ControlSyncError('工作组创建者账户已失效 / Coordinator account unavailable',403)
        return doc

    def _host(self,gid,user):
        group=self._group(gid)
        if group['owner']!=user['username']:raise ControlSyncError('仅创建者可主持此工作组 / Only its creator can moderate',403)
        return group

    def _access(self,gid,user):
        group=self.groups.find_one({'_id':hex_id(gid),'enabled':True,'owner':user['username']})
        if group:return {'host':True,'group':group,'member_id':gid}
        link=self.links.find_one({'group_id':gid,'owner':user['username'],'state':'approved','deleted_at':{'$exists':False},'expires_at':{'$gt':self.clock()}})
        if not link:raise ControlSyncError('尚未获批或成员凭证已过期 / Membership not approved or expired',403)
        return {'host':False,'link':link,'member_id':link['_id']}

    def _pending_count(self,group):
        if not group.get('enabled'):return 0
        return self.members.count_documents({'group_id':group['_id'],'host':{'$ne':True},'expires_at':{'$gt':self.clock()},'$or':[{'state':'pending'},{'state':'approved','rename_request.state':'pending'}]})

    def pending(self,user):
        groups=self.groups.find({'owner':user['username'],'enabled':True,'deleted_at':{'$exists':False}})
        counts={g['_id']:self._pending_count(g) for g in groups}
        self.cache.notifications.watch(user)
        return {'total':sum(counts.values()),'groups':counts,**self.cache.notifications.summary(user)}

    def _public_group(self,group,host=False):
        result={k:group.get(k) for k in ('_id','name','owner','created_at','invite_expires_at','enabled','source','public_target','max_members','approval_required')}
        if isinstance(group.get('invitations'),list):
            primary=next((row for row in group['invitations'] if row.get('primary')),None)
            if primary:result['invite_expires_at']=primary.get('expires_at')
        if host:result['pending_count']=self._pending_count(group)
        if not host:result.pop('owner',None)
        result['source']=profiles.source_public(group.get('source') or {},group.get('host_name') or group['name'])
        result['cache_policy']=cache_policy(group.get('cache_policy'))
        result['crypto_format']=group.get('crypto_format',0)
        result['legacy_history']=group.get('legacy_history',False)
        result['node_descriptor']=self.cache.descriptor(group)
        return result

    def _public_member(self,member):
        return profiles.public(self,member)

    def create(self,user,body):
        duration,settings=invitation_settings(body);member_duration=ttl(body.get('member_expires_in'),300,365*86400)
        name=text(body.get('name'),80);gid=secrets.token_hex(16);secret=secrets.token_urlsafe(32);now=self.clock()
        group={'_id':gid,'name':name,'owner':user['username'],'enabled':True,'created_at':now,'invite_expires_at':now+duration if duration else None,**settings,
               'member_duration':member_duration,'invite':self.control.secrets.seal(secret,gid+':group-invite'),'source':self.identity(user),
               'crypto_format':1,'cache_policy':cache_policy()}
        primary=invitation_keys.record(self,gid,secret,duration,settings,primary=True)
        group['invitations']=[primary];group['invitation_format']=2;group['invite_primary_id']=primary['_id']
        if primary['single_use']:group['invite_expires_at']=now-1
        self.groups.insert_one(group)
        self.members.insert_one({'_id':gid,'group_id':gid,**profiles.fields(self,group,group['source'],True),'state':'approved','host':True,'source':group['source'],'created_at':now,'expires_at':None})
        (self.directory/gid).mkdir(exist_ok=True)
        preferences.save(self.repo,user,'group_target',group.get('public_target'))
        return {**self._public_group(group),'key':'wt_group.'+gid+'.'+secret}

    def invite(self,gid,user,body):
        return invitation_keys.issue(self,gid,user,body)

    def invite_keys(self,gid,user):return invitation_keys.list_keys(self,gid,user)
    def reveal_invite(self,gid,iid,user):return invitation_keys.reveal(self,gid,iid,user)
    def revoke_invite(self,gid,iid,user):return invitation_keys.revoke(self,gid,iid,user)

    def join(self,user,body):
        return durable_join.join(self,user,body)

    def _public_link(self,link):
        out={k:link.get(k) for k in ('_id','group_id','name','owner','target','state','created_at','expires_at','source','peer_error','peer_retry_at','cache_policy')}
        if self.clock()>=link.get('expires_at',0) and link['state'] not in ('rejected','revoked'):out['state']='expired'
        return out

    def _request(self,link,action,body,seconds=None):
        fresh=self.links.find_one({'_id':link['_id'],'owner':link['owner'],'deleted_at':{'$exists':False},'state':{'$in':['pending','approved']},'expires_at':{'$gt':self.clock()}})
        if not fresh:raise ControlSyncError('工作组连接已失效 / Workgroup link expired or revoked',410)
        if action!='status' and fresh['state']!='approved':raise ControlSyncError('工作组申请尚未获批 / Application not approved',403)
        secret=self.control.secrets.open(fresh['secret'],fresh['_id']+':group-member')
        if action in ('status','workspace'):body={**body,'_crypto_identity':self.cache.identity({'username':fresh['owner']})}
        packet=encode_peer(secret,fresh['_id'],action,body,self.clock)
        result=decode_peer(secret,self.deliver(fresh,action,packet,{'username':fresh['owner']},**({'seconds':seconds} if seconds is not None else {})),action+':response',self.clock)
        if result.get('error'):raise ControlSyncError(result['error'],result.get('status',400))
        return self.cache.remember_reply(fresh,result)

    def refresh(self,mid,user,background=False):
        link=self.links.find_one({'_id':hex_id(mid),'owner':user['username']})
        if not link:raise ControlSyncError('工作组连接不存在 / Link not found',404)
        if link.get('state')=='joining':
            if background and link.get('peer_retry_at',0)>self.clock():return self._public_link(link)
            return durable_join.refresh(self,link,user)
        def fetch(current):
            result=self._request(current,'status',{})
            return {'state':result['state'],'expires_at':result['expires_at'],'cache_policy':result.get('cache_policy',current.get('cache_policy'))}
        return refresh_peer(self.links,link,fetch,self._public_link,self.clock,background)

    def decide(self,gid,mid,user,accepted):
        if not isinstance(accepted,bool):raise ControlSyncError('审核决定无效 / Invalid approval decision')
        group=self._host(gid,user);state='approved' if accepted is True else 'rejected'
        changed=self.members.find_one_and_update({'_id':hex_id(mid),'group_id':gid,'state':'pending','expires_at':{'$gt':self.clock()}},
                                {'$set':{'state':state,'expires_at':self.clock()+group['member_duration'],'reviewed_by':user['username']}},return_document=ReturnDocument.AFTER)
        if not changed:
            existing=self.members.find_one({'_id':mid,'group_id':gid})
            if not existing or existing.get('state')!=state or existing.get('expires_at',0)<=self.clock():raise ControlSyncError('申请已处理或过期 / Application already decided or expired',409)
        return {'state':state}

    def remove(self,gid,mid,user):
        self._host(gid,user)
        if gid==mid:raise ControlSyncError('主持者不能移除自己 / Cannot remove the creator')
        self.members.update_one({'_id':hex_id(mid),'group_id':gid},{'$set':{'state':'revoked'}});return {'revoked':True}

    def delete_group(self,gid,user):
        gid=hex_id(gid)
        group=self.groups.find_one({'_id':gid,'owner':user['username']})
        if not group:raise ControlSyncError('无权删除此工作组 / Cannot delete this workgroup',403)
        prepared=self.cache.replicas.prepare_close(group,user) if group.get('enabled') else []
        self.groups.update_one({'_id':gid,'owner':user['username'],'deleted_at':{'$exists':False}},
            {'$set':{'enabled':False,'deleted_at':self.clock(),'deleted_by':user['username']},'$unset':{'invite':'','invitations':''}})
        # Group closure is the durable access gate even if this secondary write is interrupted.
        notified=self.cache.replicas.notify_close(user,prepared)
        self.members.update_many({'group_id':gid},{'$set':{'state':'revoked'}})
        self.cache.close_group(group,user)
        self.cache.notifications.rows.delete_many({'group_id':gid,'owner':user['username']})
        return {'deleted':True,'kind':'group','group_id':gid,**notified}

    def delete_link(self,mid,user):
        mid=hex_id(mid)
        from .collaboration_cache import leave_notices
        original=self.links.find_one({'_id':mid,'owner':user['username'],'deleted_at':{'$exists':False}})
        if original:leave_notices.prepare(self.cache,original,user)
        old=self.links.find_one_and_update({'_id':mid,'owner':user['username'],'deleted_at':{'$exists':False}},
            {'$set':{'state':'revoked','deleted_at':self.clock()},'$unset':{'secret':'','join_invitation':''}},return_document=ReturnDocument.BEFORE)
        if old is None:
            if not self.links.find_one({'_id':mid,'owner':user['username']}):raise ControlSyncError('无权删除此连接 / Cannot delete this link',403)
            return {'deleted':True,'kind':'link','peer_notified':None}
        notified=leave_notices.send(self.cache,mid,user,seconds=2)
        self.links.update_one({'_id':mid,'owner':user['username']},{'$max':{'peer_notified':notified}})
        pending=bool(self.cache.tasks.find_one({'_id':'leave-notice:'+mid,'owner':user['username']}))
        return {'deleted':True,'kind':'link','peer_notified':notified,'notification_pending':pending}

    def state(self,user):
        return {'groups':[self._public_group(g,host=True) for g in self.groups.find({'owner':user['username'],'deleted_at':{'$exists':False}}).sort('created_at',-1)],
                'links':[self._public_link(l) for l in self.links.find({'owner':user['username'],'deleted_at':{'$exists':False}}).sort('created_at',-1)],'identity':self.identity(user),'notifications':self.cache.notifications.summary(user),'preferences':preferences.get(self.repo,user)}

    def workspace(self,gid,user):
        return self.cache.workspace(gid,user)

    def _workspace(self,gid,mid,host=False):
        group=self._group(gid)
        self.room_member(gid,mid)
        if group.get('crypto_format')==1:
            features={'attachments':1}
            self.groups.update_one({'_id':gid,'enabled':True,'source.crypto_features.attachments':{'$ne':1}},{'$set':{'source.crypto_features':features}})
            self.members.update_one({'_id':gid,'group_id':gid,'host':True,'state':'approved','source.crypto_features.attachments':{'$ne':1}},{'$set':{'source.crypto_features':features}})
            group={**group,'source':{**group.get('source',{}),'crypto_features':features}}
        query=self.visible_items_query(gid,mid,host)
        member_query={'group_id':gid,'state':'approved'}
        return {'group':self._public_group(group,host=host),'members':[self._public_member(m) for m in self.members.find(member_query)],
                'items':[self.public_item(item) for item in self.items.find(query).sort('created_at',-1).limit(200)],
                'self_member_id':mid,'contacts':self.room_contacts(gid,mid),
                'applications':[self._public_member(m) for m in self.members.find({'group_id':gid,'state':'pending','expires_at':{'$gt':self.clock()}})] if host else [],
                'rename_requests':profiles.rename_requests(self,gid) if host else []}

    @staticmethod
    def public_item(item):
        result={k:item.get(k) for k in ('_id','group_id','kind','title','sender','recipients','source','created_at','bytes','sha256','summary','state','participants','published_revision')}
        result['audience']=item.get('audience','legacy')
        return result

    def request_name(self,gid,user,body):
        access=self._access(gid,user)
        if not access['host']:return self._request(access['link'],'rename_request',body)
        return profiles.rename(self,gid,gid,user,body)

    def rename_member(self,gid,mid,user,body,decision=False):
        return profiles.rename(self,gid,hex_id(mid),user,body,decision)

    def candidates(self,user):
        admin=user.get('role')=='admin' or 'pentest:view_all' in user.get('permissions',[])
        sessions=list(self.repo.collection(Collections.PENTEST_SESSION).find({} if admin else {'owner':user['username']},{'messages':0,'console_messages':0,'tool_log':0}).sort('save_date',-1).limit(100))
        result={'session':[{'_id':str(s['_id']),'title':s.get('task_name') or s.get('system_name') or s.get('site') or str(s['_id']),'status':s.get('status')} for s in sessions]}
        sids=[str(s['_id']) for s in sessions]
        for kind,collection,query in [('finding',Collections.INTEL_FINDING,{} if admin else {'session_id':{'$in':sids}}),('report',Collections.PENTEST_REPORT,{} if admin else {'source_session':{'$in':sids}})]:
            result[kind]=[{'_id':str(d['_id']),'title':d.get('title') or d.get('vuln_type') or str(d['_id'])} for d in self.repo.collection(collection).find(query).limit(100)]
        return result

    def _package(self,kind,object_id,user):
        if kind=='session':
            service=get_registry().get(ROLE.PENTEST_DISPATCH)
            if not service or not hasattr(service,'export_session_package'):raise ControlSyncError('会话交接服务未就绪 / Session handoff unavailable',503)
            raw,summary=service.export_session_package(object_id,user['username'],user.get('role')=='admin' or 'pentest:view_all' in user.get('permissions',[]))
            return raw,summary
        if kind not in ('finding','report'):raise ControlSyncError('共享类型无效 / Invalid share type')
        collection=Collections.INTEL_FINDING if kind=='finding' else Collections.PENTEST_REPORT
        record=self.repo.collection(collection).find_one({'_id':oid(object_id)})
        if not record:raise ControlSyncError('共享对象不存在 / Object not found',404)
        if user.get('role')!='admin' and 'pentest:view_all' not in user.get('permissions',[]):
            sid=record.get('session_id') or record.get('source_session')
            session=self.repo.collection(Collections.PENTEST_SESSION).find_one({'_id':oid(sid),'owner':user['username']}) if sid else None
            if not session:raise ControlSyncError('无权分享此对象 / Cannot share this object',403)
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:archive.writestr('data.json',json_util.dumps({'schema':1,'kind':kind,'record':record}).encode('utf-8'))
        return stream.getvalue(),{'source_object_id':str(record['_id'])}

    def _folder(self,gid,iid):
        path=self.directory/hex_id(gid)/'items'/hex_id(iid);path.mkdir(parents=True,exist_ok=True);return path

    def _part(self,gid,iid,index):
        if isinstance(index,bool) or not isinstance(index,int) or not 0<=index<MAX_PACKAGE//CHUNK:raise ControlSyncError('共享数据块索引无效 / Invalid package chunk')
        return self._folder(gid,iid)/(str(index).zfill(4)+'.part')

    def share(self,gid,user,body):
        access=self._access(gid,user);kind=body.get('kind');raw,summary=self._package(kind,text(body.get('object_id'),64),user)
        archive_manifest(raw)
        group=access.get('group') or access['link'].get('workspace_snapshot',{}).get('group',{})
        if group.get('crypto_format')==1 and body.get('audience') in ('group','direct'):
            return self.cache.queue(gid,user,body,kind,raw,summary)
        if len(raw)>MAX_PACKAGE:raise ControlSyncError('共享包过大 / Share package too large',413)
        title=text(body.get('title') or kind,100);recipients=body.get('recipients')
        audience=body.get('audience') or 'legacy'
        if audience not in ('legacy','group','direct'):raise ControlSyncError('工作区类型无效 / Invalid workspace type')
        if audience=='legacy' and (not isinstance(recipients,list) or not recipients or any(not isinstance(m,str) for m in recipients)):raise ControlSyncError('请选择接收成员 / Select recipients')
        if audience!='legacy' and recipients not in (None,[]):raise ControlSyncError('新工作区使用单点成员字段而非接收清单 / Use the workspace peer field')
        iid=secrets.token_hex(16);meta={'_id':iid,'group_id':gid,'kind':kind,'title':title,'recipients':recipients,'bytes':len(raw),
                                     'sha256':hashlib.sha256(raw).hexdigest(),'summary':summary,'audience':audience,'peer_id':body.get('peer_id','')}
        member=access['member_id']
        if access['host']:
            meta=self._begin(gid,member,meta,self.identity(user));atomic_file(self._folder(gid,iid).joinpath('package.zip'),raw)
            self.items.update_one({'_id':iid},{'$set':{'state':'complete'}})
            self.publish_room_item(self.items.find_one({'_id':iid}))
        else:
            self._request(access['link'],'begin',meta)
            for index in range((len(raw)+CHUNK-1)//CHUNK):
                chunk=raw[index*CHUNK:(index+1)*CHUNK]
                self._request(access['link'],'put_part',{'item_id':iid,'index':index,'data':b64(chunk),'sha256':hashlib.sha256(chunk).hexdigest()})
            self._request(access['link'],'commit',{'item_id':iid})
        return {'item_id':iid,'bytes':len(raw),'source':self.identity(user)}

    def _begin(self,gid,mid,body,source):
        iid=hex_id(body.get('_id'));kind=body.get('kind');size=body.get('bytes')
        scope=self.share_scope(gid,mid,body);recipients=scope['recipients']
        if scope['audience']=='group':recipients=[]
        if kind not in ('finding','report','session') or isinstance(size,bool) or not isinstance(size,int) or not 0<size<=MAX_PACKAGE:raise ControlSyncError('共享包清单无效 / Invalid package manifest')
        if not isinstance(recipients,list) or (not recipients and scope['audience']!='group') or len(recipients)>100:raise ControlSyncError('接收成员无效 / Invalid recipients')
        for recipient in recipients:
            member=self.members.find_one({'_id':hex_id(recipient),'group_id':gid,'state':'approved'})
            if not member or member.get('expires_at') is not None and member['expires_at']<=self.clock():raise ControlSyncError('接收成员已失效 / Recipient unavailable',403)
        sha=body.get('sha256')
        if not isinstance(sha,str) or len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha):raise ControlSyncError('共享包摘要无效 / Invalid package digest')
        summary=body.get('summary') or {}
        if not isinstance(summary,dict) or len(json.dumps(summary,ensure_ascii=False))>4096:raise ControlSyncError('共享包摘要信息过大 / Package metadata too large')
        doc={'_id':iid,'group_id':gid,'sender':mid,'source':source,'created_at':self.clock(),'state':'uploading',
             'kind':kind,'bytes':size,'sha256':sha,'summary':summary,'audience':scope['audience'],'participants':scope['participants'],'published':False}
        doc['title']=text(body.get('title'),100);doc['recipients']=sorted(set(recipients))
        try:self.items.insert_one(doc)
        except DuplicateKeyError:
            existing=self.items.find_one({'_id':iid,'group_id':gid,'sender':mid})
            comparable={**(existing or {}),'audience':(existing or {}).get('audience','legacy'),'participants':(existing or {}).get('participants',[])}
            if not existing or any(comparable.get(k)!=doc.get(k) for k in ('kind','bytes','sha256','recipients','title','summary','audience','participants')):raise ControlSyncError('重复上传清单不一致 / Conflicting upload manifest',409) from None
            return existing
        return doc

    def _item(self,gid,iid,mid,host=False):
        self._group(gid);self.room_member(gid,mid)
        doc=self.items.find_one({'_id':hex_id(iid),'group_id':gid,'state':'complete'})
        if not doc or doc.get('kind') not in ('finding','report','session') or not self.item_allowed(doc,mid,host):raise ControlSyncError('无权读取此共享包 / Cannot read this package',403)
        return doc

    def receive(self,gid,iid,user,provider_id='',resume=False):
        access=self._access(gid,user)
        received=self.cache.received.find_one({'owner':user['username'],'group_id':gid,'item_id':iid})
        if received and not self.cache._entry(received).get('legacy'):
            item,raw=self.cache.fetch_package(gid,iid,user)
        elif access['host']:
            item=self._item(gid,iid,access['member_id'],True);raw=self._folder(gid,iid).joinpath('package.zip').read_bytes()
        else:
            item=self._request(access['link'],'item',{'item_id':iid})['item']
            stream=io.BytesIO()
            for index in range((item['bytes']+CHUNK-1)//CHUNK):
                result=self._request(access['link'],'get_part',{'item_id':iid,'index':index});stream.write(unb64(result['data'],3*1024*1024))
            raw=stream.getvalue()
        if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ControlSyncError('共享包完整性校验失败 / Package integrity check failed')
        archive_manifest(raw)
        if item['kind']=='file':
            meta,_=inspect_package(raw)
            return {'item':item,'preview':meta}
        if not access['host']:atomic_file(self._folder(gid,iid).joinpath('package.zip'),raw)
        if item['kind']=='session':
            service=get_registry().get(ROLE.PENTEST_DISPATCH)
            if resume:
                result=service.restore_session_package(raw,user['username'],'group:'+gid,provider_id,item['source'])
                return {'item':item,'restored':result}
            package,files=service.inspect_session_package(raw)
            return json.loads(json_util.dumps({'item':item,'preview':{'session':package['session'],'files':list(files),'findings':package.get('findings',[]),'reports':package.get('reports',[])}}))
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if archive.namelist()!=['data.json'] or archive.getinfo('data.json').file_size>256*1024*1024:raise ControlSyncError('共享数据包格式无效 / Invalid data package')
            data=json_util.loads(archive.read('data.json').decode('utf-8'))
        if data.get('schema')!=1 or data.get('kind')!=item['kind']:raise ControlSyncError('共享数据契约无效 / Invalid shared data contract')
        return json.loads(json_util.dumps({'item':item,'preview':data['record']}))

    def peer(self,action,packet,via_peer=None):
        if action=='service':return self.cache.replicas.peer(packet,via_peer)
        ident=hex_id((packet or {}).get('id'))
        if action=='join':
            group=self._group(ident)
            invitation=invitation_keys.selected(self,group,packet.get('invite_id'))
            secret=self.control.secrets.open(invitation['secret'],invitation_keys.context(ident,invitation));actor=None
        else:
            actor=self.members.find_one({'_id':ident,'host':{'$ne':True}})
            if not actor or self.clock()>=actor['expires_at']:raise ControlSyncError('成员凭证无效或已过期 / Member credential expired',401)
            group=self._group(actor['group_id']);secret=self.control.secrets.open(actor['secret'],ident+':group-member')
        body=decode_peer(secret,packet,action,self.clock)
        if actor and action in ('status','workspace') and body.get('_crypto_identity'):
            update=body['_crypto_identity'];pub=update.get('crypto_public');cache_crypto.public(pub)
            if update.get('crypto_peer')!=cache_crypto.peer_id(pub):raise ControlSyncError('成员通信身份不匹配 / Member communication identity mismatch')
            previous=actor.get('source',{}).get('crypto_public')
            if previous and cache_crypto.peer_id(previous)!=cache_crypto.peer_id(pub):raise ControlSyncError('成员通信密钥变化，请重新核验 / Member communication key changed; verify again',409)
            if not previous:
                source={**actor.get('source',{}),'crypto_public':pub,'crypto_peer':update['crypto_peer'],'crypto_protocol':1,
                        'crypto_fingerprint':cache_crypto.fingerprint(pub)}
                self.members.update_one({'_id':actor['_id'],'group_id':actor['group_id']},{'$set':{'source':source}});actor={**actor,'source':source}
            features=profiles.crypto_features(update)
            self.members.update_one({'_id':actor['_id'],'group_id':actor['group_id']},{'$set':{'source.crypto_features':features}})
            actor={**actor,'source':{**actor.get('source',{}),'crypto_features':features}}
        if via_peer and action!='join' and (not actor.get('source',{}).get('crypto_public') or cache_crypto.peer_id(actor['source']['crypto_public'])!=via_peer):
            raise ControlSyncError('转发身份与成员身份不匹配 / Relayed identity does not match membership',403)
        try:self.nonces.insert_one({'_id':digest(ident+':'+packet['nonce']),'expires':datetime.fromtimestamp(self.clock()+300,timezone.utc)})
        except DuplicateKeyError:raise ControlSyncError('工作组请求已使用 / Request already used',409) from None
        try:
            gid=group['_id']
            if action=='join':
                mid=hex_id(body.get('member_id'));source=body.get('source')
                if not isinstance(source,dict) or source.get('product') not in ('web','win'):raise ControlSyncError('来源客户端标识无效 / Invalid source client')
                supplied=source
                source={k:text(source.get(k),100) for k in ('instance_id','product','platform','version','name','member')}
                if supplied.get('crypto_public'):
                    pub=supplied['crypto_public'];cache_crypto.public(pub)
                    if supplied.get('crypto_peer')!=cache_crypto.peer_id(pub):raise ControlSyncError('成员加密身份不匹配 / Member cryptographic identity mismatch')
                    source.update(crypto_public=pub,crypto_peer=supplied['crypto_peer'],crypto_protocol=1)
                    source['crypto_features']=profiles.crypto_features(supplied)
                if via_peer and source.get('crypto_peer')!=via_peer:raise ControlSyncError('转发申请身份不匹配 / Relayed join identity mismatch',403)
                if group.get('crypto_format')==1 and not source.get('crypto_public'):raise ControlSyncError('请更新客户端后加入加密工作组 / Update your client before joining an encrypted workgroup',409)
                if body.get('invite_id') is not None and body['invite_id']!=invitation['_id']:raise ControlSyncError('邀请标识不匹配 / Invitation identifier mismatch',401)
                member=invitation_keys.admit_key(self,group,{**body,'member_id':mid},source,invitation['_id'])
                result={'group':self._public_group(group),'expires_at':member['expires_at'],'state':member['state'],**self.cache.access_reply(group,member)}
            elif action=='status':result={'state':actor['state'],'expires_at':actor['expires_at'],'group':self._public_group(group),**self.cache.access_reply(group,actor)}
            elif action=='leave':
                self.members.update_one({'_id':ident,'group_id':gid},{'$set':{'state':'revoked','left_at':self.clock()}})
                result={'left':True}
            elif actor['state']!='approved':raise ControlSyncError('成员申请尚未获批或已移除 / Membership not approved',403)
            elif action=='workspace':result={**self._workspace(gid,ident),**self.cache.access_reply(group,actor)}
            elif action=='service_offer':result=self.cache.replicas.accept_offer(group,actor,body)
            elif action=='rename_request':result=profiles.request_name(self,gid,ident,body)
            elif action=='cache_heartbeat':
                self.members.update_one({'_id':ident,'group_id':gid,'state':'approved'},{'$set':{'online_at':self.clock()}});result={'alive':True}
            elif action=='cache_call':result=self.cache.local_call(group,ident,body.get('request') or {})
            elif action=='message':result=self.store_message(gid,ident,body,actor['source'])
            elif action=='conversation':result=self.read_conversation(gid,ident,body)
            elif action=='begin':result={'item':self.public_item(self._begin(gid,ident,body,actor['source']))}
            elif action=='put_part':
                item=self.items.find_one({'_id':hex_id(body.get('item_id')),'group_id':gid,'sender':ident,'state':'uploading'})
                if not item:raise ControlSyncError('上传任务无效 / Invalid upload',403)
                index=body.get('index');path=self._part(gid,item['_id'],index);raw=unb64(body.get('data'),3*1024*1024)
                expected=min(CHUNK,item['bytes']-index*CHUNK)
                if expected<=0 or len(raw)!=expected or hashlib.sha256(raw).hexdigest()!=body.get('sha256'):raise ControlSyncError('数据块校验失败 / Chunk check failed')
                part_id=item['_id']+':'+str(index)
                try:self.parts.insert_one({'_id':part_id,'sha256':body['sha256'],'group_id':gid})
                except DuplicateKeyError:
                    stored=self.parts.find_one({'_id':part_id}) or {}
                    if stored.get('sha256')!=body['sha256']:raise ControlSyncError('重复块内容不一致 / Conflicting chunk',409) from None
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=body['sha256']:atomic_file(path,raw)
                result={'received':index}
            elif action=='commit':
                item=self.items.find_one({'_id':hex_id(body.get('item_id')),'group_id':gid,'sender':ident})
                if not item:raise ControlSyncError('上传不存在 / Upload not found',404)
                path=self._folder(gid,item['_id'])/'package.zip';sha=hashlib.sha256();size=0;temporary=None
                if item.get('state')=='complete':
                    self.publish_room_item(item)
                    return encode_peer(secret,ident,action+':response',{'complete':True},self.clock)
                try:
                    with tempfile.NamedTemporaryFile(dir=str(path.parent),prefix='.commit-',delete=False) as out:
                        temporary=Path(out.name);os.chmod(str(temporary),0o600)
                        for index in range((item['bytes']+CHUNK-1)//CHUNK):
                            part=self._part(gid,item['_id'],index)
                            if not part.is_file():raise ControlSyncError('会话包未完整上传 / Package incomplete',409)
                            raw=part.read_bytes();size+=len(raw);sha.update(raw);out.write(raw)
                        out.flush();os.fsync(out.fileno())
                    if size!=item['bytes'] or sha.hexdigest()!=item['sha256']:raise ControlSyncError('会话包校验失败 / Package checksum failed')
                    os.replace(str(temporary),str(path))
                finally:
                    if temporary is not None and temporary.exists():temporary.unlink()
                self.items.update_one({'_id':item['_id'],'state':'uploading'},{'$set':{'state':'complete'}})
                self.publish_room_item(self.items.find_one({'_id':item['_id']}));result={'complete':True}
            elif action in ('item','get_part'):
                item=self._item(gid,body.get('item_id'),ident)
                if action=='item':result={'item':self.public_item(item)}
                else:
                    index=body.get('index');self._part(gid,item['_id'],index)
                    if index*CHUNK>=item['bytes']:raise ControlSyncError('数据块越界 / Chunk outside package')
                    with self._folder(gid,item['_id']).joinpath('package.zip').open('rb') as stream:stream.seek(index*CHUNK);result={'data':b64(stream.read(CHUNK))}
            else:raise ControlSyncError('协同操作不支持 / Unknown collaboration action')
        except (ControlSyncError,CacheError) as exc:result={'error':str(exc),'status':exc.status}
        return encode_peer(secret,ident,action+':response',result,self.clock)

_service=None
_service_lock=threading.Lock()
def get_service():
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                from .control_sync import get_service as controls
                control=controls();candidate=CollaborationService(control.repo,control)
                candidate.cache.start()
                _service=candidate
    return _service
