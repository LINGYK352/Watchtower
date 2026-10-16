"""Host-approved co-host service with resumable public reconciliation."""
import hashlib
import json
import secrets
from pathlib import Path
from .client import NodeClient
from . import relay_waits
from datetime import datetime, timezone
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from . import crypto, rpc, service_roster, service_transport,replica_objects
from .policy import CacheError, canonical, identifier, normalize
from ..control_sync.security import normalize_target,ControlSyncError


class Replicas:
    def __init__(self,cache):
        self.cache=cache;self.service=cache.collaboration;self.clock=cache.clock

    def offer(self,gid,user,body):
        access=self.service._access(gid,user)
        if access['host']:raise CacheError('主持人已拥有服务权限 / The host already owns service authority')
        enabled=body.get('enabled')
        if not isinstance(enabled,bool):raise CacheError('启用状态无效 / Invalid enabled state')
        url=normalize_target(body.get('public_target'),resolve=False) if body.get('public_target') else ''
        identity=self.cache.identity(user)
        offer={'enabled':enabled,'url':url,'public':identity['crypto_public'],'node_public':self.cache.local.public,'updated_at':self.clock()}
        self.service.links.update_one({'_id':access['link']['_id'],'owner':user['username'],'state':'approved'},{'$set':{'service_offer':offer}})
        result=self.service._request(access['link'],'service_offer',offer)
        return {'offered':enabled,**result}

    def accept_offer(self,group,actor,body):
        if body.get('public')!=actor.get('source',{}).get('crypto_public') or not isinstance(body.get('enabled'),bool):
            raise CacheError('服务申请身份不匹配 / Service offer identity mismatch',403)
        crypto.public(body.get('node_public'))
        url=normalize_target(body['url'],resolve=False) if body.get('url') else ''
        self.service.members.update_one({'_id':actor['_id'],'group_id':group['_id'],'state':'approved'},
            {'$set':{'service_offer':dict(body,url=url),'service_state':'offered' if body['enabled'] else 'disabled'},
             **({'$unset':{'cohost':'','service_ready':''}} if not body['enabled'] else {})})
        return {'service_state':'offered' if body['enabled'] else 'disabled'}

    def grant(self,gid,mid,user,body):
        group=self.service._host(gid,user);actor=self.service.room_member(gid,identifier(mid))
        accepted=body.get('accepted');priority=body.get('priority',50)
        if not isinstance(accepted,bool) or isinstance(priority,bool) or not isinstance(priority,int) or not 1<=priority<=100:
            raise CacheError('副主持角色参数无效 / Invalid co-host role parameters')
        if actor.get('host'):raise CacheError('管理主持不能设为副主持 / Administrative host cannot be a co-host')
        if accepted and not (actor.get('service_offer') or {}).get('enabled'):
            raise CacheError('成员须先本人启用服务 / Member must opt in to service first',409)
        state='ready' if accepted and actor.get('cohost') and actor.get('service_state')=='ready' else 'preparing' if accepted else 'revoked'
        values={'cohost':accepted,'service_priority':priority,'service_state':state}
        if accepted and state!='ready':values['service_sync']={'phase':'pull','cursor':None,'inventory':[]}
        if not accepted:values['service_revoke_pending']=True
        self.service.members.update_one({'_id':mid,'group_id':gid,'state':'approved'},{'$set':values})
        # A role grant only schedules preparation. Large public archives never hold the HTTP response open.
        if not accepted:
            try:self.revoke_pending(gid,mid,user)
            except CacheError as exc:
                if exc.status not in (502,503,504):raise
        return {'cohost':accepted,'state':state,'preparation_pending':accepted and state!='ready'}

    def revoke_pending(self,gid,mid,user):
        group=self.service._host(gid,user);actor=self.service.members.find_one({'_id':mid,'group_id':gid})
        if not actor or not actor.get('service_revoke_pending'):return
        offer=actor.get('service_offer') or {}
        self.call(gid,user,{'public':offer['public'],'url':offer.get('url') or ''},'setup',
            {'roster':service_roster.issue(self.cache,group),'config':self.cache.direct_access(group,actor)})
        self.service.members.update_one({'_id':mid,'group_id':gid,'cohost':False},{'$unset':{'service_revoke_pending':''}})

    def call(self,gid,user,destination,action,body):
        access=self.service._access(gid,user);mid=access['member_id']
        if access['host']:
            config=self.cache.direct_access(access['group'],self.service.room_member(gid,mid))
            relay=self.cache._host_config(access['group'],user) if access['group'].get('node_access') else None
        else:
            config=self.cache.link_config(access['link'],'peer_config');relay=self.cache.link_config(access['link'],'node_config')
        if not config:raise CacheError('缺少服务授权，请刷新连接 / Service grant missing; refresh membership',409)
        packet=rpc.encode(self.cache.key(user),destination['public'],gid,mid,action,body,config['grant'],now=self.clock())
        try:answer=self.transmit(user,destination,packet,relay)
        except ControlSyncError as exc:raise CacheError(str(exc),exc.status) from None
        opened=rpc.decode(self.cache.key(user),answer,gid,destination['public'],rid=packet['envelope']['header']['context']['id'],action=action+':response',now=self.clock())
        value=opened['body']
        if value.get('error'):raise CacheError(value['error'],value.get('status',400))
        return value

    def transmit(self,user,destination,packet,relay=None,seconds=18):
        gid=packet['envelope']['header']['context']['group']
        try:self._local(gid,crypto.peer_id(destination['public']))
        except CacheError as exc:
            if exc.status!=404:raise
        else:
            # The same encrypted frame still passes account, grant, roster and replay checks.
            answer=self.peer(packet)
            from . import routes
            routes.remember(self.cache,user,gid,destination['public'],'local')
            return answer
        return service_transport.send(self.cache,user,destination,packet,relay,seconds=seconds)

    def prepare_close(self,group,user):
        actors=list(self.service.members.find({'group_id':group['_id'],'state':'approved','cohost':True}))
        if not actors:return []
        config=self.cache.direct_access(group,self.service.room_member(group['_id'],group['_id']))
        relay=self.cache._host_config(group,user) if group.get('node_access') else None
        prepared=[]
        for actor in actors:
            offer=actor.get('service_offer') or {}
            if not offer.get('enabled'):continue
            destination={'public':offer['public'],'url':offer.get('url') or ''}
            packet=rpc.encode(self.cache.key(user),destination['public'],group['_id'],group['_id'],'close',{},config['grant'],now=self.clock())
            prepared.append((destination,packet,relay))
        return prepared

    def notify_close(self,user,prepared):
        if not prepared:return {'services_notified':0,'services_unreachable':0}
        import time
        from concurrent.futures import ThreadPoolExecutor
        deadline=time.monotonic()+8
        def notify(value):
            destination,packet,relay=value
            remaining=deadline-time.monotonic()
            if remaining<=0:return 0
            try:
                answer=self.transmit(user,destination,packet,relay,seconds=min(5,remaining))
                context=packet['envelope']['header']['context']
                result=rpc.decode(self.cache.key(user),answer,context['group'],destination['public'],rid=context['id'],action='close:response',now=self.clock())
                return int(bool(result['body'].get('closed')))
            except (CacheError,ControlSyncError):pass
            return 0
        with ThreadPoolExecutor(max_workers=min(4,len(prepared))) as pool:notified=sum(pool.map(notify,prepared))
        return {'services_notified':notified,'services_unreachable':len(prepared)-notified}

    def roster(self,group):
        if not group.get('service_revision') and not self.service.members.find_one({'group_id':group['_id'],'cohost':True,'state':'approved'}):return None
        return service_roster.issue(self.cache,group)

    def fallback_workspace(self,gid,user,link):
        directory=link.get('service_directory')
        if not directory:return None
        issuer=link['source']['crypto_public']
        try:claim=service_roster.verify(directory,issuer,gid,self.clock())
        except CacheError as exc:
            if exc.status==410:return None
            raise
        for candidate in claim['services']:
            if not candidate.get('ready'):continue
            try:
                result=self.call(gid,user,candidate,'workspace',{})
                current=service_roster.verify(result['roster'],issuer,gid,self.clock(),claim['version'])
                active=[dict(m,state='expired') if m.get('expires_at') is not None and m['expires_at']<=self.clock() else m for m in current['members']]
                value={'group':current['group'],'members':active,'contacts':[m for m in active if m['_id']!=link['_id']],
                       'items':[],'applications':[],'rename_requests':[],'self_member_id':link['_id'],
                       'service_member_id':candidate['member_id'],'offline':False,'host_offline':True}
                self.service.links.update_one({'_id':link['_id'],'owner':user['username']},{'$set':{
                    'active_service':candidate,'workspace_snapshot':value,'snapshot_at':self.clock(),'service_directory':result['roster']}})
                return value
            except CacheError as exc:
                if exc.status not in (404,502,503,504,410):raise
        return None

    def poll_services(self):
        now=self.clock();rows=self.service.nonces
        for link in self.service.links.find({'state':'approved','deleted_at':{'$exists':False},'expires_at':{'$gt':now},'service_offer.enabled':True}).limit(100):
            config=self.cache.link_config(link,'node_config')
            if not config:continue
            user={'username':link['owner']};lid='cohost-poller:'+link['_id'];token=secrets.token_hex(16)
            try:rows.insert_one({'_id':lid,'until':0,'expires':datetime.fromtimestamp(now+180,timezone.utc)})
            except DuplicateKeyError:pass
            held=rows.find_one_and_update({'_id':lid,'until':{'$lte':now}},{'$set':{'until':now+60,'owner_token':token}},return_document=ReturnDocument.AFTER)
            if not held:continue
            try:
                client=NodeClient(config,self.cache.key(user),self.clock)
                relay_waits.dispatch(self.cache,user,client,client.call('poll',{'wait':0})['frames'])
            except CacheError:pass
            finally:rows.delete_one({'_id':lid,'owner_token':token})

    def reconcile(self,gid,mid,user,initial=False):
        from .replica_sync import reconcile
        return reconcile(self,gid,mid,user,initial)

    def reconcile_ready(self):
        from .replica_sync import background
        background(self)

    def _local(self,gid,peer):
        group=self.service.groups.find_one({'_id':gid,'enabled':True,'source.crypto_peer':peer})
        if group:return {'username':group['owner']},group,None
        for link in self.service.links.find({'group_id':gid,'state':'approved','deleted_at':{'$exists':False},'expires_at':{'$gt':self.clock()},'service_offer.enabled':True}).limit(100):
            user={'username':link['owner']}
            if self.cache.identity(user)['crypto_peer']==peer:return user,None,link
        raise CacheError('本机未开放此工作区服务 / This workspace service is not enabled locally',404)

    def peer(self,packet,via_peer=None):
        context=((packet or {}).get('envelope') or {}).get('header',{}).get('context') or {}
        gid=identifier(context.get('group'));user,group,link=self._local(gid,context.get('peer'))
        from sentinel_platform.contracts import Collections
        account=self.cache.repo.collection(Collections.USER).find_one({'username':user['username']})
        if not account or account.get('disabled'):raise CacheError('服务账户已停用 / Service account disabled',403)
        opened=rpc.decode(self.cache.key(user),packet,gid,now=self.clock());action=opened['context']['action']
        issuer=(group['source']['crypto_public'] if group else (link.get('source') or {}).get('crypto_public'))
        claim=rpc.grant(issuer,opened['grant'],gid,opened['public'],self.clock())
        if via_peer and via_peer!=opened['peer']:raise CacheError('中转来源与服务身份不符 / Relay origin differs from service identity',403)
        if action in ('hello','setup','close'):
            if opened['peer']!=crypto.peer_id(issuer) or claim['role']!='host' or opened['context']['sender_mid']!=gid:
                raise CacheError('只有管理主持可准备副主持服务 / Only administrative host may prepare co-host service',403)
        else:
            roster=(link.get('service_roster') if link else service_roster.issue(self.cache,group))
            approved=service_roster.verify(roster,issuer,gid,self.clock())
            actor=next((m for m in approved['members'] if m['_id']==opened['context']['sender_mid']),None)
            if not actor or actor['source']['crypto_public']!=opened['public'] or actor.get('expires_at') is not None and actor['expires_at']<=self.clock():
                raise CacheError('调用成员未批准或已过期 / Calling member unapproved or expired',403)
            if link:
                own=next((m for m in approved['members'] if m['_id']==link['_id']),None)
                if not own or own.get('cohost') is not True or own.get('expires_at') is not None and own['expires_at']<=self.clock():
                    raise CacheError('本机副主持资格已撤销或到期 / Local co-host role revoked or expired',403)
                if link.get('service_state')!='ready' and claim['role']!='host':
                    raise CacheError('副主持公共资料尚未就绪 / Co-host public data is not ready',503)
        opened['now']=self.clock()
        marker='service-rpc:'+hashlib.sha256((gid+':'+opened['peer']+':'+opened['context']['id']).encode()).hexdigest()
        digest=hashlib.sha256(canonical(packet)).hexdigest();token=secrets.token_hex(16);now=self.clock();rows=self.service.nonces
        try:rows.insert_one({'_id':marker,'digest':digest,'until':0,'expires':datetime.fromtimestamp(now+180,timezone.utc)})
        except DuplicateKeyError:pass
        existing=rows.find_one({'_id':marker})
        if existing['digest']!=digest:raise CacheError('服务请求ID对应不同内容 / Service request ID conflicts',409)
        if existing.get('answer'):return existing['answer']
        held=rows.find_one_and_update({'_id':marker,'until':{'$lte':now},'answer':{'$exists':False}},
            {'$set':{'until':now+60,'lease_owner':token}},return_document=ReturnDocument.AFTER)
        if not held:raise CacheError('服务请求正在处理 / Service request in progress',425)
        try:
            result=self._execute(user,group,link,gid,action,opened)
        except CacheError as exc:result={'error':str(exc),'status':exc.status}
        except Exception:result={'error':'服务暂不可用 / Service temporarily unavailable','status':503}
        answer=rpc.encode(self.cache.key(user),opened['public'],gid,gid if group else link['_id'],action+':response',result,
            rid=opened['context']['id'],now=self.clock())
        rows.update_one({'_id':marker,'lease_owner':token},{'$set':{'answer':answer,'until':0}})
        return answer

    def _execute(self,user,group,link,gid,action,opened):
        body=opened['body'];issuer=group['source']['crypto_public'] if group else link['source']['crypto_public']
        if action=='hello':return {'public':self.cache.identity(user)['crypto_public'],'node_public':self.cache.local.public,'group_id':gid}
        if action=='close':
            if group:raise CacheError('远端不得关闭管理主持 / Remote service cannot close administrative host',403)
            self.service.links.update_many({'group_id':gid,'source.crypto_public':issuer,'state':{'$in':['joining','approved']}},
                {'$set':{'state':'revoked','service_state':'revoked','service_offer.enabled':False},'$unset':{'service_storage':'','active_service':''}})
            self.cache.tasks.update_many({'group_id':gid,'record_type':'delivery','state':{'$nin':['delivered','cancelled','expired']}},
                {'$set':{'state':'cancelled','error':'工作组已关闭 / Workgroup closed'},'$unset':{'lease_token':'','lease_until':''}})
            with self.cache.local.store._db(True) as db:
                row=db.execute('SELECT meta FROM realms WHERE id=?',(gid,)).fetchone()
                if row:
                    value=json.loads(row['meta']);value['closed']=True
                    db.execute('UPDATE realms SET meta=? WHERE id=?',(canonical(value).decode(),gid))
            return {'closed':True}
        if action=='setup':
            old=link.get('service_roster') if link else None;previous=(old or {}).get('claim',{}).get('version',0)
            approved=service_roster.verify(body.get('roster'),issuer,gid,self.clock(),previous)
            candidate=next((c for c in approved['services'] if c['public']==self.cache.identity(user)['crypto_public']),None)
            if candidate is None:
                if link:self.service.links.update_one({'_id':link['_id'],'owner':user['username']},{'$set':{'service_roster':body['roster'],'service_state':'revoked'},'$unset':{'service_storage':''}})
                with self.cache.local.store._db(True) as db:
                    existing=db.execute('SELECT meta FROM realms WHERE id=?',(gid,)).fetchone()
                    if existing:
                        value=json.loads(existing['meta']);value['closed']=True;db.execute('UPDATE realms SET meta=? WHERE id=?',(canonical(value).decode(),gid))
                return {'revoked':True,'version':approved['version']}
            if candidate['node_public']!=self.cache.local.public:raise CacheError('副主持服务身份未被批准 / Co-host service identity not approved',403)
            config=body.get('config') or {}
            if config.get('realm')!=gid or config.get('issuer_public')!=issuer:raise CacheError('服务存储作用域不匹配 / Service storage scope mismatch',403)
            self.cache.local.setup(self.cache.local.admin,{'realm':gid,'host_public':issuer,'join_token':config['join_token'],
                'member_token':config['member_token'],'policy':dict(approved['policy'],mode='hosted'),'revoked':[]})
            if link:self.service.links.update_one({'_id':link['_id'],'owner':user['username']},
                {'$set':{'service_roster':body['roster'],'service_storage':self.cache.save_config(link['_id'],'service_storage',config),
                         'service_state':link.get('service_state') if link.get('service_state')=='ready' else 'preparing'}})
            return {'installed':True,'version':approved['version'],'node_public':self.cache.local.public,'features':['public-receipts-1']}
        if action=='workspace':
            roster=service_roster.issue(self.cache,group) if group else link['service_roster']
            return {'roster':roster,'service_member_id':gid if group else link['_id'],'node_public':self.cache.local.public}
        if action=='node':
            request=body.get('request') or {};frame=request.get('frame') or {}
            if frame.get('realm')!=gid or frame.get('peer')!=opened['peer']:raise CacheError('存储来源与成员不符 / Storage origin differs from member',403)
            approved=service_roster.verify(service_roster.issue(self.cache,group) if group else link['service_roster'],issuer,gid,self.clock())
            replica_objects.validate_node_request(opened,request,approved)
            if group:return self.cache.local_call(group,opened['context']['sender_mid'],request)
            return self.cache.local.call(request)
        if action in ('mirror_begin','mirror_progress','mirror_put','mirror_commit','mirror_ready','mirror_receipts'):
            if opened['peer']!=crypto.peer_id(issuer) or opened['context']['sender_mid']!=gid:
                raise CacheError('只有主持可准备公共副本 / Only host may prepare public replicas',403)
            approved=service_roster.verify(link['service_roster'],issuer,gid,self.clock())
            if action=='mirror_ready':
                actual=replica_objects.inventory(self.cache,gid)
                expected=body.get('inventory')
                if not isinstance(expected,list) or len(expected)>10000:raise CacheError('公共对账清单无效 / Invalid public inventory')
                stored={i['id']:i for i in actual['items']}
                if any(stored.get(i.get('id'))!=i for i in expected):raise CacheError('公共资料尚有缺块或摘要不符 / Public data missing or checksum mismatched',409)
                self.service.links.update_one({'_id':link['_id'],'owner':user['username']},{'$set':{'service_state':'ready','service_inventory':actual['digest'],'service_ready_at':self.clock()}})
                return {'ready':True,'digest':actual['digest']}
            return replica_objects.mirror(self.cache,gid,approved,action,body,trusted_host=True,recipient_user=user)
        raise CacheError('副主持服务不提供管理操作 / Co-host service does not provide administrative operations',403)
