"""Independent migration realms over the existing signed node transport and AES channel."""
import hashlib,json,secrets,threading,time
from datetime import datetime,timezone
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from .security import ControlSyncError
from ..collaboration_cache import crypto,relay_waits,rpc
from ..collaboration_cache.client import NodeClient,request,endpoint
from ..collaboration_cache.policy import CacheError,normalize,identifier

ACTIONS={'pair','status','confirm','reject','propose','run_status','chunk_status','receive_chunk','receive_commit','export_chunk','complete'}

class NodeRoutes:
    def __init__(self,pairing):
        self.pairing=pairing;self.repo=pairing.repo;self.clock=pairing.clock
        self.collaboration=self;self.nonces=pairing.nonces;self._started=False

    def key(self,user):
        owner=user['username'];ident='sync-node-key:'+hashlib.sha256(owner.encode()).hexdigest()
        rows=self.repo.collection('control_sync_identity');row=rows.find_one({'_id':ident})
        if row is None:
            private=crypto.generate();row={'_id':ident,'owner':owner,'private':self.pairing.secrets.seal(private,ident),'public':crypto.public_pem(private)}
            try:rows.insert_one(row)
            except DuplicateKeyError:row=rows.find_one({'_id':ident})
        if row.get('owner')!=owner:raise ControlSyncError('迁移身份归属不符 / Migration identity owner mismatch',403)
        return self.pairing.secrets.open(row['private'],ident)

    def identity(self,user):
        public=crypto.public_pem(self.key(user));return {'crypto_public':public,'crypto_peer':crypto.peer_id(public)}

    def seal(self,lid,name,value):
        return self.pairing.secrets.seal(json.dumps(value),lid+':'+name)

    def link_config(self,link,name):
        value=link.get(name)
        return json.loads(self.pairing.secrets.open(value,link['_id']+':'+name)) if isinstance(value,str) else value

    def configure(self,doc,user,body):
        if not isinstance(body,dict):raise ControlSyncError('迁移节点参数无效 / Invalid migration node parameters')
        try:
            url=body.get('url');endpoint(url)
            admin=body.get('admin_key');fingerprint=body.get('tls_fingerprint') or ''
            if not isinstance(admin,str) or not 32<=len(admin)<=128:raise CacheError('节点管理凭据无效 / Invalid node administration credential')
            if not isinstance(fingerprint,str) or fingerprint and (len(fingerprint)!=64 or any(c not in '0123456789abcdef' for c in fingerprint)):
                raise CacheError('节点TLS指纹无效 / Invalid node TLS fingerprint')
            config={'url':url,'tls_fingerprint':fingerprint};info=request(config,'/v1/info')
            if info.get('protocol')!='watchtower-node-1' or crypto.peer_id(info.get('public'))!=info.get('peer'):
                raise CacheError('节点身份无效 / Invalid node identity',409)
            config.update(realm=doc['_id'],node_public=info['public'],join_token=secrets.token_urlsafe(32),member_token=secrets.token_urlsafe(32),
                issuer_public=self.identity(user)['crypto_public'],host_peer=self.identity(user)['crypto_peer'])
            request(config,'/v1/setup',{'realm':doc['_id'],'host_public':config['issuer_public'],'join_token':config['join_token'],
                'member_token':config['member_token'],'policy':normalize({'mode':'realtime'}),'revoked':[]},admin)
            config['admin_key']=admin
            return {'route_mode':'node','node_config':self.seal(doc['_id'],'node_config',config)}
        except CacheError as exc:raise ControlSyncError(str(exc),exc.status) from None

    def descriptor(self,doc):
        config=self.link_config(doc,'node_config')
        return {key:config[key] for key in ('url','tls_fingerprint','realm','join_token','issuer_public','host_peer','node_public')}

    def validate(self,value,lid):
        from ..collaboration_cache.service import CacheService
        try:identifier(lid);return CacheService.validate_descriptor(value,lid)
        except CacheError as exc:raise ControlSyncError(str(exc),exc.status) from None

    def connect(self,user,body,lid,secret,descriptor):
        from .security import encode_peer,decode_peer,text,digest
        pairing=self.pairing;rows=pairing.links;doc=rows.find_one({'_id':lid})
        if doc is None:
            now=self.clock();channel=secrets.token_urlsafe(32)
            candidate={'_id':lid,'kind':'initiator','owner':user['username'],'name':text(body.get('name') or descriptor['url'],100),
                'state':'connecting','created_at':now,'pair_expires_at':now+3600,'connection_expires_at':None,'route_mode':'node',
                'local':pairing.identity(),'target':descriptor['url'],'categories':[],'source_confirmed':False,'receiver_confirmed':False,
                'pair_hash':digest(secret),'pair_secret':pairing.secrets.seal(secret,lid+':pair'),
                'channel':pairing.secrets.seal(channel,lid+':channel'),'node_pair_request':secrets.token_hex(16),
                'node_descriptor':self.seal(lid,'node_descriptor',descriptor)}
            try:rows.insert_one(candidate);doc=candidate
            except DuplicateKeyError:doc=rows.find_one({'_id':lid})
        if doc.get('owner')!=user['username'] or doc.get('kind')!='initiator' or doc.get('state')!='connecting' or doc.get('pair_hash')!=digest(secret) or self.link_config(doc,'node_descriptor')!=descriptor:
            raise ControlSyncError('该配对已存在或属于另一身份 / Pairing already exists or belongs to another identity',409)
        pairing.require_owner(doc)
        if self.clock()>=doc['pair_expires_at']:raise ControlSyncError('配对申请已过期 / Pairing request expired',401)
        payload={'identity':pairing.identity(),'channel':pairing.secret_for(doc),'transport_public':self.identity(user)['crypto_public'],
                 'request_id':doc['node_pair_request']}
        packet=encode_peer(secret,lid,'pair',payload,self.clock)
        response=decode_peer(secret,self.send(doc,'pair',packet),'pair:response',self.clock)
        if response.get('error'):raise ControlSyncError(response['error'],response.get('status',400))
        remote=response['link']
        if remote.get('local',{}).get('instance_id')==pairing.instance_id:raise ControlSyncError('不能同步到当前系统 / Cannot pair with the same system')
        values={key:remote.get(key) for key in ('state','pair_expires_at','connection_expires_at','categories','source_confirmed','receiver_confirmed','paired_at')}
        values['remote']=remote['local']
        rows.update_one({'_id':lid,'owner':user['username'],'state':'connecting'},
            {'$set':values,'$unset':{'pair_secret':'','pair_hash':'','peer_error':'','peer_retry_at':''}})
        pairing.remember(doc['target'],doc['name'])
        return pairing.public(rows.find_one({'_id':lid}))

    def resume(self,doc):
        return self.connect({'username':doc['owner']},{'name':doc['name']},doc['_id'],self.pairing.secret_for(doc,pair=True),self.link_config(doc,'node_descriptor'))

    def grant(self,doc,public,role='member'):
        expiry=doc.get('connection_expires_at') if doc.get('state')=='paired' else doc.get('pair_expires_at')
        claim={'realm':doc['_id'],'peer':crypto.peer_id(public),'public':public,'role':role,'expires_at':min(expiry,self.clock()+7*86400)}
        return {'claim':claim,'signature':crypto.sign(self.key({'username':doc['owner']}),claim)}

    def response_config(self,doc):
        if doc.get('route_mode')!='node' or doc.get('state')!='paired':return None
        config=self.link_config(doc,'node_config');config.pop('admin_key',None);config['grant']=self.grant(doc,doc['remote_crypto'])
        return config

    def remember(self,doc,value):
        if not value:return
        original=self.link_config(doc,'node_descriptor');user={'username':doc['owner']}
        try:
            if not isinstance(value,dict) or any(value.get(k)!=original.get(k) for k in original):raise CacheError('迁移节点授权身份改变 / Migration route identity changed',409)
            rpc.grant(original['issuer_public'],value.get('grant'),doc['_id'],self.identity(user)['crypto_public'],self.clock())
            if not isinstance(value.get('member_token'),str) or not 32<=len(value['member_token'])<=128:raise CacheError('迁移节点授权无效 / Invalid migration node grant',403)
        except CacheError as exc:raise ControlSyncError(str(exc),exc.status) from None
        self.pairing.links.update_one({'_id':doc['_id'],'owner':doc['owner'],'state':{'$nin':['revoked','rejected']}},
            {'$set':{'node_config':self.seal(doc['_id'],'node_config',value)}})

    def direct_send(self,target,action,packet,seconds=None):
        from .pairing import transport
        return transport(target,action,packet,timeout_override=seconds)

    def send(self,doc,action,packet,seconds=None):
        if action not in ACTIONS:raise ControlSyncError('迁移节点操作不支持 / Unsupported migration node action',403)
        if not isinstance(packet,dict) or packet.get('id')!=doc['_id'] or packet.get('action')!=action:
            raise ControlSyncError('迁移消息与连接路径不符 / Migration message differs from its route',403)
        from ..collaboration_cache.service import CacheService
        config=self.link_config(doc,'node_config') or self.link_config(doc,'node_descriptor')
        route=dict(doc,target=config['url'],group_id=doc['_id'],source={'crypto_public':config['issuer_public']})
        budget=seconds if seconds is not None else 60 if action in ('propose','receive_commit') else 18
        try:return CacheService.transport(self,route,action,packet,{'username':doc['owner']},seconds=budget)
        except CacheError as exc:raise ControlSyncError(str(exc),exc.status) from None

    def close(self,doc,defer=False):
        if doc.get('kind')!='receiver' or doc.get('route_mode')!='node':return
        jobs=self.repo.collection('control_sync_node_closures')
        jobs.update_one({'_id':doc['_id']},{'$setOnInsert':{'owner':doc['owner'],'node_config':doc['node_config'],
            'until':self.clock()+7*86400+120,'retry_at':self.clock()+(3 if defer else 0)}},upsert=True)
        if not defer:self.flush_closures()

    def flush_closures(self):
        jobs=self.repo.collection('control_sync_node_closures');now=self.clock()
        jobs.delete_many({'until':{'$lte':now}})
        for job in jobs.find({'retry_at':{'$lte':now}}).limit(2):
            token=secrets.token_hex(16)
            held=jobs.find_one_and_update({'_id':job['_id'],'$or':[{'lease_until':{'$exists':False}},{'lease_until':{'$lte':now}}]},
                {'$set':{'lease_until':now+30,'lease_owner':token}})
            if not held:continue
            try:
                config=self.link_config(job,'node_config')
                request(config,'/v1/setup',{'realm':job['_id'],'host_public':config['issuer_public'],'join_token':config['join_token'],
                    'member_token':config['member_token'],'policy':normalize({'mode':'realtime'}),'closed':True},config['admin_key'],timeout=2)
                jobs.delete_one({'_id':job['_id'],'lease_owner':token})
            except (ControlSyncError,CacheError):
                jobs.update_one({'_id':job['_id'],'lease_owner':token},{'$set':{'retry_at':self.clock()+10},'$unset':{'lease_owner':'','lease_until':''}})

    def peer(self,action,packet,via_peer=None):
        if action not in ACTIONS or not via_peer:raise ControlSyncError('迁移节点来源无效 / Invalid migration relay origin',403)
        return self.pairing.handle_peer(action,packet,via_peer=via_peer)

    def peer_relay(self,action,packet,via_peer=None,via_realm=None):
        if not isinstance(packet,dict) or packet.get('id')!=via_realm:
            raise ControlSyncError('迁移消息不属于该中转路径 / Migration message belongs to another relay realm',403)
        return self.peer(action,packet,via_peer=via_peer)

    def tick(self):
        self.flush_closures()
        now=self.clock();rows=self.pairing.links
        query={'kind':'receiver','route_mode':'node','state':{'$in':['available','pending','paired']},'deleted_at':{'$exists':False},
            '$or':[{'state':{'$in':['available','pending']},'pair_expires_at':{'$gt':now}},{'state':'paired','connection_expires_at':{'$gt':now}}]}
        for doc in rows.find(query).sort('node_polled_at',1).limit(4):
            lid='sync-node-poll:'+doc['_id'];token=secrets.token_hex(16)
            try:self.nonces.insert_one({'_id':lid,'until':0,'expires':datetime.fromtimestamp(now+120,timezone.utc)})
            except DuplicateKeyError:pass
            held=self.nonces.find_one_and_update({'_id':lid,'until':{'$lte':self.clock()}},
                {'$set':{'until':self.clock()+120,'expires':datetime.fromtimestamp(self.clock()+180,timezone.utc),'lease_owner':token}},return_document=ReturnDocument.AFTER)
            if not held:continue
            try:
                fresh=rows.find_one({'_id':doc['_id'],'state':doc['state'],'deleted_at':{'$exists':False}})
                if not fresh:continue
                self.pairing.require_owner(fresh);user={'username':doc['owner']}
                config=self.link_config(fresh,'node_config');config['grant']=self.grant(fresh,self.identity(user)['crypto_public'],'host')
                client=NodeClient(config,self.key(user),self.clock);client.deadline=time.monotonic()+2
                frames=client.call('poll',{'wait':0})['frames']
                # A snapshot/apply operation must not consume the short poll network budget.
                client.deadline=None
                relay_waits.dispatch(self,user,client,frames)
                rows.update_one({'_id':doc['_id']},{'$unset':{'node_error':''}})
            except (ControlSyncError,CacheError) as exc:rows.update_one({'_id':doc['_id']},{'$set':{'node_error':str(exc)}})
            finally:
                rows.update_one({'_id':doc['_id']},{'$set':{'node_polled_at':self.clock()}})
                self.nonces.delete_one({'_id':lid,'lease_owner':token})

    def start(self):
        if self._started:return
        self._started=True
        def run():
            while True:
                try:self.tick()
                except Exception:pass
                time.sleep(1)
        threading.Thread(target=run,daemon=True,name='watchtower-migration-node').start()
