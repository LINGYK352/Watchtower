"""Application adapter: owned node settings, identities and outbound peer routing."""
import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from sentinel_platform.contracts import Collections
from . import crypto
from .client import NodeClient, endpoint, request
from .policy import CacheError, canonical, identifier, normalize, managed_path
from .delivery import DeliveryService
from .node import NodeCore
from . import node_settings
from .notifications import Notifications
from . import relay_waits
from . import leave_notices
from .service_replica import Replicas


class CacheService(DeliveryService):
    def __init__(self, collaboration):
        self.collaboration = collaboration
        self.repo, self.control, self.clock = collaboration.repo, collaboration.control, collaboration.clock
        self.keys = self.repo.collection('control_sync_identity')
        self.nodes = self.repo.collection('collaboration_nodes')
        self.tasks = collaboration.uploads
        self.trust = self.repo.collection('collaboration_peer_trust')
        self.directory = managed_path(collaboration.directory / 'delivery')
        self.directory.mkdir(parents=True, exist_ok=True)
        self.receive_locks=self.repo.collection('collaboration_receive_locks')
        self.receive_locks.create_index('expires',expireAfterSeconds=0)
        self.received = self.repo.collection('collaboration_received')
        self.received.create_index([('owner', 1), ('group_id', 1), ('audience', 1), ('participants', 1), ('sequence', 1)])
        self.received.create_index([('owner',1),('group_id',1),('audience',1),('posted_at',-1),('item_id',-1)])
        self.tasks.create_index([('record_type', 1), ('state', 1), ('retry_at', 1)])
        self.received.create_index([('owner',1),('group_id',1),('sequence',1),('sender',1)])
        self.local = NodeCore(self.directory / 'local-relay', 'cache', clock=self.clock,shared_relay=True)
        self.notifications=Notifications(self)
        self.replicas=Replicas(self)
        self._started = False

    def key(self, user):
        owner = user['username']
        ident = 'collaboration-key:' + hashlib.sha256(owner.encode()).hexdigest()
        row = self.keys.find_one({'_id': ident})
        if row is None:
            value = crypto.generate()
            row = {'_id': ident, 'owner': owner, 'private': self.control.secrets.seal(value, ident),
                   'public': crypto.public_pem(value), 'created_at': self.clock()}
            try:
                self.keys.insert_one(row)
            except DuplicateKeyError:
                row = self.keys.find_one({'_id': ident})
        if row.get('owner') != owner:
            raise CacheError('本机身份归属不匹配 / Local identity ownership mismatch', 403)
        return self.control.secrets.open(row['private'], ident)

    def identity(self, user):
        pub = crypto.public_pem(self.key(user))
        return {'crypto_public': pub, 'crypto_peer': crypto.peer_id(pub),
                'crypto_fingerprint': crypto.fingerprint(pub), 'crypto_protocol': 1,'crypto_features':{'attachments':1}}

    def peer_identity(self,gid,mid,user):
        access,snapshot=self._snapshot(gid,user)
        member=next((m for m in snapshot['members'] if m['_id']==mid and m['state']=='approved'),None)
        if not member or not member.get('source',{}).get('crypto_public'):raise CacheError('成员通信身份不可用 / Member communication identity unavailable',404)
        fingerprint=crypto.fingerprint(member['source']['crypto_public'])
        known=self.trust.find_one({'owner':user['username'],'group_id':gid,'member_id':mid})
        return {'member_id':mid,'name':member['name'],'fingerprint':fingerprint,'verified':bool(known and known['fingerprint']==fingerprint),
                'self_fingerprint':self.identity(user)['crypto_fingerprint']}

    def pin_peer(self,gid,mid,user,public):
        # The roster was obtained via the authenticated membership channel and
        # verified host/service directory. First use is automatic; key changes
        # still require explicit identity recovery, never an automatic overwrite.
        fingerprint=crypto.fingerprint(public)
        rid=hashlib.sha256((user['username']+':'+gid+':'+mid).encode()).hexdigest()
        try:
            self.trust.update_one({'_id':rid},{'$setOnInsert':{'owner':user['username'],'group_id':gid,'member_id':mid,'fingerprint':fingerprint,'verified_at':self.clock(),'method':'authenticated_roster'}},upsert=True)
        except DuplicateKeyError:pass
        known=self.trust.find_one({'_id':rid})
        # Old manually verified rows may predate the deterministic identifier.
        others=self.trust.find({'owner':user['username'],'group_id':gid,'member_id':mid})
        if not known or any(row.get('fingerprint')!=fingerprint for row in others):
            raise CacheError('成员通信身份发生变化，请重新核验 / Member cryptographic identity changed; verify before continuing',409)
        return fingerprint

    def verify_peer(self,gid,mid,user,body):
        info=self.peer_identity(gid,mid,user)
        expected=body.get('fingerprint')
        if body.get('confirmed') is not True or not isinstance(expected,str) or expected.lower().strip()!=info['fingerprint']:
            raise CacheError('指纹不匹配，请通过独立可信渠道核验 / Fingerprint mismatch; verify through an independent trusted channel',409)
        rid=hashlib.sha256((user['username']+':'+gid+':'+mid).encode()).hexdigest()
        self.trust.update_one({'_id':rid},{'$set':{'owner':user['username'],'group_id':gid,'member_id':mid,
            'fingerprint':info['fingerprint'],'verified_at':self.clock()}},upsert=True)
        return dict(info,verified=True)

    @staticmethod
    def public_node(row, now=None):
        from .node_health import public
        result = {key: row.get(key) for key in ('_id','group_id','name','url','tls_fingerprint','peer','mode','enabled','checked_at','error')}
        result['health'] = public(row, time.time() if now is None else now)
        return result

    def node_list(self, user, gid=None, refresh=False):
        return node_settings.list_nodes(self,user,gid,refresh=refresh)

    def add_node(self, user, body):
        return node_settings.add(self,user,body)

    def _node(self, nid, user, gid=None):
        return node_settings.owned(self,nid,user,gid)

    def close_group(self,group,user):
        return node_settings.close_group(self,group,user)

    def delete_node(self, nid, user):
        self._node(nid, user)
        if self.collaboration.groups.find_one({'owner': user['username'], 'enabled': True, 'cache_policy.node_id': nid}):
            raise CacheError('节点仍被工作组使用，请先切换缓存/路由 / Node still used by a workgroup; switch its cache/route first', 409)
        if self.collaboration.groups.find_one({'owner':user['username'],'draining_nodes':{'$elemMatch':{'access.node_id':nid,'until':{'$gt':self.clock()}}}}):
            raise CacheError('节点仍有保留期内的缓存路径 / Node has cache routes within their retention window',409)
        if self.tasks.find_one({'owner': user['username'], 'record_type': 'delivery', 'node_id': nid,
                                'state': {'$in': ['queued', 'uploading', 'hosted']}}):
            raise CacheError('节点仍有待交付任务 / Node has pending deliveries', 409)
        self.nodes.delete_one({'_id': nid, 'owner': user['username']})
        return {'deleted': True}

    def configure(self, gid, user, body):
        group = self.collaboration._host(gid, user)
        if not group.get('source',{}).get('crypto_public'):
            identity=self.identity(user);source=dict(group.get('source') or {},**identity)
            self.collaboration.groups.update_one({'_id':gid,'owner':user['username']},{'$set':{'source':source}})
            self.collaboration.members.update_one({'_id':gid,'group_id':gid,'host':True},{'$set':{'source':source}})
            group=dict(group,source=source)
        policy = normalize(body, group.get('cache_policy'))
        incompatible = [m['name'] for m in self.collaboration.members.find({'group_id': gid, 'state': 'approved'})
                        if not m.get('source', {}).get('crypto_public')]
        if incompatible:
            raise CacheError('成员尚未升级加密交付，请先更新 / Members must upgrade encrypted delivery before hosting', 409)
        if policy['mode'] == 'hosted' and not policy['node_id']:
            raise CacheError('离线托管模式必须选择节点 / Offline hosting requires a node')
        access = group.get('node_access')
        drains=[r for r in group.get('draining_nodes',[]) if r['until']>self.clock()]
        previous=normalize(group.get('cache_policy'))
        if access and previous['mode']=='hosted' and (policy['node_id']!=previous['node_id'] or policy['mode']!='hosted'):
            if len(drains)>=4:raise CacheError('先等待旧缓存到期后再切换更多节点 / Wait for old cache retention before adding more routes',409)
            drains.append({'access':access,'until':self.clock()+max(previous['pending_days'],previous['shared_days'])*86400,
                           'policy':dict(previous,mode='realtime')})
        if policy['node_id']:
            node = self._node(policy['node_id'], user,gid)
            policy['node_id']=node['_id']
            if access and access.get('node_id')==node.get('migrated_from'):access=dict(access,node_id=node['_id'])
            if not node.get('enabled'):
                raise CacheError('节点已停用 / Node disabled', 409)
            if policy['mode'] == 'hosted' and node['mode'] != 'cache':
                raise CacheError('所选节点未开启托管 / Selected node has no hosting capability', 409)
            key = self.key(user)
            if not access or access.get('node_id') != node['_id']:
                access = {'node_id': node['_id'], 'join': self.control.secrets.seal(secrets.token_urlsafe(32), gid + ':node-join'),
                          'member': self.control.secrets.seal(secrets.token_urlsafe(32), gid + ':node-member')}
            config = self._host_config(dict(group, node_access=access, cache_policy=policy), user)
            self._setup(dict(group, cache_policy=policy), config, node, user)
        self.collaboration.groups.update_one({'_id': gid, 'owner': user['username'], 'enabled': True},
                                             {'$set': {'cache_policy': policy, 'node_access': access,'draining_nodes':drains,'crypto_format':1,
                                                       'legacy_history':group.get('legacy_history') or group.get('crypto_format')!=1}})
        return {'policy': policy, 'node': self.public_node(self._node(policy['node_id'], user)) if policy['node_id'] else None}

    def _grant(self, gid, key, pub, expires, role='member'):
        claim = {'realm': gid, 'peer': crypto.peer_id(pub), 'public': pub, 'expires_at': expires, 'role': role}
        return {'claim': claim, 'signature': crypto.sign(key, claim)}

    def _host_config(self, group, user):
        access = group['node_access']; node = self._node(access['node_id'], user,group['_id'])
        key = self.key(user); pub = crypto.public_pem(key)
        return {'url': node['url'], 'tls_fingerprint': node.get('tls_fingerprint') or '', 'realm': group['_id'],
                'node_public': node['public'], 'join_token': self.control.secrets.open(access['join'], group['_id'] + ':node-join'),
                'member_token': self.control.secrets.open(access['member'], group['_id'] + ':node-member'),
                'issuer_public': pub, 'host_peer': crypto.peer_id(pub),
                'grant': self._grant(group['_id'], key, pub, self.clock() + 7 * 86400, 'host')}

    def _setup(self, group, config, node, user):
        key = self.control.secrets.open(node['admin_key'], node['_id'] + ':node-admin')
        revoked = [crypto.peer_id(m['source']['crypto_public']) for m in self.collaboration.members.find(
            {'group_id': group['_id'], 'host': {'$ne': True}, 'state': {'$in': ['revoked', 'rejected']}})
            if m.get('source', {}).get('crypto_public')]
        return request(config, '/v1/setup', {'realm': group['_id'], 'host_public': config['issuer_public'],
                    'join_token': config['join_token'], 'member_token': config['member_token'],
                    'policy': normalize(group.get('cache_policy')), 'revoked': revoked,'closed':not group.get('enabled',True)}, key)

    def descriptor(self, group):
        if not group.get('node_access') or not (group.get('cache_policy') or {}).get('node_id'):
            return None
        config = self._host_config(group, {'username': group['owner']})
        return {key: config[key] for key in ('url', 'tls_fingerprint', 'realm', 'join_token', 'issuer_public', 'host_peer', 'node_public')}

    @staticmethod
    def validate_descriptor(value, gid):
        fields = ('url', 'tls_fingerprint', 'realm', 'join_token', 'issuer_public', 'host_peer', 'node_public')
        if not isinstance(value, dict) or set(value) != set(fields) or value['realm'] != gid:
            raise CacheError('节点邀请连接格式无效 / Invalid node invitation route')
        endpoint(value['url'])
        if crypto.peer_id(value['issuer_public']) != value['host_peer']:
            raise CacheError('邀请主持身份不匹配 / Invitation host identity mismatch', 401)
        crypto.public(value['node_public'])
        if not isinstance(value['join_token'], str) or not 32 <= len(value['join_token']) <= 128:
            raise CacheError('邀请路径凭据无效 / Invalid invitation route credential')
        fingerprint = value['tls_fingerprint']
        if not isinstance(fingerprint, str) or fingerprint and (len(fingerprint) != 64 or any(c not in '0123456789abcdef' for c in fingerprint)):
            raise CacheError('节点证书指纹无效 / Invalid node certificate fingerprint')
        return {key: value[key] for key in fields}

    def member_access(self, group, actor):
        if actor.get('state') != 'approved' or not group.get('node_access'):
            return None
        pub = actor.get('source', {}).get('crypto_public')
        if not pub:
            return None
        key = self.key({'username': group['owner']})
        config = self._host_config(group, {'username': group['owner']})
        config['grant'] = self._grant(group['_id'], key, pub, min(actor['expires_at'], self.clock() + 7 * 86400))
        return config

    def transport(self, link, action, packet, user, seconds=None):
        config = self.link_config(link, 'node_config') or self.link_config(link, 'node_descriptor')
        from . import routes
        public=(link.get('source') or {}).get('crypto_public') or (config or {}).get('issuer_public')
        gid=link.get('group_id') or (config or {}).get('realm')
        def done(value,path):
            routes.remember(self,user,gid,public,path)
            return value
        if not config:
            return done(self.collaboration.direct_send(link['target'],action,packet,seconds=seconds),'direct')
        if link['target'].rstrip('/') != config['url'].rstrip('/'):
            try:
                return done(self.collaboration.direct_send(link['target'],action,packet,seconds=seconds),'direct')
            except Exception as exc:
                if getattr(exc, 'status', 0) not in (502, 503, 504):
                    raise
        key = self.key(user); client = NodeClient(config, key, self.clock)
        budget=seconds if seconds is not None else (2 if action=='leave' else 18)
        client.deadline=time.monotonic()+budget
        joining = not bool(config.get('grant')) or (config.get('grant') or {}).get('claim',{}).get('expires_at',0)<=self.clock()
        rid = secrets.token_hex(16)
        marker=relay_waits.register(self,user,config['realm'],rid,config['issuer_public'])
        try:
            client.call('relay',{'id':rid,'destination':config['host_peer'],'data':{'action':action,'packet':packet}},joining)
            until=client.deadline
            while time.monotonic()<until:
                answer=relay_waits.take(self,user,marker)
                if answer is not None:return done(answer,'node')
                frames=client.call('poll',{'wait':1},joining)['frames']
                relay_waits.dispatch(self,user,client,frames)
            raise CacheError('主持节点暂不可达，本地资料保留 / Host temporarily unreachable; local data retained',502)
        finally:relay_waits.discard(self,user,marker)

    def start(self):
        if self._started:
            return
        self._started = True
        self.notifications.start()
        threading.Thread(target=self._run, daemon=True, name='watchtower-collaboration-delivery').start()

    def _run(self):
        while True:
            try:
                self.tick()
            except Exception:
                pass  # No content or credential logging; operations expose their own status.
            time.sleep(2)

    def tick(self):
        node_settings.flush_closures(self)
        lock=self.collaboration.nonces
        for group in self.collaboration.groups.find({'node_access':{'$ne':None},'enabled':True}).limit(100):
            if not group.get('node_access'):continue
            now=self.clock();token=secrets.token_hex(16);lid='node-poller:'+group['_id']
            try:lock.insert_one({'_id':lid,'until':0,'expires':datetime.fromtimestamp(now+360,timezone.utc)})
            except DuplicateKeyError:pass
            held=lock.find_one_and_update({'_id':lid,'until':{'$lte':now}},{'$set':{'owner_token':token,'until':now+240,
                'expires':datetime.fromtimestamp(now+360,timezone.utc)}},return_document=ReturnDocument.AFTER)
            if not held:continue
            try:
                user={'username':group['owner']};owner=self.repo.collection(Collections.USER).find_one({'username':group['owner']})
                if not owner or owner.get('disabled'):group=dict(group,enabled=False)
                routes=[group]+[dict(group,node_access=r['access'],cache_policy=r['policy']) for r in group.get('draining_nodes',[]) if r['until']>now and r['access']['node_id']!=group['node_access']['node_id']]
                for route in routes:
                    node=self._node(route['node_access']['node_id'],user,group['_id']);config=self._host_config(route,user)
                    self._setup(route,config,node,user)
                    if not group.get('enabled'):continue
                    key=self.key(user);client=NodeClient(config,key,self.clock)
                    relay_waits.dispatch(self,user,client,client.call('poll',{'wait':0})['frames'])
                    lock.update_one({'_id':lid,'owner_token':token},{'$set':{'until':self.clock()+240}})
                    self.nodes.update_one({'_id':node['_id'],'owner':user['username']},{'$set':{'checked_at':self.clock(),'error':''}})
            except Exception as exc:
                self.collaboration.groups.update_one({'_id':group['_id']},{'$set':{'node_error':str(exc) if isinstance(exc,CacheError) else '节点路径暂不可用 / Node route temporarily unavailable'}})
            finally:lock.delete_one({'_id':lid,'owner_token':token})
        self.replicas.poll_services()
        self.replicas.reconcile_ready()
        self.advance_tasks()  # One unreachable group must not block another source outbox.
