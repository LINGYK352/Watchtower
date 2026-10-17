"""Durable source outbox and recipient receipts; routing never owns plaintext."""
import hashlib
import io
import json
import secrets
import shutil
import struct
from datetime import datetime, timezone
from pathlib import Path
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from . import crypto
from .client import NodeClient
from .policy import CacheError, MIB, canonical, identifier, normalize, archive_manifest


class LocalClient(NodeClient):
    """Same signed object protocol over an existing authenticated group connection."""
    def __init__(self, service, gid, user, config):
        super().__init__(config, service.key(user), service.clock)
        self.service, self.gid, self.user = service, gid, user

    def call(self, action, body=None, joining=False):
        frame = {'realm': self.gid, 'peer': self.peer, 'public': self.public,
                 'ts': int(self.clock()), 'nonce': secrets.token_hex(16), 'action': action,
                 'body': body or {}, 'token': self.config['member_token'], 'grant': self.config['grant']}
        packet = {'frame': frame, 'signature': crypto.sign(self.private, frame)}
        access = self.service.collaboration._access(self.gid, self.user)
        if access['host']:
            return self.service.local_call(access['group'], self.gid, packet)
        return self.service.collaboration._request(access['link'], 'cache_call', {'request': packet})


class DeliveryService:
    def save_config(self, mid, name, value):
        return self.control.secrets.seal(json.dumps(value, ensure_ascii=False), mid + ':' + name) if value else None

    def link_config(self, link, name):
        value = link.get(name)
        if isinstance(value, str):
            return json.loads(self.control.secrets.open(value, link['_id'] + ':' + name))
        return value  # Existing test preparations may contain a raw dictionary.

    def direct_access(self, group, actor):
        access = group.get('delivery_access')
        if not access:
            candidate = {'join': self.control.secrets.seal(secrets.token_urlsafe(32), group['_id'] + ':direct-join'),
                         'member': self.control.secrets.seal(secrets.token_urlsafe(32), group['_id'] + ':direct-member')}
            self.collaboration.groups.update_one({'_id': group['_id'], 'delivery_access': {'$exists': False}},
                                                 {'$set': {'delivery_access': candidate}})
            access = self.collaboration.groups.find_one({'_id': group['_id']})['delivery_access']
        host_key = self.key({'username': group['owner']}); pub = crypto.public_pem(host_key)
        recipient = actor.get('source', {}).get('crypto_public')
        if not recipient or actor.get('state') != 'approved':
            return None
        until = min(actor.get('expires_at') or self.clock() + 7 * 86400, self.clock() + 7 * 86400)
        return {'realm': group['_id'], 'node_public': self.local.public, 'issuer_public': pub,
                'join_token': self.control.secrets.open(access['join'], group['_id'] + ':direct-join'),
                'member_token': self.control.secrets.open(access['member'], group['_id'] + ':direct-member'),
                'grant': self._grant(group['_id'], host_key, recipient, until, 'host' if actor.get('host') else 'member')}

    def access_reply(self, group, actor):
        if actor.get('state') != 'approved':
            return {}
        if actor.get('source',{}).get('crypto_public'):
            try:self.extend_public(group,actor)
            except CacheError as exc:
                if exc.status not in (409,429,502,503,504,507):raise
        return {'peer_config': self.direct_access(group, actor), 'node_config': self.member_access(group, actor),
                'service_roster':self.replicas.roster(group),
                'drain_configs':[self.member_access(dict(group,node_access=r['access']),actor) for r in group.get('draining_nodes',[]) if r['until']>self.clock()],
                'cache_policy': normalize(group.get('cache_policy'))}

    def remember_reply(self, link, result):
        values = {}
        if result.get('service_roster'):
            roster=result['service_roster'];issuer=(link.get('source') or {}).get('crypto_public') or ((result.get('group') or {}).get('source') or {}).get('crypto_public')
            from . import service_roster
            service_roster.verify(roster,issuer,link['group_id'],self.clock(),(link.get('service_directory') or {}).get('claim',{}).get('version',0))
            values['service_directory']=roster
        values['active_service']=None
        for name in ('peer_config', 'node_config','drain_configs'):
            if name in result:
                configs=result[name] if name=='drain_configs' else [result[name]]
                expected=link.get('source',{}).get('crypto_public')
                if expected and any(value and crypto.peer_id(value.get('issuer_public'))!=crypto.peer_id(expected) for value in configs or []):
                    raise CacheError('主持通信身份发生变化，已停止连接 / Host communication identity changed; connection stopped',409)
                values[name] = self.save_config(link['_id'], name, result.pop(name))
        if 'cache_policy' in result:
            values['cache_policy'] = result['cache_policy']
        if values:
            source=(result.get('group') or {}).get('source') or {}
            if source.get('crypto_public') and not link.get('source',{}).get('crypto_public'):
                values['source']={**link.get('source',{}),**{k:source[k] for k in ('crypto_public','crypto_peer','crypto_protocol') if k in source}}
            self.collaboration.links.update_one({'_id': link['_id'], 'owner': link['owner'], 'deleted_at': {'$exists': False}}, {'$set': values})
        return result

    def extend_public(self,group,actor,limit=10):
        """Later-approved members retain public history without rewriting its author's signature."""
        if actor.get('host'):return
        user={'username':group['owner']};pub=actor.get('source',{}).get('crypto_public')
        if not pub:return
        recipient=crypto.peer_id(pub);client=self._client(group['_id'],user)
        key=self.key(user);count=0
        for summary in client.call('list')['items']:
            if summary['state']!='stored':continue
            if summary.get('audience')!='group':continue
            if recipient in summary.get('recipients',[]):
                delegated=summary.get('delegation_expires',{})
                if recipient not in delegated or delegated[recipient]>self.clock()+86400:continue
            meta=client.call('metadata',{'id':summary['id']})['manifest']
            if meta['audience']!='group' or recipient in meta['envelope']['header']['keys']:continue
            previous=(meta['envelope'].get('recipient_grants') or {}).get(recipient,{}).get('claim',{}).get('expires_at',0)
            if recipient in meta['recipients'] and previous>self.clock()+86400:continue
            until=min(actor.get('expires_at') or self.clock()+7*86400,self.clock()+7*86400)
            grants={'main':crypto.grant_recipient(meta['envelope'],key,pub,until),
                    'caption':crypto.grant_recipient(meta['caption']['envelope'],key,pub,until)}
            client.call('grant_recipient',{'id':summary['id'],'grants':grants});count+=1
            if count>=limit:break

    def local_call(self, group, mid, packet):
        actor = self.collaboration.room_member(group['_id'], mid)
        pub = actor.get('source', {}).get('crypto_public')
        if not pub or (packet.get('frame') or {}).get('peer') != crypto.peer_id(pub):
            raise CacheError('请求身份与成员不一致 / Request identity does not match membership', 403)
        config = self.direct_access(group, actor)
        revoked = [crypto.peer_id(m['source']['crypto_public']) for m in self.collaboration.members.find(
            {'group_id': group['_id'], 'state': {'$in': ['revoked', 'rejected']}}) if m.get('source', {}).get('crypto_public')]
        policy = dict(normalize(group.get('cache_policy')), mode='hosted')
        self.local.setup(self.local.admin, {'realm': group['_id'], 'host_public': config['issuer_public'],
                         'join_token': config['join_token'], 'member_token': config['member_token'], 'policy': policy, 'revoked': revoked})
        frame = packet.get('frame') or {}; action = frame.get('action'); body = frame.get('body') or {}
        if action in ('put','progress','commit') and body.get('id'):
            with self.local.store._db(True) as db:
                row=db.execute('SELECT * FROM objects WHERE id=? AND realm=? AND sender=?',(identifier(body['id']),group['_id'],frame.get('peer'))).fetchone()
                if row and not row['shared'] and row['state'] in ('uploading','committing','stored') and row['expires']>self.clock():
                    original=((json.loads(row['meta']).get('envelope') or {}).get('header') or {}).get('context',{}).get('expires_at',row['expires'])
                    db.execute('UPDATE objects SET expires=? WHERE id=?',(min(original,self.clock()+120),body['id']))
        if action == 'reserve':
            meta = body.get('manifest') or {}; context = ((meta.get('envelope') or {}).get('header') or {}).get('context') or {}
            if context.get('sender_mid') != mid:
                raise CacheError('发送成员不匹配 / Sender membership mismatch', 403)
            if meta.get('audience') == 'direct':
                target = self.collaboration.room_member(group['_id'], context.get('peer_mid'))
                allowed = {crypto.peer_id(pub), crypto.peer_id(target.get('source', {}).get('crypto_public'))}
            else:
                approved = [m for m in self.collaboration.members.find({'group_id': group['_id'], 'state': 'approved'})
                            if m.get('expires_at') is None or m['expires_at'] > self.clock()]
                allowed = {crypto.peer_id(m['source']['crypto_public']) for m in approved if m.get('source', {}).get('crypto_public')}
            actual=set(meta.get('recipients') or [])
            if meta.get('audience')=='direct' and actual!=allowed or meta.get('audience')=='group' and (not actual.issubset(allowed) or crypto.peer_id(pub) not in actual or self.identity({'username':group['owner']})['crypto_peer'] not in actual):
                raise CacheError('接收范围已变化，请重新确认 / Recipient scope changed; reconfirm', 409)
            if meta.get('audience') == 'direct':
                if not target.get('host') and target.get('online_at', 0) < self.clock() - 45:
                    raise CacheError('接收者离线，原数据在发送方等待 / Recipient offline; source retained by sender', 425)
                self.local.store.renew_ephemeral(meta['id'], group['_id'], frame['peer'], meta)
        result = self.local.call(packet)
        if action == 'reserve' and (body.get('manifest') or {}).get('audience') == 'direct':
            with self.local.store._db(True) as db:
                db.execute('UPDATE objects SET expires=MIN(expires,?) WHERE id=?', (self.clock() + 120, body['manifest']['id']))
        return result

    def workspace(self, gid, user):
        service = self.collaboration; access = service._access(gid, user)
        if access['host']:
            result = service._workspace(gid, access['member_id'], host=True)
        else:
            link = access['link']
            try:
                result = service._request(link,'workspace',{},seconds=3 if link.get('service_directory') else None)
                previous = link.get('workspace_snapshot') or {}
                previous_keys = {m['_id']: m.get('source', {}).get('crypto_public') for m in previous.get('members', [])}
                for member in result.get('members', []):
                    known = previous_keys.get(member['_id']); present = member.get('source', {}).get('crypto_public')
                    if known and present != known:
                        raise CacheError('成员身份密钥变化，已停止同步；请重新核验连接 / Member identity changed; sync stopped; verify the connection', 409)
                service.links.update_one({'_id': link['_id'], 'owner': user['username'], 'deleted_at': {'$exists': False}},
                                         {'$set': {'workspace_snapshot': result, 'snapshot_at': self.clock()}})
            except Exception as exc:
                if getattr(exc, 'status', 0) not in (502, 503, 504) or not link.get('workspace_snapshot'):
                    raise
                alternative=self.replicas.fallback_workspace(gid,user,link)
                result = alternative if alternative is not None else dict(link['workspace_snapshot'], offline=True)
        from . import routes
        if result.get('offline'):
            result['service_member_id']=None;result['service_route']='offline';result['host_offline']=True
        elif access['host']:
            result['service_member_id']=gid;result['service_route']='local';result['host_offline']=False
        else:
            selected=not result.get('host_offline')
            if selected:result['service_member_id']=gid
            member=next((m for m in result.get('members',[]) if m['_id']==result.get('service_member_id')),None)
            result['service_route']=routes.latest(self,user,gid,(member or {}).get('source',{}).get('crypto_public'))
        if not access['host']:
            own=access['link'].get('service_offer') or {}
            result['self_service']={'enabled':bool(own.get('enabled')),'url':own.get('url') or '',
                                    'state':access['link'].get('service_state') or ''}
        result['cache_policy'] = normalize(result['group'].get('cache_policy') or access.get('link', {}).get('cache_policy'))
        result['delivery'] = self.delivery_status(gid, user)
        return result

    def _snapshot(self, gid, user):
        access = self.collaboration._access(gid, user)
        if access['host']:
            snapshot = self.collaboration._workspace(gid, gid, host=True)
        else:
            snapshot = access['link'].get('workspace_snapshot')
            if not snapshot:
                snapshot = self.workspace(gid, user)
            access = self.collaboration._access(gid, user)
        return access, snapshot

    def _client(self, gid, user, access=None, explicit=None):
        access = access or self.collaboration._access(gid, user)
        if explicit is not None:
            if explicit.get('rpc_service'):
                from .service_client import ServiceClient
                return ServiceClient(self,gid,user,explicit)
            return NodeClient(explicit, self.key(user), self.clock) if explicit.get('url') else LocalClient(self, gid, user, explicit)
        if access['host']:
            policy = normalize(access['group'].get('cache_policy'))
            if policy['mode'] == 'hosted':
                from .public_union import PublicUnionClient
                primary=NodeClient(self._host_config(access['group'],user),self.key(user),self.clock)
                actor=self.collaboration.members.find_one({'_id':gid,'group_id':gid})
                return PublicUnionClient(primary,LocalClient(self,gid,user,self.direct_access(access['group'],actor)))
            actor = self.collaboration.members.find_one({'_id': gid, 'group_id': gid})
            return LocalClient(self, gid, user, self.direct_access(access['group'], actor))
        link = access['link']; policy = normalize(link.get('cache_policy'))
        if link.get('active_service'):
            from .service_client import ServiceClient
            config=dict(self.link_config(link,'peer_config') or {},rpc_service=link['active_service'],node_public=link['active_service']['node_public'])
            alternate=ServiceClient(self,gid,user,config)
            node=self.link_config(link,'node_config')
            if policy['mode']=='hosted' and node:
                from .public_union import PublicUnionClient
                return PublicUnionClient(NodeClient(node,self.key(user),self.clock),alternate,public_writes=True)
            return alternate
        config = self.link_config(link, 'node_config' if policy['mode'] == 'hosted' else 'peer_config')
        if not config:
            raise CacheError('对端未提供加密交付能力，请更新并刷新连接 / Peer lacks encrypted delivery; update and refresh the connection', 409)
        if policy['mode']=='hosted':
            primary=NodeClient(config,self.key(user),self.clock)
            if link.get('service_directory'):
                from .public_union import PublicUnionClient
                from .service_client import ServiceClient
                direct=self.link_config(link,'peer_config')
                destination={'public':link['source']['crypto_public'],'url':link['target'],'node_public':direct['node_public']}
                return PublicUnionClient(primary,ServiceClient(self,gid,user,dict(direct,rpc_service=destination)))
            return primary
        return LocalClient(self,gid,user,config)

    def _folder(self, user, iid, category='outgoing'):
        path = self.directory / category / hashlib.sha256(user['username'].encode()).hexdigest()[:32] / identifier(iid)
        path.resolve().relative_to(self.directory.resolve()); path.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise CacheError('交付路径无效 / Invalid delivery path', 503)
        return path

    def _save_entry(self, gid, user, iid, entry, **extra):
        rid = hashlib.sha256((user['username'] + ':' + gid + ':' + iid).encode()).hexdigest()
        current = self.received.find_one({'_id': rid})
        if current is None:
            counter = self.repo.collection('collaboration_rooms').find_one_and_update(
                {'_id': 'delivery:' + hashlib.sha256((user['username'] + ':' + gid).encode()).hexdigest()},
                {'$inc': {'revision': 1}}, upsert=True, return_document=ReturnDocument.AFTER)
            document = {'_id': rid, 'owner': user['username'], 'group_id': gid, 'item_id': iid,
                        'audience': entry['audience'], 'participants': entry.get('participants', []), 'sequence': counter['revision'],'posted_at':entry['created_at'],
                        'sender':entry['sender'],'kind':entry['kind'],
                        'entry': self.control.secrets.seal(json.dumps(entry, ensure_ascii=False), rid + ':entry'), **extra}
            try:
                self.received.insert_one(document)
            except DuplicateKeyError:
                pass
        else:
            self.received.update_one({'_id': rid, 'owner': user['username']}, {'$set': dict(extra,sender=entry['sender'],kind=entry['kind'])})
        return self.received.find_one({'_id': rid})

    def _entry(self, row):
        value = json.loads(self.control.secrets.open(row['entry'], row['_id'] + ':entry'))
        if value.get('kind')=='report' and type(value.get('attachment_schema')) is int and value['attachment_schema']==1:
            value['kind']='file'
        from .. import collaboration_profiles as profiles
        member=self.collaboration.members.find_one({'_id':value['sender'],'group_id':row['group_id']})
        if member and self.collaboration.groups.find_one({'_id':row['group_id'],'enabled':True}):
            name=self.collaboration._public_member(member)['name']
        else:
            link=self.collaboration.links.find_one({'owner':row['owner'],'group_id':row['group_id'],'deleted_at':{'$exists':False}}) or {}
            known=next((m for m in (link.get('workspace_snapshot') or {}).get('members',[]) if m['_id']==value['sender']),{})
            name=known.get('name') or 'W-'+value['sender'][:8]
        value['source']=profiles.source_public(value.get('source') or {},name)
        value['published_revision'] = row['sequence']
        if row.get('complete') is not None:
            value['received'] = row['complete']
        if row.get('task_id'):
            task = self.tasks.find_one({'_id': row['task_id'], 'owner': row['owner']})
            if task:
                value['delivery_state'] = task['state']; value['delivery_error'] = task.get('error', '')
        return value

    def queue(self, gid, user, body, kind='message', raw=b'', summary=None):
        self.workspace(gid, user)  # Refresh recipient roles and pinned keys before a new send.
        access, snapshot = self._snapshot(gid, user); mid = access['member_id']; audience = body.get('audience') or 'group'
        if audience not in ('group', 'direct'):
            raise CacheError('加密交付使用总工作区或单点工作区 / Encrypted delivery requires a group or direct workspace')
        active = {m['_id']: m for m in snapshot['members'] if m['state'] == 'approved'}
        if mid not in active:
            raise CacheError('发送成员已失效 / Sender membership unavailable', 403)
        peer = body.get('peer_id') or ''; participants = []
        if audience == 'direct':
            identifier(peer)
            if peer == mid or peer not in active:
                raise CacheError('接收成员不存在或失效 / Recipient unavailable', 403)
            participants = sorted((mid, peer)); selected = [active[m] for m in participants]
            peer_pub=active[peer].get('source',{}).get('crypto_public')
            if not peer_pub:raise CacheError('成员通信身份尚未就绪 / Member cryptographic identity unavailable',409)
            self.pin_peer(gid,peer,user,peer_pub)
        else:
            selected = list(active.values())
        recipients = {}
        from ..collaboration_profiles import crypto_features
        for member in selected:
            if kind=='file' and crypto_features(member.get('source',{})).get('attachments')!=1:
                raise CacheError('接收成员尚不支持附件，请更新并刷新连接 / A recipient lacks attachments; update and refresh the connection',409)
            pub = member.get('source', {}).get('crypto_public')
            if not pub:
                raise CacheError('接收成员尚未升级加密协议，请先更新 / Recipient has not upgraded the encrypted protocol', 409)
            recipients[crypto.peer_id(pub)] = pub
        nonce = body.get('nonce') or secrets.token_hex(16); identifier(nonce)
        iid = hashlib.sha256((gid + ':' + mid + ':' + nonce).encode()).hexdigest()[:32]
        source = dict(active[mid]['source']); now = self.clock(); policy = normalize(snapshot.get('cache_policy') or snapshot['group'].get('cache_policy'))
        # Old clients must still read the room after a rollback. Keep a known
        # caption category on the wire and identify attachments with a subtype;
        # no pentest report record is created for this transport category.
        entry = {'_id': iid, 'group_id': gid, 'kind': 'report' if kind=='file' else kind, 'sender': mid, 'source': source, 'created_at': now,
                 'audience': audience, 'participants': participants, 'recipients': [peer] if peer else [], 'state': 'complete'}
        if kind=='file':entry['attachment_schema']=1
        if kind == 'message':
            content = body.get('text')
            if not isinstance(content, str) or not content.strip() or len(content) > 2000 or len(content.encode()) > 8192:
                raise CacheError('消息不能为空且最多2000字 / Message required, maximum 2000 characters')
            entry['text'] = content
        else:
            manifest = archive_manifest(raw)
            title = body.get('title') or kind
            if not isinstance(title, str) or not title.strip() or len(title) > 100:
                raise CacheError('共享标题无效 / Invalid share title')
            entry.update(title=title, summary=summary or {}, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                         files={'count':len(manifest['files']),'expanded_bytes':manifest['expanded_bytes']})
        fingerprint = hashlib.sha256(canonical({'kind': kind, 'audience': audience, 'participants': participants,
            'text': entry.get('text'), 'title': entry.get('title'), 'raw': hashlib.sha256(raw).hexdigest()})).hexdigest()
        tid = 'delivery:' + iid
        old = self.tasks.find_one({'_id': tid})
        if old:
            if old.get('owner') != user['username'] or old.get('fingerprint') != fingerprint:
                raise CacheError('发送凭据已用于不同内容 / Send nonce conflict', 409)
            row=self.received.find_one({'task_id':tid,'owner':user['username']})
            if row is None:
                caption=old['manifest']['caption'];entry=json.loads(crypto.open_object(caption['envelope'],crypto.decode(caption['data'],128*1024),self.key(user)).decode())
                path=self._folder(user,iid)/'payload.bin'
                if not path.is_file():
                    rebuilt=crypto.recover_payload(old['manifest']['envelope'],self.key(user),raw if kind!='message' else canonical(entry))
                    from ..collaboration import atomic_file
                    atomic_file(path,rebuilt)
                row=self._save_entry(gid,user,iid,entry,task_id=tid,complete=True)
                self.tasks.update_one({'_id':tid,'state':'preparing'},{'$set':{'state':'queued'}})
            return {'item_id': iid, 'entry': self._entry(row), 'queued': True}
        expires = now + (policy['shared_days'] if audience == 'group' else policy['pending_days']) * 86400
        context = {'id': iid, 'group': gid, 'audience': audience, 'sender_mid': mid, 'peer_mid': peer,
                   'created_at': now, 'expires_at': expires}
        key = self.key(user); caption, caption_bytes = crypto.seal(canonical(entry), key, recipients, context)
        context = dict(context, caption_hash=hashlib.sha256(canonical(caption) + caption_bytes).hexdigest())
        envelope, encrypted = crypto.seal(raw if kind != 'message' else canonical(entry), key, recipients, context)
        meta = {'id': iid, 'bytes': len(encrypted), 'sha256': hashlib.sha256(encrypted).hexdigest(),
                'recipients': sorted(recipients), 'audience': audience, 'envelope': envelope,
                'caption': {'envelope': caption, 'data': crypto.encode(caption_bytes)}}
        client = self._client(gid, user, access)
        if hasattr(client,'upload_target'):client=client.upload_target(meta)
        # A shared Mongo lease serializes reservations across gunicorn workers.
        lockid = 'outbox:shared-reservation'; token = secrets.token_hex(16)
        locks = self.collaboration.nonces
        try:
            locks.insert_one({'_id': lockid, 'until': 0})
        except DuplicateKeyError:
            pass
        held = locks.find_one_and_update({'_id': lockid, 'until': {'$lte': now}}, {'$set': {'owner_token': token, 'until': now + 60,
             'expires': datetime.fromtimestamp(now + 120, timezone.utc)}}, return_document=ReturnDocument.AFTER)
        if not held:
            raise CacheError('同组发送正在准备，请稍后重试 / Group delivery is being prepared; retry shortly', 409)
        try:
            pending = list(self.tasks.find({'record_type': 'delivery',
                'state': {'$in': ['preparing', 'queued', 'uploading', 'hosted', 'paused']}}))
            if len(pending)>=4000 or sum(t['bytes'] for t in pending) + len(encrypted) > 1024 * MIB or sum(t['bytes'] for t in pending if t['group_id'] == gid and t['owner']==user['username']) + len(encrypted) > policy['sender_quota']:
                raise CacheError('本地待发空间不足，新发送已暂停；原数据保留 / Local outbox full; new send paused, original data retained', 507)
            folder = self._folder(user, iid)
            if shutil.disk_usage(str(folder)).free < len(encrypted) + 64 * MIB:
                raise CacheError('本机磁盘空间不足 / Insufficient local disk space', 507)
            task = {'_id': tid, 'record_type': 'delivery', 'item_id': iid, 'group_id': gid, 'owner': user['username'],
                    'state': 'preparing', 'kind': kind, 'audience': audience, 'bytes': len(encrypted), 'manifest': meta, 'recipient_public':recipients,
                    'fingerprint': fingerprint, 'created_at': now, 'expires_at': expires, 'retry_at': now, 'attempts': 0,'recovery_hours':policy['received_hours'],
                    'node_id': policy['node_id'], 'route': self.save_config(iid, 'route', client.config), 'error': ''}
            task['source_object_id']=body.get('object_id') or ''
            try:
                self.tasks.insert_one(task)
            except DuplicateKeyError:
                raise CacheError('发送正在准备，请稍后重试 / Send preparation in progress; retry shortly', 409) from None
            from ..collaboration import atomic_file
            atomic_file(folder / 'payload.bin', encrypted)
            self._save_entry(gid, user, iid, entry, task_id=tid, complete=True)
            self.tasks.update_one({'_id': tid, 'owner': user['username']}, {'$set': {'state': 'queued'}})
        finally:
            locks.delete_one({'_id': lockid, 'owner_token': token})
        return {'item_id': iid, 'entry': dict(entry,kind=kind,delivery_state='queued'), 'bytes': len(raw), 'queued': True}

    def _decode_caption(self, gid, meta, user, members):
        main = meta['manifest']['envelope']; header = main['header']; context = header.get('context') or {}
        sender = members.get(context.get('sender_mid'))
        expected = sender.get('source', {}).get('crypto_public') if sender else None
        if not expected or crypto.peer_id(expected) != header.get('sender'):
            raise CacheError('发送者身份不在已核验成员表 / Sender identity absent from verified roster', 409)
        crypto.verify(expected, header, main.get('signature'))
        if context.get('group') != gid or context.get('id') != meta['id']:
            raise CacheError('共享对象范围不匹配 / Shared object scope mismatch', 403)
        posted=context.get('created_at')
        if isinstance(posted,bool) or not isinstance(posted,(int,float)) or not self.clock()-90*86400<=posted<=self.clock()+120:
            raise CacheError('共享对象时间无效 / Invalid shared object time')
        caption = meta['manifest'].get('caption') or {}; raw = crypto.decode(caption.get('data'), 128 * 1024)
        immutable={k:(caption.get('envelope') or {}).get(k) for k in ('header','signature')}
        if hashlib.sha256(canonical(immutable) + raw).hexdigest() != context.get('caption_hash'):
            raise CacheError('共享说明与正文不一致 / Shared caption does not match payload', 409)
        issuer=self._client(gid,user).config['issuer_public']
        entry = json.loads(crypto.open_object(caption['envelope'], raw, self.key(user), expected,issuer,self.clock()).decode())
        if entry.get('_id') != meta['id'] or entry.get('group_id') != gid or entry.get('sender') != context.get('sender_mid') or entry.get('audience') != context.get('audience') or entry.get('created_at')!=posted:
            raise CacheError('共享说明身份不匹配 / Caption identity mismatch', 403)
        if entry['kind'] not in ('message', 'finding', 'report', 'session'):
            raise CacheError('共享类型无效 / Invalid shared kind')
        return entry

    def incoming(self, gid, user):
        from .incoming_gate import run
        return run(self,gid,user,lambda guard,token:self._incoming(gid,user,guard,token))

    def _incoming(self,gid,user,guard,token):
        access, snapshot = self._snapshot(gid, user); members = {m['_id']: m for m in snapshot['members']}
        client = self._client(gid, user, access)
        clients=[client]
        if access['host']:
            for r in access['group'].get('draining_nodes',[]):
                if r['until']>self.clock():clients.append(self._client(gid,user,explicit=self._host_config(dict(access['group'],node_access=r['access']),user)))
        else:
            for config in self.link_config(access['link'],'drain_configs') or []:
                if config:clients.append(self._client(gid,user,explicit=config))
        records=[]
        for source in clients:
            guard()
            marker='delivery-scan:'+hashlib.sha256((user['username']+gid+source.config['node_public']).encode()).hexdigest()
            scan=self.collaboration.nonces.find_one({'_id':marker}) or {}
            page=source.call('list',{'limit':25});records.extend((source,item) for item in page['items'])
            cursor=scan.get('cursor') or page.get('next')
            if cursor:
                history=source.call('list',{'limit':25,'before':cursor});records.extend((source,item) for item in history['items'])
                self.collaboration.nonces.update_one({'_id':marker},{'$set':{'cursor':history.get('next'),'expires':datetime.fromtimestamp(self.clock()+3600,timezone.utc)}},upsert=True)
        for client,summary in records:
            guard()
            if summary['state'] != 'stored':
                continue
            known=self.received.find_one({'owner':user['username'],'group_id':gid,'item_id':summary['id']})
            if known and known.get('acknowledged'):
                continue
            meta = client.call('metadata', {'id': summary['id']})
            entry = self._decode_caption(gid, meta, user, members)
            guard()
            row = self._save_entry(gid, user, entry['_id'], entry, cached_manifest=meta['manifest'],
                                   route=self.save_config(entry['_id'], 'route', client.config), expires_at=meta['expires_at'])
            if entry['kind'] == 'message' or entry['sender'] == access['member_id']:
                if entry['kind'] == 'message' and row.get('complete') is not True:
                    parent=self._folder(user,entry['_id'],'incoming');folder=parent/('message-'+token)
                    folder.resolve().relative_to((self.directory/'incoming').resolve());folder.mkdir(exist_ok=True)
                    try:
                        downloaded=client.download(entry['_id'],folder/'payload.bin',guard=guard)
                        content=crypto.open_object(meta['manifest']['envelope'],(folder/'payload.bin').read_bytes(),self.key(user),expected_issuer=client.config['issuer_public'],now=self.clock())
                        if json.loads(content.decode())!=entry:raise CacheError('消息正文与说明不一致 / Message payload does not match caption',409)
                        guard();self.collaboration._access(gid,user)
                        self.received.update_one({'_id':row['_id'],'owner':user['username']},{'$set':{'complete':True}})
                        guard();client.acknowledge(entry['_id'],'object',downloaded.get('read_lease'))
                    finally:
                        # The invocation owns this leaf, even after losing its lease.
                        folder.resolve().relative_to((self.directory/'incoming').resolve())
                        try:shutil.rmtree(str(folder))
                        except FileNotFoundError:pass
                        try:parent.rmdir()
                        except OSError:pass  # Another invocation may still own a nonempty leaf.
                else:
                    client.acknowledge(entry['_id'], 'object')
            else:
                client.acknowledge(entry['_id'], 'message')
            guard();self.received.update_one({'_id':row['_id'],'owner':user['username']},{'$set':{'acknowledged':True}})
        return [r for _,r in records]

    def read_room(self, gid, user, body):
        access, snapshot = self._snapshot(gid, user); mid = access['member_id']; audience = body.get('audience', 'group'); peer = body.get('peer_id', '')
        if audience not in ('group', 'direct') or audience == 'direct' and (not isinstance(peer, str) or peer == mid):
            raise CacheError('工作区范围无效 / Invalid workspace scope')
        if audience == 'direct':
            identifier(peer)
        self.heartbeat(gid, user)
        # Existing plaintext history stays on the original host. Import only an
        # authorized reader's view locally; never upload it to a hosting node.
        marker='legacy-room:'+hashlib.sha256((user['username']+gid+audience+peer).encode()).hexdigest()
        imported=self.collaboration.nonces.find_one({'_id':marker})
        if snapshot['group'].get('legacy_history') and (not imported or imported.get('before')):
            legacy_body={'audience':audience,'peer_id':peer}
            if imported and imported.get('before'):legacy_body['before']=imported['before']
            try:
                legacy=self.collaboration.read_conversation(gid,mid,legacy_body) if access['host'] else self.collaboration._request(access['link'],'conversation',legacy_body)
                for entry in legacy['entries']:self._save_entry(gid,user,entry['_id'],dict(entry,legacy=True),complete=entry['kind']=='message')
                self.collaboration.nonces.update_one({'_id':marker},{'$set':{'before':legacy['oldest'] if legacy['has_older'] else None,
                    'expires':datetime.fromtimestamp(self.clock()+30*86400,timezone.utc)}},upsert=True)
            except Exception as exc:
                if getattr(exc,'status',0) not in (502,503,504):raise
        warning = ''
        try:
            self.incoming(gid, user)
        except Exception as exc:
            if getattr(exc, 'status', 0) not in (403,409,410,425,429,502,503,504,507):
                raise
            warning = str(exc)
        query = {'owner': user['username'], 'group_id': gid, 'audience': audience}
        if audience == 'direct':
            query['participants'] = sorted((mid, peer))
        cursor, before = body.get('cursor'), body.get('before')
        if cursor is not None and (isinstance(cursor,bool) or not isinstance(cursor,int) or cursor<0):raise CacheError('消息游标无效 / Invalid message cursor')
        boundary=None
        if before is not None:
            if not isinstance(before,str) or not before.startswith('c.') or len(before)>200:raise CacheError('历史游标无效 / Invalid history cursor')
            try:boundary=json.loads(crypto.decode(before[2:],160).decode())
            except (ValueError,TypeError):raise CacheError('历史游标无效 / Invalid history cursor') from None
            if not isinstance(boundary,list) or len(boundary)!=2 or isinstance(boundary[0],bool) or not isinstance(boundary[0],(int,float)):raise CacheError('历史游标无效 / Invalid history cursor')
            identifier(boundary[1])
        counter = self.repo.collection('collaboration_rooms').find_one({'_id': 'delivery:' + hashlib.sha256((user['username'] + ':' + gid).encode()).hexdigest()}) or {}
        revision = counter.get('revision', 0)
        if boundary is not None:
            query['$or']=[{'posted_at':{'$lt':boundary[0]}},{'posted_at':boundary[0],'item_id':{'$lt':boundary[1]}}]
        elif cursor is not None and cursor <= revision:
            query['sequence'] = {'$gt': cursor}
        rows = list(self.received.find(query).sort([('posted_at',-1),('item_id',-1)]).limit(100)); rows.reverse()
        if cursor is not None and before is None:
            ids={row['_id'] for row in rows}
            own=list(self.received.find({k:v for k,v in query.items() if k!='sequence'}).sort('sequence',-1).limit(20))
            rows=[row for row in own if row['_id'] not in ids and row.get('task_id')]+rows
        entries = [self._entry(row) for row in rows]
        first=min(rows,key=lambda row:(row['posted_at'],row['item_id'])) if rows else None
        oldest='c.'+crypto.encode(canonical([first['posted_at'],first['item_id']])) if first else before
        old_query={k:v for k,v in query.items() if k not in ('sequence','$or')}
        if first:old_query['$or']=[{'posted_at':{'$lt':first['posted_at']}},{'posted_at':first['posted_at'],'item_id':{'$lt':first['item_id']}}]
        has_older=bool(first and self.received.find_one(old_query))
        can_send = audience == 'group' or any(m['_id'] == peer and m['state'] == 'approved' for m in snapshot['members'])
        return {'entries': entries, 'cursor': revision, 'oldest': oldest, 'has_older': has_older,
                'reset': cursor is not None and cursor > revision, 'can_send': can_send,
                'self_member_id': mid, 'audience': audience, 'participants': sorted((mid, peer)) if peer else [], 'delivery_warning': warning}

    def heartbeat(self, gid, user):
        access = self.collaboration._access(gid, user)
        policy = normalize(access.get('group', {}).get('cache_policy') or access.get('link', {}).get('cache_policy'))
        if policy['mode'] == 'hosted':
            return  # Reading an already-hosted object must not require the host to be online.
        if access['host']:
            self.collaboration.members.update_one({'_id': gid, 'group_id': gid}, {'$set': {'online_at': self.clock()}})
        else:
            try:
                self.collaboration._request(access['link'], 'cache_heartbeat', {})
            except Exception as exc:
                if getattr(exc, 'status', 0) not in (502, 503, 504):
                    raise

    def fetch_package(self,gid,iid,user):
        import time,threading
        iid=identifier(iid);self.collaboration._access(gid,user)
        lock_id=hashlib.sha256((user['username']+':'+gid+':'+iid).encode()).hexdigest()
        token=secrets.token_hex(16);deadline=time.monotonic()+15
        while True:
            now=self.clock()
            try:
                self.receive_locks.find_one_and_update({'_id':lock_id,'$or':[{'until':{'$exists':False}},{'until':{'$lte':now}}]},
                    {'$set':{'token':token,'until':now+180,'expires':datetime.fromtimestamp(now+360,timezone.utc)}},upsert=True,return_document=ReturnDocument.AFTER)
                break
            except DuplicateKeyError:
                if time.monotonic()>=deadline:raise CacheError('资料正在收取，请稍后再次预览 / This package is being received; preview it again shortly',409) from None
                time.sleep(.08)
        stop=threading.Event()
        def renew():
            while not stop.wait(10):
                try:self.receive_locks.update_one({'_id':lock_id,'token':token},{'$set':{'until':self.clock()+180,'expires':datetime.fromtimestamp(self.clock()+360,timezone.utc)}})
                except Exception:pass  # The fresh guard below still fails closed.
        def guard():
            if not self.receive_locks.find_one({'_id':lock_id,'token':token,'until':{'$gt':self.clock()}}):
                raise CacheError('收取已由其他请求接续，请重新预览 / Another request resumed this receipt; preview again',409)
        threading.Thread(target=renew,daemon=True,name='collaboration-receive-lease').start()
        try:return self._fetch_package(gid,iid,user,guard)
        finally:
            stop.set();self.receive_locks.delete_one({'_id':lock_id,'token':token})

    def _fetch_package(self, gid, iid, user, guard):
        guard()
        access = self.collaboration._access(gid, user)
        row = self.received.find_one({'owner': user['username'], 'group_id': gid, 'item_id': identifier(iid)})
        if not row:
            self.incoming(gid, user)
            row = self.received.find_one({'owner': user['username'], 'group_id': gid, 'item_id': iid})
        if not row:
            raise CacheError('共享包不存在或未授权 / Share package unavailable or unauthorized', 403)
        item = self._entry(row)
        if item.get('legacy'):
            raise CacheError('历史包使用原主持端领取通道 / Legacy package uses its original host channel',409)
        if item['kind'] == 'message':
            raise CacheError('此对象不是文件包 / Object is not a file package')
        folder = self._folder(user, iid, 'received'); target = folder / 'package.zip'
        if not target.is_file() and item.get('sender')==access['member_id'] and row.get('task_id')=='delivery:'+iid:
            task=self.tasks.find_one({'_id':'delivery:'+iid,'owner':user['username'],'group_id':gid,'item_id':iid,'record_type':'delivery'})
            source=self._folder(user,iid)/'payload.bin'
            if task and source.is_file():
                envelope=task['manifest']['envelope'];context=envelope.get('header',{}).get('context') or {}
                if context.get('id')!=iid or context.get('group')!=gid or context.get('sender_mid')!=access['member_id'] or context.get('audience')!=item.get('audience'):
                    raise CacheError('本机待发对象范围不匹配 / Local source scope mismatch',403)
                if item.get('audience')=='direct' and sorted((context['sender_mid'],context.get('peer_mid','')))!=item.get('participants'):
                    raise CacheError('本机待发私聊范围不匹配 / Local private source scope mismatch',403)
                key=self.key(user)
                raw=crypto.open_object(envelope,source.read_bytes(),key,expected_public=crypto.public_pem(key),now=self.clock())
                archive_manifest(raw)
                if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:
                    raise CacheError('本机原件完整性校验失败 / Local source integrity failed',409)
                from ..collaboration import atomic_file
                guard();atomic_file(target,raw)
                self.received.update_one({'_id':row['_id'],'owner':user['username'],'group_id':gid},{'$set':{'complete':True,'source_copy_at':self.clock()}})
                row={**row,'complete':True}
        if not row.get('complete') or not target.is_file():
            if not row.get('route') or not row.get('cached_manifest'):
                raise CacheError('原件尚未交付或本机副本已回收，请稍后重试 / Original not delivered or local source reclaimed; retry later',409)
            config = json.loads(self.control.secrets.open(row['route'], iid + ':route'))
            client = self._client(gid, user, access, config)
            downloaded = client.download(iid, folder / 'payload.bin',guard=guard)
            lease = downloaded.get('read_lease')
            try:
                raw = crypto.open_object(row['cached_manifest']['envelope'], (folder / 'payload.bin').read_bytes(), self.key(user),expected_issuer=client.config['issuer_public'],now=self.clock())
                if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                    raise CacheError('解密包完整性校验失败 / Decrypted package integrity failed', 409)
                archive_manifest(raw)
                from ..collaboration import atomic_file
                guard();atomic_file(target, raw)
                self.received.update_one({'_id': row['_id'], 'owner': user['username']}, {'$set': {'complete': True, 'received_at': self.clock()}})
                client.acknowledge(iid, 'object', lease)
                guard();(folder/'payload.bin').unlink(missing_ok=True)
                parts=folder/'payload.bin.parts'
                if parts.is_dir():parts.resolve().relative_to(folder.resolve());shutil.rmtree(str(parts))
            except Exception:
                if lease:
                    client.call('end_read', {'id': iid, 'lease': lease})
                raise
        guard();raw = target.read_bytes(); archive_manifest(raw)
        if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise CacheError('本地已收文件损坏，请重新收取 / Received local file damaged; fetch again', 409)
        return item, raw

    def delivery_status(self, gid, user):
        self.collaboration._access(gid, user)
        rows = list(self.tasks.find({'record_type': 'delivery', 'group_id': gid, 'owner': user['username']}).sort('created_at', -1).limit(100))
        return {'items': [{k: row.get(k) for k in ('item_id', 'kind', 'state', 'bytes', 'uploaded_bytes','created_at', 'expires_at', 'retry_at', 'attempts', 'error', 'received_count', 'recipient_count','remote_cancel_pending')} for row in rows],
                'pending_bytes': sum(row['bytes'] for row in rows if row['state'] in ('queued', 'uploading', 'hosted', 'paused', 'preparing'))}

    def change_task(self, gid, iid, user, action):
        self.collaboration._access(gid, user); iid = identifier(iid)
        row = self.tasks.find_one({'_id': 'delivery:' + iid, 'owner': user['username'], 'group_id': gid})
        if not row:
            raise CacheError('待发任务不存在 / Pending task unavailable', 404)
        if action not in ('pause', 'retry', 'reroute', 'cancel'):
            raise CacheError('任务操作无效 / Invalid task action')
        if row['state'] in ('cancelled', 'expired', 'delivered'):
            raise CacheError('任务已经结束 / Task already terminal', 410)
        values = {'state': 'paused' if action == 'pause' else 'cancelled' if action == 'cancel' else 'queued', 'retry_at': self.clock(), 'error': ''}
        if action == 'reroute':
            client = self._client(gid, user)
            values['route'] = self.save_config(iid, 'route', client.config)
            access=self.collaboration._access(gid,user);values['node_id']=normalize(access.get('group',{}).get('cache_policy') or access.get('link',{}).get('cache_policy'))['node_id']
        changed = self.tasks.update_one({'_id': row['_id'], 'owner': user['username'], 'lease_until': {'$not': {'$gt': self.clock()}}}, {'$set': values})
        if not changed.matched_count:
            raise CacheError('传输正在提交，请稍后操作 / Transfer is committing; retry shortly', 409)
        if action == 'cancel':
            try:
                config = json.loads(self.control.secrets.open(row['route'], iid + ':route'))
                self._client(gid, user, explicit=config).call('cancel', {'id': iid})
            except Exception:
                values['remote_cancel_pending'] = True
                self.tasks.update_one({'_id': row['_id']}, {'$set': {'remote_cancel_pending': True}})
        return {k: v for k, v in values.items() if k != 'route'}

    def advance_tasks(self):
        now = self.clock()
        self.tasks.update_many({'record_type':'delivery','state':{'$in':['preparing','queued','uploading','hosted','paused']},
            'expires_at':{'$lte':now},'lease_until':{'$not':{'$gt':now}}},{'$set':{'state':'expired','cleanup_at':now,
            'error':'交付期限已到，原始资料未删除 / Delivery expired; original data preserved'}})
        for row in self.tasks.find({'record_type':'delivery','state':'cancelled','remote_cancel_pending':True,'retry_at':{'$lte':now}}).limit(5):
            try:
                config=json.loads(self.control.secrets.open(row['route'],row['item_id']+':route'))
                self._client(row['group_id'],{'username':row['owner']},explicit=config).call('cancel',{'id':row['item_id']})
                self.tasks.update_one({'_id':row['_id'],'state':'cancelled'},{'$set':{'remote_cancel_pending':False}})
            except Exception as exc:
                self.tasks.update_one({'_id':row['_id'],'state':'cancelled'},{'$set':{'remote_cancel_pending':getattr(exc,'status',0) not in (404,410),
                    'retry_at':self.clock()+60}})
        for row in self.tasks.find({'record_type': 'delivery', 'state': {'$in': ['preparing', 'queued', 'uploading', 'hosted']}, 'retry_at': {'$lte': now}}).sort('retry_at', 1).limit(4):
            token = secrets.token_hex(16)
            held = self.tasks.find_one_and_update({'_id': row['_id'], 'state': row['state'], 'lease_until': {'$not': {'$gt': self.clock()}}},
                    {'$set': {'lease_token': token, 'lease_until': self.clock() + 300}}, return_document=ReturnDocument.AFTER)
            if not held:
                continue
            user = {'username': row['owner']}; update = {}; iid = row['item_id']
            try:
                account=self.repo.collection('user').find_one({'username':user['username']})
                if not account or account.get('disabled'):raise CacheError('发送账户已停用 / Sender account disabled',403)
                self.collaboration._access(row['group_id'], user)
                if row['expires_at'] <= self.clock():
                    update = {'state': 'expired', 'error': '交付期限已到，原始资料未删除 / Delivery expired; original data preserved'}
                else:
                    path = self._folder(user, iid) / 'payload.bin'
                    if not path.is_file():
                        caption=row['manifest']['caption'];entry=json.loads(crypto.open_object(caption['envelope'],crypto.decode(caption['data'],128*1024),self.key(user)).decode())
                        if row['kind']=='message':raw=canonical(entry)
                        elif row.get('source_object_id'):
                            account=self.repo.collection('user').find_one({'username':user['username']}) or user
                            raw,_=self.collaboration._package(row['kind'],row['source_object_id'],account)
                        else:raise CacheError('待发快照尚未完成，原始资料未删除 / Outbox snapshot incomplete; original data retained',409)
                        from ..collaboration import atomic_file
                        atomic_file(path,crypto.recover_payload(row['manifest']['envelope'],self.key(user),raw))
                        self._save_entry(row['group_id'],user,iid,entry,task_id=row['_id'],complete=True)
                    config = json.loads(self.control.secrets.open(row['route'], iid + ':route'))
                    client = self._client(row['group_id'], user, explicit=config)
                    def checkpoint(confirmed):
                        changed=self.tasks.update_one({'_id':row['_id'],'lease_token':token},{'$set':{'uploaded_bytes':confirmed,'lease_until':self.clock()+300}})
                        if not changed.matched_count:raise CacheError('交付租约发生变化 / Delivery lease changed',409)
                    def deliver(client,force=False):
                        client.on_progress=checkpoint
                        if force or row['state']!='hosted' or row.get('last_verified_at',0)+300<=self.clock():
                            client.upload(row['manifest'],path)
                            client.acknowledge(iid,'object')
                            verified=self.clock()
                        else:verified=row.get('last_verified_at',self.clock())
                        return client.call('metadata',{'id':iid}),verified
                    if row['state']!='hosted':self.tasks.update_one({'_id':row['_id'],'lease_token':token},{'$set':{'state':'uploading'}})
                    try:record,verified=deliver(client)
                    except CacheError as original:
                        if original.status not in (401,403,410,502,503,504):raise
                        view=self.workspace(row['group_id'],user)
                        if view.get('offline') or original.status in (401,403,410) and view.get('host_offline'):raise original
                        # A newly authenticated workspace confirms the current member and service.
                        # Only the route changes: original ID, signature, ciphertext and recipient proof stay intact.
                        client=self._client(row['group_id'],user)
                        if hasattr(client,'upload_target'):client=client.upload_target(row['manifest'])
                        updated=self.tasks.update_one({'_id':row['_id'],'lease_token':token},{'$set':{
                            'route':self.save_config(iid,'route',client.config),'route_changed_at':self.clock()}})
                        if not updated.matched_count:raise CacheError('交付租约发生变化 / Delivery lease changed',409)
                        record,verified=deliver(client,True)
                    recipients = set(row['manifest']['recipients']); received=set()
                    if row['manifest'].get('audience')=='group' and len([r for r in (record or {}).get('receipts',[]) if r.get('kind')=='object'])<len(recipients):
                        try:record=self._client(row['group_id'],user).call('metadata',{'id':iid})
                        except CacheError as exc:
                            if exc.status not in (404,410,502,503,504):raise
                    for receipt in (record or {}).get('receipts',[]):
                        if receipt.get('kind')!='object' or receipt.get('recipient') not in recipients:continue
                        proof=json.loads(receipt['proof']);claim=proof.get('claim') or {}
                        if claim!={'id':iid,'recipient':receipt['recipient'],'kind':'object'}:raise CacheError('接收回执不匹配 / Recipient receipt mismatch',409)
                        crypto.verify(row['recipient_public'][receipt['recipient']],claim,proof.get('signature'))
                        received.add(receipt['recipient'])
                    update = {'state': 'delivered' if recipients.issubset(received) else 'hosted', 'received_count': len(received & recipients),
                              'recipient_count': len(recipients), 'error': '', 'retry_at': self.clock() + 8,
                              'stored_at': self.clock(),'last_verified_at':verified,
                              'cleanup_at': self.clock() + row.get('recovery_hours',24)*3600 if recipients.issubset(received) else row['expires_at']}
            except Exception as exc:
                status = getattr(exc, 'status', 503)
                update = {'state': 'paused' if status in (401, 403) else 'queued', 'error': str(exc) if isinstance(exc, CacheError) or hasattr(exc, 'status') else '交付暂不可用 / Delivery temporarily unavailable',
                          'attempts': row.get('attempts', 0) + 1, 'retry_at': self.clock() + min(60, 2 ** min(row.get('attempts', 0) + 1, 6))}
                if status == 410:
                    update['state'] = 'expired' if row['expires_at']<=self.clock() else 'queued'
            finally:
                self.tasks.update_one({'_id': row['_id'], 'lease_token': token}, {'$set': update, '$unset': {'lease_token': '', 'lease_until': ''}})
        self.local.store.collect()
        # Only our ciphertext staging; received user packages and source databases are not GC targets.
        for row in self.tasks.find({'record_type': 'delivery', 'state': {'$in': ['delivered', 'expired', 'cancelled']},
                                  'stage_cleared': {'$ne': True}, 'lease_until': {'$not': {'$gt': self.clock()}}}).limit(100):
            if (row.get('cleanup_at') or row['expires_at']) > self.clock() and row['state'] != 'cancelled':
                continue
            folder = self._folder({'username': row['owner']}, row['item_id'])
            folder.resolve().relative_to((self.directory / 'outgoing').resolve())
            shutil.rmtree(str(folder))
            self.tasks.update_one({'_id': row['_id']}, {'$set': {'stage_cleared': True}})
