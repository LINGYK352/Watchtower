"""Host-authorized public replication with original author signatures and bounded storage."""
import hashlib,json,math
from . import crypto
from .policy import CacheError,canonical,identifier,CHUNK

def check_manifest(meta,gid,members,trusted_host=False):
    if not isinstance(meta,dict) or meta.get('audience')!='group':
        raise CacheError('只能预热公共对象 / Only public objects may be replicated',403)
    envelope=meta.get('envelope') or {};header=envelope.get('header') or {};context=header.get('context') or {}
    sender=next((m for m in members if m['_id']==context.get('sender_mid')),None)
    # A current, authenticated host may restore a historical author after membership expiry.
    # The original author's signature is still mandatory; no co-host can invent this authority.
    if (sender is None and not trusted_host) or sender is not None and (sender.get('source') or {}).get('crypto_public')!=header.get('public'):
        raise CacheError('公共对象作者不在签名成员表 / Public author absent from signed roster',403)
    if crypto.peer_id(header.get('public'))!=header.get('sender'):
        raise CacheError('公共对象作者身份无效 / Invalid original public author',403)
    crypto.verify(header['public'],header,envelope.get('signature'))
    if context.get('group')!=gid or context.get('audience')!='group' or context.get('id')!=meta.get('id') or header.get('sha256')!=meta.get('sha256') or header.get('bytes')!=meta.get('bytes'):
        raise CacheError('公共对象原签名不一致 / Public object differs from original signature',409)
    identifier(meta['id']);identifier(context.get('sender_mid'))
    caption=meta.get('caption') or {};description=caption.get('envelope') or {};signed=description.get('header') or {}
    crypto.verify(header['public'],signed,description.get('signature'))
    plain=crypto.decode(caption.get('data'),CHUNK);immutable={k:description.get(k) for k in ('header','signature')}
    if signed.get('public')!=header['public'] or any((signed.get('context') or {}).get(k)!=context.get(k) for k in ('id','group','audience','sender_mid','peer_mid','created_at')) or hashlib.sha256(canonical(immutable)+plain).hexdigest()!=context.get('caption_hash'):
        raise CacheError('公共说明与原签名不一致 / Public caption differs from original signature',409)
    return header['sender']

def _verify_delegations(meta,issuer,now):
    mappings=[]
    for envelope in (meta['envelope'],meta['caption']['envelope']):
        granted=envelope.get('recipient_grants') or {}
        for recipient,grant in granted.items():
            until=(grant.get('claim') or {}).get('expires_at')
            if isinstance(until,bool) or not isinstance(until,(int,float)) or not math.isfinite(until) or until<=0:
                raise CacheError('公共历史授权期限无效 / Invalid historical delegation expiry',403)
            # Validate old root signatures for archival storage, not for present-time access.
            # All read/decrypt paths continue to enforce the real current expiry.
            claim=crypto.verify_grant(envelope,grant,issuer,min(now,until-1))
            if claim['recipient']!=recipient:raise CacheError('公共授权接收身份不符 / Public delegation recipient mismatch',403)
        mappings.append(set(envelope['header'].get('keys') or {})|set(granted))
    if set(meta.get('recipients') or [])!=mappings[0] or mappings[0]!=mappings[1] or crypto.peer_id(issuer) not in mappings[0]:
        raise CacheError('公共对象接收范围无效 / Invalid public object recipient scope',403)

def mirror(cache,gid,approved,action,body,trusted_host=False,recipient_user=None):
    store=cache.local.store;oid=identifier(body.get('id') or (body.get('manifest') or {}).get('id'))
    if action=='mirror_begin':
        meta=body.get('manifest') or {};author=check_manifest(meta,gid,approved['members'],trusted_host)
        issuer=approved['group']['source']['crypto_public'];_verify_delegations(meta,issuer,cache.clock())
        with store._db() as db:existing=db.execute('SELECT * FROM objects WHERE id=? AND realm=?',(oid,gid)).fetchone()
        if existing:
            current=json.loads(existing['meta'])
            def immutable(value):
                value=json.loads(json.dumps(value));value.pop('recipients',None)
                value['envelope'].pop('recipient_grants',None);value['caption']['envelope'].pop('recipient_grants',None)
                return value
            if existing['sender']!=author or immutable(current)!=immutable(meta):
                raise CacheError('公共对象ID对应不同原文 / Public object ID conflicts with original content',409)
            for recipient,grant in (meta['envelope'].get('recipient_grants') or {}).items():
                old=(current['envelope'].get('recipient_grants') or {}).get(recipient,{})
                if grant['claim']['expires_at']>(old.get('claim') or {}).get('expires_at',0):
                    store.grant_recipient(oid,gid,crypto.peer_id(issuer),{'main':grant,'caption':meta['caption']['envelope']['recipient_grants'][recipient]})
            return store._public(existing)
        created=body.get('created_at',meta['envelope']['header']['context']['created_at'])
        if isinstance(created,bool) or not isinstance(created,(int,float)) or not math.isfinite(created) or created>cache.clock()+120:
            raise CacheError('公共原对象时间无效 / Invalid public object creation time',409)
        result=store.reserve(gid,author,meta,dict(approved['policy'],mode='hosted'))
        with store._db(True) as db:db.execute('UPDATE objects SET created=? WHERE id=? AND realm=?',(created,oid,gid))
        return result
    with store._db() as db:
        row=db.execute('SELECT * FROM objects WHERE id=? AND realm=?',(oid,gid)).fetchone()
        if not row:raise CacheError('公共副本预留不存在 / Public replica reservation missing',404)
        meta=json.loads(row['meta']);author=check_manifest(meta,gid,approved['members'],trusted_host)
    def acknowledge_copy(result):
        if result.get('state')=='stored' and recipient_user:
            key=cache.key(recipient_user);public=crypto.public_pem(key);recipient=crypto.peer_id(public)
            if recipient in meta['recipients']:
                claim={'id':oid,'recipient':recipient,'kind':'object'}
                store.acknowledge(oid,gid,recipient,'object',canonical({'claim':claim,'signature':crypto.sign(key,claim),'public':public}).decode())
        return result
    if action=='mirror_progress':return acknowledge_copy(store.progress(oid,gid,author))
    if action=='mirror_put':
        raw=crypto.decode(body.get('data'),CHUNK)
        return store.put(oid,gid,author,body.get('index'),raw,body.get('sha256'))
    if action=='mirror_commit':return acknowledge_copy(store.commit(oid,gid,author))
    if action=='mirror_receipts':
        receipts=body.get('receipts')
        if not isinstance(receipts,list) or len(receipts)>202:raise CacheError('公共回执范围无效 / Invalid public receipt scope')
        if store.progress(oid,gid,author)['state']!='stored':raise CacheError('公共副本未完整存储 / Public replica is incomplete',409)
        public_keys={crypto.peer_id(m['source']['crypto_public']):m['source']['crypto_public'] for m in approved['members']}
        verified=[]
        for receipt in receipts:
            try:proof=json.loads(receipt['proof']);claim=proof['claim']
            except (KeyError,TypeError,ValueError):raise CacheError('公共回执格式无效 / Invalid public receipt') from None
            recipient=receipt.get('recipient');kind=receipt.get('kind');pub=proof.get('public') or public_keys.get(recipient)
            if not pub and not proof.get('public'):continue  # An old departed member's unresolvable proof grants no delivery credit.
            if recipient not in meta['recipients'] or kind not in ('message','object') or claim!={'id':oid,'recipient':recipient,'kind':kind} or not pub or crypto.peer_id(pub)!=recipient:
                raise CacheError('公共回执身份或范围不符 / Public receipt identity or scope mismatch',403)
            crypto.verify(pub,claim,proof.get('signature'))
            encoded=canonical(proof).decode()
            if len(encoded)>8192:raise CacheError('公共回执超限 / Public receipt exceeds limit',413)
            verified.append((recipient,kind,encoded))
        for recipient,kind,encoded in verified:store.acknowledge(oid,gid,recipient,kind,encoded)
        return {'accepted':len(verified)}
    raise CacheError('副本操作不支持 / Unsupported replica operation')

def inventory(cache,gid):
    with cache.local.store._db() as db:
        rows=db.execute("SELECT id,meta,size FROM objects WHERE realm=? AND state='stored' AND shared=1 AND expires>? ORDER BY id",(gid,cache.clock())).fetchall()
    entries=[]
    for row in rows:
        meta=json.loads(row['meta']);entries.append({'id':row['id'],'sha256':meta['sha256'],'bytes':row['size']})
    return {'items':entries,'digest':hashlib.sha256(canonical(entries)).hexdigest()}



def validate_node_request(opened,request,approved):
    frame=request.get('frame') or {};gid=approved['group']['_id']
    if frame.get('realm')!=gid or frame.get('peer')!=opened['peer'] or frame.get('public')!=opened['public']:
        raise CacheError('存储来源与成员不符 / Storage origin differs from member',403)
    if frame.get('action')=='relay':
        destination=(frame.get('body') or {}).get('destination');allowed={crypto.peer_id(m['source']['crypto_public']) for m in approved['members']
            if m.get('expires_at') is None or m['expires_at']>opened.get('now',0)}
        if destination not in allowed:raise CacheError('目的地不是已批准成员 / Destination is not an approved member',403)
    if frame.get('action')!='reserve':return
    meta=(frame.get('body') or {}).get('manifest') or {};context=((meta.get('envelope') or {}).get('header') or {}).get('context') or {}
    sender=next((m for m in approved['members'] if m['_id']==opened['context']['sender_mid']),None)
    if context.get('sender_mid')!=opened['context']['sender_mid'] or not sender:raise CacheError('发件成员不匹配 / Sender membership mismatch',403)
    active={m['_id']:m for m in approved['members'] if m.get('expires_at') is None or m['expires_at']>opened.get('now',0)}
    if meta.get('audience')=='direct':
        target=active.get(context.get('peer_mid'))
        if not target:raise CacheError('接收成员已失效 / Recipient membership expired',403)
        allowed={crypto.peer_id(sender['source']['crypto_public']),crypto.peer_id(target['source']['crypto_public'])}
        if set(meta.get('recipients') or [])!=allowed:raise CacheError('单点接收范围不匹配 / Private recipient scope mismatch',403)
    elif meta.get('audience')=='group':
        allowed={crypto.peer_id(m['source']['crypto_public']) for m in active.values()};actual=set(meta.get('recipients') or [])
        root=crypto.peer_id(approved['group']['source']['crypto_public'])
        if not actual.issubset(allowed) or root not in actual or opened['peer'] not in actual:raise CacheError('公共接收范围不匹配 / Public recipient scope mismatch',403)
    else:raise CacheError('接收范围无效 / Invalid recipient scope')
