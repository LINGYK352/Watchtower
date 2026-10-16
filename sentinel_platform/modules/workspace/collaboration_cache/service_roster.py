"""Host-signed service roster; replicas cannot create membership or administrative roles."""
import copy
import math
import hashlib
from pymongo import ReturnDocument
from . import crypto
from .policy import CacheError, identifier, normalize,canonical


def issue(cache, group):
    service=cache.collaboration
    for _ in range(5):
        # Re-read both management and membership after each CAS conflict.
        # A signer that lost to revocation must never publish its earlier role snapshot.
        row=service.groups.find_one({'_id':group['_id'],'enabled':True})
        if not row:raise CacheError('工作组已关闭 / Workgroup closed',410)
        now=cache.clock()
        members=[service._public_member(m) for m in service.members.find({'group_id':group['_id'],
            'state':'approved','$or':[{'expires_at':None},{'expires_at':{'$gt':now}}]})]
        actors=list(service.members.find({'group_id':group['_id'],'state':'approved','cohost':True,'expires_at':{'$gt':now}}))
        services=[]
        for actor in actors:
            offer=actor.get('service_offer') or {}
            if offer.get('enabled') and offer.get('public')==actor.get('source',{}).get('crypto_public'):
                services.append({'member_id':actor['_id'],'public':offer['public'],'node_public':offer['node_public'],
                    'url':offer.get('url') or '','priority':int(actor.get('service_priority') or 50),'ready':actor.get('service_state')=='ready'})
        services.sort(key=lambda s:(s['priority'],s['member_id']))
        state={'schema':1,'group':service._public_group(row),'members':members,'services':services,'policy':normalize(row.get('cache_policy'))}
        digest=hashlib.sha256(canonical(state)).hexdigest();previous=row.get('service_revision',0)
        cached=row.get('service_snapshot') or {}
        if row.get('service_snapshot_hash')==digest and isinstance(cached,dict):
            try:
                claim=verify(cached,row['source']['crypto_public'],group['_id'],now,previous)
                if claim['version']==previous and claim['expires_at']>now+12*3600:return cached
            except (CacheError,KeyError,TypeError,AttributeError):
                pass  # Reissue an invalid historical cache; permissions and state were read fresh.
        issued_at=cache.clock()
        claim=dict(state,version=previous+1,created_at=issued_at,expires_at=issued_at+7*86400)
        signed={'claim':claim,'signature':crypto.sign(cache.key({'username':row['owner']}),claim)}
        selector={'_id':row['_id'],'enabled':True,'service_revision':previous if 'service_revision' in row else {'$exists':False}}
        changed=service.groups.update_one(selector,{'$set':{'service_revision':previous+1,'service_snapshot':signed,'service_snapshot_hash':digest}})
        if changed.matched_count:return signed
    raise CacheError('成员表正在变动，请稍后重试 / Roster changing; retry shortly',409)



def verify(value, issuer_public, gid, now, previous=0):
    if not isinstance(value, dict) or set(value) != {'claim', 'signature'}:
        raise CacheError('服务成员表无效 / Invalid service roster')
    claim = value.get('claim') or {}; crypto.verify(issuer_public, claim, value.get('signature'))
    if claim.get('schema') != 1 or (claim.get('group') or {}).get('_id') != gid:
        raise CacheError('服务成员表工作区不匹配 / Service roster workspace mismatch', 403)
    version = claim.get('version'); created, expires = claim.get('created_at'), claim.get('expires_at')
    if isinstance(version, bool) or not isinstance(version, int) or version < previous or version < 1:
        raise CacheError('服务成员表版本倒退 / Service roster version regressed', 409)
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in (created, expires)) or created > now + 120 or not now < expires <= created + 7 * 86400 or expires > now + 7 * 86400 + 120:
        raise CacheError('服务成员表已过期 / Service roster expired', 410)
    members, services = claim.get('members'), claim.get('services')
    if not isinstance(members, list) or not 1 <= len(members) <= 101 or not isinstance(services, list) or len(services) > 20:
        raise CacheError('服务成员表范围超限 / Service roster exceeds its scope')
    ids, peers = set(), set(); host = None; table = {}
    for member in members:
        if not isinstance(member, dict):
            raise CacheError('服务成员格式无效 / Invalid service member')
        mid = identifier(member.get('_id')); pub = (member.get('source') or {}).get('crypto_public'); peer = crypto.peer_id(pub)
        if mid in ids or peer in peers or member.get('state') != 'approved':
            raise CacheError('服务成员重复或未批准 / Duplicate or unapproved service member')
        ids.add(mid); peers.add(peer); table[mid] = member
        until = member.get('expires_at')
        if until is not None and (isinstance(until, bool) or not isinstance(until, (int, float)) or not math.isfinite(until)):
            raise CacheError('服务成员授权期限无效 / Invalid service membership expiry', 410)
        if member.get('host'):
            if host is not None or mid != gid or peer != crypto.peer_id(issuer_public):
                raise CacheError('服务管理主持身份不匹配 / Service administrative host identity mismatch', 403)
            host = member
    if host is None:
        raise CacheError('服务成员表缺少管理主持 / Service roster has no administrative host', 403)
    seen = set()
    for candidate in services:
        if not isinstance(candidate, dict):
            raise CacheError('副主持服务格式无效 / Invalid co-host service')
        mid = identifier(candidate.get('member_id')); member = table.get(mid)
        if mid in seen or not member or member.get('host') or member.get('cohost') is not True or candidate.get('public') != member['source']['crypto_public']:
            raise CacheError('副主持资格未被主持批准 / Co-host role is not approved by the host', 403)
        priority = candidate.get('priority')
        if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 100:
            raise CacheError('服务优先级无效 / Invalid service priority')
        crypto.public(candidate.get('node_public'))
        if candidate.get('url'):
            from ..control_sync.security import normalize_target
            normalize_target(candidate['url'], resolve=False)
        seen.add(mid)
    return copy.deepcopy(claim)
