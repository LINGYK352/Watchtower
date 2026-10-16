"""Shared response demultiplexing for all workers polling the same member route."""
import hashlib
from datetime import datetime, timezone
from . import crypto
from .policy import CacheError, identifier


def key(realm, actor, rid):
    identifier(realm); identifier(actor); identifier(rid)
    return 'relay-wait:' + hashlib.sha256((realm + ':' + actor + ':' + rid).encode()).hexdigest()


def register(cache, user, realm, rid, public, ttl=180):
    actor = cache.identity(user)['crypto_peer']
    marker = key(realm, actor, rid)
    value = {'_id': marker, 'owner': user['username'], 'expected_peer': crypto.peer_id(public),
             'expected_public': public, 'until': cache.clock() + ttl,
             'expires': datetime.fromtimestamp(cache.clock() + ttl, timezone.utc)}
    cache.collaboration.nonces.update_one({'_id': marker}, {'$setOnInsert': value}, upsert=True)
    return marker


def accept(cache, user, realm, frame):
    if frame.get('type') != 'response':
        return False
    rid = frame.get('id'); marker = key(realm, cache.identity(user)['crypto_peer'], rid)
    pending = cache.collaboration.nonces.find_one({'_id': marker, 'owner': user['username'], 'until': {'$gt': cache.clock()}})
    if pending is None:
        return False
    if frame.get('source') != pending['expected_peer']:
        raise CacheError('中转回复者与目标服务不匹配 / Relay reply sender differs from target service', 401)
    value = frame.get('data') or {}; reply = value.get('reply') or {}
    crypto.verify(pending['expected_public'], reply, value.get('signature'))
    if reply.get('id') != rid:
        raise CacheError('中转回复标识不匹配 / Relay reply identity mismatch', 409)
    # First verified response wins. Another polling worker leaves it untouched.
    cache.collaboration.nonces.update_one({'_id': marker, 'owner': user['username'],
            'until': {'$gt': cache.clock()}, 'answer': {'$exists': False}},
            {'$set': {'answer': reply}})
    return True


def take(cache, user, marker):
    value = cache.collaboration.nonces.find_one_and_delete({'_id': marker, 'owner': user['username'],
                   'until': {'$gt': cache.clock()}, 'answer': {'$exists': True}})
    if not value:
        return None
    result = value['answer']
    if result.get('error'):
        raise CacheError(result['error'], result.get('status', 503))
    return result['packet']


def discard(cache, user, marker):
    cache.collaboration.nonces.delete_one({'_id': marker, 'owner': user['username']})


def dispatch(cache,user,client,frames):
    for frame in frames:
        if frame.get('type')=='response':
            try:accept(cache,user,client.config['realm'],frame)
            except CacheError:pass  # Reject spoofed replies without starving unrelated requests.
            continue
        if frame.get('type')!='request':continue
        data=frame.get('data') or {};rid=frame.get('id')
        try:
            bound=getattr(cache.collaboration,'peer_relay',None)
            packet=bound(data['action'],data['packet'],via_peer=frame['source'],via_realm=client.config['realm']) if bound else cache.collaboration.peer(data['action'],data['packet'],via_peer=frame['source'])
            reply={'id':rid,'packet':packet}
        except Exception as exc:
            reply={'id':rid,'error':str(exc) if hasattr(exc,'status') else '协同服务暂不可用 / Collaboration service unavailable',
                   'status':getattr(exc,'status',503)}
        try:client.call('reply',{'id':rid,'data':{'reply':reply,'signature':crypto.sign(cache.key(user),reply)}})
        except CacheError:pass  # The sender's original outbox/request survives a lost route.
