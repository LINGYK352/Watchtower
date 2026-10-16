"""Verified service destination over direct HTTP or a pre-authorized outbound route."""
import hashlib
import secrets
import time
from datetime import datetime, timezone
from . import crypto
from .client import NodeClient
from .policy import CacheError
from . import relay_waits,routes
from ..control_sync.security import normalize_target


def send(cache, user, destination, packet, relay=None, seconds=18):
    pub = destination['public']; peer = crypto.peer_id(pub)
    url = normalize_target(destination['url'], resolve=False) if destination.get('url') else ''
    now = cache.clock(); markers = cache.collaboration.nonces
    health_id = 'service-route:' + hashlib.sha256((user['username'] + ':' + peer + ':' + url).encode()).hexdigest()
    health = markers.find_one({'_id': health_id}) or {}
    if url and (not relay or url.rstrip('/') != relay.get('url', '').rstrip('/')) and health.get('retry_at', 0) <= now:
        try:
            sender=getattr(cache.collaboration,'direct_send',None)
            answer = sender(url,'service',packet,seconds=seconds) if sender else cache.collaboration.send(url,'service',packet)
            markers.delete_one({'_id': health_id})
            routes.remember(cache,user,packet['envelope']['header']['context']['group'],pub,'direct')
            return answer
        except Exception as exc:
            if getattr(exc, 'status', 0) not in (502, 503, 504):
                raise
            if not relay:
                raise
            markers.update_one({'_id': health_id}, {'$set': {'retry_at': now + 12,
                'expires': datetime.fromtimestamp(now + 30, timezone.utc)}}, upsert=True)
    if not relay:
        raise CacheError('服务入口暂不可达，本地数据保持 / Service entrance unavailable; local data retained', 502)
    client = NodeClient(relay, cache.key(user), cache.clock)
    client.deadline = time.monotonic() + seconds
    grant = relay.get('grant') or {}
    joining = (grant.get('claim') or {}).get('expires_at', 0) <= now
    if joining:
        raise CacheError('服务转发授权已过期，请刷新工作组连接 / Service route grant expired; refresh membership', 410)
    rid = secrets.token_hex(16)
    marker = relay_waits.register(cache,user,relay['realm'],rid,pub)
    try:
        client.call('relay', {'id': rid, 'destination': peer, 'data': {'action': 'service', 'packet': packet}})
        while time.monotonic() < client.deadline:
            found = relay_waits.take(cache,user,marker)
            if found is not None:
                routes.remember(cache,user,packet['envelope']['header']['context']['group'],pub,'node')
                return found
            frames = client.call('poll', {'wait': 1})['frames']
            relay_waits.dispatch(cache,user,client,frames)
        raise CacheError('服务节点未及时回应，待发资料保持 / Service node did not respond; outbox retained', 502)
    finally:relay_waits.discard(cache,user,marker)
