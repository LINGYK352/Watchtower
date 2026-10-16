"""Durable, encrypted preparation lets a one-time invitation survive a lost reply."""
from contextlib import contextmanager
from datetime import datetime, timezone
import secrets
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from .control_sync.security import ControlSyncError, text, digest, normalize_target, encode_peer, decode_peer


@contextmanager
def joining(service, user, gid, target):
    ident = 'join-lock:' + digest(user['username'] + '\0' + gid + '\0' + target)
    token = secrets.token_hex(16);now = service.clock()
    try:
        service.nonces.insert_one({'_id': ident, 'until': 0, 'expires': datetime.fromtimestamp(now + 60, timezone.utc)})
    except DuplicateKeyError:
        pass
    lock = service.nonces.find_one_and_update({'_id': ident, 'until': {'$lte': now}},
        {'$set': {'owner': token, 'until': now + 60, 'expires': datetime.fromtimestamp(now + 120, timezone.utc)}},
        return_document=ReturnDocument.AFTER)
    if lock is None: raise ControlSyncError('正在申请此工作组，请稍后重试 / Join already in progress; retry shortly', 409)
    try: yield
    finally: service.nonces.delete_one({'_id': ident, 'owner': token})


def _complete(service, link, user):
    # Query using the prepared membership secret first. It is independent of the
    # invitation and remains valid even if the host consumed the one-time Key.
    secret = service.control.secrets.open(link['secret'], link['_id'] + ':group-member')
    try:
        packet = encode_peer(secret, link['_id'], 'status', {}, service.clock)
        answer = decode_peer(secret, service.deliver(link, 'status', packet, user), 'status:response', service.clock)
        if answer.get('error'): answer = None
    except ControlSyncError:
        answer = None
    if not answer:
        key = service.control.secrets.open(link['join_invitation'], link['_id'] + ':group-join')
        parts = key.split('.');iid = digest(parts[2])
        packet = encode_peer(parts[2], link['group_id'], 'join', {
            'member_id': link['_id'], 'invite_id': iid, 'name': user['username'],
            'source': service.identity(user), 'secret': secret}, service.clock)
        packet['invite_id'] = iid
        answer = decode_peer(parts[2], service.deliver(link, 'join', packet, user), 'join:response', service.clock)
        if answer.get('error'): raise ControlSyncError(answer['error'], answer.get('status', 400))
    group = answer.get('group') or {}
    values = {'state': answer['state'], 'expires_at': answer['expires_at'],
              'name': group.get('name', link.get('name', '')), 'source': group.get('source', link.get('source', {}))}
    for name in ('peer_config','node_config'):
        if answer.get(name):values[name]=service.cache.save_config(link['_id'],name,answer[name])
    if answer.get('cache_policy'):values['cache_policy']=answer['cache_policy']
    changed = service.links.update_one({'_id': link['_id'], 'owner': user['username'], 'state': 'joining',
        'deleted_at': {'$exists': False}}, {'$set': values, '$unset': {'join_invitation': '', 'peer_error': '', 'peer_retry_at': ''}})
    if not changed.matched_count: raise ControlSyncError('申请已取消 / Join was canceled', 410)
    return service._public_link(dict(link, **values))


def complete(service, link, user):
    try:
        return _complete(service, link, user)
    except ControlSyncError as exc:
        permanent = exc.status in (400, 401, 403, 410)
        service.links.update_one({'_id': link['_id'], 'owner': user['username'], 'state': 'joining', 'deleted_at': {'$exists': False}},
            {'$set': {'state': 'join_failed' if permanent else 'joining', 'peer_error': str(exc), 'peer_retry_at': service.clock() + 30}})
        raise


def join(service, user, body):
    target = normalize_target(body.get('target'));key = text(body.get('key'), 100);parts = key.split('.')
    if len(parts) != 3 or parts[0] != 'wt_group' or len(parts[2]) != 43:
        raise ControlSyncError('工作组Key格式无效 / Invalid workgroup Key')
    from .collaboration import hex_id
    gid = hex_id(parts[1])
    with joining(service, user, gid, target):
        existing = service.links.find_one({'owner': user['username'], 'target': target, 'group_id': gid,
            'state': {'$in': ['joining', 'join_failed', 'pending', 'approved']}, 'deleted_at': {'$exists': False}, 'expires_at': {'$gt': service.clock()}})
        if existing:
            if existing['state'] in ('joining', 'join_failed'):
                # A corrected Key may replace a failed preparation; an already
                # admitted member still resumes through its membership secret.
                service.links.update_one({'_id': existing['_id'], 'owner': user['username'], 'state': existing['state']},
                    {'$set': {'state': 'joining', 'join_invitation': service.control.secrets.seal(key, existing['_id'] + ':group-join')}})
                existing['state'] = 'joining'
                existing['join_invitation'] = service.control.secrets.seal(key, existing['_id'] + ':group-join')
            return complete(service, existing, user) if existing['state'] == 'joining' else service._public_link(existing)
        mid = secrets.token_hex(16);secret = secrets.token_urlsafe(32);now = service.clock()
        prepared = {'_id': mid, 'group_id': gid, 'name': gid, 'owner': user['username'], 'target': target,
            'state': 'joining', 'created_at': now, 'expires_at': now + 1800, 'source': {},
            'secret': service.control.secrets.seal(secret, mid + ':group-member'),
            'join_invitation': service.control.secrets.seal(key, mid + ':group-join')}
        if body.get('node_descriptor'):
            descriptor=service.cache.validate_descriptor(body['node_descriptor'],gid)
            prepared['node_descriptor']=service.cache.save_config(mid,'node_descriptor',descriptor)
        service.links.insert_one(prepared)
        return complete(service, prepared, user)


def refresh(service, link, user):
    with joining(service, user, link['group_id'], link['target']):
        fresh = service.links.find_one({'_id': link['_id'], 'owner': user['username'], 'state': 'joining',
            'deleted_at': {'$exists': False}, 'expires_at': {'$gt': service.clock()}})
        if not fresh: raise ControlSyncError('申请已过期或处理 / Join expired or already completed', 410)
        return complete(service, fresh, user)
