"""Bounded node probes; persisted CAS leases are shared by every web worker."""
from concurrent.futures import ThreadPoolExecutor
import secrets
import threading
import time
from . import crypto
from .client import request
from .policy import CacheError

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='node-health')
_slots = threading.BoundedSemaphore(8)  # Capacity only; never an authority for health.


def public(row, now):
    if row.get('enabled') is False:
        return {'state': 'disabled', 'checking': False, 'checked_at': row.get('health_checked_at') or 0,
                'last_success': row.get('health_success_at') or 0, 'latency_ms': None, 'reason': 'disabled'}
    checked = row.get('health_checked_at') or 0
    checking = (row.get('health_until') or 0) > now
    fresh = checked and 0 <= now - checked < 15
    state = ('healthy' if row.get('health_ok') else 'unhealthy') if fresh else ('checking' if checking else 'unknown')
    return {'state': state, 'checking': checking, 'checked_at': checked,
            'last_success': row.get('health_success_at') or 0,
            'latency_ms': row.get('health_latency_ms') if fresh else None,
            'reason': row.get('health_reason') if fresh else 'stale' if checked else 'not_checked'}


def _probe(service, row, token):
    started = time.monotonic(); ok = False; reason = 'network'
    try:
        info = request({'url': row['url'], 'tls_fingerprint': row.get('tls_fingerprint') or ''}, '/v1/info', timeout=2)
        if info.get('protocol') != 'watchtower-node-1' or info.get('peer') != row['peer'] or crypto.peer_id(info.get('public')) != row['peer']:
            reason = 'identity_changed'
        elif row.get('mode') == 'cache' and info.get('mode') != 'cache':
            reason = 'hosting_unavailable'
        else:
            ok = True; reason = ''
    except CacheError as exc:
        reason = 'identity_changed' if exc.status == 409 else 'network'
    except Exception:
        reason = 'invalid_response'
    finally:
        try:
            now = service.clock()
            values = {'health_ok': ok, 'health_reason': reason, 'health_checked_at': now,
                      'health_latency_ms': round((time.monotonic()-started)*1000),
                      'health_next_at': now+5, 'health_until': 0}
            if ok:
                values['health_success_at'] = now
            service.nodes.update_one({'_id': row['_id'], 'owner': row['owner'], 'group_id': row['group_id'],
                                      'health_token': token, 'url': row['url'], 'peer': row['peer'],
                                      'tls_fingerprint': row.get('tls_fingerprint') or ''}, {'$set': values})
        finally:
            _slots.release()


def schedule(service, rows):
    """Return immediately, bound queued work, and never resurrect a deleted node."""
    for row in rows:
        if not row.get('enabled') or not _slots.acquire(blocking=False):
            continue
        token = secrets.token_hex(16); now = service.clock()
        try:
            changed = service.nodes.update_one({'_id': row['_id'], 'owner': row['owner'], 'group_id': row['group_id'],
                '$and': [{'$or': [{'health_until': {'$exists': False}}, {'health_until': {'$lte': now}}]},
                         {'$or': [{'health_next_at': {'$exists': False}}, {'health_next_at': {'$lte': now}}]}]},
                {'$set': {'health_token': token, 'health_until': now+30}})
            if not changed.matched_count:
                _slots.release(); continue
            _pool.submit(_probe, service, dict(row), token)
        except Exception:
            _slots.release()
            raise
