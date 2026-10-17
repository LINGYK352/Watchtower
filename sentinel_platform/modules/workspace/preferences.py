"""Per-account reachable address hints; no credentials, no discovery assumption."""
import hashlib
from .control_sync.security import normalize_target


def key(user):
    return 'workspace-address:' + hashlib.sha256(user['username'].encode()).hexdigest()


def get(repo, user):
    row = repo.collection('control_sync_identity').find_one({'_id': key(user), 'owner': user['username']}) or {}
    from .network_hints import addresses
    return {**{field: row.get(field, '') for field in ('group_target', 'sync_target')},'local_addresses':addresses()}


def save(repo, user, field, value):
    if field not in ('group_target', 'sync_target'):
        raise ValueError('Unknown reachable address preference')
    if value:
        target = normalize_target(value, resolve=False)
        repo.collection('control_sync_identity').update_one({'_id': key(user)},
            {'$set': {'owner': user['username'], field: target}}, upsert=True)
