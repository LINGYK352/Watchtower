"""Workspace-owned node settings, lazy legacy migration and bounded closure retries."""
import hashlib
import secrets
from . import crypto
from .client import endpoint, request
from .policy import CacheError, identifier, normalize
from ..collaboration_invites import admission


def owned(service, nid, user, gid=None):
    row = service.nodes.find_one({'_id': identifier(nid), 'owner': user['username']})
    if row is None and gid:
        # A simultaneous worker may have completed the same legacy conversion.
        row = service.nodes.find_one({'_id': hashlib.sha256((gid + ':' + nid).encode()).hexdigest()[:32],
                                      'group_id': gid, 'owner': user['username'], 'migrated_from': nid})
    if row is None:
        raise CacheError('节点配置不存在或无权限 / Node configuration unavailable', 404)
    if gid is None:
        return row
    if row.get('group_id'):
        if row['group_id'] != gid:
            raise CacheError('节点属于另一工作区 / Node belongs to another workspace', 403)
        return row
    # Only migrate an old setting which is already referenced by this group.
    group = service.collaboration.groups.find_one({'_id': gid, 'owner': user['username']})
    refs = [group.get('node_access') or {}] + [r.get('access') or {} for r in group.get('draining_nodes', [])] if group else []
    if not any(r.get('node_id') == nid for r in refs):
        raise CacheError('旧节点未绑定此工作区，请在区内重新添加 / Legacy node is not bound to this workspace; add it here', 409)
    new_id = hashlib.sha256((gid + ':' + nid).encode()).hexdigest()[:32]
    secret = service.control.secrets.open(row['admin_key'], nid + ':node-admin')
    migrated = dict(row, _id=new_id, group_id=gid, migrated_from=nid,
                    admin_key=service.control.secrets.seal(secret, new_id + ':node-admin'))
    service.nodes.update_one({'_id': new_id}, {'$setOnInsert': migrated}, upsert=True)
    update = {}
    if (group.get('node_access') or {}).get('node_id') == nid:
        update['node_access.node_id'] = new_id
        if (group.get('cache_policy') or {}).get('node_id') == nid:
            update['cache_policy.node_id'] = new_id
    drains = group.get('draining_nodes', [])
    if any(r.get('access', {}).get('node_id') == nid for r in drains):
        update['draining_nodes'] = [{**r, 'access': dict(r['access'], node_id=new_id)}
                                  if r.get('access', {}).get('node_id') == nid else r for r in drains]
    if update:
        service.collaboration.groups.update_one({'_id': gid, 'owner': user['username']}, {'$set': update})
    service.tasks.update_many({'owner': user['username'], 'group_id': gid, 'node_id': nid}, {'$set': {'node_id': new_id}})
    # Shared legacy settings remain private until their other groups also migrate.
    if not service.collaboration.groups.find_one({'owner': user['username'], '$or': [
            {'node_access.node_id': nid}, {'draining_nodes.access.node_id': nid}]}):
        service.nodes.delete_one({'_id': nid, 'owner': user['username'], 'group_id': {'$exists': False}})
    return service.nodes.find_one({'_id': new_id, 'group_id': gid, 'owner': user['username']})


def list_nodes(service, user, gid, refresh=False):
    if not gid:
        raise CacheError('请先进入工作区再配置维持节点 / Enter a workspace before configuring maintenance nodes')
    group = service.collaboration._host(identifier(gid), user)
    refs = [group.get('node_access') or {}] + [r.get('access') or {} for r in group.get('draining_nodes', [])]
    for ref in refs:
        if ref.get('node_id'):
            owned(service, ref['node_id'], user, gid)
    query = {'owner': user['username'], 'group_id': gid}
    if refresh:
        from . import node_health
        node_health.schedule(service, list(service.nodes.find(query)))
    return {'items': [service.public_node(row, now=service.clock()) for row in service.nodes.find(query)]}


def add(service, user, body):
    gid = identifier(body.get('group_id'))
    service.collaboration._host(gid, user)
    if service.nodes.count_documents({'owner': user['username'], 'group_id': gid}) >= 20:
        raise CacheError('每个工作区最多20个维持节点 / Maximum 20 maintenance nodes per workspace', 409)
    name = body.get('name', '')
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise CacheError('节点名称必填且最多80字 / Node name required, maximum 80 characters')
    url = body.get('url', ''); endpoint(url)
    secret = body.get('admin_key')
    if not isinstance(secret, str) or not 32 <= len(secret) <= 128:
        raise CacheError('节点接入凭据无效 / Invalid node administration credential')
    config = {'url': url, 'tls_fingerprint': body.get('tls_fingerprint') or ''}
    info = request(config, '/v1/info')
    if info.get('protocol') != 'watchtower-node-1' or crypto.peer_id(info.get('public')) != info.get('peer'):
        raise CacheError('目标不是兼容的Watchtower节点 / Target is not a compatible Watchtower node', 409)
    request(config, '/v1/admin/check', {}, secret)
    nid = secrets.token_hex(16)
    row = {'_id': nid, 'group_id': gid, 'owner': user['username'], 'name': name.strip(), 'url': url,
           'tls_fingerprint': config['tls_fingerprint'], 'peer': info['peer'], 'public': info['public'],
           'mode': info['mode'], 'enabled': True, 'checked_at': service.clock(), 'error': '',
           'admin_key': service.control.secrets.seal(secret, nid + ':node-admin')}
    with admission(service.collaboration, gid):
        if service.nodes.count_documents({'owner': user['username'], 'group_id': gid}) >= 20:
            raise CacheError('每个工作区最多20个维持节点 / Maximum 20 maintenance nodes per workspace', 409)
        service.nodes.insert_one(row)
    return service.public_node(row)


def close_group(service, group, user):
    gid = group['_id']
    refs = [group] + [dict(group, node_access=r['access'], cache_policy=r['policy']) for r in group.get('draining_nodes', [])]
    visited = set()
    for route in refs:
        nid = (route.get('node_access') or {}).get('node_id')
        if not nid or nid in visited:
            continue
        visited.add(nid)
        try:
            node = owned(service, nid, user, gid)
            config = service._host_config(route, user)
            # Keep only a sealed revocation job if the external node is offline.
            job_id = 'node-close:' + gid + ':' + node['_id']
            job = {'_id': job_id, 'record_type': 'node_close', 'owner': user['username'], 'group_id': gid,
                   'state': 'queued', 'retry_at': service.clock(), 'expires_at': service.clock() + 7 * 86400 + 120,
                   'node': service.save_config(job_id, 'node', node), 'config': service.save_config(job_id, 'config', config)}
            service.tasks.update_one({'_id': job_id}, {'$setOnInsert': job}, upsert=True)
        except CacheError:
            pass  # Group tombstone remains the local authorization gate.
    service.nodes.delete_many({'owner': user['username'], 'group_id': gid})
    flush_closures(service)


def flush_closures(service):
    now = service.clock()
    service.tasks.delete_many({'record_type': 'node_close', 'expires_at': {'$lte': now}})
    for job in service.tasks.find({'record_type': 'node_close', 'retry_at': {'$lte': now}}).limit(2):
        token = secrets.token_hex(16)
        held = service.tasks.find_one_and_update({'_id': job['_id'], '$or': [
            {'lease_until': {'$exists': False}}, {'lease_until': {'$lte': now}}]},
            {'$set': {'lease_until': now + 60, 'lease_owner': token}})
        if not held:
            continue
        try:
            node = service.link_config(job, 'node'); config = service.link_config(job, 'config')
            secret = service.control.secrets.open(node['admin_key'], node['_id'] + ':node-admin')
            request(config, '/v1/setup', {'realm': job['group_id'], 'host_public': config['issuer_public'],
                    'join_token': config['join_token'], 'member_token': config['member_token'],
                    'policy': normalize(), 'revoked': [], 'closed': True}, secret)
            service.tasks.delete_one({'_id': job['_id'], 'lease_owner': token})
        except Exception:
            service.tasks.update_one({'_id': job['_id'], 'lease_owner': token},
                {'$set': {'retry_at': now + 60}, '$unset': {'lease_until': '', 'lease_owner': ''}})
