"""Workgroup-scoped public aliases. Transport credentials keep their opaque IDs."""
import secrets
import string
import unicodedata
from .control_sync.security import ControlSyncError
from .collaboration_invites import admission

ALPHABET = string.ascii_letters + string.digits


def name_key(value):
    if not isinstance(value, str):
        raise ControlSyncError('工作区名称必须是文字 / Workspace name must be text')
    name = unicodedata.normalize('NFKC', value).strip()
    if not name or len(name) > 80 or any(unicodedata.category(ch).startswith('C') for ch in name):
        raise ControlSyncError('名称须为1至80字，不能包含控制字符 / Name must be 1–80 characters without controls')
    return name, name.casefold()


def fields(service, group, source, host=False):
    for _ in range(12):
        alias = ''.join(secrets.choice(ALPHABET) for _ in range(8))
        if service.members.find_one({'group_id': group['_id'], 'alias_id': alias}):
            continue
        prefix = 'W-win-' if source.get('product') == 'win' else 'W-linux-'
        proposed = (group.get('host_name') or group['name']) if host else prefix + alias
        name, key = name_key(proposed)
        if service.members.find_one({'group_id': group['_id'], 'name_key': key}):
            name, key = name_key(prefix + alias)
        if not service.members.find_one({'group_id': group['_id'], 'name_key': key}):
            return {'alias_id': alias, 'name': name, 'name_key': key, 'profile_format': 1}
    else:
        raise ControlSyncError('暂时无法分配工作区编号 / Cannot allocate a workspace identifier', 503)


def ensure(service, member):
    if member.get('profile_format') == 1:
        return member
    with admission(service, member['group_id']) as group:
        fresh = service.members.find_one({'_id': member['_id'], 'group_id': member['group_id']})
        if not fresh:
            raise ControlSyncError('成员已不存在 / Member no longer exists', 404)
        if fresh.get('profile_format') != 1:
            update = fields(service, group, fresh.get('source') or {}, fresh.get('host', False))
            service.members.update_one({'_id': fresh['_id'], 'profile_format': {'$ne': 1}}, {'$set': update})
            fresh = dict(fresh, **update)
        return fresh


def crypto_features(source):
    value=source.get('crypto_features') if isinstance(source,dict) else None
    return {'attachments':1} if isinstance(value,dict) and type(value.get('attachments')) is int and value['attachments']==1 else {}


def source_public(source, name):
    # A workspace participant sees aliases, never another installation's login.
    allowed = ('instance_id', 'product', 'platform', 'version', 'crypto_public',
               'crypto_peer', 'crypto_protocol', 'crypto_fingerprint')
    return {**{key: source[key] for key in allowed if key in source}, 'crypto_features':crypto_features(source), 'name': name, 'member': name}


def public(service, member):
    member = ensure(service, member)
    result = {key: member.get(key) for key in ('_id', 'group_id', 'alias_id', 'name',
              'state', 'created_at', 'expires_at', 'host', 'cohost')}
    result['source'] = source_public(member.get('source') or {}, member['name'])
    result['service_offered']=bool((member.get('service_offer') or {}).get('enabled'))
    result['service_state']=member.get('service_state') or ''
    if member.get('service_error'):result['service_error']=member['service_error']
    result['service_priority']=member.get('service_priority') or 50
    if result['state'] == 'approved' and result['expires_at'] is not None and result['expires_at'] <= service.clock():
        result['state'] = 'expired'
    if result['source'].get('crypto_public'):
        from .collaboration_cache.crypto import fingerprint
        result['source']['crypto_fingerprint'] = fingerprint(result['source']['crypto_public'])
    return result


def request_name(service, gid, mid, body):
    member = ensure(service, service.room_member(gid, mid))
    if member.get('host'):
        raise ControlSyncError('主持人请直接修改名称 / Host should rename directly')
    name, key = name_key(body.get('name'))
    previous = member.get('rename_request') or {}
    if previous.get('state') == 'pending' and previous.get('name_key') == key:
        return {'state': 'pending', 'name': previous['name']}
    if previous.get('created_at', 0) > service.clock() - 30:
        raise ControlSyncError('更名请求过于频繁，请稍后再试 / Rename requests are too frequent', 429)
    with admission(service, gid):
        if service.members.find_one({'group_id': gid, 'name_key': key, '_id': {'$ne': mid}}):
            raise ControlSyncError('名称已被本工作区使用 / Name already used in this workspace', 409)
        request = {'name': name, 'name_key': key, 'created_at': service.clock(), 'state': 'pending'}
        changed = service.members.update_one({'_id': mid, 'group_id': gid, 'state': 'approved'}, {'$set': {'rename_request': request}})
        if not changed.matched_count:
            raise ControlSyncError('成员已失效 / Membership no longer active', 410)
    return {'state': 'pending', 'name': name}


def rename(service, gid, mid, user, body, decision=False):
    service._host(gid, user)
    if decision and not isinstance(body.get('accepted'), bool):
        raise ControlSyncError('审核决定无效 / Invalid approval decision')
    with admission(service, gid):
        member = service.members.find_one({'_id': mid, 'group_id': gid, 'state': 'approved'})
        if not member:
            raise ControlSyncError('成员不存在或已失效 / Member unavailable', 404)
        request = member.get('rename_request') or {}
        if decision and request.get('state') != 'pending':
            raise ControlSyncError('更名请求已处理或不存在 / Rename request already handled or missing', 409)
        accepted = not decision or body['accepted']
        update = {}
        if accepted:
            name, key = name_key(request.get('name') if decision else body.get('name'))
            if service.members.find_one({'group_id': gid, 'name_key': key, '_id': {'$ne': mid}}):
                raise ControlSyncError('名称已被本工作区使用 / Name already used in this workspace', 409)
            update.update(name=name, name_key=key)
        if request:
            update['rename_request'] = dict(request, state='approved' if accepted else 'rejected', reviewed_at=service.clock())
        service.members.update_one({'_id': mid, 'group_id': gid, 'state': 'approved'}, {'$set': update})
        if accepted and member.get('host'):
            service.groups.update_one({'_id': gid}, {'$set': {'host_name': name}})
    return {'renamed': accepted, 'name': name if accepted else member['name']}


def rename_requests(service, gid):
    return [{**public(service, row), 'requested_name': row['rename_request']['name'],
             'requested_at': row['rename_request']['created_at']}
            for row in service.members.find({'group_id': gid, 'state': 'approved', 'rename_request.state': 'pending'})]
