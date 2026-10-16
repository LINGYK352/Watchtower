"""Independent invitation lifecycles, stored in the existing group document."""
import copy
import hmac
import secrets
from .control_sync.security import ControlSyncError, digest, text
from .collaboration_invites import admission, invitation_settings
from . import collaboration_profiles as profiles

MAX_KEYS = 100


def context(gid, row):
    return gid + ':group-invite' if row.get('legacy') else gid + ':' + row['_id'] + ':group-invite'


def rows(service, group):
    if isinstance(group.get('invitations'), list):
        return copy.deepcopy(group['invitations'])
    if not group.get('invite'):
        return []
    secret = service.control.secrets.open(group['invite'], group['_id'] + ':group-invite')
    return [{'_id': digest(secret), 'secret': group['invite'], 'legacy': True, 'primary': True,
             'name': '', 'created_at': group['created_at'], 'expires_at': group.get('invite_expires_at'),
             'single_use': False, 'max_members': group.get('max_members', 100),
             'approval_required': group.get('approval_required', True), 'uses': 0}]


def record(service, gid, secret, duration, settings, primary=False, name=''):
    row = {'_id': digest(secret), 'primary': primary, 'legacy': primary, 'name': name,
           'created_at': service.clock(), 'expires_at': service.clock() + duration if duration else None,
           'single_use': settings.get('single_use', False), 'max_members': settings['max_members'],
           'approval_required': settings['approval_required'], 'public_target': settings['public_target'], 'uses': 0}
    row['secret'] = service.control.secrets.seal(secret, context(gid, row))
    return row


def used(service, gid, row):
    return bool(row.get('consumed_by') or service.members.find_one({'group_id': gid, 'invite_id': row['_id'], 'host': {'$ne': True}}))


def check(service, gid, row, allow_consumed=False):
    if row.get('revoked_at') is not None:
        raise ControlSyncError('邀请Key已撤销 / Invitation Key revoked', 410)
    if row.get('expires_at') is not None and row['expires_at'] <= service.clock():
        raise ControlSyncError('邀请Key已过期 / Invitation Key expired', 410)
    if row.get('single_use') and not allow_consumed and used(service, gid, row):
        raise ControlSyncError('一次性邀请Key已使用 / One-time invitation Key consumed', 410)


def selected(service, group, invitation_id=None):
    entries = rows(service, group)
    if invitation_id is None:
        row = next((entry for entry in entries if entry.get('legacy')), None)
    else:
        if not isinstance(invitation_id, str) or len(invitation_id) != 64 or any(c not in '0123456789abcdef' for c in invitation_id):
            raise ControlSyncError('邀请标识无效 / Invalid invitation identifier', 401)
        row = next((entry for entry in entries if entry['_id'] == invitation_id), None)
    if row is None:
        raise ControlSyncError('邀请Key不存在 / Invitation Key unavailable', 401)
    check(service, group['_id'], row, allow_consumed=True)
    return row


def store(service, group, entries):
    update = {'invitations': entries, 'invitation_format': 2}
    primary = next((entry for entry in entries if entry.get('legacy')), None)
    if primary:
        update['invite_primary_id'] = primary['_id']
        # A rollback to the old single-Key implementation must fail closed for
        # one-time or revoked originals, rather than resurrect a reusable Key.
        if primary.get('single_use') or primary.get('revoked_at') is not None:
            update['invite_expires_at'] = service.clock() - 1
    changed = service.groups.update_one({'_id': group['_id'], 'enabled': True,
        'deleted_at': {'$exists': False}, 'admission_owner': group['admission_owner']}, {'$set': update})
    if not changed.matched_count:
        raise ControlSyncError('工作组已关闭或操作租约失效 / Group closed or lease lost', 409)


def metadata(service, group, row):
    status = 'active'
    if row.get('revoked_at') is not None: status = 'revoked'
    elif row.get('expires_at') is not None and row['expires_at'] <= service.clock(): status = 'expired'
    elif row.get('single_use') and used(service, group['_id'], row): status = 'consumed'
    result = {key: row.get(key) for key in ('_id', 'primary', 'name', 'created_at', 'expires_at',
            'single_use', 'max_members', 'approval_required', 'uses', 'public_target')}
    result['state'] = status
    return result


def list_keys(service, gid, user):
    group = service._host(gid, user)
    return {'items': [metadata(service, group, row) for row in reversed(rows(service, group))], 'max_keys': MAX_KEYS}


def reveal(service, gid, iid, user):
    group = service._host(gid, user)
    row = selected(service, group, iid)
    check(service, gid, row)
    secret = service.control.secrets.open(row['secret'], context(gid, row))
    return {'key': 'wt_group.' + gid + '.' + secret,
            'public_target': row.get('public_target') or group.get('public_target', ''), 'invitation': metadata(service, group, row)}


def issue(service, gid, user, body):
    group = service._host(gid, user)
    duration, settings = invitation_settings(body, group)
    if settings['max_members'] > group.get('max_members', 100):
        raise ControlSyncError('邀请名额不能超过工作组总人数上限 / Invitation quota exceeds group limit')
    secret = secrets.token_urlsafe(32)
    with admission(service, gid) as current:
        entries = rows(service, current)
        if len(entries) >= MAX_KEYS:
            raise ControlSyncError('邀请Key记录已达上限 / Invitation history limit reached', 409)
        row = record(service, gid, secret, duration, settings, name=text(body.get('name') or '', 80, required=False))
        entries.append(row)
        store(service, current, entries)
    return {'key': 'wt_group.' + gid + '.' + secret, 'expires_at': row['expires_at'],
            'public_target': row['public_target'], 'invitation': metadata(service, current, row)}


def revoke(service, gid, iid, user):
    service._host(gid, user)
    with admission(service, gid) as group:
        entries = rows(service, group)
        row = next((entry for entry in entries if entry['_id'] == iid), None)
        if row is None: raise ControlSyncError('邀请Key不存在 / Invitation Key unavailable', 404)
        if row.get('revoked_at') is None:
            row['revoked_at'] = service.clock()
            store(service, group, entries)
    return {'revoked': True}


def admit_key(service, original, body, identity, invitation_id):
    with admission(service, original['_id']) as group:
        entries = rows(service, group)
        row = next((entry for entry in entries if entry['_id'] == invitation_id), None)
        if row is None: raise ControlSyncError('邀请已变化 / Invitation changed', 401)
        check(service, group['_id'], row, allow_consumed=True)
        secret = text(body.get('secret'), 43)
        if len(secret) != 43: raise ControlSyncError('成员凭证无效 / Invalid membership secret')
        existing = service.members.find_one({'_id': body['member_id']})
        if existing:
            if existing.get('host') or existing.get('group_id') != group['_id'] or existing.get('invite_id') != invitation_id:
                raise ControlSyncError('成员身份冲突 / Conflicting member identity', 409)
            old = service.control.secrets.open(existing['secret'], existing['_id'] + ':group-member')
            if not hmac.compare_digest(old, secret): raise ControlSyncError('成员凭证不匹配 / Membership secret mismatch', 401)
            if existing['state'] not in ('pending', 'approved') or existing['expires_at'] <= service.clock():
                raise ControlSyncError('申请已失效 / Application expired or rejected', 410)
            return existing
        if row.get('single_use') and used(service, group['_id'], row):
            raise ControlSyncError('一次性邀请Key已使用 / One-time invitation Key consumed', 410)
        active = {'group_id': group['_id'], 'host': {'$ne': True}, 'state': {'$in': ['pending', 'approved']}, 'expires_at': {'$gt': service.clock()}}
        if service.members.count_documents(active) >= group.get('max_members', 100):
            raise ControlSyncError('工作组人数已满（含待审） / Workgroup full, including pending applications', 409)
        if service.members.count_documents(dict(active, invite_id=invitation_id)) >= row['max_members']:
            raise ControlSyncError('此邀请的名额已满（含待审） / Invitation quota full, including pending applications', 409)
        now = service.clock(); approved = row['approval_required'] is False
        duration = group['member_duration'] if approved else min(group['member_duration'], 86400)
        member = {'_id': body['member_id'], 'group_id': group['_id'], 'invite_id': invitation_id,
                  **profiles.fields(service,group,identity), 'source': identity, 'state': 'approved' if approved else 'pending',
                  'host': False, 'created_at': now, 'expires_at': now + duration,
                  'secret': service.control.secrets.seal(secret, body['member_id'] + ':group-member')}
        service.members.insert_one(member)
        row['uses'] = row.get('uses', 0) + 1
        row['last_used_at'] = now
        if row.get('single_use'): row['consumed_by'] = member['_id']
        store(service, group, entries)
        return member
