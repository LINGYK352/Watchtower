"""Invitation policy and a shared admission lease; no in-process membership limits."""
from contextlib import contextmanager
import secrets
import time
from pymongo import ReturnDocument
from .control_sync.security import ControlSyncError, ttl, normalize_target, text


def invitation_settings(body, current=None):
    current = current or {}
    duration = body.get('expires_in', 0)
    if isinstance(duration, bool) or not isinstance(duration, int):
        raise ControlSyncError('邀请有效期无效 / Invalid invitation expiry')
    if duration != 0:
        duration = ttl(duration, 60, 90 * 86400)
    limit = body.get('max_members', current.get('max_members', 50))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ControlSyncError('成员上限须为1至100人（不含主持者） / Member limit must be 1–100, excluding the host')
    approval = body.get('approval_required', current.get('approval_required', True))
    if not isinstance(approval, bool):
        raise ControlSyncError('审核选项必须为布尔值 / Approval option must be boolean')
    single = body.get('single_use', False)
    if not isinstance(single, bool):
        raise ControlSyncError('邀请使用方式必须为布尔值 / Invitation use mode must be boolean')
    raw = body.get('public_target', current.get('public_target', ''))
    target = normalize_target(raw, resolve=False) if raw else ''  # Legacy clients still submit address and key separately.
    return duration, {'max_members': limit, 'approval_required': approval, 'public_target': target, 'single_use': single}


@contextmanager
def admission(service, gid):
    token = secrets.token_hex(16)
    deadline = time.monotonic() + 3
    while True:
        now = service.clock()
        group = service.groups.find_one_and_update(
            {'_id': gid, 'enabled': True, 'deleted_at': {'$exists': False}, '$or': [
                {'admission_until': {'$exists': False}}, {'admission_until': {'$lte': now}}]},
            {'$set': {'admission_owner': token, 'admission_until': now + 15}},
            return_document=ReturnDocument.AFTER)
        if group:
            break
        if time.monotonic() >= deadline:
            raise ControlSyncError('工作组正在处理加入请求，请稍后重试 / Admission is busy; retry shortly', 409)
        time.sleep(.03)
    try:
        yield group
    finally:
        service.groups.update_one({'_id': gid, 'admission_owner': token}, {'$unset': {'admission_owner': '', 'admission_until': ''}})


def admit(service, original, body, identity):
    with admission(service, original['_id']) as group:
        expires = group.get('invite_expires_at')
        if group.get('invite') != original.get('invite') or expires is not None and expires <= service.clock():
            raise ControlSyncError('邀请已更新或过期 / Invitation changed or expired', 401)
        if service.members.count_documents({'group_id': group['_id'], 'host': {'$ne': True}, 'state': {'$in': ['pending', 'approved']}, 'expires_at': {'$gt': service.clock()}}) >= group.get('max_members', 100):
            raise ControlSyncError('工作组人数已满（含待审申请） / Workgroup is full, including pending applications', 409)
        now = service.clock()
        approved = group.get('approval_required', True) is False
        duration = group['member_duration'] if approved else min(group['member_duration'], 86400)
        from . import collaboration_profiles as profiles
        member = {'_id': body['member_id'], 'group_id': group['_id'], **profiles.fields(service,group,identity), 'source': identity,
                  'state': 'approved' if approved else 'pending', 'host': False, 'created_at': now, 'expires_at': now + duration,
                  'secret': service.control.secrets.seal(text(body.get('secret'), 43), body['member_id'] + ':group-member')}
        service.members.insert_one(member)
        return member
