"""End-to-end sealed service frames. Transport may relay them, never change identity."""
import hashlib
import json
import math
import secrets
import time
from . import crypto
from .policy import CacheError, canonical, identifier, MIB

MAX_PLAINTEXT = 5 * MIB
CONTEXT = {'id', 'group', 'audience', 'sender_mid', 'peer', 'action', 'created_at', 'expires_at', 'grant_hash'}


def encode(private, recipient_public, gid, mid, action, body, grant=None, rid=None, now=None):
    now = time.time() if now is None else now
    gid, mid, rid = identifier(gid), identifier(mid), identifier(rid or secrets.token_hex(16))
    if not isinstance(action, str) or not action or len(action) > 64 or not isinstance(body, dict):
        raise CacheError('协同服务参数无效 / Invalid collaboration service parameters')
    raw = canonical(body)
    if len(raw) > MAX_PLAINTEXT:
        raise CacheError('协同服务帧超限 / Collaboration service frame exceeds limit', 413)
    peer = crypto.peer_id(recipient_public)
    context = {'id': rid, 'group': gid, 'audience': 'direct', 'sender_mid': mid, 'peer': peer,
               'action': action, 'created_at': now, 'expires_at': now + 120,
               'grant_hash': hashlib.sha256(canonical(grant)).hexdigest()}
    envelope, encrypted = crypto.seal(raw, private, {peer: recipient_public}, context)
    return {'rpc': 1, 'envelope': envelope, 'data': crypto.encode(encrypted), 'grant': grant}


def decode(private, packet, gid, expected_sender=None, rid=None, action=None, now=None):
    now = time.time() if now is None else now
    identifier(gid)
    if not isinstance(packet, dict) or set(packet) != {'rpc', 'envelope', 'data', 'grant'} or packet.get('rpc') != 1:
        raise CacheError('协同服务帧格式无效 / Invalid collaboration service frame')
    envelope = packet['envelope']
    if not isinstance(envelope, dict) or set(envelope) != {'header', 'signature'}:
        raise CacheError('协同服务封装无效 / Invalid collaboration service envelope')
    header = envelope.get('header') or {}; context = header.get('context') or {}
    if not isinstance(context, dict) or set(context) != CONTEXT or context.get('group') != gid or context.get('audience') != 'direct':
        raise CacheError('协同服务作用域不匹配 / Collaboration service scope mismatch', 403)
    identifier(context.get('id')); identifier(context.get('sender_mid'))
    public = crypto.public_pem(private); peer = crypto.peer_id(public)
    if context.get('peer') != peer or set(header.get('keys') or {}) != {peer}:
        raise CacheError('协同服务接收身份不匹配 / Collaboration service recipient mismatch', 403)
    if rid is not None and context['id'] != rid or action is not None and context['action'] != action:
        raise CacheError('协同服务请求与回复不匹配 / Collaboration service reply does not match request', 409)
    created, expires = context.get('created_at'), context.get('expires_at')
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in (created, expires)) or not now - 120 <= created <= now + 120 or expires <= now or not 0 < expires - created <= 120:
        raise CacheError('协同服务帧已过期 / Collaboration service frame expired', 410)
    if context.get('grant_hash') != hashlib.sha256(canonical(packet['grant'])).hexdigest():
        raise CacheError('协同服务权限证明已变化 / Collaboration service authorization changed', 401)
    raw = crypto.decode(packet.get('data'), MAX_PLAINTEXT + 16)
    if len(raw) > MAX_PLAINTEXT + 16:
        raise CacheError('协同服务帧超限 / Collaboration service frame exceeds limit', 413)
    decrypted = crypto.open_object(envelope, raw, private, expected_sender)
    try:
        body = json.loads(decrypted.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise CacheError('协同服务正文无效 / Invalid collaboration service body') from None
    if not isinstance(body, dict):
        raise CacheError('协同服务正文必须是对象 / Collaboration service body must be an object')
    return {'context': context, 'public': header['public'], 'peer': header['sender'],
            'grant': packet['grant'], 'body': body}


def grant(issuer_public, value, gid, member_public, now=None):
    now = time.time() if now is None else now
    if not isinstance(value, dict) or set(value) != {'claim', 'signature'}:
        raise CacheError('缺少成员服务授权 / Member service authorization required', 403)
    claim = value.get('claim') or {}
    crypto.verify(issuer_public, claim, value.get('signature'))
    if claim.get('realm') != gid or claim.get('peer') != crypto.peer_id(member_public) or claim.get('public') != member_public or claim.get('role') not in ('host', 'member'):
        raise CacheError('成员服务授权范围不匹配 / Member service authorization scope mismatch', 403)
    if claim['role']=='host' and crypto.peer_id(member_public)!=crypto.peer_id(issuer_public):
        raise CacheError('管理主持身份不可委托 / Administrative host identity cannot be delegated',403)
    expires = claim.get('expires_at')
    if isinstance(expires, bool) or not isinstance(expires, (int, float)) or not math.isfinite(expires) or not now < expires <= now + 7 * 86400 + 120:
        raise CacheError('成员服务授权已过期 / Member service authorization expired', 410)
    return claim
