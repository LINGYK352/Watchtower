"""Authenticated opaque object envelopes using existing cryptography primitives.

RSA-OAEP wraps a fresh AES-256-GCM object key for each recipient; RSA-PSS
authenticates the immutable header. No session/private keys are sent to a cache.
This object format is not a Signal/MLS implementation or an FS/PCS claim.
"""
import base64
import hashlib
import os
import math
from functools import lru_cache
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError:
    # The175/176 native baseline omits the public alias, but already embeds
    # this same Rust AEAD implementation (also used by control_sync.security).
    from cryptography.hazmat.bindings._rust import openssl as _rust_openssl
    AESGCM = _rust_openssl.aead.AESGCM
from .policy import CacheError, MAX_PACKAGE, MIB, CHUNK, canonical, identifier


def encode(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii')


def decode(value, maximum=8192):
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise CacheError('加密字段无效 / Invalid encrypted field')
    try:
        raw = base64.b64decode(value.encode('ascii'), altchars=b'-_', validate=True)
    except (ValueError, UnicodeError):
        raise CacheError('加密字段无效 / Invalid encrypted field') from None
    if len(raw) > maximum:
        raise CacheError('加密字段过大 / Encrypted field too large')
    return raw


def generate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode('ascii')


@lru_cache(maxsize=64)
def _private_value(value):
    try:
        key = serialization.load_pem_private_key(value.encode('ascii'), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
            raise ValueError()
        return key
    except (ValueError, TypeError, UnicodeError):
        raise CacheError('本机身份密钥不可用 / Local identity key unavailable', 503) from None


def private(value):
    # Parsing performs the RSA mathematical validation. It is immutable for an
    # exact PEM value; authorization and fresh identity lookup are never cached.
    if not isinstance(value,str) or len(value)>4096:
        raise CacheError('本机身份密钥不可用 / Local identity key unavailable',503)
    return _private_value(value)


def public(value):
    try:
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError()
        key = serialization.load_pem_public_key(value.encode('ascii'))
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048 or key.public_numbers().e != 65537:
            raise ValueError()
        return key
    except (ValueError, TypeError, UnicodeError):
        raise CacheError('通信身份公钥无效 / Invalid communication public key') from None


def public_pem(key):
    if isinstance(key, str):
        key = private(key)
    if hasattr(key, 'private_numbers'):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')


def peer_id(value):
    return fingerprint(value)[:32]


def fingerprint(value):
    key = public(value)
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def sign(key, value):
    key = private(key) if isinstance(key, str) else key
    return encode(key.sign(canonical(value), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))


def verify(public_key, value, signature):
    try:
        public(public_key).verify(decode(signature, 512), canonical(value),
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError):
        raise CacheError('通信签名校验失败 / Communication signature validation failed', 401) from None


def seal(raw, key, recipients, context):
    if not isinstance(raw, bytes) or len(raw) > MAX_PACKAGE + 256 * 1024:
        raise CacheError('待封装对象过大 / Object too large', 413)
    if not isinstance(context, dict) or not isinstance(recipients, dict) or not 1 <= len(recipients) <= 101:
        raise CacheError('封装范围无效 / Invalid envelope scope')
    identifier(context.get('id')); identifier(context.get('group'))
    if context.get('audience') not in ('group', 'direct'):
        raise CacheError('封装工作区无效 / Invalid envelope audience')
    identity = public_pem(key)
    secret, nonce = os.urandom(32), os.urandom(12)
    encrypted = AESGCM(secret).encrypt(nonce, raw, canonical(context))
    wrapped = {}
    for recipient, pub in recipients.items():
        if peer_id(pub) != recipient:
            raise CacheError('接收公钥与身份不匹配 / Recipient key does not match identity')
        wrapped[recipient] = encode(public(pub).encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=canonical(context))))
    header = {'v': 1, 'context': context, 'sender': peer_id(identity), 'public': identity,
              'nonce': encode(nonce), 'keys': wrapped, 'bytes': len(encrypted),
              'sha256': hashlib.sha256(encrypted).hexdigest(),
              'chunks': [hashlib.sha256(encrypted[offset:offset+CHUNK]).hexdigest() for offset in range(0, len(encrypted), CHUNK)]}
    return {'header': header, 'signature': sign(key, header)}, encrypted


def grant_recipient(envelope, host_key, recipient_public, expires_at):
    """An original authorized public recipient may delegate the unchanged object key."""
    header=envelope['header'];context=header['context']
    verify(header['public'],header,envelope['signature'])
    if context.get('audience')!='group':raise CacheError('单点密钥不能委托 / Private object keys cannot be delegated',403)
    signer=private(host_key) if isinstance(host_key,str) else host_key;own=peer_id(public_pem(signer))
    if own not in header['keys']:raise CacheError('主持端不是原始公共接收者 / Host is not an original public recipient',403)
    secret=signer.decrypt(decode(header['keys'][own],512),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=canonical(context)))
    wrapped=public(recipient_public).encrypt(secret,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=canonical(context)))
    claim={'id':context['id'],'group':context['group'],'recipient':peer_id(recipient_public),'public':recipient_public,
           'header_hash':hashlib.sha256(canonical(header)).hexdigest(),'wrapped':encode(wrapped),'expires_at':expires_at}
    return {'claim':claim,'signature':sign(signer,claim),'issuer':public_pem(signer)}


def recover_payload(envelope, key, raw):
    """Recover an interrupted immutable source snapshot; exact ciphertext must match."""
    header=envelope['header'];verify(header['public'],header,envelope['signature'])
    signer=private(key);own=peer_id(public_pem(signer));context=header['context']
    wrapped=header['keys'].get(own)
    if not wrapped:raise CacheError('发送快照身份不匹配 / Source snapshot identity mismatch',403)
    secret=signer.decrypt(decode(wrapped,512),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=canonical(context)))
    encrypted=AESGCM(secret).encrypt(decode(header['nonce'],12),raw,canonical(context))
    if len(encrypted)!=header['bytes'] or hashlib.sha256(encrypted).hexdigest()!=header['sha256']:
        raise CacheError('原始对象已变化，无法恢复旧快照；请重新分享 / Original object changed; old snapshot cannot recover; share again',409)
    return encrypted


def verify_grant(envelope, grant, issuer, now):
    claim=grant.get('claim') or {};header=envelope['header'];context=header['context']
    if context.get('audience')!='group' or peer_id(grant.get('issuer'))!=peer_id(issuer):
        raise CacheError('公共接收授权来源不匹配 / Public recipient delegation issuer mismatch',403)
    verify(issuer,claim,grant.get('signature'))
    if claim.get('id')!=context['id'] or claim.get('group')!=context['group'] or claim.get('header_hash')!=hashlib.sha256(canonical(header)).hexdigest() or peer_id(claim.get('public'))!=claim.get('recipient'):
        raise CacheError('公共接收授权范围不匹配 / Public recipient delegation scope mismatch',403)
    expires=claim.get('expires_at')
    if isinstance(expires,bool) or not isinstance(expires,(int,float)) or not math.isfinite(expires) or expires<=now or expires>now+7*86400+120:
        raise CacheError('公共接收授权已到期 / Public recipient delegation expired',410)
    return claim


def open_object(envelope, encrypted, key, expected_public=None, expected_issuer=None, now=None):
    if not isinstance(envelope, dict) or not isinstance(envelope.get('header'), dict):
        raise CacheError('密文封装无效 / Invalid object envelope')
    header = envelope['header']
    if header.get('v') != 1 or peer_id(header.get('public')) != header.get('sender'):
        raise CacheError('发送身份不匹配 / Sender identity mismatch', 401)
    if expected_public is not None and peer_id(expected_public) != header['sender']:
        raise CacheError('发送公钥发生变化，请核验身份 / Sender key changed; verify identity', 409)
    verify(header['public'], header, envelope.get('signature'))
    if not isinstance(encrypted, bytes) or len(encrypted) > MAX_PACKAGE + MIB or len(encrypted) != header.get('bytes') or hashlib.sha256(encrypted).hexdigest() != header.get('sha256'):
        raise CacheError('密文对象校验失败 / Ciphertext object validation failed', 409)
    signer = private(key)
    own_id = peer_id(public_pem(signer))
    wrapped = (header.get('keys') or {}).get(own_id)
    if not wrapped and expected_issuer:
        import time
        grant=(envelope.get('recipient_grants') or {}).get(own_id)
        if grant:
            claim=verify_grant(envelope,grant,expected_issuer,time.time() if now is None else now)
            if claim['recipient']!=own_id:raise CacheError('公共接收授权身份不匹配 / Public recipient delegation identity mismatch',403)
            wrapped=claim['wrapped']
    if not wrapped:
        raise CacheError('此对象没有授权给当前接收者 / Object not authorized for this recipient', 403)
    try:
        secret = signer.decrypt(decode(wrapped, 512), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=canonical(header['context'])))
        return AESGCM(secret).decrypt(decode(header['nonce'], 12), encrypted, canonical(header['context']))
    except (ValueError, KeyError, InvalidTag, TypeError):
        raise CacheError('对象解密失败 / Object decryption failed', 401) from None
