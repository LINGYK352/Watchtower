"""Persistent credential state and authenticated peer envelopes (no process-local trust)."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import time
from urllib.parse import urlsplit

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError:
    # The175/176 native baseline already ships this Rust implementation for its
    # signing runtime, but its frozen importer omitted the tiny public aead alias.
    # Reuse the same authenticated cipher so this fix remains a source hot-update.
    from cryptography.hazmat.bindings._rust import openssl as _rust_openssl
    AESGCM = _rust_openssl.aead.AESGCM


class ControlSyncError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def ttl(value, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ControlSyncError(f"有效期必填且必须为{minimum}至{maximum}秒 / Expiry must be {minimum}–{maximum} seconds")
    return value


def text(value, maximum: int = 100, required: bool = True) -> str:
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ControlSyncError("文本参数无效 / Invalid text parameter")
    if any(ord(c) < 32 for c in value):
        raise ControlSyncError("文本不能含控制字符 / Control characters are not allowed")
    return value.strip()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def unb64(value: str, maximum: int = 96 * 1024 * 1024) -> bytes:
    if not isinstance(value, str) or len(value) > maximum or not re.fullmatch(r"[A-Za-z0-9_=-]+", value):
        raise ControlSyncError("加密消息格式无效 / Invalid encrypted message")
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True)
    except Exception:
        raise ControlSyncError("加密消息格式无效 / Invalid encrypted message") from None


def normalize_target(value: str, *, resolve: bool = True) -> str:
    value = text(value, 300)
    if "://" not in value:
        value = "http://" + value
    try:
        u = urlsplit(value)
        port = u.port
        host = u.hostname or ""
    except ValueError:
        raise ControlSyncError("地址或端口无效 / Invalid address or port") from None
    if u.scheme not in ("http", "https") or not host or u.username is not None or u.password is not None:
        raise ControlSyncError("请输入HTTP(S)目标IP/域名和端口 / Enter target IP/domain and port")
    if u.path not in ("", "/") or u.query or u.fragment or "\\" in value or "%" in host:
        raise ControlSyncError("目标仅能包含IP/域名和端口 / Target must contain only a host and port")
    port = (443 if u.scheme == "https" else 80) if port is None else port
    if not 1 <= port <= 65535:
        raise ControlSyncError("端口无效 / Invalid port")
    try:
        host = host.encode("idna").decode("ascii").lower()
        ip = ipaddress.ip_address(host)
        addresses = [ip]
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ControlSyncError("域名无效 / Invalid domain") from None
        addresses = []
        if resolve:
            try:
                addresses = [ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
            except OSError:
                raise ControlSyncError("目标域名无法解析 / Cannot resolve target") from None
    blocked = {ipaddress.ip_address(x) for x in ("169.254.169.254", "100.100.100.200", "192.0.0.192")}
    effective = [getattr(a, "ipv4_mapped", None) or a for a in addresses]
    if any(a.is_link_local or a.is_multicast or a.is_unspecified or a in blocked for a in effective):
        raise ControlSyncError("目标地址不支持 / Unsupported target address")
    netloc = f"[{host}]" if ":" in host else host
    return f"{u.scheme}://{netloc}:{port}"


class LocalSecrets:
    """The machine key is runtime data and never shipped with application updates."""
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "machine.key"
        if not self.path.exists():
            # O_EXCL closes a simultaneous first-start race. Only the winning process writes.
            try:
                fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as f:
                    f.write(secrets.token_bytes(32))
                    f.flush()
                    os.fsync(f.fileno())
        # A concurrent creator can be between open and write; bounded read, no key regeneration.
        key = b""
        for _ in range(50):
            key = self.path.read_bytes()
            if len(key) == 32:
                break
            time.sleep(.02)
        if len(key) != 32:
            raise ControlSyncError("本机同步密钥不可用 / Machine sync key unavailable", 503)
        self._key = key

    def seal(self, value: str, context: str) -> str:
        nonce = secrets.token_bytes(12)
        return b64(nonce + AESGCM(self._key).encrypt(nonce, value.encode(), context.encode()))

    def open(self, value: str, context: str) -> str:
        try:
            raw = unb64(value)
            return AESGCM(self._key).decrypt(raw[:12], raw[12:], context.encode()).decode()
        except Exception:
            raise ControlSyncError("本机凭据无法解密 / Cannot decrypt local credential", 503) from None


def encode_peer(secret: str, link_id: str, action: str, value, clock=time.time) -> dict:
    ts = int(clock())
    nonce = secrets.token_bytes(12)
    aad = canonical([1, link_id, action, ts])
    ciphertext = AESGCM(bytes.fromhex(digest(secret))).encrypt(nonce, canonical(value), aad)
    return {"v": 1, "id": link_id, "action": action, "ts": ts, "nonce": b64(nonce), "data": b64(ciphertext)}


def decode_peer(secret: str, packet: dict, action: str, clock=time.time):
    if not isinstance(packet, dict) or packet.get("v") != 1 or packet.get("action") != action:
        raise ControlSyncError("同步消息不匹配 / Sync message mismatch", 401)
    ts = packet.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int) or abs(clock() - ts) > 120:
        raise ControlSyncError("同步消息已过期，请检查双方时间 / Message expired; check both system clocks", 401)
    nonce = unb64(packet.get("nonce"), 30)
    if len(nonce) != 12:
        raise ControlSyncError("同步消息无效 / Invalid sync message", 401)
    try:
        raw = AESGCM(bytes.fromhex(digest(secret))).decrypt(nonce, unb64(packet.get("data")), canonical([1, packet["id"], action, ts]))
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except Exception:
        raise ControlSyncError("同步认证失败 / Sync authentication failed", 401) from None
