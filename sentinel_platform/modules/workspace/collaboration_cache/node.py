"""Independent Linux node: bounded relay, optional opaque ciphertext hosting."""
import argparse
import hashlib
import hmac
import json
import os
import sys
import secrets
import ssl
import threading
import time
import math
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from . import crypto
from .policy import CacheError, CHUNK, MIB, canonical, identifier, normalize
from .store import CipherStore

MAX_FRAME = 8 * MIB


from contextlib import contextmanager

@contextmanager
def _identity_lock(directory):
    # An OS lock is released even when a worker dies. Shared by all gunicorn
    # workers; no stale lock-file ownership or process-local initialization.
    with (directory/'.identity.lock').open('a+b') as handle:
        if handle.seek(0,2)==0:handle.write(b'0');handle.flush()
        handle.seek(0)
        if os.name=='nt':
            import msvcrt
            deadline=time.monotonic()+15
            while True:
                try:msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1);break
                except OSError:
                    if time.monotonic()>=deadline:raise CacheError('节点身份初始化繁忙，请重试 / Node identity initialization busy; retry',503)
                    time.sleep(.05)
        else:
            import fcntl
            fcntl.flock(handle,fcntl.LOCK_EX)
        try:yield
        finally:
            handle.seek(0)
            if os.name=='nt':msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(handle,fcntl.LOCK_UN)


class NodeCore:
    def __init__(self, directory, mode='relay', quota=1024 * MIB, clock=time.time, shared_relay=False):
        self.directory = Path(directory).resolve(); self.directory.mkdir(parents=True, exist_ok=True)
        if mode not in ('relay', 'cache'):
            raise ValueError('Invalid node mode')
        self.mode, self.clock = mode, clock
        self.store = CipherStore(self.directory / 'cache', quota, clock) if mode == 'cache' else None
        self.shared_relay=None
        if shared_relay:
            if self.store is None:raise ValueError('Application shared relay requires its transaction store')
            from .shared_relay import SharedRelay
            self.shared_relay=SharedRelay(self.store,clock)
        self._lock = threading.Condition(threading.RLock())
        self._realms, self._mailboxes, self._requests, self._nonces = {}, {}, {}, {}
        self._relay_bytes = 0
        identity = self.directory / 'node.key'
        access = self.directory / 'admin.key'
        with _identity_lock(self.directory):
            for path, generate in ((identity, crypto.generate), (access, lambda: secrets.token_urlsafe(32))):
                # Old versions created the final file before RSA generation. A
                # crash left an empty file which every future startup trusted.
                # Only empty interrupted files are recoverable automatically;
                # existing nonempty identities must never be silently rotated.
                if path.exists() and path.stat().st_size == 0:
                    os.replace(path, path.with_name(path.name+'.interrupted-empty'))
                if not path.exists():
                    value=generate()
                    import tempfile
                    fd, temporary=tempfile.mkstemp(prefix='.'+path.name+'-',dir=self.directory)
                    try:
                        with os.fdopen(fd,'w',encoding='ascii') as handle:
                            handle.write(value);handle.flush();os.fsync(handle.fileno())
                        os.replace(temporary,path)
                    finally:
                        if os.path.exists(temporary):os.unlink(temporary)
            self.private=identity.read_text(encoding='ascii')
            self.admin=access.read_text(encoding='ascii')
            if len(self.admin)<32:
                raise CacheError('节点管理凭据损坏，请恢复备份 / Node administration key is damaged; restore its backup',503)
        self.public = crypto.public_pem(self.private)
        self.peer = crypto.peer_id(self.public)
        if self.store:
            with self.store._db() as db:
                db.execute('CREATE TABLE IF NOT EXISTS realms(id TEXT PRIMARY KEY,meta TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS auth_nonces(id TEXT PRIMARY KEY,expires REAL NOT NULL)')
                self._realms = {r['id']: json.loads(r['meta']) for r in db.execute('SELECT * FROM realms')}

    def info(self):
        return {'protocol': 'watchtower-node-1', 'version': '1.0.0-test', 'mode': self.mode,
                'peer': self.peer, 'public': self.public, 'max_frame': MAX_FRAME,
                'usage': self.store.usage() if self.store else {'reserved_bytes': 0, 'objects': 0, 'quota_bytes': 0}}

    def setup(self, admin, body):
        self.check_admin(admin)
        realm = identifier(body.get('realm')); host = body.get('host_public')
        host_id = crypto.peer_id(host)
        join, member = body.get('join_token'), body.get('member_token')
        if any(not isinstance(token, str) or not 32 <= len(token) <= 128 for token in (join, member)):
            raise CacheError('节点接入凭据无效 / Invalid node access credential')
        policy = normalize(body.get('policy'))
        if policy['mode'] == 'hosted' and not self.store:
            raise CacheError('该节点未开启密文托管 / Ciphertext hosting is not enabled on this node', 409)
        value = {'host_public': host, 'host': host_id, 'join_hash': hashlib.sha256(join.encode()).hexdigest(),
                 'member_hash': hashlib.sha256(member.encode()).hexdigest(), 'policy': policy,
                 'revoked': body.get('revoked') or [], 'closed': body.get('closed') is True}
        for peer in value['revoked']:
            identifier(peer)
        with self._lock:
            if self.store:
                with self.store._db(True) as db:
                    row = db.execute('SELECT meta FROM realms WHERE id=?', (realm,)).fetchone()
                    old = json.loads(row['meta']) if row else None
                    if old and old['host'] != host_id:
                        raise CacheError('工作组主持身份发生变化 / Workgroup host identity changed', 409)
                    db.execute('INSERT OR REPLACE INTO realms VALUES(?,?)', (realm, canonical(value).decode()))
            else:
                old = self._realms.get(realm)
                if old and old['host'] != host_id:
                    raise CacheError('工作组主持身份发生变化 / Workgroup host identity changed', 409)
            self._realms[realm] = value
        return {'registered': True, 'realm': realm, 'host': host_id}

    def check_admin(self, admin):
        if not isinstance(admin, str) or not hmac.compare_digest(self.admin, admin):
            raise CacheError('节点管理凭据无效 / Invalid node administration credential', 401)
        return {'valid': True, 'peer': self.peer}

    def _authenticate(self, request):
        if not isinstance(request, dict):
            raise CacheError('节点请求无效 / Invalid node request')
        frame, signature = request.get('frame'), request.get('signature')
        if not isinstance(frame, dict):
            raise CacheError('节点认证帧无效 / Invalid node authentication frame')
        realm = identifier(frame.get('realm')); actor = identifier(frame.get('peer'))
        pub = frame.get('public')
        if crypto.peer_id(pub) != actor:
            raise CacheError('节点通信身份不匹配 / Node peer identity mismatch', 401)
        crypto.verify(pub, frame, signature)
        stamp, nonce = frame.get('ts'), frame.get('nonce')
        if isinstance(stamp, bool) or not isinstance(stamp, int) or abs(self.clock() - stamp) > 120:
            raise CacheError('节点请求已过期 / Node request expired', 401)
        identifier(nonce)
        token = frame.get('token')
        if not isinstance(token, str) or len(token) > 128:
            raise CacheError('节点接入凭据无效 / Invalid node access credential', 401)
        with self._lock:
            if self.store:
                with self.store._db() as db:
                    row = db.execute('SELECT meta FROM realms WHERE id=?', (realm,)).fetchone()
                    value = json.loads(row['meta']) if row else None
            else:
                value = self._realms.get(realm)
            if value is None:
                raise CacheError('主持尚未注册节点路径 / Host has not registered this node route', 503)
            if value.get('closed'):
                raise CacheError('工作组已关闭 / Workgroup closed', 410)
            digest = hashlib.sha256(token.encode()).hexdigest()
            joining = hmac.compare_digest(value['join_hash'], digest)
            approved = hmac.compare_digest(value['member_hash'], digest)
            if not joining and not approved or actor in value['revoked']:
                raise CacheError('节点接入被拒绝 / Node access denied', 403)
            marker = actor + ':' + nonce
            if self.store:
                import sqlite3
                with self.store._db(True) as db:
                    db.execute('DELETE FROM auth_nonces WHERE expires<=?',(self.clock(),))
                    if db.execute('SELECT COUNT(*) FROM auth_nonces').fetchone()[0]>=10000:
                        raise CacheError('节点请求繁忙 / Node request capacity reached',429)
                    try:db.execute('INSERT INTO auth_nonces VALUES(?,?)',(marker,self.clock()+180))
                    except sqlite3.IntegrityError:raise CacheError('节点请求已使用 / Node request replayed',409) from None
            else:
                if marker in self._nonces:
                    raise CacheError('节点请求已使用 / Node request replayed',409)
                self._nonces={k:v for k,v in self._nonces.items() if v>self.clock()}
                if len(self._nonces)>=10000:raise CacheError('节点请求繁忙 / Node request capacity reached',429)
                self._nonces[marker]=self.clock()+180
        if approved:
            grant = frame.get('grant') or {}
            claim = grant.get('claim') or {}
            crypto.verify(value['host_public'], claim, grant.get('signature'))
            if claim.get('realm') != realm or claim.get('peer') != actor or claim.get('public') != pub:
                raise CacheError('节点授权范围不匹配 / Node grant scope mismatch', 403)
            if claim.get('role') not in ('host', 'member'):
                raise CacheError('节点授权角色无效 / Invalid node grant role', 403)
            expires = claim.get('expires_at')
            if isinstance(expires, bool) or not isinstance(expires, (int, float)) or not math.isfinite(expires) or expires <= self.clock() or expires>self.clock()+7*86400+120:
                raise CacheError('节点授权已过期 / Node authorization expired', 410)
        return frame, value, joining and not approved

    def call(self, request):
        frame, realm, joining = self._authenticate(request)
        action, body = frame.get('action'), frame.get('body') or {}
        if not isinstance(body, dict):
            raise CacheError('节点参数无效 / Invalid node parameters')
        gid, peer = frame['realm'], frame['peer']
        if action in ('relay', 'poll', 'reply'):
            return self._relay(action, gid, peer, body, realm, joining)
        if joining:
            raise CacheError('未获批成员不能使用托管 / Unapproved members cannot use hosting', 403)
        if not self.store:
            raise CacheError('工作组未开启密文托管 / Hosting is disabled for this workgroup', 409)
        oid = body.get('id')
        if action=='grant_recipient':
            if peer!=realm['host'] or (frame.get('grant') or {}).get('claim',{}).get('role')!='host':
                raise CacheError('仅主持可扩展公共对象授权 / Only host may extend public object access',403)
            meta=self.store.metadata(oid,gid,peer)['manifest'];grants=body.get('grants') or {}
            main=crypto.verify_grant(meta['envelope'],grants.get('main') or {},realm['host_public'],self.clock())
            caption=crypto.verify_grant(meta['caption']['envelope'],grants.get('caption') or {},realm['host_public'],self.clock())
            if main['recipient']!=caption['recipient']:raise CacheError('说明与文件授权身份不一致 / Caption and payload delegation differ',403)
            return self.store.grant_recipient(oid,gid,peer,grants)
        if action == 'reserve':
            meta = body.get('manifest')
            if not isinstance(meta, dict) or not isinstance(meta.get('envelope'), dict):
                raise CacheError('缺少密文封装 / Ciphertext envelope required')
            envelope = meta['envelope']; header = envelope.get('header') or {}
            crypto.verify(header.get('public'), header, envelope.get('signature'))
            context = header.get('context') or {}
            if header.get('sender') != peer or crypto.peer_id(header.get('public')) != peer or context.get('group') != gid or context.get('id') != meta.get('id') or context.get('audience') != meta.get('audience'):
                raise CacheError('托管封装身份不匹配 / Hosting envelope identity mismatch', 403)
            if header.get('bytes') != meta.get('bytes') or header.get('sha256') != meta.get('sha256') or sorted(header.get('keys') or {}) != sorted(meta.get('recipients') or []):
                raise CacheError('托管清单与密文不一致 / Manifest does not match ciphertext')
            if realm['policy']['mode'] != 'hosted':
                with self.store._db() as db:
                    row=db.execute('SELECT id FROM objects WHERE id=? AND realm=? AND sender=?',(meta.get('id'),gid,peer)).fetchone()
                if not row:raise CacheError('新托管已关闭，现有缓存可继续领取 / New hosting disabled; existing cache remains retrievable',409)
            return self.store.reserve(gid, peer, meta, realm['policy'])
        if action == 'progress':
            return self.store.progress(oid, gid, peer)
        if action == 'put':
            raw = crypto.decode(body.get('data'), CHUNK)
            return self.store.put(oid, gid, peer, body.get('index'), raw, body.get('sha256'))
        if action == 'commit':
            receipt = self.store.commit(oid, gid, peer)
            return {'receipt': receipt, 'signature': crypto.sign(self.private, receipt)}
        if action == 'list':
            limit=body.get('limit',100);rows=self.store.list(gid,peer,limit=limit,before=body.get('before'))
            return {'items':rows,'next':[rows[-1]['created_at'],rows[-1]['id']] if len(rows)==limit else None}
        if action == 'metadata':
            return self.store.metadata(oid, gid, peer)
        if action == 'begin_read':
            return self.store.begin_read(oid, gid, peer)
        if action == 'end_read':
            return self.store.end_read(oid, gid, peer, body.get('lease'))
        if action == 'get':
            raw = self.store.read(oid, gid, peer, body.get('index'), body.get('lease'))
            return {'data': crypto.encode(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        if action == 'ack':
            proof = body.get('proof') or {}; claim = proof.get('claim') or {}
            crypto.verify(frame['public'], claim, proof.get('signature'))
            if claim.get('id') != oid or claim.get('recipient') != peer or claim.get('kind') != body.get('kind'):
                raise CacheError('收取回执范围不匹配 / Receipt scope mismatch', 403)
            return self.store.acknowledge(oid, gid, peer, body.get('kind'), canonical(proof).decode(), body.get('lease'))
        if action == 'cancel':
            return self.store.cancel(oid, gid, peer)
        if action == 'usage':
            return self.store.usage(gid)
        raise CacheError('节点操作不支持 / Unsupported node operation')

    def _relay(self, action, realm, peer, body, config, joining):
        if self.shared_relay is not None:
            return self.shared_relay.call(action,realm,peer,body,config,joining)
        with self._lock:
            now = self.clock()
            for key, queue in list(self._mailboxes.items()):
                kept = deque()
                for frame in queue:
                    if frame['expires'] > now:
                        kept.append(frame)
                    else:
                        self._relay_bytes -= frame['size']
                self._mailboxes[key] = kept
            self._requests = {k: v for k, v in self._requests.items() if v['expires'] > now}
            if action == 'relay':
                destination = identifier(body.get('destination')); rid = identifier(body.get('id'))
                if joining and destination != config['host']:
                    raise CacheError('申请路径仅可指向主持 / Join route may only target the host', 403)
                data = body.get('data')
                encoded = canonical(data)
                if len(encoded) > MAX_FRAME or self._relay_bytes + len(encoded) > 64 * MIB:
                    raise CacheError('转发缓冲繁忙，请稍后重试 / Relay buffer busy; retry shortly', 429)
                old = self._requests.get(rid)
                digest = hashlib.sha256(encoded).hexdigest()
                if old:
                    if old['realm'] != realm or old['source'] != peer or old['destination'] != destination or old['hash'] != digest:
                        raise CacheError('转发请求标识冲突 / Relay request identity conflict', 409)
                    return {'queued': True, 'id': rid}
                queue = self._mailboxes.setdefault((realm, destination), deque())
                if len(queue) >= 100:
                    raise CacheError('目标转发队列繁忙 / Destination relay queue busy', 429)
                self._requests[rid] = {'realm': realm, 'source': peer, 'destination': destination, 'hash': digest, 'expires': now + 120}
                frame = {'id': rid, 'source': peer, 'destination': destination, 'type': 'request', 'data': data, 'expires': now + 120, 'size': len(encoded)}
                queue.append(frame); self._relay_bytes += len(encoded); self._lock.notify_all()
                return {'queued': True, 'id': rid}
            if action == 'reply':
                rid = identifier(body.get('id')); original = self._requests.get(rid)
                if original is None or original['realm'] != realm or original['destination'] != peer:
                    raise CacheError('转发回复无权限 / Relay response not authorized', 403)
                if joining:
                    raise CacheError('未获批成员不能回复服务请求 / Unapproved peer cannot reply', 403)
                data = body.get('data'); encoded = canonical(data)
                if len(encoded) > MAX_FRAME or self._relay_bytes + len(encoded) > 64 * MIB:
                    raise CacheError('回复缓冲繁忙 / Relay response buffer busy', 429)
                destination = original['source']; queue = self._mailboxes.setdefault((realm, destination), deque())
                if len(queue) >= 100:
                    raise CacheError('回复队列繁忙 / Response queue busy', 429)
                queue.append({'id': rid, 'source': peer, 'destination': destination, 'type': 'response', 'data': data, 'expires': now + 120, 'size': len(encoded)})
                self._relay_bytes += len(encoded); self._lock.notify_all()
                return {'queued': True}
            if action == 'poll':
                queue = self._mailboxes.setdefault((realm, peer), deque())
                wait = body.get('wait', 0)
                if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not 0 <= wait <= 10:
                    raise CacheError('轮询期限无效 / Invalid poll duration')
                if not queue and wait:
                    self._lock.wait(wait)
                values = []
                total = 0
                while queue and len(values) < 8 and total + queue[0]['size'] <= MAX_FRAME:
                    item = queue.popleft(); self._relay_bytes -= item['size']; values.append({k: v for k, v in item.items() if k != 'size'})
                    total += item['size']
                return {'frames': values}

    def collect(self):
        return self.store.collect() if self.store else {'removed': []}


def handler(core):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log envelopes, credentials, filenames or content.
        def send(self, value, status=200):
            raw = canonical(value)
            self.send_response(status); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw))); self.send_header('Cache-Control', 'no-store')
            self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            if self.path != '/v1/info':
                return self.send({'error': 'Not found'}, 404)
            self.send(core.info())
        def do_POST(self):
            try:
                if self.headers.get('Origin'):
                    raise CacheError('节点接口不接受浏览器Origin / Browser Origin is not accepted', 403)
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= MAX_FRAME:
                    raise CacheError('节点请求过大 / Node request too large', 413)
                body = json.loads(self.rfile.read(size))
                if self.path == '/v1/setup':
                    value = core.setup(self.headers.get('X-Node-Key', ''), body)
                elif self.path == '/v1/admin/check':
                    value = core.check_admin(self.headers.get('X-Node-Key', ''))
                elif self.path == '/v1/call':
                    value = core.call(body)
                else:
                    raise CacheError('节点路径不支持 / Unsupported node path', 404)
                self.send({'data': value})
            except CacheError as error:
                self.send({'error': str(error)}, error.status)
            except (ValueError, TypeError, KeyError):
                self.send({'error': 'Invalid node request'}, 400)
            except Exception:
                self.send({'error': 'Node temporarily unavailable'}, 503)
    return Handler


class BoundedServer(ThreadingHTTPServer):
    """Bound active connections, including slow clients and long polls."""
    daemon_threads = True
    def __init__(self, address, handler_class):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, handler_class)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        request.settimeout(20)
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def argument_parser():
    legacy = Path(sys.executable).resolve().parent / 'data'
    default_directory = legacy if getattr(sys, 'frozen', False) and (legacy / 'admin.key').is_file() else Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local' / 'state') / 'watchtower-node'
    parser = argparse.ArgumentParser(description='Watchtower maintenance node: encrypted forwarding and bounded ciphertext cache; no IP setup required')
    parser.add_argument('--data-dir', default=str(default_directory), help='Private persistent state directory; defaults to XDG_STATE_HOME/watchtower-node')
    parser.add_argument('--bind', default='0.0.0.0'); parser.add_argument('--port', type=int, default=7443)
    parser.add_argument('--mode', choices=('relay', 'cache'), default='cache')
    parser.add_argument('--quota-mib', type=int, default=1024)
    parser.add_argument('--cert'); parser.add_argument('--key')
    parser.add_argument('--public-host', help='Create a local self-signed certificate for this IP/domain; verify the printed fingerprint')
    return parser


def main():
    parser = argument_parser(); args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error('Provide both --cert and --key, or omit both for automatic TLS')
    if not 0 <= args.port <= 65535 or not 64 <= args.quota_mib <= 65536:
        parser.error('Port must be 0..65535; cache quota must be 64..65536 MiB')
    directory = Path(args.data_dir).resolve(); directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fingerprint=''
    # An explicit loopback bind preserves the old local HTTP testing contract.
    # The normal zero-argument listener always has a persistent pinned TLS identity.
    if not args.cert and (args.public_host or args.bind not in ('127.0.0.1', '::1')):
        from .tls import certificate
        args.cert,args.key,fingerprint=certificate(directory,args.public_host or 'watchtower-node.local')
    if args.bind not in ('127.0.0.1', '::1') and not (args.cert and args.key):
        parser.error('TLS certificate/key required for non-loopback listeners')
    core = NodeCore(args.data_dir, args.mode, args.quota_mib * MIB)
    server = BoundedServer((args.bind, args.port), handler(core))
    if args.cert and args.key:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(args.cert, args.key); server.socket = tls.wrap_socket(server.socket, server_side=True)
    stopped = threading.Event()
    def collector():
        while not stopped.wait(60):
            try:
                core.collect()
            except Exception:
                pass
    threading.Thread(target=collector, daemon=True, name='node-cache-gc').start()
    print(json.dumps({'node': core.peer, 'mode': core.mode, 'admin_credential_file': str(core.directory / 'admin.key'),
                      'listen':args.bind+':'+str(server.server_address[1]),
                      'tls_sha256':fingerprint,'hosting_quota_mib':args.quota_mib if core.store else 0}), flush=True)
    try:
        server.serve_forever()
    finally:
        stopped.set(); server.server_close()


if __name__ == '__main__':
    main()
