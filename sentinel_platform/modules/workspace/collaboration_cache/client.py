"""Backend-only node client, certificate pinning and signed scoped requests."""
import hashlib
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit
from . import crypto
from .policy import CacheError, CHUNK, MAX_PACKAGE, MIB, canonical, identifier


def endpoint(value):
    if not isinstance(value, str) or len(value) > 300 or '%' in value or '\\' in value:
        raise CacheError('节点地址无效 / Invalid node address')
    try:
        url = urlsplit(value if '://' in value else 'https://' + value)
        port = url.port or (443 if url.scheme == 'https' else 80)
        host = url.hostname.encode('idna').decode('ascii')
    except (ValueError, AttributeError, UnicodeError):
        raise CacheError('节点地址无效 / Invalid node address') from None
    if url.scheme not in ('http', 'https') or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment or not 1 <= port <= 65535:
        raise CacheError('节点地址只支持IP/域名和端口 / Node address must contain only host and port')
    return url.scheme, host, port


def request(config, path, body=None, admin=None, timeout=20):
    scheme, host, port = endpoint(config['url'])
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise CacheError('节点无法解析 / Cannot resolve node', 502) from None
    if not addresses:
        raise CacheError('节点没有可达地址 / Node has no reachable address', 502)
    blocked = {'169.254.169.254', '100.100.100.200', '192.0.0.192'}
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0]); ip = getattr(ip, 'ipv4_mapped', None) or ip
        if ip.is_multicast or ip.is_link_local or ip.is_unspecified or str(ip) in blocked:
            raise CacheError('节点地址不支持 / Unsupported node address')
        if scheme == 'http' and not (ip.is_private or ip.is_loopback):
            raise CacheError('公网节点必须使用HTTPS / Public node requires HTTPS')
    fingerprint = config.get('tls_fingerprint') or ''
    if fingerprint and (len(fingerprint) != 64 or any(c not in '0123456789abcdef' for c in fingerprint)):
        raise CacheError('TLS证书指纹无效 / Invalid TLS certificate fingerprint')
    if scheme == 'https':
        context = ssl.create_default_context()
        if fingerprint:
            # Explicitly pinned certificate, checked before sending any secret or payload.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn._create_connection = lambda _addr, timeout=timeout, source_address=None: socket.create_connection((addresses[0][4][0], port), timeout, source_address)
    try:
        conn.connect()
        if fingerprint:
            if scheme != 'https' or hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != fingerprint:
                raise CacheError('节点TLS身份变化，连接已停止 / Node TLS identity changed; connection stopped', 409)
        headers = {'Accept': 'application/json'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        if admin:
            headers['X-Node-Key'] = admin
        conn.request('GET' if body is None else 'POST', path, body=canonical(body) if body is not None else None, headers=headers)
        response = conn.getresponse(); raw = response.read(12 * MIB + 1)
        if len(raw) > 12 * MIB:
            raise CacheError('节点响应过大 / Node response too large', 413)
        value = json.loads(raw)
        if response.status != 200:
            raise CacheError(value.get('error', 'Node rejected request'), response.status)
        return value.get('data', value)
    except CacheError:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        raise CacheError('节点连接中断，任务已保留 / Node connection interrupted; task retained', 502) from None
    finally:
        conn.close()


class NodeClient:
    def __init__(self, config, private_key, clock=time.time):
        self.config, self.private, self.clock = dict(config), private_key, clock
        self.public = crypto.public_pem(private_key); self.peer = crypto.peer_id(self.public)

    def call(self, action, body=None, joining=False):
        frame = {'realm': identifier(self.config['realm']), 'peer': self.peer, 'public': self.public,
                 'ts': int(self.clock()), 'nonce': secrets.token_hex(16), 'action': action, 'body': body or {},
                 'token': self.config['join_token' if joining else 'member_token']}
        if not joining:
            frame['grant'] = self.config['grant']
        packet={'frame':frame,'signature':crypto.sign(self.private,frame)}
        deadline=getattr(self,'deadline',None)
        if deadline is not None:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise CacheError('节点通知时限已到，本地撤销保持 / Node notification deadline reached; local revocation retained',502)
            return request(self.config,'/v1/call',packet,timeout=min(20,remaining))
        return request(self.config, '/v1/call', packet)

    def upload(self, manifest, path):
        try:self.call('reserve',{'manifest':manifest})
        except CacheError as exc:
            if exc.status!=409 or manifest.get('audience')!='group':raise
            existing=self.call('metadata',{'id':manifest['id']})['manifest']
            def original(value):
                return {k:value.get(k) for k in ('id','bytes','sha256','audience')},value['envelope']['header'],value['envelope']['signature'],value['caption']['envelope']['header'],value['caption']['envelope']['signature'],value['caption']['data']
            try:matches=original(existing)==original(manifest)
            except (KeyError,TypeError,AttributeError):raise exc
            if not matches:raise exc
            from .replica_objects import _verify_delegations
            _verify_delegations(existing,self.config['issuer_public'],self.clock())
            # Existing public replicas can have newer host-signed recipient delegations.
            # Progress/commit below still check ownership and all original ciphertext bytes.

        progress = self.call('progress', {'id': manifest['id']})
        present = set(progress['indices'])
        def checkpoint():
            callback=getattr(self,'on_progress',None)
            if callback:callback(sum(min(CHUNK,manifest['bytes']-i*CHUNK) for i in present))
        checkpoint()
        with open(str(path), 'rb') as handle:
            for index in range((manifest['bytes'] + CHUNK - 1) // CHUNK):
                raw = handle.read(CHUNK)
                if index not in present:
                    self.call('put', {'id': manifest['id'], 'index': index, 'data': crypto.encode(raw),
                                      'sha256': hashlib.sha256(raw).hexdigest()})
                    present.add(index);checkpoint()
        result = self.call('commit', {'id': manifest['id']})
        receipt = result['receipt']
        if receipt.get('id') != manifest['id'] or receipt.get('bytes') != manifest['bytes'] or receipt.get('state') != 'stored':
            raise CacheError('托管回执与任务不一致 / Hosted receipt does not match task', 409)
        if self.config.get('node_public'):
            crypto.verify(self.config['node_public'], receipt, result.get('signature'))
        return receipt

    def download(self, oid, path):
        meta = self.call('metadata', {'id': oid})
        if meta['bytes'] > MAX_PACKAGE + MIB:
            raise CacheError('托管对象超限 / Hosted object too large', 413)
        envelope = meta['manifest']['envelope']; header = envelope['header']
        crypto.verify(header['public'], header, envelope['signature'])
        if header['context']['id'] != oid or header['context']['group'] != self.config['realm'] or header['bytes'] != meta['bytes'] or header['sha256'] != meta['manifest']['sha256']:
            raise CacheError('下载清单与原签名对象不一致 / Download manifest differs from signed object', 409)
        count = (meta['bytes'] + CHUNK - 1) // CHUNK
        hashes = header.get('chunks') or []
        if len(hashes) != count:
            raise CacheError('密文块清单无效 / Invalid ciphertext chunk manifest')
        lease = self.call('begin_read', {'id': oid})['lease']
        from pathlib import Path
        path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
        stage = path.with_name(path.name + '.partial')
        completed = False
        try:
            # Local block files persist across a dropped route; verify each before skipping.
            parts = path.with_name(path.name + '.parts'); parts.mkdir(exist_ok=True)
            digest = hashlib.sha256(); total = 0
            with stage.open('wb') as output:
                for index in range(count):
                    part = parts / ('%06d.bin' % index)
                    if part.is_file() and not part.is_symlink() and hashlib.sha256(part.read_bytes()).hexdigest() == hashes[index]:
                        raw = part.read_bytes()
                    else:
                        response = self.call('get', {'id': oid, 'index': index, 'lease': lease})
                        raw = crypto.decode(response['data'], CHUNK)
                        if hashlib.sha256(raw).hexdigest() != response['sha256'] or response['sha256'] != hashes[index]:
                            raise CacheError('托管数据块校验失败 / Hosted chunk checksum failed', 409)
                        temporary = part.with_name(part.name + '.' + secrets.token_hex(8))
                        with temporary.open('xb') as handle:
                            handle.write(raw); handle.flush()
                            import os; os.fsync(handle.fileno())
                        temporary.replace(part)
                    output.write(raw); digest.update(raw); total += len(raw)
                output.flush()
                import os; os.fsync(output.fileno())
            if total != meta['bytes'] or digest.hexdigest() != meta['manifest']['sha256']:
                raise CacheError('托管对象整体校验失败 / Hosted object checksum failed', 409)
            stage.replace(path)
            completed = True; meta['read_lease'] = lease
            return meta
        finally:
            if not completed:
                try:
                    self.call('end_read', {'id': oid, 'lease': lease})
                except CacheError:
                    pass

    def acknowledge(self, oid, kind='object', read_lease=None):
        claim = {'id': oid, 'recipient': self.peer, 'kind': kind}
        try:
            return self.call('ack', {'id': oid, 'kind': kind, 'lease': read_lease,
                                     'proof': {'claim': claim, 'signature': crypto.sign(self.private, claim),'public':self.public}})
        finally:
            if read_lease:
                try:
                    self.call('end_read', {'id': oid, 'lease': read_lease})
                except CacheError:
                    pass
