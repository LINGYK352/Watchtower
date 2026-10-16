"""Opaque ciphertext cache. Shared SQLite state fences upload/read/GC races."""
import hashlib
import json
import os
import secrets
import shutil
from .runtime import sqlite_module
sqlite3 = sqlite_module()
import time
import math
from contextlib import contextmanager
from pathlib import Path
from .policy import CacheError, CHUNK, MAX_PACKAGE, MIB, canonical, identifier, integer


class CipherStore:
    def __init__(self, directory, quota=1024 * MIB, clock=time.time):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.payloads = self.directory / 'objects'
        self.payloads.mkdir(exist_ok=True)
        self.database = self.directory / 'cache.sqlite3'
        self.quota = integer(quota, 'quota', MAX_PACKAGE, 1024 * 1024 * MIB)
        self.clock = clock
        with self._db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS objects (
                    id TEXT PRIMARY KEY, realm TEXT NOT NULL, sender TEXT NOT NULL,
                    meta TEXT NOT NULL, meta_hash TEXT NOT NULL, size INTEGER NOT NULL,
                    state TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                    received_after INTEGER NOT NULL, shared INTEGER NOT NULL,
                    activity REAL NOT NULL, collecting REAL, error TEXT);
                CREATE TABLE IF NOT EXISTS chunks (
                    object_id TEXT NOT NULL, number INTEGER NOT NULL, size INTEGER NOT NULL,
                    sha TEXT NOT NULL, PRIMARY KEY(object_id,number));
                CREATE TABLE IF NOT EXISTS receipts (
                    object_id TEXT NOT NULL, recipient TEXT NOT NULL, kind TEXT NOT NULL,
                    proof TEXT NOT NULL, received REAL NOT NULL,
                    PRIMARY KEY(object_id,recipient,kind));
                CREATE TABLE IF NOT EXISTS leases (
                    object_id TEXT NOT NULL, token TEXT PRIMARY KEY, expires REAL NOT NULL,
                    actor TEXT NOT NULL DEFAULT '');
                CREATE INDEX IF NOT EXISTS objects_realm ON objects(realm,sender,state);
                CREATE INDEX IF NOT EXISTS objects_expiry ON objects(state,expires);
            ''')

    @contextmanager
    def _db(self, write=False):
        db = sqlite3.connect(str(self.database), timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        try:
            if write:
                db.execute('BEGIN IMMEDIATE')
            yield db
            if write:
                db.execute('COMMIT')
        except Exception:
            if write:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()

    def _folder(self, oid):
        target = self.payloads / identifier(oid)
        target.resolve().relative_to(self.payloads.resolve())
        if target.is_symlink():
            raise CacheError('缓存路径无效 / Invalid cache path', 503)
        return target

    def _row(self, db, oid, realm=None):
        row = db.execute('SELECT * FROM objects WHERE id=?', (identifier(oid),)).fetchone()
        if row is None or realm is not None and row['realm'] != realm:
            raise CacheError('缓存对象不存在 / Cache object unavailable', 404)
        return row

    def _available(self, row, writing=False):
        if row['state'] in ('collecting', 'expired', 'cancelled') or row['expires'] <= self.clock():
            raise CacheError('缓存已过期或撤销 / Cache expired or revoked', 410)
        if writing and row['state'] != 'uploading':
            raise CacheError('缓存对象已提交 / Cache already committed', 409)

    def reserve(self, realm, sender, meta, policy):
        identifier(realm); identifier(sender)
        if not isinstance(meta, dict):
            raise CacheError('缓存清单无效 / Invalid cache manifest')
        oid = identifier(meta.get('id'))
        size = integer(meta.get('bytes'), 'bytes', 1, MAX_PACKAGE + MIB)
        checksum = meta.get('sha256')
        if not isinstance(checksum, str) or len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum):
            raise CacheError('密文摘要无效 / Invalid ciphertext checksum')
        recipients = meta.get('recipients')
        if not isinstance(recipients, list) or not recipients or len(recipients) > 101 or len(set(recipients)) != len(recipients):
            raise CacheError('接收身份无效 / Invalid recipients')
        for recipient in recipients:
            identifier(recipient)
        encoded = canonical(meta)
        if len(encoded) > 96 * 1024:
            raise CacheError('缓存清单过大 / Cache manifest too large', 413)
        fingerprint = hashlib.sha256(encoded).hexdigest()
        now = self.clock()
        shared = meta.get('audience') == 'group'
        days = policy['shared_days'] if shared else policy['pending_days']
        expires = now + days * 86400
        signed_expiry = ((meta.get('envelope') or {}).get('header') or {}).get('context', {}).get('expires_at')
        if signed_expiry is not None:
            if isinstance(signed_expiry, bool) or not isinstance(signed_expiry, (int, float)) or not math.isfinite(signed_expiry) or signed_expiry <= now or signed_expiry>now+90*86400+120:
                raise CacheError('源端交付任务已到期 / Source delivery expired', 410)
            expires = min(expires, signed_expiry)
        with self._db(True) as db:
            previous = db.execute('SELECT * FROM objects WHERE id=?', (oid,)).fetchone()
            if previous:
                if previous['realm'] != realm or previous['sender'] != sender or previous['meta_hash'] != fingerprint:
                    raise CacheError('重复缓存清单不一致 / Conflicting repeated manifest', 409)
                self._available(previous)
                return self._public(previous)
            active = "state IN ('uploading','committing','stored','collecting')"
            total = db.execute('SELECT COALESCE(SUM(CASE WHEN state IN (\'uploading\',\'committing\') THEN size*2+? ELSE size END),0) FROM objects WHERE '+active, (CHUNK,)).fetchone()[0]
            group = db.execute('SELECT COALESCE(SUM(size),0) FROM objects WHERE '+active+' AND realm=?', (realm,)).fetchone()[0]
            author = db.execute('SELECT COALESCE(SUM(size),0) FROM objects WHERE '+active+' AND realm=? AND sender=?', (realm, sender)).fetchone()[0]
            peak = size * 2 + CHUNK
            metadata_bytes = db.execute('SELECT COALESCE(SUM(LENGTH(meta)),0) FROM objects').fetchone()[0]
            object_count = db.execute('SELECT COUNT(*) FROM objects WHERE '+active).fetchone()[0]
            if object_count >= 10000 or total + peak + metadata_bytes + len(encoded) > self.quota or group + size > policy['group_quota'] or author + size > policy['sender_quota']:
                raise CacheError('托管空间不足，新上传已暂停；原数据保留 / Cache capacity full; new upload paused, existing data preserved', 507)
            if shutil.disk_usage(str(self.directory)).free < total + peak + 64 * MIB:
                raise CacheError('磁盘剩余空间不足，托管已暂停 / Insufficient free disk; hosting paused', 507)
            # Reserve full bytes before creating files; concurrent uploads cannot oversubscribe.
            db.execute('INSERT INTO objects(id,realm,sender,meta,meta_hash,size,state,created,expires,received_after,shared,activity) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                       (oid, realm, sender, encoded.decode(), fingerprint, size, 'uploading', now, expires,
                        policy['received_hours'] * 3600, int(shared), now))
            row = self._row(db, oid)
        return self._public(row)

    @staticmethod
    def _public(row):
        return {'id': row['id'], 'realm': row['realm'], 'sender': row['sender'], 'bytes': row['size'],
                'state': row['state'], 'created_at': row['created'], 'expires_at': row['expires'],
                'manifest_hash': row['meta_hash'], 'error': row['error'] or ''}

    @contextmanager
    def lease(self, oid, realm, seconds=120):
        token = secrets.token_hex(16)
        with self._db(True) as db:
            row = self._row(db, oid, realm)
            self._available(row)
            db.execute('INSERT INTO leases(object_id,token,expires) VALUES(?,?,?)', (oid, token, self.clock() + seconds))
        try:
            yield token
        finally:
            with self._db(True) as db:
                db.execute('DELETE FROM leases WHERE token=?', (token,))

    def _owned(self, row, sender):
        if row['sender'] != sender:
            raise CacheError('只能修改自己托管的对象 / Only the sender may modify this object', 403)

    def put(self, oid, realm, sender, index, raw, checksum):
        with self.lease(oid, realm):
            with self._db(True) as db:
                row = self._row(db, oid, realm); self._owned(row, sender); self._available(row, True)
                count = (row['size'] + CHUNK - 1) // CHUNK
                integer(index, 'index', 0, count - 1)
                expected = min(CHUNK, row['size'] - index * CHUNK)
                if not isinstance(raw, bytes) or len(raw) != expected or hashlib.sha256(raw).hexdigest() != checksum:
                    raise CacheError('缓存分块校验失败 / Cache chunk validation failed')
                previous = db.execute('SELECT sha FROM chunks WHERE object_id=? AND number=?', (oid, index)).fetchone()
                if previous and previous['sha'] != checksum:
                    raise CacheError('同一分块内容冲突 / Chunk content conflict', 409)
                folder = self._folder(oid); folder.mkdir(exist_ok=True)
                target = folder / ('%06d.part' % index)
                if target.is_symlink():
                    raise CacheError('缓存分块路径无效 / Invalid chunk path', 503)
                if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
                    temporary = folder / ('.upload-' + secrets.token_hex(12))
                    try:
                        with temporary.open('xb') as handle:
                            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
                        os.replace(str(temporary), str(target))
                    finally:
                        temporary.unlink(missing_ok=True)
                db.execute('INSERT OR IGNORE INTO chunks VALUES(?,?,?,?)', (oid, index, len(raw), checksum))
                db.execute('UPDATE objects SET activity=? WHERE id=?', (self.clock(), oid))
        return {'received': index}

    def progress(self, oid, realm, sender):
        with self.lease(oid, realm):
            with self._db(True) as db:
                row = self._row(db, oid, realm); self._owned(row, sender)
                if row['state'] in ('stored', 'committing'):
                    payload = self._folder(oid) / 'payload.bin'
                    expected = json.loads(row['meta'])['sha256']
                    digest = hashlib.sha256()
                    if payload.is_file() and not payload.is_symlink():
                        with payload.open('rb') as handle:
                            for block in iter(lambda: handle.read(256 * 1024), b''):
                                digest.update(block)
                        if payload.stat().st_size == row['size'] and digest.hexdigest() == expected:
                            return dict(self._public(row), indices=list(range((row['size'] + CHUNK - 1) // CHUNK)))
                    # Existing receipts must not be used to pretend a missing replica is present.
                    db.execute("UPDATE objects SET state='uploading',error='replica_missing' WHERE id=?", (oid,))
                    db.execute('DELETE FROM chunks WHERE object_id=?', (oid,))
                    row = self._row(db, oid)
                records = db.execute('SELECT * FROM chunks WHERE object_id=? ORDER BY number', (oid,)).fetchall()
            folder = self._folder(oid)
            valid = []
            for record in records:
                path = folder / ('%06d.part' % record['number'])
                if path.is_file() and not path.is_symlink() and path.stat().st_size == record['size'] and hashlib.sha256(path.read_bytes()).hexdigest() == record['sha']:
                    valid.append(record['number'])
            return dict(self._public(row), indices=valid)

    def commit(self, oid, realm, sender):
        with self.lease(oid, realm):
            with self._db(True) as db:
                row = self._row(db, oid, realm); self._owned(row, sender); self._available(row)
                if row['state'] == 'stored':
                    payload = self._folder(oid) / 'payload.bin'
                    if not self._valid_payload(payload, row):
                        raise CacheError('托管副本缺失，请恢复上传 / Hosted copy missing; resume upload', 503)
                    return self._public(row)
                folder = self._folder(oid); target = folder / 'payload.bin'
                temporary = folder / ('.commit-' + secrets.token_hex(12))
                meta = json.loads(row['meta']); digest = hashlib.sha256(); size = 0
                try:
                    if row['state'] != 'committing':
                        with temporary.open('xb') as output:
                            for index in range((row['size'] + CHUNK - 1) // CHUNK):
                                record = db.execute('SELECT * FROM chunks WHERE object_id=? AND number=?', (oid, index)).fetchone()
                                path = folder / ('%06d.part' % index)
                                if record is None or not path.is_file() or path.is_symlink():
                                    raise CacheError('缓存分块尚未完整 / Cache chunks incomplete', 409)
                                raw = path.read_bytes()
                                if len(raw) != record['size'] or hashlib.sha256(raw).hexdigest() != record['sha']:
                                    raise CacheError('缓存分块损坏，需要补传 / Damaged cache chunk; retransmit', 409)
                                output.write(raw); digest.update(raw); size += len(raw)
                            output.flush(); os.fsync(output.fileno())
                        if size != row['size'] or digest.hexdigest() != meta['sha256']:
                            raise CacheError('缓存完整性校验失败 / Cache integrity validation failed', 409)
                        os.replace(str(temporary), str(target))
                        # Keep the peak reservation until redundant parts are safely removed.
                        db.execute("UPDATE objects SET state='committing',activity=? WHERE id=?", (self.clock(), oid))
                    elif not self._valid_payload(target, row):
                        raise CacheError('提交中的副本缺失，请恢复上传 / Commit payload missing; resume upload', 503)
                finally:
                    temporary.unlink(missing_ok=True)
            # The committing checkpoint survives a crash here, without losing upload history.
            for index in range((row['size'] + CHUNK - 1) // CHUNK):
                (folder / ('%06d.part' % index)).unlink(missing_ok=True)
            with self._db(True) as db:
                current = self._row(db, oid, realm); self._available(current)
                if current['state'] == 'committing':
                    db.execute("UPDATE objects SET state='stored',error='',activity=? WHERE id=?", (self.clock(), oid))
                    db.execute('DELETE FROM chunks WHERE object_id=?', (oid,))
                result = self._public(self._row(db, oid))
        return result

    @staticmethod
    def _valid_payload(path, row):
        if not path.is_file() or path.is_symlink() or path.stat().st_size != row['size']:
            return False
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for block in iter(lambda: handle.read(256 * 1024), b''):
                digest.update(block)
        return digest.hexdigest() == json.loads(row['meta'])['sha256']

    def renew_ephemeral(self, oid, realm, sender, meta):
        """Only the application relay uses this; immutable source retry, never hosted renewal."""
        self.collect()
        with self._db(True) as db:
            row = db.execute('SELECT * FROM objects WHERE id=?', (identifier(oid),)).fetchone()
            if row and row['state'] == 'expired':
                if row['realm'] != realm or row['sender'] != sender or row['meta_hash'] != hashlib.sha256(canonical(meta)).hexdigest():
                    raise CacheError('实时重试对象发生变化 / Realtime retry object changed', 409)
                db.execute('DELETE FROM receipts WHERE object_id=?', (oid,))
                db.execute('DELETE FROM objects WHERE id=?', (oid,))

    def begin_read(self, oid, realm, recipient):
        self.metadata(oid, realm, recipient)
        token = secrets.token_hex(16)
        with self._db(True) as db:
            row = self._row(db, oid, realm); self._available(row)
            expires = self.clock() + 120
            db.execute('INSERT INTO leases(object_id,token,expires,actor) VALUES(?,?,?,?)', (oid, token, expires, recipient))
        return {'lease': token, 'expires_at': expires}

    def end_read(self, oid, realm, recipient, token):
        with self._db(True) as db:
            self._row(db, oid, realm)
            db.execute('DELETE FROM leases WHERE object_id=? AND token=? AND actor=?', (oid, token, recipient))
        return {'released': True}

    def metadata(self, oid, realm, recipient):
        with self._db() as db:
            row = self._row(db, oid, realm); self._available(row)
            meta = json.loads(row['meta'])
            if recipient not in meta['recipients'] and recipient != row['sender']:
                raise CacheError('无权领取此缓存 / Cache access denied', 403)
            if row['state'] != 'stored':
                raise CacheError('缓存仍在上传 / Cache upload incomplete', 409)
            return dict(self._public(row), manifest=meta,receipts=[dict(r) for r in db.execute('SELECT recipient,kind,received,proof FROM receipts WHERE object_id=?',(oid,))])

    def grant_recipient(self, oid, realm, host, grants):
        """A verified host delegation changes visibility, not bytes, expiry, or original signature."""
        with self._db(True) as db:
            row=self._row(db,oid,realm);self._available(row)
            meta=json.loads(row['meta'])
            if row['state']!='stored' or not row['shared'] or host not in meta['envelope']['header']['keys']:
                raise CacheError('此对象不允许公共授权扩展 / Object cannot extend public recipient access',403)
            recipient=grants['main']['claim']['recipient']
            if recipient not in meta['recipients']:
                if len(meta['recipients'])>=201:raise CacheError('公共历史接收人数超限，请续存档案 / Public historical recipient limit reached; renew archive',409)
                meta['recipients'].append(recipient)
            meta['envelope'].setdefault('recipient_grants',{})[recipient]=grants['main']
            meta['caption']['envelope'].setdefault('recipient_grants',{})[recipient]=grants['caption']
            encoded=canonical(meta)
            if len(encoded)>384*1024:raise CacheError('公共授权记录过大 / Public delegation records too large',413)
            used=db.execute("SELECT COALESCE(SUM(size+LENGTH(meta)),0) FROM objects WHERE state IN ('uploading','committing','stored','collecting')").fetchone()[0]
            if used+len(encoded)-len(row['meta'].encode())>self.quota:raise CacheError('公共授权空间不足 / Public delegation capacity full',507)
            db.execute('UPDATE objects SET meta=? WHERE id=?',(encoded.decode(),oid))
        return {'granted':True,'recipient':recipient}

    def read(self, oid, realm, recipient, index, read_lease=None):
        @contextmanager
        def reading():
            if not read_lease:
                with self.lease(oid, realm):
                    yield self.metadata(oid, realm, recipient)
                return
            identifier(read_lease)
            with self._db(True) as db:
                row = self._row(db, oid, realm)
                record = db.execute('SELECT * FROM leases WHERE token=? AND object_id=? AND actor=? AND expires>?',
                                    (read_lease, oid, recipient, self.clock())).fetchone()
                value = json.loads(row['meta'])
                if record is None or row['state'] != 'stored' or recipient not in value['recipients'] or row['error'] == 'cancelled':
                    raise CacheError('读取租约失效 / Read lease unavailable', 410)
                until = min(self.clock() + 120, row['expires'] + 300)
                if until <= self.clock():
                    raise CacheError('读取恢复窗口已结束 / Read recovery window ended', 410)
                db.execute('UPDATE leases SET expires=? WHERE token=?', (until, read_lease))
                meta = dict(self._public(row), manifest=value)
            yield meta
        with reading() as meta:
            integer(index, 'index', 0, (meta['bytes'] + CHUNK - 1) // CHUNK - 1)
            path = self._folder(oid) / 'payload.bin'
            if not path.is_file() or path.is_symlink():
                raise CacheError('托管副本缺失，请请求补传 / Hosted copy missing; request retransmission', 503)
            with path.open('rb') as handle:
                handle.seek(index * CHUNK); raw = handle.read(CHUNK)
            return raw

    def list(self, realm, actor, limit=100, before=None):
        integer(limit, 'limit', 1, 100)
        with self._db() as db:
            args = [realm]; condition = ''
            if before is not None:
                if not isinstance(before, list) or len(before) != 2 or isinstance(before[0], bool) or not isinstance(before[0], (int,float)):
                    raise CacheError('缓存游标无效 / Invalid cache cursor')
                identifier(before[1]);condition=' AND (created<? OR (created=? AND id<?))';args += [before[0],before[0],before[1]]
            rows = db.execute('SELECT * FROM objects WHERE realm=?'+condition+' ORDER BY created DESC,id DESC',args)
            values = []
            for row in rows:
                meta = json.loads(row['meta'])
                if row['sender'] == actor or actor in meta['recipients']:
                    value = self._public(row)
                    value['audience']=meta.get('audience');value['recipients']=meta.get('recipients',[])
                    value['delegation_expires']={pid:grant.get('claim',{}).get('expires_at',0) for pid,grant in (meta.get('envelope') or {}).get('recipient_grants',{}).items()}
                    if row['expires'] <= self.clock() and value['state'] not in ('cancelled', 'expired'):
                        value['state'] = 'expired'
                    value['receipts'] = [dict(r) for r in db.execute('SELECT recipient,kind,received,proof FROM receipts WHERE object_id=?', (row['id'],))]
                    values.append(value)
                    if len(values) == limit:
                        break
            return values

    def acknowledge(self, oid, realm, recipient, kind, proof, read_lease=None):
        if kind not in ('message', 'object') or not isinstance(proof, str) or len(proof) > 8192:
            raise CacheError('收取回执无效 / Invalid receipt')
        with self._db(True) as db:
            row = self._row(db, oid, realm)
            if read_lease:
                lease = db.execute('SELECT * FROM leases WHERE token=? AND object_id=? AND actor=? AND expires>?',
                                   (identifier(read_lease), oid, recipient, self.clock())).fetchone()
                if lease is None or row['error'] == 'cancelled':
                    raise CacheError('读取租约失效 / Read lease unavailable', 410)
            else:
                self._available(row)
            meta = json.loads(row['meta'])
            if recipient not in meta['recipients'] or row['state'] != 'stored':
                raise CacheError('收取回执无权限 / Receipt not authorized', 403)
            db.execute('INSERT OR IGNORE INTO receipts VALUES(?,?,?,?,?)', (oid, recipient, kind, proof, self.clock()))
            # A message/preview receipt cannot clear an attachment. Public archives retain their lease.
            received = {r[0] for r in db.execute("SELECT recipient FROM receipts WHERE object_id=? AND kind='object'", (oid,))}
            if not row['shared'] and set(meta['recipients']).issubset(received):
                last = db.execute("SELECT MAX(received) FROM receipts WHERE object_id=? AND kind='object'", (oid,)).fetchone()[0]
                db.execute('UPDATE objects SET expires=MIN(expires,?) WHERE id=?', (last + row['received_after'], oid))
        return {'accepted': True, 'kind': kind}

    def cancel(self, oid, realm, sender):
        with self._db(True) as db:
            row = self._row(db, oid, realm); self._owned(row, sender)
            if row['state'] not in ('collecting', 'expired', 'cancelled'):
                db.execute('UPDATE objects SET expires=?,error=? WHERE id=?', (self.clock(), 'cancelled', oid))
        return {'cancelled': True}

    def collect(self, idle=86400, maximum=100):
        """Mark first, block new reads, then clear only fenced unreferenced cache folders."""
        integer(maximum, 'maximum', 1, 1000)
        now = self.clock(); candidates = []
        with self._db(True) as db:
            db.execute('DELETE FROM leases WHERE expires<=?', (now,))
            old = [r['id'] for r in db.execute("SELECT id FROM objects WHERE state IN ('expired','cancelled') AND created<? LIMIT ?",(now-120*86400,maximum))]
            for oid in old:
                db.execute('DELETE FROM receipts WHERE object_id=?',(oid,));db.execute('DELETE FROM objects WHERE id=?',(oid,))
            rows = db.execute("SELECT * FROM objects WHERE state IN ('uploading','committing','stored','collecting') AND (expires<=? OR (state='uploading' AND activity<=?) OR state='collecting') ORDER BY expires LIMIT ?", (now, now - idle, maximum)).fetchall()
            for row in rows:
                if db.execute('SELECT 1 FROM leases WHERE object_id=? AND expires>?', (row['id'], now)).fetchone():
                    continue
                db.execute("UPDATE objects SET state='collecting',collecting=? WHERE id=?", (now, row['id']))
                candidates.append(row['id'])
        removed = []
        for oid in candidates:
            folder = self._folder(oid)
            try:
                if folder.exists():
                    # Only our exact validated object folder; never a user workspace or original file.
                    folder.resolve().relative_to(self.payloads.resolve())
                    shutil.rmtree(str(folder))
            except OSError:
                continue
            with self._db(True) as db:
                row = self._row(db, oid)
                if row['state'] != 'collecting':
                    continue
                state = 'cancelled' if row['error'] == 'cancelled' else 'expired'
                meta=json.loads(row['meta']);tombstone={k:meta.get(k) for k in ('recipients','audience','sha256')}
                db.execute('UPDATE objects SET state=?,collecting=NULL,meta=? WHERE id=?', (state,canonical(tombstone).decode(),oid))
                db.execute('DELETE FROM receipts WHERE object_id=?',(oid,))
                db.execute('DELETE FROM chunks WHERE object_id=?', (oid,))
            removed.append(oid)
        return {'removed': removed}

    def usage(self, realm=None):
        with self._db() as db:
            query = "SELECT COALESCE(SUM(CASE WHEN state IN ('uploading','committing') THEN size*2+2097152 ELSE size END),0),COUNT(*) FROM objects WHERE state IN ('uploading','committing','stored','collecting')"
            if realm is not None:
                query += ' AND realm=?'; values = (identifier(realm),)
            else:
                values = ()
            total, count = db.execute(query, values).fetchone()
        return {'reserved_bytes': total, 'objects': count, 'quota_bytes': self.quota}
