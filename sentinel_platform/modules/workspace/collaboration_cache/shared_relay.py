"""Bounded short-lived ciphertext mailboxes shared by application workers."""
import hashlib
import json
import time
from .policy import CacheError, MIB, canonical, identifier

MAX_FRAME=8*MIB


class SharedRelay:
    def __init__(self,store,clock=time.time):
        self.store,self.clock=store,clock
        with store._db(True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS relay_requests(id TEXT PRIMARY KEY,realm TEXT NOT NULL,source TEXT NOT NULL,destination TEXT NOT NULL,digest TEXT NOT NULL,expires REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS relay_frames(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL,realm TEXT NOT NULL,source TEXT NOT NULL,destination TEXT NOT NULL,kind TEXT NOT NULL,data TEXT NOT NULL,bytes INTEGER NOT NULL,expires REAL NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS relay_mailbox ON relay_frames(realm,destination,sequence)')
            db.execute('CREATE INDEX IF NOT EXISTS relay_expiry ON relay_frames(expires)')

    def call(self,action,realm,peer,body,config,joining=False):
        if action not in ('relay','reply','poll'):raise CacheError('转发操作不支持 / Unsupported relay operation')
        wait=body.get('wait',0)
        if action=='poll' and (isinstance(wait,bool) or not isinstance(wait,(int,float)) or not 0<=wait<=10):
            raise CacheError('轮询期限无效 / Invalid poll duration')
        deadline=time.monotonic()+wait
        while True:
            now=self.clock()
            with self.store._db(True) as db:
                db.execute('DELETE FROM relay_frames WHERE expires<=?',(now,));db.execute('DELETE FROM relay_requests WHERE expires<=?',(now,))
                if action=='poll':
                    rows=db.execute('SELECT * FROM relay_frames WHERE realm=? AND destination=? ORDER BY sequence LIMIT 8',(realm,peer)).fetchall()
                    values=[];size=0
                    for row in rows:
                        if size+row['bytes']>MAX_FRAME:break
                        values.append({'id':row['id'],'source':row['source'],'destination':peer,'type':row['kind'],'data':json.loads(row['data']),'expires':row['expires']})
                        size+=row['bytes'];db.execute('DELETE FROM relay_frames WHERE sequence=?',(row['sequence'],))
                    if values or time.monotonic()>=deadline:return {'frames':values}
                else:
                    rid=identifier(body.get('id'));raw=canonical(body.get('data'));digest=hashlib.sha256(raw).hexdigest()
                    if len(raw)>MAX_FRAME:raise CacheError('转发帧超限 / Relay frame exceeds limit',413)
                    original=db.execute('SELECT * FROM relay_requests WHERE id=?',(rid,)).fetchone()
                    if action=='relay':
                        destination=identifier(body.get('destination'))
                        if joining and destination!=config['host']:raise CacheError('申请路径仅可指向主持 / Join route may only target host',403)
                        if original:
                            if original['realm']!=realm or original['source']!=peer or original['destination']!=destination or original['digest']!=digest:
                                raise CacheError('转发请求标识冲突 / Relay request identity conflict',409)
                            return {'queued':True,'id':rid}
                        if db.execute('SELECT COUNT(*) FROM relay_requests').fetchone()[0]>=10000:raise CacheError('转发请求繁忙 / Relay request capacity reached',429)
                        kind='request'
                    else:
                        if joining or not original or original['realm']!=realm or original['destination']!=peer:
                            raise CacheError('转发回复无权限 / Relay response not authorized',403)
                        destination=original['source'];kind='response'
                    if db.execute('SELECT COALESCE(SUM(bytes),0) FROM relay_frames').fetchone()[0]+len(raw)>64*MIB:
                        raise CacheError('转发缓存繁忙 / Relay capacity reached',429)
                    if db.execute('SELECT COUNT(*) FROM relay_frames WHERE realm=? AND destination=?',(realm,destination)).fetchone()[0]>=100:
                        raise CacheError('目标转发队列繁忙 / Destination relay queue busy',429)
                    if action=='relay':db.execute('INSERT INTO relay_requests VALUES(?,?,?,?,?,?)',(rid,realm,peer,destination,digest,now+120))
                    db.execute('INSERT INTO relay_frames(id,realm,source,destination,kind,data,bytes,expires) VALUES(?,?,?,?,?,?,?,?)',
                               (rid,realm,peer,destination,kind,raw.decode('utf-8'),len(raw),now+120))
                    return {'queued':True,'id':rid}
            time.sleep(min(.03,max(0,deadline-time.monotonic())))
