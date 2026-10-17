"""Cross-worker inbox scan lease; authorization stays fresh, data stays persistent."""
import hashlib,secrets,threading
from datetime import datetime,timezone
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from .policy import CacheError

def run(cache,gid,user,receive):
    cache.collaboration._access(gid,user)
    key='inbox:'+hashlib.sha256((user['username']+':'+gid).encode()).hexdigest()
    token=secrets.token_hex(16);now=cache.clock();rows=cache.receive_locks
    try:
        rows.find_one_and_update({'_id':key,'$and':[
            {'$or':[{'until':{'$exists':False}},{'until':{'$lte':now}}]},
            {'$or':[{'next_at':{'$exists':False}},{'next_at':{'$lte':now}}]}]},
            {'$set':{'token':token,'until':now+90,'expires':datetime.fromtimestamp(now+180,timezone.utc)}},
            upsert=True,return_document=ReturnDocument.AFTER)
    except DuplicateKeyError:
        return []  # Another worker receives; readers still see their durable local inbox.
    stop=threading.Event();success=False
    def guard():
        if not rows.find_one({'_id':key,'token':token,'until':{'$gt':cache.clock()}},{'_id':1}):
            raise CacheError('接收已由其他请求接续，本机消息保留 / Another request resumed receipt; local messages retained',409)
    def renew():
        while not stop.wait(10):
            try:rows.update_one({'_id':key,'token':token,'until':{'$gt':cache.clock()}},{'$set':{'until':cache.clock()+90,'expires':datetime.fromtimestamp(cache.clock()+180,timezone.utc)}})
            except Exception:pass  # Fresh guard must still confirm ownership before publication.
    thread=threading.Thread(target=renew,daemon=True,name='collaboration-inbox-lease');thread.start()
    try:
        guard();answer=receive(guard,token);guard();success=True;return answer
    finally:
        stop.set()
        rows.update_one({'_id':key,'token':token},{'$unset':{'token':'','until':''},'$set':{'next_at':cache.clock()+(1 if success else 0),'expires':datetime.fromtimestamp(cache.clock()+180,timezone.utc)}})
