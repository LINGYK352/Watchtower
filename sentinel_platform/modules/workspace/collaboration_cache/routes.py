"""Short-lived shared diagnostics of a successful transport; never used as authorization."""
import hashlib
from datetime import datetime,timezone
from . import crypto

def _key(user,gid,public):
    return 'workspace-route:'+hashlib.sha256((user['username']+':'+gid+':'+crypto.peer_id(public)).encode()).hexdigest()

def remember(cache,user,gid,public,path):
    if not gid or not public:return
    cache.collaboration.nonces.update_one({'_id':_key(user,gid,public)},{'$set':{
        'owner':user['username'],'path':path,'until':cache.clock()+120,
        'expires':datetime.fromtimestamp(cache.clock()+120,timezone.utc)}},upsert=True)

def latest(cache,user,gid,public):
    if not public:return 'unknown'
    row=cache.collaboration.nonces.find_one({'_id':_key(user,gid,public),'owner':user['username'],'until':{'$gt':cache.clock()}})
    return row.get('path','unknown') if row else 'unknown'

