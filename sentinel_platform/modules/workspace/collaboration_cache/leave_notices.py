"""Bounded durable membership-revocation notice after local link deletion."""
import secrets
from pymongo import ReturnDocument
from .policy import CacheError
from ..control_sync.security import ControlSyncError, encode_peer, decode_peer


def prepare(cache, link, user):
    if not link.get('secret') or link.get('state') not in ('pending','approved') or link.get('expires_at',0)<=cache.clock():
        return False
    minimal={k:link[k] for k in ('_id','group_id','owner','target','secret','expires_at','state','node_config','node_descriptor') if k in link}
    iid='leave-notice:'+link['_id']
    row={'_id':iid,'record_type':'leave_notice','owner':user['username'],'group_id':link['group_id'],
         'link_id':link['_id'],'state':'queued','retry_at':cache.clock(),'expires_at':min(link['expires_at'],cache.clock()+7*86400),
         'link':cache.save_config(iid,'link',minimal)}
    cache.tasks.update_one({'_id':iid},{'$setOnInsert':row},upsert=True)
    return True


def send(cache, mid, user, seconds=6):
    iid='leave-notice:'+mid;now=cache.clock();token=secrets.token_hex(16)
    current=cache.collaboration.links.find_one({'_id':mid,'owner':user['username'],'deleted_at':{'$exists':True}})
    if current is None:return False
    held=cache.tasks.find_one_and_update({'_id':iid,'owner':user['username'],'expires_at':{'$gt':now},'$or':[
          {'lease_until':{'$exists':False}},{'lease_until':{'$lte':now}}]},
          {'$set':{'lease_until':now+seconds+30,'lease_owner':token}},return_document=ReturnDocument.AFTER)
    if held is None:return bool(current.get('peer_notified'))
    try:
        link=cache.link_config(held,'link');secret=cache.control.secrets.open(link['secret'],mid+':group-member')
        packet=encode_peer(secret,mid,'leave',{},cache.clock)
        answer=decode_peer(secret,cache.collaboration.deliver(link,'leave',packet,user,seconds=seconds),'leave:response',cache.clock)
        if answer.get('left') is not True:raise CacheError('主持尚未确认退出 / Host has not confirmed departure',409)
        cache.collaboration.links.update_one({'_id':mid,'owner':user['username'],'deleted_at':{'$exists':True}},
            {'$set':{'peer_notified':True,'peer_notified_at':cache.clock()}})
        cache.tasks.delete_one({'_id':iid,'lease_owner':token})
        return True
    except (CacheError,ControlSyncError):
        # A route may revoke the member before its final signed reply arrives.
        # Never call that a confirmed receipt; keep the minimal pending notice.
        cache.tasks.update_one({'_id':iid,'lease_owner':token},{'$set':{'retry_at':cache.clock()+30},
            '$unset':{'lease_until':'','lease_owner':''}})
        return False


def flush(cache):
    now=cache.clock()
    cache.tasks.delete_many({'record_type':'leave_notice','expires_at':{'$lte':now}})
    for row in cache.tasks.find({'record_type':'leave_notice','retry_at':{'$lte':now}}).limit(2):
        try:send(cache,row['link_id'],{'username':row['owner']})
        except Exception:
            cache.tasks.update_one({'_id':row['_id']},{'$set':{'retry_at':now+30}})
