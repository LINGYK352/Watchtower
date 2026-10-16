"""Shared passive peer refresh: bounded polling, truthful availability, no modal storms."""
import secrets
from pymongo import ReturnDocument
from .security import ControlSyncError


def refresh_peer(collection, doc, fetch, public, clock, background=False):
    now=clock()
    if background and doc.get('peer_retry_at',0)>now:
        return public(doc)
    token=secrets.token_hex(16)
    current=collection.find_one_and_update({'_id':doc['_id'],'deleted_at':{'$exists':False},'$or':[
        {'peer_poll_until':{'$exists':False}},{'peer_poll_until':{'$lte':now}}]},
        {'$set':{'peer_poll_owner':token,'peer_poll_until':now+30}},return_document=ReturnDocument.AFTER)
    if not current:
        fresh=collection.find_one({'_id':doc['_id'],'deleted_at':{'$exists':False}})
        if not fresh:raise ControlSyncError('连接已删除 / Connection deleted',410)
        return public(fresh)
    query={'_id':doc['_id'],'deleted_at':{'$exists':False},'peer_poll_owner':token}
    try:
        result=fetch(current)
        collection.update_one({**query,'state':current['state']},{'$set':result,'$unset':{'peer_error':'','peer_retry_at':'','peer_failures':''}})
    except ControlSyncError as error:
        count=min(10,int(current.get('peer_failures',0))+1)
        collection.update_one({**query,'state':current['state']},{'$set':{'peer_error':str(error)[:500],'peer_failures':count,'peer_retry_at':clock()+min(300,30*2**(count-1))}})
        if not background:raise
    finally:
        collection.update_one(query,{'$unset':{'peer_poll_owner':'','peer_poll_until':''}})
    fresh=collection.find_one({'_id':doc['_id'],'deleted_at':{'$exists':False}})
    if not fresh:raise ControlSyncError('连接已删除 / Connection deleted',410)
    return public(fresh)
