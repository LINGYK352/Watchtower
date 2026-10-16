"""Host-owned, resumable public set reconciliation. No private payloads or new node protocol."""
import hashlib,secrets
from datetime import datetime,timezone
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from . import crypto,replica_objects,service_roster
from .policy import CacheError,CHUNK
from .service_client import ServiceClient

def copy_page(source,target,cursor=None,receipts=False):
    page=source.call('list',{'limit':20,**({'before':cursor} if cursor else {})})
    inventory=[]
    for summary in page['items']:
        if summary.get('audience')!='group' or summary['state']!='stored':continue
        oid=summary['id'];record=source.call('metadata',{'id':oid});meta=record['manifest']
        target('mirror_begin',{'manifest':meta,'created_at':summary['created_at']})
        progress=target('mirror_progress',{'id':oid})
        present=set(progress['indices']);hashes=meta['envelope']['header'].get('chunks') or []
        count=(meta['bytes']+CHUNK-1)//CHUNK
        if len(hashes)!=count:raise CacheError('公共原签名分块表无效 / Invalid signed public chunk list',409)
        missing=[i for i in range(count) if i not in present]
        if missing:
            lease=source.call('begin_read',{'id':oid})['lease']
            try:
                for index in missing:
                    value=source.call('get',{'id':oid,'index':index,'lease':lease})
                    raw=crypto.decode(value['data'],CHUNK)
                    if hashlib.sha256(raw).hexdigest()!=hashes[index] or value['sha256']!=hashes[index]:
                        raise CacheError('公共副本分块摘要不符 / Public replica chunk checksum mismatch',409)
                    target('mirror_put',{'id':oid,'index':index,'data':value['data'],'sha256':hashes[index]})
            finally:
                try:source.call('end_read',{'id':oid,'lease':lease})
                except CacheError:pass
        if progress.get('state')!='stored':target('mirror_commit',{'id':oid})
        if receipts:target('mirror_receipts',{'id':oid,'receipts':record.get('receipts',[])})
        inventory.append({'id':oid,'sha256':meta['sha256'],'bytes':meta['bytes']})
    return page.get('next'),inventory

def reconcile(replicas,gid,mid,user,initial=False):
    cache=replicas.cache;service=replicas.service;now=cache.clock()
    group=service._host(gid,user);actor=service.room_member(gid,mid)
    if not actor.get('cohost') or not (actor.get('service_offer') or {}).get('enabled'):
        raise CacheError('副主持服务未获授权 / Co-host service is not approved',403)
    rows=service.nonces;lid='replica-sync:'+gid+':'+mid;token=secrets.token_hex(16)
    try:rows.insert_one({'_id':lid,'until':0,'expires':datetime.fromtimestamp(now+360,timezone.utc)})
    except DuplicateKeyError:pass
    held=rows.find_one_and_update({'_id':lid,'until':{'$lte':now}},{'$set':{'owner_token':token,'until':now+240,'expires':datetime.fromtimestamp(now+360,timezone.utc)}},return_document=ReturnDocument.AFTER)
    if not held:return {'state':actor.get('service_state','preparing'),'busy':True}
    try:
        offer=actor['service_offer'];destination={'public':offer['public'],'url':offer.get('url') or ''}
        roster=service_roster.issue(cache,group);approved=service_roster.verify(roster,group['source']['crypto_public'],gid,now)
        installed=replicas.call(gid,user,destination,'setup',{'roster':roster,'config':cache.direct_access(group,actor)})
        from .delivery import LocalClient
        own=cache.direct_access(group,service.room_member(gid,gid))
        local=LocalClient(cache,gid,user,own);local.call('usage')
        remote=ServiceClient(cache,gid,user,dict(own,rpc_service=destination,node_public=offer['node_public']))
        state=actor.get('service_sync') or {'phase':'pull','cursor':None,'inventory':[]}
        for _ in range(2 if initial else 1):
            if state['phase']=='pull':
                cursor,_=copy_page(remote,lambda a,b:replica_objects.mirror(cache,gid,approved,a,b,trusted_host=True,recipient_user=user),state.get('cursor'),receipts=True)
                state={'phase':'pull','cursor':cursor,'inventory':[]} if cursor else {'phase':'push','cursor':None,'inventory':[]}
                service.members.update_one({'_id':mid,'group_id':gid,'cohost':True},{'$set':{'service_sync':state}})
                if cursor or not initial:break
            else:
                cursor,entries=copy_page(cache._client(gid,user),lambda a,b:replicas.call(gid,user,destination,a,b),state.get('cursor'),receipts='public-receipts-1' in installed.get('features',[]))
                inventory={row['id']:row for row in state.get('inventory',[])}
                inventory.update({row['id']:row for row in entries})
                state={'phase':'push','cursor':cursor,'inventory':list(inventory.values())}
                if cursor:
                    service.members.update_one({'_id':mid,'group_id':gid,'cohost':True},{'$set':{'service_sync':state}})
                else:
                    replicas.call(gid,user,destination,'mirror_ready',{'inventory':sorted(inventory.values(),key=lambda i:i['id'])})
                    service.members.update_one({'_id':mid,'group_id':gid,'cohost':True},{'$set':{
                        'service_state':'ready','service_ready_at':cache.clock(),'service_sync':{'phase':'pull','cursor':None,'inventory':[]},
                        'service_synced_at':cache.clock()},'$unset':{'service_error':''}})
                    replicas.call(gid,user,destination,'setup',{'roster':service_roster.issue(cache,service._host(gid,user)),'config':cache.direct_access(group,service.room_member(gid,mid))})
                break
        return {'state':service.members.find_one({'_id':mid})['service_state']}
    except Exception as exc:
        service.members.update_one({'_id':mid,'group_id':gid},{'$set':{'service_error':str(exc) if isinstance(exc,CacheError) else '公共资料对账暂不可用 / Public reconciliation temporarily unavailable'}})
        raise
    finally:
        service.members.update_one({'_id':mid,'group_id':gid},{'$set':{'service_sync_checked_at':cache.clock()}})
        rows.delete_one({'_id':lid,'owner_token':token})

def background(replicas):
    service=replicas.service;now=replicas.clock()
    for actor in service.members.find({'state':'approved','service_offer.enabled':True,'expires_at':{'$gt':now},'$or':[{'cohost':True},{'service_revoke_pending':True}]}).sort('service_sync_checked_at',1).limit(20):
        group=service.groups.find_one({'_id':actor['group_id'],'enabled':True})
        if not group:continue
        from sentinel_platform.contracts import Collections
        account=service.repo.collection(Collections.USER).find_one({'username':group['owner']})
        if not account or account.get('disabled'):continue
        try:
            if actor.get('service_revoke_pending'):replicas.revoke_pending(group['_id'],actor['_id'],{'username':group['owner']})
            else:reconcile(replicas,group['_id'],actor['_id'],{'username':group['owner']})
        except Exception:pass

