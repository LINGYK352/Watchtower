"""Durable intake digests: one notification per update, shared leases and batch retries."""
from __future__ import annotations
import threading,time,uuid
from contextlib import contextmanager
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from sentinel_platform.core import get_repo,get_config
from sentinel_platform.contracts import Collections,ROLE,get_registry


def enabled():
    doc=get_repo().collection(Collections.API_KEYS).find_one({'name':'default'}) or {}
    conf=doc.get('feishu')
    if isinstance(conf,dict) and conf:
        return bool(conf.get('enabled') and conf.get('webhook') and conf.get('vuln_feed_notify',True))
    cfg=get_config()
    return bool(cfg.section('FEISHU','WEBHOOK',default=''))


def eligible(doc):
    return bool(doc.get('in_kev') or str(doc.get('severity','')).lower() in ('high','critical'))

def events():return get_repo().collection('vuln_intel_notifications')
def batches():return get_repo().collection('vuln_intel_notification_batches')

@contextmanager
def intake_batch(source):
    identity=uuid.uuid4().hex
    batches().insert_one({'_id':identity,'state':'open','source':source,'created_at':time.time(),'heartbeat':time.time(),'attempts':0,'next_try':0})
    try:yield identity
    finally:
        batches().update_one({'_id':identity,'state':'open'},{'$set':{'state':'pending','closed_at':time.time(),'next_try':time.time()}})
        _wake.set();start()


def enqueue(doc):
    if not doc.get('intel_push_pending'):
        return
    event={'_id':str(doc['_id']),'vuln_id':doc['_id'],'state':'pending','attempts':0,'next_try':time.time(),
           'created_at':doc.get('intel_push_created_at',time.time()),'title':str(doc.get('title',''))[:200],
           'identifier':doc.get('cve_id') or doc.get('watchtower_id',''),'severity':doc.get('severity',''),'in_kev':bool(doc.get('in_kev'))}
    if doc.get('intel_push_batch'):event['batch_id']=doc['intel_push_batch']
    queue=get_repo().collection('vuln_intel_notifications')
    queue.update_one({'_id':event['_id']},{'$setOnInsert':event},upsert=True)
    if event.get('batch_id'):batches().update_one({'_id':event['batch_id'],'state':'open'},{'$set':{'heartbeat':time.time()}})
    get_repo().collection(Collections.VULN_INTEL).update_one({'_id':doc['_id']},{'$set':{'intel_push_pending':False}})
    _wake.set();start()


def status():
    queue=get_repo().collection('vuln_intel_notifications')
    counts={name:queue.count_documents({'state':name}) for name in ('pending','retry','sending','sent','failed','cancelled')}
    return {'enabled':enabled(),**counts,'delivery_mode':'update_digest','pending_batches':batches().count_documents({'state':{'$in':['open','pending','retry','sending']}})}


def retry_failed():
    ids=[row['_id'] for row in batches().find({'state':'failed'},{'_id':1})]
    batches().update_many({'_id':{'$in':ids}},{'$set':{'state':'retry','attempts':0,'next_try':time.time()}})
    result=get_repo().collection('vuln_intel_notifications').update_many({'state':'failed'}, {'$set':{'state':'retry','attempts':0,'next_try':time.time()}})
    _wake.set();start();return {'retrying':result.modified_count,'batches':len(ids)}


def drain(limit=10):
    repo=get_repo();now=time.time();queue=repo.collection('vuln_intel_notifications');leases=repo.collection('vuln_intel_notify_leases');owner=uuid.uuid4().hex
    try:
        leadership=leases.find_one_and_update({'_id':'drain','$or':[{'until':{'$lte':now}},{'until':{'$exists':False}}]},
                                              {'$set':{'owner':owner,'until':now+60}},upsert=True,return_document=ReturnDocument.AFTER)
    except DuplicateKeyError:
        return {'sent':0,'busy':True}
    if not leadership:return {'sent':0,'busy':True}
    sent=0;sent_batches=0
    try:
        if not _recover(repo,now):return {'sent':0,'sent_batches':0,'recovering':True}
        for _ in range(limit):
            now=time.time()
            renewed=leases.update_one({'_id':'drain','owner':owner,'until':{'$gt':now}},{'$set':{'until':now+60}})
            if not renewed.matched_count:break
            batch=batches().find_one_and_update({'state':{'$in':['pending','retry']},'next_try':{'$lte':now}},
                {'$set':{'state':'sending','lease_until':now+90},'$inc':{'attempts':1}},sort=[('created_at',1)],return_document=ReturnDocument.AFTER)
            if not batch:break
            identity=batch['_id'];text,count=_digest(identity)
            if not count:batches().update_one({'_id':identity},{'$set':{'state':'sent','empty':True}});continue
            if not enabled():
                batches().update_one({'_id':identity},{'$set':{'state':'cancelled','reason':'push_disabled'}})
                queue.update_many({'batch_id':identity},{'$set':{'state':'cancelled','reason':'push_disabled'}});continue
            queue.update_many({'batch_id':identity},{'$set':{'state':'sending','attempts':batch['attempts']}})
            svc=get_registry().get(ROLE.NOTIFY)
            try:
                result=svc.notify(text,title='瞭望塔 Watchtower · 漏洞情报更新 / Intelligence update',channel='feishu') if svc else {'ok':False}
                success=bool(result.get('ok') and 'feishu' in result.get('sent',[]))
            except Exception:
                success=False
            fields={'state':'sent','delivered_at':time.time()} if success else {'state':'failed' if batch['attempts']>=8 else 'retry','next_try':time.time()+min(1800,5*2**batch['attempts']),'last_error':'delivery_failed'}
            batches().update_one({'_id':identity},{'$set':fields,'$unset':{'lease_until':''}})
            queue.update_many({'batch_id':identity},{'$set':fields,'$unset':{'lease_until':''}})
            if success:sent+=count;sent_batches+=1
    finally:
        leases.update_one({'_id':'drain','owner':owner},{'$set':{'until':0}})
    return {'sent':sent,'sent_batches':sent_batches}

def _recover(repo,now):
    for doc in repo.collection(Collections.VULN_INTEL).find({'intel_push_pending':True}).limit(500):enqueue(doc)
    if repo.collection(Collections.VULN_INTEL).count_documents({'intel_push_pending':True},limit=1):return False
    batches().update_many({'state':'open','heartbeat':{'$lt':now-300}},{'$set':{'state':'pending','next_try':now,'intake_interrupted':True}})
    batches().update_many({'state':'sending','lease_until':{'$lt':now}},{'$set':{'state':'retry','next_try':now}})
    unbatched={'batch_id':{'$exists':False},'state':{'$in':['pending','retry','failed','sending']}}
    latest=events().find_one(unbatched,sort=[('created_at',-1)])
    if latest and latest.get('created_at',0)<=now-10:
        identity='legacy-'+uuid.uuid4().hex
        batches().insert_one({'_id':identity,'state':'open','source':'intake','created_at':now,'heartbeat':now,'attempts':0,'next_try':now})
        events().update_many(unbatched,{'$set':{'batch_id':identity,'state':'pending','attempts':0}})
        batches().update_one({'_id':identity},{'$set':{'state':'pending'}})
    for row in events().find({'batch_id':{'$exists':True},'state':{'$in':['pending','retry','sending']}}).limit(500):
        batches().update_one({'_id':row['batch_id']},{'$setOnInsert':{'state':'pending','created_at':row['created_at'],'attempts':0,'next_try':now,'source':'recovered'}},upsert=True)
    return True

def _digest(identity):
    query={'batch_id':identity};queue=events();count=queue.count_documents(query)
    severity={name:queue.count_documents(dict(query,severity=name)) for name in ('critical','high')};kev=queue.count_documents(dict(query,in_kev=True))
    samples=list(queue.find(query,{'identifier':1,'title':1}).sort([('created_at',1),('_id',1)]).limit(10))
    lines=['本轮新增 {} 条高危/在野漏洞情报 · {} new high-risk/KEV entries'.format(count,count),
           '严重 Critical: {} · 高危 High: {} · 已知在野 KEV: {}'.format(severity['critical'],severity['high'],kev)]
    lines.extend('{} · {}'.format(row.get('identifier') or '—',row.get('title','')) for row in samples)
    if count>len(samples):lines.append('其余 {} 条请在漏洞情报查看 · View the remaining {} in Vulnerability intelligence'.format(count-len(samples),count-len(samples)))
    lines.extend(['工作台 → 漏洞情报 / Workspace → Vulnerability intelligence','批次 Batch: '+identity])
    return '\n'.join(lines),count


_wake=threading.Event();_lock=threading.Lock();_started=False


def start():
    global _started
    with _lock:
        if _started:return
        _started=True
        def worker():
            while True:
                _wake.wait(5);_wake.clear()
                try:drain()
                except Exception:pass  # durable state survives a DB/network outage
        threading.Thread(target=worker,daemon=True,name='watchtower-intel-notifications').start()
