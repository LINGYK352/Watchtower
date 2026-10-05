"""Durable native transport for the common task/session/console entry points."""
from pathlib import Path
import os,time,uuid

KINDS={'task','session','console'}

def deliver(kind,identifier,**payload):
    if kind not in KINDS or not identifier:raise ValueError('Unsupported native job')
    from sentinel_platform.core import get_repo
    if kind=='task' and payload.get('options') is not None:
        from sentinel_platform.modules.kernel import orchestration
        doc=get_repo().collection('task').find_one(orchestration._task_query(identifier)) or {}
        if payload['options']==doc.get('options'):payload['options']=None
    job=uuid.uuid4().hex
    get_repo().collection('native_dispatch_queue').insert_one({'_id':job,'kind':kind,'task_id':identifier,'payload':payload,'state':'queued','created':time.time()})
    return job

def run_job(job):
    from sentinel_platform.modules.kernel import orchestration
    from sentinel_platform.modules.ai_pentest import session
    if job['kind']=='task':return orchestration.run_task(job['task_id'],**job.get('payload',{}))
    if job['kind']=='session':return session.run_session(job['task_id'])
    if job['kind']=='console':return session.run_console_session(job['task_id'])
    raise ValueError('Invalid persisted native job kind')

def consume(root,boot):
    from pymongo import ReturnDocument
    from sentinel_platform.core import get_repo
    queue=get_repo().collection('native_dispatch_queue')
    while not (Path(root)/'state/shutdown').exists():
        job=queue.find_one_and_update({'state':'queued'},{'$set':{'state':'running','boot':boot,'pid':os.getpid(),'started':time.time()}},sort=[('created',1)],return_document=ReturnDocument.AFTER)
        if not job:time.sleep(.1);continue
        lease={'_id':job['_id'],'state':'running','boot':boot,'pid':os.getpid()}
        try:queue.update_one(lease,{'$set':{'state':'done','result':run_job(job),'finished':time.time()}})
        except Exception as exc:queue.update_one(lease,{'$set':{'state':'error','error_type':type(exc).__name__,'finished':time.time()}})

def recover(boot):
    """Called only after the previous supervisor's owned process tree has exited."""
    from sentinel_platform.core import get_repo
    from sentinel_platform.modules.kernel import orchestration
    queue=get_repo().collection('native_dispatch_queue')
    for job in queue.find({'state':'running','boot':{'$ne':boot}}):
        identifier=job['task_id']
        if job['kind']=='task':
            get_repo().collection('task').update_one({**orchestration._task_query(identifier),'status':'running'},{'$set':{'status':'queued'}})
        else:
            coll=get_repo().collection('intel_pentest_session');query={'_id':orchestration._oid(identifier)}
            if job['kind']=='session':
                coll.update_one({**query,'status':{'$in':['running','dispatching']},'stop_requested':{'$ne':True},'console_taken_over':{'$ne':True}},{'$set':{'status':'dispatching'}})
            elif job['kind']=='console':
                coll.update_one({**query,'console_running':True},{'$set':{'console_running':True,'console_update':int(time.time())},'$unset':{'console_execution_token':''}})
        queue.update_one({'_id':job['_id'],'state':'running','boot':job.get('boot')},{'$set':{'state':'queued','recovered':time.time()}})
