"""Persistent mandatory chain. OS lock owns work; readiness owns advancement."""
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlencode
import json
import os
import socket
import time
import uuid
from sentinel_platform.core import update_policy
from sentinel_platform.core.update_commit import write, sha256


def fetch(updater, source, credential, root, target=''):
    url=source.rstrip('/')+'/chain'+('?' + urlencode({'target':target}) if target else '')
    with urlopen(Request(url,headers=updater._auth_headers(credential,root)),timeout=30) as response:
        raw=response.read(1024**2+1)
    if len(raw)>1024**2:raise ValueError('Update chain metadata too large')
    data=json.loads(raw)
    current=updater._client_version(root)
    if data.get('schema')!=1 or data.get('policy')!='mandatory-chain' or data.get('current')!=current:
        raise ValueError('Distribution chain does not match current installation')
    guardian=data.get('guardian','')
    if update_policy.key(guardian)[:3]!=update_policy.key(update_policy.GUARDIAN)[:3]:raise ValueError('Unexpected guardian version')
    if '-' in guardian and '-' not in current:raise ValueError('A stable client may not enter a test chain')
    steps=data.get('steps')
    if not isinstance(steps,list) or len(steps)>2048 or len(set(steps))!=len(steps):raise ValueError('Invalid update chain')
    previous=current
    rollback=data.get('direction')=='rollback'
    if update_policy.key(current)[:3]>=(1,21,175) and update_policy.key(data['target'])[:3]<(1,21,175):raise ValueError('175新基板禁止回退到较早版本')
    for step in steps:
        update_policy.key(step)
        bootstrap=(not previous or update_policy.key(previous)<update_policy.key(guardian)) and step==guardian
        neighbor=update_policy.adjacent(step,previous) if rollback else update_policy.adjacent(previous,step)
        if not bootstrap and not neighbor:raise ValueError('Distribution plan skips a version')
        previous=step
    if steps and (steps[-1]!=data['target'] or data['next']!=steps[0]):raise ValueError('Chain endpoints mismatch')
    return data


def begin(updater,source,key,root,target=''):
    with updater._apply_lock(root) as acquired:
        if not acquired:return
        from sentinel_platform.core.update_commit import recover
        recover(root)
        old=updater._read_chain_state(root)
        if old.get('schema')==2 and old.get('source_url')==source and old.get('cursor',0)<len(old.get('steps',[])):
            # Resume a failed or interrupted fixed plan. Already completed hops stay.
            state=old
            resume_phase='await_running' if updater._client_version(root)==state.get('current_target') else 'checking'
            state.update(active=True,error='',phase=resume_phase)
        else:
            plan=fetch(updater,source,key,root,target)
            state={'schema':2,'id':uuid.uuid4().hex,'active':True,'source_url':source,
                   'origin':updater._client_version(root),'target':plan['target'],'guardian':plan['guardian'],
                   'steps':plan['steps'],'kind':plan['direction'],'cursor':0,'completed':[],'phase':'checking','started':time.time()}
        updater._write_chain_state(root,state)
    step(updater,source,key,root)


def await_running(updater,root,state):
    expected=state['current_target']
    # A scheduler/worker can win the shared resume lock. Its loopback belongs
    # to that container, not to Gunicorn. Compose guarantees the web DNS name.
    host='web' if Path('/.dockerenv').is_file() else '127.0.0.1'
    url=os.environ.get('SENTINEL_UPDATE_HEALTH_URL','http://'+host+':5013/api/meta/health/update-ready')
    from urllib.request import build_opener,ProxyHandler
    direct=build_opener(ProxyHandler({})).open
    deadline=time.monotonic()+180
    reason='等待当前一级服务启动'
    while time.monotonic()<deadline:
        updater.set_progress('restarting',msg=reason)
        try:
            with direct(Request(url,headers={'Cache-Control':'no-cache'}),timeout=3) as response:data=json.load(response).get('data',{})
            if data.get('migration',{}).get('error'):
                raise RuntimeError('当前一级已落盘，启动迁移失败：'+data['migration']['error'])
            if data.get('ready') and data.get('version')==expected and (not state.get('frontend_sha') or data.get('frontend_sha')==state['frontend_sha']):return
            background=data.get('background',{})
            reason=('后台任务正在完成当前工作并温和换版，进度已保留' if 'draining' in background.values()
                    else '等待当前一级的Web、扫描worker、scheduler和前端产物就绪')
        except (OSError,ValueError):reason='服务正在重载，已保留更新进度'
        time.sleep(.5)
    raise RuntimeError('当前一级 '+expected+' 已落盘但运行检查未通过；未进入下一级，可继续更新')


def step(updater,source,key,root):
    with updater._apply_lock(root) as acquired:
        if not acquired:return
        from sentinel_platform.core.update_commit import recover
        recover(root)
        state=updater._read_chain_state(root)
        if not state.get('active'):return
        try:
            if state.get('schema')!=2:
                # Upgrade an old pending intent, without retaining its TTL claims.
                plan=fetch(updater,source,key,root)
                state={'schema':2,'id':uuid.uuid4().hex,'active':True,'source_url':source,'origin':updater._client_version(root),
                       'target':plan['target'],'guardian':plan['guardian'],'steps':plan['steps'],'cursor':0,'completed':[],'phase':'checking'}
            state.update(owner_pid=os.getpid(),owner_host=socket.gethostname())
            updater._write_chain_state(root,state)
            if state.get('phase')=='await_running' and updater._client_version(root)!=state['current_target']:
                journal=Path(root)/'.update_stage/.commit.json'
                if journal.exists() and json.loads(journal.read_text())['phase']=='recovered':state['phase']='checking'
                else:raise ValueError('已提交版本标识与更新链不一致')
            if state.get('phase')=='await_running':
                await_running(updater,root,state)
                state['completed'].append(state['current_target']);state['cursor']+=1;state['phase']='checking'
                updater._write_chain_state(root,state)
            if state['cursor']>=len(state['steps']):
                state.update(active=False,phase='done',finished=time.time())
                updater._write_chain_state(root,state)
                updater.set_progress('done',msg='链式更新完成，目标版本已运行：'+updater._client_version(root))
                return
            target=state['steps'][state['cursor']]
            plan=fetch(updater,source,key,root,state['target'])
            if not plan['steps'] or plan['steps'][0]!=target:raise ValueError('当前版本与已保存更新链不一致，停止跳级')
            state.update(phase='downloading',current_target=target,last_local=updater._client_version(root),last_target=target)
            updater._write_chain_state(root,state)
            updater._run_update_impl(source,key,root,target,chain_hop=True)
            if updater.get_progress().get('phase')=='error':raise RuntimeError(updater.get_progress().get('error','当前一级更新失败'))
            # A re-created container kills this process; startup resumes from disk.
            # HUP survives, so dispatch a FRESH interpreter for the installed code.
        except Exception as exc:
            state=updater._read_chain_state(root) or state
            state.update(active=False,phase='error',error=str(exc)[:600])
            updater._write_chain_state(root,state)
            updater.set_progress('error',error=state['error'],msg='更新已暂停；已下载内容保留，点击继续更新')
            return
    updater._spawn_chain_step(source,key,root)


def pending(updater,root=''):
    root=root or os.environ['SENTINEL_GUARDIAN_ROOT']
    state=updater._read_chain_state(root)
    if not state.get('active'):return {'active':False}
    with updater._apply_lock(root) as acquired:
        if not acquired:return {'active':True,'action':'running'}
    from sentinel_platform.modules.system import activation
    credential=activation.read_key()
    if not credential:
        state.update(active=False,phase='error',error='激活凭证不可用，请激活后继续更新');updater._write_chain_state(root,state)
        updater.set_progress('error',error=state['error']);return {'active':False,'action':'activation_required'}
    updater._spawn_chain_step(state['source_url'],credential,root)
    return {'active':True,'action':'resume'}


def runtime_ready(root,boot_version):
    """Called after routes are mounted; unique PID/start time prevents stale markers."""
    import psutil
    process=psutil.Process()
    stamp={'pid':process.pid,'started':process.create_time(),'version':boot_version}
    write(Path(root)/'.update_stage/ready'/f'{socket.gethostname()}-{process.pid}.json',stamp)


def ready_status(root,boot_version):
    import psutil
    root=Path(root);ready=True;count=0
    process=psutil.Process();parent=process.parent()
    peers=parent.children() if parent and 'gunicorn' in ' '.join(parent.cmdline()) else [process]
    for peer in peers:
        if 'gunicorn' not in ' '.join(peer.cmdline()) and peer.pid!=process.pid:continue
        count+=1
        try:
            stamp=json.loads((root/'.update_stage/ready'/f'{socket.gethostname()}-{peer.pid}.json').read_text())
            if stamp['version']!=boot_version or abs(stamp['started']-peer.create_time())>.01:ready=False
        except (OSError,ValueError,KeyError):ready=False
    journal=root/'.update_stage/.commit.json'
    if journal.exists() and json.loads(journal.read_text()).get('phase')=='committing':ready=False
    guard=root/'.update_stage/guardian/installation.json'
    if guard.exists():
        installed=json.loads(guard.read_text())
        if installed.get('installed') and os.environ.get('SENTINEL_GUARDIAN_GENERATION')!=installed.get('generation'):ready=False
        if installed.get('requires_recreate'):ready=False
    from sentinel_platform.core import get_repo
    get_repo()._db().command('ping')
    index=root/'docker/frontend/index.html'
    background={}
    migration={}
    state=root/'.update_stage/guardian/installation.json'
    if state.exists():
        installation=json.loads(state.read_text())
        migration={'required':bool(installation.get('requires_recreate')),'phase':installation.get('dispatch_state',''), 'error':installation.get('last_error','')}
        carrier=root/'.update_stage/guardian/generations'/installation['generation']/'manifest.json'
        required='guardian_runtime.py' in json.loads(carrier.read_text())['descriptor']['files']
        if required:
            for role in ('worker','scheduler'):
                try:
                    row=json.loads((root/'.update_stage/background-ready'/(role+'.json')).read_text())
                    background[role]=row.get('phase','unknown')
                    if not row.get('ready') or row.get('version')!=boot_version or time.time()-row['heartbeat']>5:ready=False
                except (OSError,ValueError,KeyError):ready=False;background[role]='not_ready'
    return {'ready':ready and count>0,'version':boot_version,'workers':count,'background':background,'migration':migration,'guardian_revision':int(os.environ.get('SENTINEL_GUARDIAN_REVISION','0')),'frontend_sha':sha256(index) if index.is_file() else ''}
