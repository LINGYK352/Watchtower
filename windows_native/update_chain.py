"""Native chain intent persists across EXE replacement and normal GUI relaunch."""
from pathlib import Path
import uuid,time
from windows_native import update_state,update_channel as channel

def state(root):
    try:return update_state.read(Path(root)/'state/native-update-chain.json')
    except (OSError,ValueError):return {}

def save(root,data):update_state.write(Path(root)/'state/native-update-chain.json',data)

def begin(root,target='',full=False):
    if target:
        from sentinel_platform.core.update_policy import key
        if key(channel.headers(root)['X-Client-Version'])[:3]>=(1,21,175) and key(target)[:3]<(1,21,175):raise ValueError('Windows175禁止回退到较早版本')
    with update_state.lock(root):
        progress=update_state.get_progress(root);command=Path(root)/'state/native-update-command.json'
        if progress.get('phase') in update_state.ACTIVE or command.exists():return {'started':False,'msg':'更新正在进行中'}
        old=state(root)
        if old.get('schema')==1 and old.get('cursor',0)<len(old.get('steps',[])):
            plan=channel.chain(root,old['target']);current=channel.headers(root)['X-Client-Version']
            if current==old['steps'][old['cursor']]:
                # Committed code was started, but the former helper died before
                # advancing its chain cursor. The running GUI validates this hop.
                from windows_native.readiness import running_version
                if not running_version(root,current):raise ValueError('本级文件已落盘，但Windows服务和后台进程尚未就绪；保留本级进度，恢复启动后继续')
                old['completed'].append(current);old['cursor']+=1
            if old['cursor']<len(old['steps']) and (not plan['steps'] or plan['steps'][0]!=old['steps'][old['cursor']]):raise ValueError('保存的Windows更新链与当前版本不一致')
            data=old;data.update(active=True,phase='pending',error='')
        else:
            plan=channel.chain(root,target)
            data={'schema':1,'id':uuid.uuid4().hex,'origin':channel.headers(root)['X-Client-Version'],'target':plan['target'],
                  'steps':plan['steps'],'kind':plan['direction'],'full':bool(full),'cursor':0,'completed':[],'active':True,'phase':'pending','started':time.time()}
        save(root,data)
        return _enqueue_locked(root,data)

def _enqueue_locked(root,data):
    if data['cursor']>=len(data['steps']):
        data.update(active=False,phase='done');save(root,data)
        update_state.progress(root,phase='done',msg='Windows链式更新完成，目标版本已运行',target=data['target'])
        return {'started':False,'msg':'已经完成更新'}
    target=data['steps'][data['cursor']]
    request={'id':uuid.uuid4().hex,'action':'rollback' if data.get('kind')=='rollback' else 'apply','target':target,'full':data.get('full',False),'created':time.time(),'chain_id':data['id']}
    data['phase']='running';save(root,data)
    update_state.write(Path(root)/'state/native-update-command.json',request)
    update_state.progress(root,phase='checking',msg='继续Windows链式更新',target=target,request_id=request['id'])
    return {'started':True,'target_version':target,'request_id':request['id']}

def tick(root):
    data=state(root)
    if not data.get('active') or data.get('phase')!='pending':return
    try:
        with update_state.lock(root):
            data=state(root)
            if not data.get('active') or data.get('phase')!='pending':return
            if (Path(root)/'state/native-update-command.json').exists():return
            plan=channel.chain(root,data['target'])
            if data['cursor']<len(data['steps']) and (not plan['steps'] or plan['steps'][0]!=data['steps'][data['cursor']]):raise ValueError('Windows链式版本顺序不一致')
            _enqueue_locked(root,data)
    except update_state.UpdateBusyError:pass
    except Exception as exc:failed(root,str(exc))

def success(root,request):
    if not request.get('chain_id'):return
    data=state(root)
    if data.get('id')!=request['chain_id'] or data['steps'][data['cursor']]!=request['target']:raise ValueError('Native chain request does not match cursor')
    if channel.headers(root)['X-Client-Version']!=request['target']:raise ValueError('Running native version differs from committed hop')
    data['completed'].append(request['target']);data['cursor']+=1
    final=data['cursor']==len(data['steps']);data.update(active=not final,phase='done' if final else 'pending');save(root,data)
    update_state.progress(root,phase='done' if final else 'checking',msg='Windows链式更新完成，目标版本已运行' if final else '本级运行检查通过，准备下一级',target=data['target'])

def failed(root,error):
    data=state(root)
    if data.get('id') and data.get('cursor',0)<len(data.get('steps',[])):
        data.update(active=False,phase='error',error=error[:600]);save(root,data)
    update_state.progress(root,phase='error',msg='更新暂停，已下载内容保留，可继续更新',error=error[:600])
