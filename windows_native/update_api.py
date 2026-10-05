"""Keep the existing Web update UI/API contract on the native update channel."""
from pathlib import Path
from urllib.error import HTTPError
import json
from windows_native import update_channel as channel,update_state

def local_version(root):return (Path(root)/'app/version.txt').read_text(encoding='utf-8').strip()

def _cmp(a,b):
    from sentinel_platform.modules.about.update_check import _cmp as compare
    return compare(a,b)

def check(root,client):
    server=local_version(root);url=channel.source(root)
    try:
        cat=channel.catalog(root);plan=channel.chain(root);latest=plan['target']
        return {'server_version':server,'client_version':client,'latest_version':latest,'source':url,'remote_ok':True,'has_update':_cmp(latest,server)>0,'message':('发现 Windows 新版本 '+latest) if _cmp(latest,server)>0 else '当前 Windows 版本已是最新','runtime_abi':channel.ABI,'channel':cat.get('channel'),'requires_restart':True}
    except HTTPError as exc:
        kind='unauthorized' if exc.code==403 else 'channel_unavailable' if exc.code==404 else 'network'
    except Exception:kind='network'
    return {'server_version':server,'client_version':client,'latest_version':server,'source':url,'remote_ok':False,'has_update':False,'error_type':kind,'message':'Windows 更新通道未就绪，请检查网络或凭证','runtime_abi':channel.ABI}

def versions(root):
    cat=channel.catalog(root)
    return {'latest':cat['latest'],'min_rollback':cat.get('minimum_rollback','v1.21.171'),'versions':[{'version':r['version'],'published_at':r.get('published_at',''),'files':r.get('files',0),'prev':r.get('prev','')} for r in cat['releases']]}

def changes(root,target):
    catalog=channel.catalog(root)
    if catalog.get('paired'):
        entry=next((r for r in catalog['releases'] if r['version']==target),None)
        if not entry:raise ValueError('目标版本不在分发索引中')
        summary=entry.get('changes',{}).get('windows-amd64')
        if not summary:raise ValueError('该版缺少预制变更记录')
        return summary
    release=channel.manifest(root,target);before=receipt(root).get('files',{});after={n:m['sha256'] for n,m in release['files'].items()}
    added=[n for n in after if not (Path(root)/n).is_file()]
    changed=[n for n in after if (Path(root)/n).is_file() and channel.sha256(Path(root)/n)!=after[n]]
    removed=[n for n in before if n not in after]
    return {'from':local_version(root),'to':target,'added':added,'changed':changed,'removed':removed,'total':len(added)+len(changed)+len(removed),'published_at':release.get('published_at','')}

def receipt(root):
    try:return update_state.read(Path(root)/'state/native-release-receipt.json')
    except (OSError,ValueError):return {'version':local_version(root),'files':{}}

def apply(root,target='',rollback=False,full=False):
    if rollback and (not target or _cmp(target,local_version(root))>=0):raise ValueError('回退目标必须低于当前版本')
    if not rollback and target and _cmp(target,local_version(root))<0:raise ValueError('升级目标必须高于当前版本')
    from windows_native.update_chain import begin
    try:return begin(root,target,full)
    except update_state.UpdateBusyError:return {'started':False,'msg':'更新正在进行中'}

def install(app,root):
    from flask import request,jsonify
    routes={'/api/about/check','/api/about/apply','/api/about/rollback','/api/about/versions','/api/about/changes','/api/about/progress'}
    @app.before_request
    def native_update_routes():
        path=request.path
        if path not in routes:return None
        # The existing gateway registered before this hook enforces auth/RBAC.
        try:
            if request.method=='GET' and path=='/api/about/check':data=check(root,request.args.get('client',''))
            elif request.method=='GET' and path=='/api/about/versions':data=versions(root)
            elif request.method=='GET' and path=='/api/about/changes':data=changes(root,request.args.get('version',''))
            elif request.method=='GET' and path=='/api/about/progress':data=update_state.get_progress(root)
            elif request.method=='POST' and path in {'/api/about/apply','/api/about/rollback'}:
                body=request.get_json(silent=True) or {};full=body.get('full',False)
                if type(full) is not bool:raise ValueError('full 必须为布尔值')
                data=apply(root,body.get('version',''),path.endswith('/rollback'),full)
            else:return None
            return jsonify(code=200,message='success',data=data)
        except HTTPError as exc:return jsonify(code=400,message='原生更新源请求失败：'+str(exc.code),data=None),400
        except Exception as exc:return jsonify(code=400,message=str(exc)[:200],data=None),400
