"""Signed native file transaction with owned-file pruning and recovery journal."""
from pathlib import Path
import json,os,uuid,shutil,time,sys
from windows_native import update_channel as channel,update_state
from windows_native.update_api import receipt,local_version

def _inside(root,name):
    channel.name(name);path=Path(root)/name
    path.resolve().relative_to(Path(root).resolve())
    for part in [path]+list(path.parents):
        if part==Path(root).resolve():break
        if part.is_symlink() or part.exists() and getattr(part.stat(follow_symlinks=False),'st_file_attributes',0)&0x400:raise ValueError('Update destination may not traverse a link')
    return Path(channel.long_path(path))

def prepare(root,target,full=False):
    root=Path(root);release=channel.manifest(root,target,full);old=receipt(root);files=release['files']
    state=Path(channel.long_path(root/'state'))
    stage=state/('.wu-'+uuid.uuid4().hex[:12]);stage.mkdir();changed=[];removed=[name for name in old.get('files',{}) if name not in files]
    update_state.write(stage/'transaction.json',{'product':'watchtower-native-update-stage','target':target})
    try:
        for name in removed:
            path=_inside(root,name)
            if path.is_file() and channel.sha256(path)!=old['files'][name]:raise ValueError('Obsolete managed file was modified locally: '+name)
        packaged=set()
        if release.get('bundle'):
            packaged={'app/'+n if p['kind']=='common' else n for p in release['bundle']['packages'] for n in p['members']}
            if release['bundle']['mode']=='delta' and old.get('version')!=release['bundle']['base_version']:raise ValueError('Installed receipt does not match package baseline')
        for name,item in files.items():
            path=_inside(root,name)
            if packaged:
                if name in packaged:changed.append(name)
                elif not path.is_file() or full and channel.sha256(path)!=item['sha256']:raise ValueError('Unchanged managed file is missing/corrupt; repair the base installation: '+name)
            elif not path.is_file() or channel.sha256(path)!=item['sha256']:changed.append(name)
        required=sum(files[n]['bytes'] for n in changed)
        backup_bytes=sum((root/name).stat().st_size for name in changed+removed if (root/name).is_file())
        if shutil.disk_usage(stage).free<required+backup_bytes+128*1024**2:raise ValueError('Insufficient update staging/rollback space')
        update_state.progress(root,phase='downloading',total=len(changed),done=0,msg='正在下载 Windows 差异文件',base=local_version(root),target=target)
        if release.get('bundle'):
            from sentinel_platform.core import update_bundle
            bundle=release['bundle'];available={'app/'+n if p['kind']=='common' else n for p in bundle['packages'] for n in p['members']}
            if not set(changed).issubset(available):
                repair=channel.manifest(root,target,True)
                if not repair.get('bundle') or repair['files']!=files:raise ValueError('Full repair package inventory mismatch')
                bundle=repair['bundle']
            if shutil.disk_usage(stage).free<required+backup_bytes+sum(p['bytes'] for p in bundle['packages'])+128*1024**2:raise ValueError('Insufficient two-package cache/staging space')
            def package_progress(done,size):update_state.progress(root,phase='downloading',total=size,done=done,msg='正在下载公共包与Windows专属包',target=target)
            extracted=update_bundle.stage(bundle,channel.source(root),channel.headers(root),state/'update-cache',stage/'changes',changed,package_progress)
            for name,path in extracted.items():
                if name.endswith('.py'):compile(Path(path).read_bytes(),name,'exec')
        for index,name in enumerate([] if release.get('bundle') else changed):
            blob=channel.download(root,files[name]);channel.unpack(blob,stage/'changes'/name,files[name])
            if name.endswith('.py'):compile((stage/'changes'/name).read_bytes(),name,'exec')
            update_state.progress(root,phase='downloading',total=len(changed),done=index+1,msg='正在下载 Windows 差异文件',target=target)
        # The health candidate has program files only; same-volume hardlinks do not
        # duplicate unchanged browsers/tools and do not copy credentials/state.
        candidate=stage/'candidate'
        for name,item in files.items():
            destination=candidate/name;destination.parent.mkdir(parents=True,exist_ok=True)
            source=stage/'changes'/name if name in changed else root/name
            channel.link(source,destination)
        if (candidate/'app/version.txt').read_text(encoding='utf-8').strip()!=target:raise ValueError('Release version marker mismatch')
        return {'release':release,'stage':stage,'changed':changed,'removed':removed,'old':old,'base':local_version(root)}
    except Exception:
        stage.resolve().relative_to(state.resolve());shutil.rmtree(stage);raise

def _restore(root,journal):
    backup=Path(journal['backup']);backup.resolve().relative_to(Path(channel.long_path(Path(root)/'state/update-backups')).resolve())
    errors=[]
    for name,existed in reversed(list(journal['operations'].items())):
        target=_inside(root,name)
        try:
            saved=backup/'program'/name
            if existed:target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(saved,target)
            else:target.unlink(missing_ok=True)
        except OSError:errors.append(name)
    if errors:raise RuntimeError('Update recovery could not restore managed files: '+', '.join(errors[:5]))
    update_state.write(Path(root)/'state/native-release-receipt.json',journal['receipt'])

def recover(root):
    path=Path(root)/'state/native-update-journal.json'
    try:journal=update_state.read(path)
    except (OSError,ValueError):return
    if journal.get('phase')=='committing':
        _restore(root,journal);journal['phase']='recovered';update_state.write(path,journal)
        update_state.progress(root,phase='error',msg='上次更新中断，已自动恢复原版本',error='Interrupted native update recovered',terminal=True)

def apply(root,target,health,start,stop,full=False):
    root=Path(root);stage=None;stop_attempted=False;completed=None
    with update_state.lock(root):
        recover(root)
        prepared=prepare(root,target,full);stage=prepared['stage'];backup=Path(channel.long_path(root/'state/update-backups'))/uuid.uuid4().hex;backup.mkdir(parents=True)
        journal={'phase':'preparing','base':prepared['base'],'target':target,'backup':str(backup),'operations':{},'receipt':prepared['old'],'owner_pid':os.getpid(),'helper_exe':sys.executable}
        journal_path=root/'state/native-update-journal.json'
        try:
            update_state.progress(root,phase='validating',total=len(prepared['changed']),done=len(prepared['changed']),msg='正在检查 Windows 更新候选',target=target)
            if not health(stage/'candidate',prepared['release']):raise ValueError('Candidate native health check failed')
            stop_attempted=True;stop()
            # Complete backups before the first overwrite. Journal lists the entire
            # transaction so a killed helper can restore even an in-flight replace.
            for name in prepared['changed']+prepared['removed']:
                path=_inside(root,name);existed=path.is_file();journal['operations'][name]=existed
                if existed:
                    saved=backup/'program'/name;saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
            journal['phase']='committing';update_state.write(journal_path,journal)
            update_state.progress(root,phase='applying',total=len(journal['operations']),done=0,msg='正在应用 Windows 更新',target=target)
            for index,name in enumerate(sorted(prepared['changed'],key=lambda n:(n=='app/docker/frontend/index.html',n=='app/version.txt',n))):
                path=_inside(root,name);path.parent.mkdir(parents=True,exist_ok=True);os.replace(stage/'changes'/name,path)
                update_state.progress(root,phase='applying',total=len(journal['operations']),done=index+1,msg='正在应用 Windows 更新',target=target)
            for name in prepared['removed']:_inside(root,name).unlink(missing_ok=True)
            checked=prepared['release']['files'] if full or not prepared['release'].get('bundle') else {n:prepared['release']['files'][n] for n in prepared['changed']}
            for name,item in checked.items():
                if channel.sha256(root/name)!=item['sha256']:raise ValueError('Committed native inventory mismatch')
            update_state.write(root/'state/native-release-receipt.json',{'version':target,'files':{n:f['sha256'] for n,f in prepared['release']['files'].items()}})
            update_state.progress(root,phase='restarting',total=len(journal['operations']),done=len(journal['operations']),msg='正在启动更新后的 Windows 程序',target=target)
            if not start():raise ValueError('Updated native service failed to start')
            journal['phase']='done';update_state.write(journal_path,journal)
            completed={'phase':'done','total':len(prepared['changed']),'done':len(prepared['changed']),'msg':'Windows 更新完成','target':target,'changed_files':len(prepared['changed']),'removed_files':len(prepared['removed']),'terminal':True}
            return prepared['release']
        except Exception as exc:
            if stop_attempted:
                try:stop()
                except Exception:pass
            if journal['phase']=='committing':_restore(root,journal)
            journal['phase']='rolled_back';update_state.write(journal_path,journal)
            if stop_attempted:
                try:start()
                except Exception:pass
            update_state.progress(root,phase='error',msg='Windows 更新失败，已恢复原版本',error=type(exc).__name__+': '+str(exc)[:180],terminal=True)
            raise
        finally:
            if stage:stage.resolve().relative_to(Path(channel.long_path(root/'state')).resolve());shutil.rmtree(stage)
            if completed:update_state.progress(root,**completed)
