"""Commit an already verified offline install program without replacing user state."""
from pathlib import Path
import json,os,shutil,sys,time,uuid
import psutil
from windows_native import update_state,update_transaction as transaction
from windows_native.update_channel import sha256,link,long_path

def commit(root,stage,manifest,progress=print):
    root,stage=Path(root).resolve(),Path(stage).resolve()
    if not (root/'app/version.txt').is_file() or not (root/'state/native-release-receipt.json').is_file():
        raise ValueError('Existing folder is not a recognized Watchtower installation')
    for p in psutil.process_iter(['exe']):
        try:
            if p.info['exe'] and root in Path(p.info['exe']).resolve().parents:
                raise ValueError('Close Watchtower and its owned processes before repairing; user data will be retained')
        except (psutil.NoSuchProcess,psutil.AccessDenied):continue
    with update_state.lock(root):
        transaction.recover(root)
        old=update_state.read(root/'state/native-release-receipt.json');files=manifest['files']
        changed=[n for n,h in files.items() if not transaction._inside(root,n).is_file() or sha256(transaction._inside(root,n))!=h]
        removed=[n for n in old.get('files',{}) if n not in files]
        for n in removed:
            p=transaction._inside(root,n)
            if p.is_file() and sha256(p)!=old['files'][n]:raise ValueError('Obsolete managed file was changed locally: '+n)
        backup=Path(long_path(root/'state/update-backups'))/('repair-'+uuid.uuid4().hex[:12]);backup.mkdir(parents=True)
        journal={'phase':'preparing','base':old.get('version'),'target':manifest['version'],'backup':str(backup),
                 'operations':{},'receipt':old,'owner_pid':os.getpid(),'helper_exe':sys.executable,'repair_install':True}
        marker=root/'state/native-update-journal.json'
        helper=root/'state'/('.update-helper-repair-'+uuid.uuid4().hex[:12])
        # A cold restart can recover even if the setup EXE was killed mid-commit.
        shutil.copytree(root/'runtime/service',helper,copy_function=link)
        update_state.write(helper/'helper.json',{'created':time.time(),'product':'watchtower-native-update-helper'})
        try:
            for n in changed+removed:
                p=transaction._inside(root,n);exists=p.is_file();journal['operations'][n]=exists
                if exists:
                    saved=backup/'program'/n;saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,saved)
            journal['phase']='committing';update_state.write(marker,journal)
            for n in sorted(changed,key=lambda n:(n=='app/docker/frontend/index.html',n=='app/version.txt',n)):
                target=transaction._inside(root,n);target.parent.mkdir(parents=True,exist_ok=True)
                os.replace(long_path(stage/n),str(target))
            for n in removed:transaction._inside(root,n).unlink(missing_ok=True)
            for n,h in files.items():
                if sha256(transaction._inside(root,n))!=h:raise ValueError('Repaired program member mismatch: '+n)
            update_state.write(root/'state/native-release-receipt.json',{'version':manifest['version'],'files':files,'base_install':manifest['version']})
            for name in ['native-update-chain.json','native-update-command.json','native-update-active.json']:
                path=root/'state'/name
                if path.is_file():
                    dest=backup/'previous-intents'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest);path.unlink()
            from windows_native import guardian
            guardian.install(root)
            journal['phase']='done';update_state.write(marker,journal)
            update_state.progress(root,phase='done',target=manifest['version'],msg='Windows修复安装完成，账号/配置/任务与浏览器数据保留，旧更新计划已归档',terminal=True)
            progress('Repair installation completed; existing user state retained')
            return {'ok':True,'version':manifest['version'],'root':str(root),'repair':True,'user_state_retained':True,'backup':str(backup)}
        except Exception:
            if journal['phase']=='committing':transaction._restore(root,journal)
            prior=backup/'previous-intents'
            if prior.exists():
                for p in prior.iterdir():shutil.copy2(p,root/'state'/p.name)
            journal['phase']='rolled_back';update_state.write(marker,journal);raise
