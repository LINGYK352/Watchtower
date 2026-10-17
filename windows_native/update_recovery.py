"""OS transaction ownership and verified live readiness govern recovery."""
from pathlib import Path
import os,psutil
from windows_native import update_state

def helper_running(record):
    try:
        pid=int(record['owner_pid'])
        if pid<=0:return False
        return os.path.normcase(os.path.abspath(psutil.Process(pid).exe()))==os.path.normcase(os.path.abspath(record['helper_exe']))
    except psutil.AccessDenied:return True
    except (psutil.NoSuchProcess,KeyError,TypeError,ValueError,OSError):return False

def required(root):
    try:
        with update_state.lock(root):
            record=update_state.read(Path(root)/'state/native-update-journal.json')
            return record.get('phase')=='committing' and not helper_running(record)
    except (update_state.UpdateBusyError,OSError,ValueError):return False

def reconcile_completed(root):
    root=Path(root);progress=update_state.get_progress(root)
    if progress.get('phase') not in ('checking','restarting','error'):return progress
    try:
        with update_state.lock(root):
            progress=update_state.get_progress(root)
            if (root/'state/native-update-command.json').exists():return progress
            journal=update_state.read(root/'state/native-update-journal.json')
            if journal.get('phase')!='done' or helper_running(journal):return progress
            expected=journal.get('target');receipt=update_state.read(root/'state/native-release-receipt.json')
            if not expected or receipt.get('version')!=expected or (root/'app/version.txt').read_text(encoding='utf-8').strip()!=expected:return progress
            from windows_native import update_chain
            chain=update_chain.state(root);cursor=chain.get('cursor',0);steps=chain.get('steps',[])
            if chain.get('id'):
                if cursor<len(steps) and steps[cursor]!=expected:return progress
                if cursor>=len(steps) and chain.get('target')!=expected:return progress
            elif progress.get('target')!=expected or progress.get('phase')!='restarting':return progress
            from windows_native.readiness import running_version
            if not running_version(root,expected):return progress
            update_state.write(root/'state/native-update-reconciled.json',{'target':expected,'prior_phase':progress.get('phase'),'prior_error':progress.get('error',''),'verified_live_hop':True})
            if chain.get('id') and cursor<len(steps):update_chain.success(root,{'chain_id':chain['id'],'target':expected})
            else:
                if chain.get('id') and (chain.get('active') or chain.get('phase')!='done'):
                    chain.update(active=False,phase='done',error='');update_chain.save(root,chain)
                update_state.progress(root,phase='done',target=expected,msg='更新目标已验证运行，收尾状态已恢复',terminal=True)
            return update_state.get_progress(root)
    except (update_state.UpdateBusyError,OSError,ValueError,KeyError,IndexError):return progress
