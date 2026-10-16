"""Managed native update storage, reached through distributed business source.

The frozen launcher need not import a new native adapter. Cleanup uses its
existing cross-process transaction lock and reads every recovery reference fresh.
"""
from pathlib import Path
import json,os,re,shutil,sys,time

ZIP=re.compile(r'[0-9a-f]{64}\.zip');BACKUP=re.compile(r'[0-9a-f]{32}');GENERATION=re.compile(r'[0-9a-f]{16}')
CACHE_BUDGET=128*1024*1024;RETENTION=7*86400


def root():
    value=os.environ.get('SENTINEL_NATIVE_ROOT')
    if os.name!='nt' or not value:return None
    from windows_native.update_channel import long_path
    return Path(long_path(Path(value).absolute()))


def _real(path):
    value=str(Path(path).resolve())
    if value.startswith('\\\\?\\UNC\\'):value='\\\\'+value[8:]
    elif value.startswith('\\\\?\\'):value=value[4:]
    return Path(value)


def _read(path,default=None):
    from windows_native.update_state import read
    if not path.exists():return default
    if path.stat().st_size>16*1024*1024:raise ValueError('Managed state exceeds its budget')
    return read(path)


def _inside(path,state):
    _real(path).relative_to(_real(state))
    for part in [path]+list(path.parents):
        if part==state.parent:break
        if part.exists() and (part.is_symlink() or getattr(part.lstat(),'st_file_attributes',0)&0x400):raise ValueError('Managed storage contains a reparse point')
    return path


def _files(path,state):
    _inside(path,state)
    if not path.exists():return []
    if path.is_file():return [path]
    output=[];pending=[path]
    while pending:
        folder=pending.pop()
        with os.scandir(folder) as entries:
            for entry in entries:
                metadata=entry.stat(follow_symlinks=False)
                if entry.is_symlink() or getattr(metadata,'st_file_attributes',0)&0x400:
                    raise ValueError('Managed storage contains a reparse point')
                if entry.is_dir(follow_symlinks=False):pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):output.append(Path(entry.path))
                if len(output)>30000:raise ValueError('Managed tree exceeds its file budget')
    return output


def _bytes(files):
    return sum(p.stat().st_size for p in files)


def _blocked(base,state):
    progress=_read(state/'native-update-progress.json',{}) or {}
    chain=_read(state/'native-update-chain.json',{}) or {}
    journal=_read(state/'native-update-journal.json',{}) or {}
    if progress.get('phase') in {'checking','downloading','validating','applying','restarting'} or chain.get('active'):
        return 'update_active'
    if state.joinpath('native-update-command.json').exists() or state.joinpath('native-update-active.json').exists():return 'update_active'
    if chain.get('steps') and chain.get('cursor',0)<len(chain['steps']):return 'update_resumable'
    if journal.get('phase') in ('preparing','committing'):return 'recovery_pending'
    if progress.get('phase')=='error':return 'recovery_pending'
    return ''


def _active(state):
    import psutil
    executables=[]
    for process in psutil.process_iter(['name','exe']):
        try:
            value=process.info.get('exe')
            if value:executables.append(_real(value))
            elif process.info.get('name') in ('WatchtowerNative.exe','NativeService.exe'):raise ValueError('Native process identity unavailable')
        except psutil.Error:
            if process.info.get('name') in ('WatchtowerNative.exe','NativeService.exe'):raise ValueError('Native process identity unavailable')
    return executables


def plan(base=None):
    from windows_native.update_channel import long_path
    base=Path(long_path(base or root()));state=base/'state';_inside(state,state)
    blocked=_blocked(base,state);keep=set();items=[]
    if blocked:return {'blocked':blocked,'items':[],'sizes':{},'candidate_logical_bytes':0,'protected_backups':0}
    journal=_read(state/'native-update-journal.json',{}) or {}
    if journal.get('backup'):
        referenced=Path(journal['backup']);_real(referenced).relative_to(_real(state/'update-backups'));keep.add(_real(referenced))
    receipt=_read(state/'native-release-receipt.json',{}) or {}
    protected_cache=set(receipt.get('packages',[]))
    cache=state/'update-cache';cache_files=_files(cache,state)
    completed=sorted([p for p in cache_files if ZIP.fullmatch(p.name)],key=lambda p:p.stat().st_mtime,reverse=True)
    retained=completed[:4];cache_size=_bytes(completed);now=time.time()
    for file in reversed(completed):
        if file in retained or file.stem in protected_cache:continue
        size=file.stat().st_size
        if now-file.stat().st_mtime>RETENTION or cache_size>CACHE_BUDGET:
            items.append(('cache',file));cache_size-=size
    backup_base=state/'update-backups';backup_files=_files(backup_base,state)
    backups=[]
    if backup_base.is_dir():
        from windows_native.update_channel import name
        for folder in backup_base.iterdir():
            if not folder.is_dir() or not BACKUP.fullmatch(folder.name):continue
            files=_files(folder,state)
            # Legacy helpers have no marker. Accept only their exact dedicated
            # UUID/program layout and existing signed-program path grammar.
            if not files or any(p.name!='program' for p in folder.iterdir()) or any(p.relative_to(folder).parts[0]!='program' for p in files):continue
            try:
                for file in files:name(file.relative_to(folder/'program').as_posix())
            except ValueError:continue
            backups.append(folder)
    backups.sort(key=lambda p:p.stat().st_mtime,reverse=True);keep.update(_real(p) for p in backups[:2])
    for folder in backups[2:]:
        if _real(folder) not in keep and now-folder.stat().st_mtime>RETENTION:items.append(('backups',folder))
    guardian=state/'guardian/generations';guardian_files=_files(guardian,state)
    pointer=_read(state/'guardian/current.json',{}) or {};generation=pointer.get('generation','')
    if generation and not GENERATION.fullmatch(generation):raise ValueError('Invalid current guardian reference')
    active=_active(state)
    generations=[]
    if guardian.is_dir():
        for folder in guardian.iterdir():
            if not folder.is_dir() or not GENERATION.fullmatch(folder.name):continue
            marker=_read(folder/'manifest.json',{}) or {}
            if marker.get('product')!='watchtower-native-guardian' or marker.get('engine_api')!=1:continue
            generations.append(folder)
    generations.sort(key=lambda p:p.stat().st_mtime,reverse=True)
    for folder in generations[2:]:
        if folder.name==generation or any(_real(folder) in path.parents for path in active):continue
        if now-folder.stat().st_mtime>RETENTION:items.append(('guardian',folder))
    # A retired SDK may contain bytecode created by the embedded interpreter.
    # Preserve ANY unrecognized/custom file; never clear an active SDK directory.
    retired=base/'runtime/optional/python/playwright';sdk_cache=[]
    marker=base/'runtime/runtime-layout.json'
    if marker.is_file() and json.loads(marker.read_text(encoding='utf-8')).get('single_playwright_sdk') is True and retired.is_dir():
        _real(retired).relative_to(_real(base));candidate=list(retired.rglob('*'))
        if any(p.is_symlink() or getattr(p.lstat(),'st_file_attributes',0)&0x400 for p in [retired]+candidate):raise ValueError('Retired SDK contains a reparse point')
        sdk_cache=[p for p in candidate if p.is_file()]
        if sdk_cache and all(p.parent.name=='__pycache__' and re.fullmatch(r'.+\.cpython-\d+(?:\.opt-\d+)?\.pyc',p.name) for p in sdk_cache):
            if not any(_real(retired) in path.parents for path in active):items.append(('retired_sdk',retired))
    helpers=[]
    for folder in state.glob('.update-helper-*'):
        if not folder.is_dir() or not re.fullmatch(r'\.update-helper-[0-9a-f]{12}',folder.name):continue
        marker=_read(folder/'helper.json',{}) or {}
        if marker.get('product')!='watchtower-native-update-helper':continue
        helpers.extend(_files(folder,state))
        if not any(_real(folder) in path.parents for path in active) and now-marker.get('created',now)>RETENTION:items.append(('helpers',folder))
    sizes={'cache':_bytes(cache_files),'backups':_bytes(backup_files),'guardian':_bytes(guardian_files),'helpers':_bytes(helpers),'retired_sdk':_bytes(sdk_cache)}
    # Logical bytes may have additional hard links. Don't label them disk space.
    logical=sum(_bytes(_files(p,state)) if category!='retired_sdk' else _bytes(sdk_cache) for category,p in items)
    return {'blocked':blocked,'items':items,'sizes':sizes,'candidate_logical_bytes':logical,'protected_backups':len(keep)}


def summary():
    base=root()
    if base is None:return {'supported':False,'platform':'web'}
    try:
        value=plan(base)
        return {'supported':True,'platform':'windows','logical_bytes':value['sizes'],'cleanable_logical_bytes':0 if value['blocked'] else value['candidate_logical_bytes'],
                'blocked':value['blocked'],'retention_days':7,'cache_budget_bytes':CACHE_BUDGET,'protected_backups':value['protected_backups'],
                'disk_free_bytes':shutil.disk_usage(base).free,'physical_reclaim_estimate_not_claimed':True}
    except (OSError,ValueError,KeyError):return {'supported':True,'platform':'windows','blocked':'storage_unavailable','logical_bytes':{},'cleanable_logical_bytes':0}


def cleanup(base=None):
    from windows_native.update_channel import long_path
    base=Path(long_path(base or root()));state=base/'state'
    from windows_native import update_state
    try:
        with update_state.lock(base):
            value=plan(base)
            if value['blocked']:return {'cleaned':False,'blocked':value['blocked'],'removed_logical_bytes':0}
            before=shutil.disk_usage(base).free;removed=0;failures=0;count=0
            for category,path in value['items']:
                try:
                    if category=='retired_sdk':_real(path).relative_to(_real(base/'runtime'));size=_bytes([p for p in path.rglob('*') if p.is_file()])
                    else:_inside(path,state);size=_bytes(_files(path,state))
                    if path.is_dir():shutil.rmtree(path)
                    else:path.unlink()
                    removed+=size;count+=1
                except (OSError,ValueError):failures+=1
            outcome={'cleaned':True,'blocked':'','removed_objects':count,'removed_logical_bytes':removed,'failures':failures,
                     'disk_free_before':before,'disk_free_after':shutil.disk_usage(base).free,'ts':time.time(),
                     'version':(base/'app/version.txt').read_text(encoding='utf-8').strip()}
            update_state.write(state/'native-storage-maintenance.json',outcome)
            return outcome
    except update_state.UpdateBusyError:return {'cleaned':False,'blocked':'update_active','removed_logical_bytes':0}


def tick():
    base=root()
    if base is None:return
    last=_read(base/'state/native-storage-maintenance.json',{}) or {};version=(base/'app/version.txt').read_text(encoding='utf-8').strip()
    if last.get('version')==version and 0<=time.time()-last.get('ts',0)<86400:return
    cleanup(base)
