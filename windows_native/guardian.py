"""Keep the GUI update controller and helper outside business rollback files."""
from pathlib import Path
import hashlib,json,os,shutil,sys,uuid
from windows_native import update_state

def current(root):
    base=Path(root)/'state/guardian'
    try:
        pointer=update_state.read(base/'current.json')['generation']
        if not isinstance(pointer,str) or len(pointer)!=16 or any(c not in '0123456789abcdef' for c in pointer):return None
        home=base/'generations'/pointer
        data=update_state.read(home/'manifest.json')
        if data.get('product')!='watchtower-native-guardian' or data.get('engine_api')!=1:return None
        for name in ['WatchtowerNative.exe','service/NativeService.exe']:
            path=home/name
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=data['files'][name]:return None
        return home
    except (OSError,ValueError,KeyError):return None

def install(root):
    root=Path(root).resolve()
    if not getattr(sys,'frozen',False):return
    previous=current(root)
    version=(root/'app/version.txt').read_text().strip()
    if previous:
        from sentinel_platform.core.update_policy import key
        metadata=update_state.read(previous/'manifest.json')
        if key(version)<=key(metadata['source_version']):return
    fingerprint=hashlib.sha256((root/'WatchtowerNative.exe').read_bytes()).digest()+hashlib.sha256((root/'runtime/service/NativeService.exe').read_bytes()).digest()
    digest=hashlib.sha256(fingerprint).hexdigest()[:16]
    base=root/'state/guardian';home=base/'generations'/digest;home.parent.mkdir(parents=True,exist_ok=True)
    def clone(source,target):
        if Path(target).exists():raise ValueError('Unverified guardian destination exists')
        os.link(source,target)
    if not home.exists():
        stage=home.parent/('.prepare-'+uuid.uuid4().hex)
        try:
            shutil.copytree(root/'runtime/service',stage/'service',copy_function=clone)
            shutil.copy2(root/'WatchtowerNative.exe',stage/'WatchtowerNative.exe')
            icon=root/'app/docker/frontend/native-icon.ico'
            if icon.is_file():shutil.copy2(icon,stage/'native-icon.ico')
            files={p.relative_to(stage).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.rglob('*') if p.is_file()}
            update_state.write(stage/'manifest.json',{'product':'watchtower-native-guardian','engine_api':1,'files':files,'source_version':version})
            os.replace(stage,home)
        finally:
            if stage.exists():stage.resolve().relative_to(home.parent.resolve());shutil.rmtree(stage)
    metadata=update_state.read(home/'manifest.json');metadata['source_version']=version;update_state.write(home/'manifest.json',metadata)
    update_state.write(base/'current.json',{'generation':digest})
    from windows_native.shortcut import create
    create(root)

def service(root):
    home=current(root)
    return home/'service' if home else Path(root)/'runtime/service'

def gui(root):
    home=current(root)
    return home/'WatchtowerNative.exe' if home else Path(root)/'WatchtowerNative.exe'
