"""Keep the GUI update controller and helper outside business rollback files."""
from pathlib import Path
import hashlib,json,os,shutil,sys,uuid,re
from windows_native import update_state
from windows_native.update_channel import long_path

def _version_key(version):
    # The persistent installer/controller must work without importing business code.
    match=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-(\d+))?',version or '')
    if not match:raise ValueError('Invalid guardian source version')
    return tuple(map(int,match.groups()[:3]))+((0,int(match[4])) if match[4] else (1,0))

def current(root):
    base=Path(root)/'state/guardian'
    try:
        pointer=update_state.read(Path(long_path(base/'current.json')))['generation']
        if not isinstance(pointer,str) or len(pointer)!=16 or any(c not in '0123456789abcdef' for c in pointer):return None
        home=base/'generations'/pointer
        data=update_state.read(Path(long_path(home/'manifest.json')))
        if data.get('product')!='watchtower-native-guardian' or data.get('engine_api')!=1:return None
        files=data.get('files',{})
        if not isinstance(files,dict) or not {'WatchtowerNative.exe','service/NativeService.exe'}<=set(files) or len(files)>20000:return None
        for name,digest in files.items():
            if name not in ('WatchtowerNative.exe','native-icon.ico') and not name.startswith('service/'):return None
            if '\\' in name or ':' in name or '..' in name.split('/'):return None
            path=Path(long_path(home/name))
            Path(str(path.resolve()).removeprefix('\\\\?\\')).relative_to(Path(str(home.resolve()).removeprefix('\\\\?\\')))
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:return None
        return home
    except (OSError,ValueError,KeyError):return None

def install(root):
    root=Path(root).resolve()
    if not getattr(sys,'frozen',False):return
    previous=current(root)
    version=(root/'app/version.txt').read_text().strip()
    if previous:
        metadata=update_state.read(Path(long_path(previous/'manifest.json')))
        if _version_key(version)<_version_key(metadata['source_version']):return
    from windows_native.update_channel import sha256
    service_root=Path(long_path(root/'runtime/service'))
    files={'service/'+p.relative_to(service_root).as_posix():sha256(p) for p in service_root.rglob('*') if p.is_file()}
    files['WatchtowerNative.exe']=sha256(Path(long_path(root/'WatchtowerNative.exe')))
    icon=root/'app/docker/frontend/native-icon.ico'
    if icon.is_file():files['native-icon.ico']=sha256(Path(long_path(icon)))
    if previous and metadata.get('files')==files:
        metadata['source_version']=version;update_state.write(Path(long_path(previous/'manifest.json')),metadata);return
    digest=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]
    base=root/'state/guardian';home=base/'generations'/digest;Path(long_path(home.parent)).mkdir(parents=True,exist_ok=True)
    if Path(long_path(home)).exists():
        # Do not reuse a same-name corrupt generation after a repair install.
        os.replace(long_path(home),long_path(home.with_name(home.name+'.damaged-'+uuid.uuid4().hex[:12])))
    def clone(source,target):
        if Path(target).exists():raise ValueError('Unverified guardian destination exists')
        os.link(source,target)
    if not Path(long_path(home)).exists():
        stage=home.parent/('.prepare-'+uuid.uuid4().hex)
        try:
            shutil.copytree(long_path(root/'runtime/service'),long_path(stage/'service'),copy_function=clone)
            shutil.copy2(long_path(root/'WatchtowerNative.exe'),long_path(stage/'WatchtowerNative.exe'))
            icon=root/'app/docker/frontend/native-icon.ico'
            if icon.is_file():shutil.copy2(long_path(icon),long_path(stage/'native-icon.ico'))
            io_stage=Path(long_path(stage))
            files={p.relative_to(io_stage).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in io_stage.rglob('*') if p.is_file()}
            update_state.write(Path(long_path(stage/'manifest.json')),{'product':'watchtower-native-guardian','engine_api':1,'files':files,'source_version':version})
            os.replace(long_path(stage),long_path(home))
        finally:
            if Path(long_path(stage)).exists():stage.resolve().relative_to(home.parent.resolve());shutil.rmtree(long_path(stage))
    metadata=update_state.read(Path(long_path(home/'manifest.json')));metadata['source_version']=version;update_state.write(Path(long_path(home/'manifest.json')),metadata)
    update_state.write(Path(long_path(base/'current.json')),{'generation':digest})
    from windows_native.shortcut import create
    create(root)

def service(root):
    home=current(root)
    return home/'service' if home else Path(root)/'runtime/service'

def gui(root):
    home=current(root)
    return home/'WatchtowerNative.exe' if home else Path(root)/'WatchtowerNative.exe'
