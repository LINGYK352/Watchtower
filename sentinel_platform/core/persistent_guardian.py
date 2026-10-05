"""Install a signed updater outside rollback-owned files, including cold boots.

The additive Compose override is not a release-owned file. Its read-only .pth
mount survives a business rollback AND container recreation. Only the first
installation needs service recreation; later source hops continue using HUP.
"""
from pathlib import Path
import base64,hashlib,json,os,shutil,sysconfig
from sentinel_platform.core.update_bundle import PUBLIC_KEY,canonical
from sentinel_platform.core.update_commit import write

def verify(source):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    envelope=json.loads((source/'manifest.json').read_text(encoding='utf-8'));data=envelope['descriptor']
    Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY)).verify(base64.b64decode(envelope['signature'],validate=True),canonical(data))
    if data.get('schema')!=1 or data.get('product')!='watchtower-persistent-web-guardian' or data.get('engine_api')!=1:raise ValueError('Invalid persistent guardian manifest')
    for name,digest in data['files'].items():
        if name.startswith('/') or '..' in name.split('/') or '\\' in name:raise ValueError('Invalid guardian path')
        path=source/name;path.resolve().relative_to(source.resolve())
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Persistent guardian source digest mismatch')
    return data

def install(root):
    root=Path(root).resolve();source=root/'sentinel_platform/core/guardian_assets'
    if not (source/'manifest.json').is_file():return {'installed':False,'reason':'signed_guardian_not_prepared'}
    data=verify(source);home=root/'.update_stage/guardian';state=home/'installation.json'
    generation=hashlib.sha256(canonical(data['files'])).hexdigest()[:16]
    engine=home/'generations'/generation
    if state.exists():
        previous=json.loads(state.read_text(encoding='utf-8'))
        from sentinel_platform.core.update_policy import key
        # A business rollback must never downgrade the independent updater.
        if previous.get('installed') and key(data['version'])<key(previous['source_version']):return previous
        if previous.get('generation')==generation and ('guardian_runtime.py' not in data['files'] or previous.get('background_api')==1):return previous
    engine.mkdir(parents=True,exist_ok=True)
    for name in data['files']:
        target=engine/name;target.parent.mkdir(parents=True,exist_ok=True)
        temporary=target.with_name(target.name+'.incoming');shutil.copy2(source/name,temporary);os.replace(temporary,target)
    shutil.copy2(source/'manifest.json',engine/'manifest.json')
    bootstrap=home/'bootstrap';bootstrap.mkdir(exist_ok=True)
    shutil.copy2(source/'guardian_boot.py',bootstrap/'guardian_boot.py')
    if 'guardian_runtime.py' in data['files']:
        shutil.copy2(source/'guardian_runtime.py',bootstrap/'guardian_runtime.py')
    write(home/'current.json',{'generation':generation})
    site=home/'site';site.mkdir(exist_ok=True)
    # Runtime layout is the container mount contract, not a developer path.
    mount_root='/opt/sentinel/current'
    line="import sys;sys.path.insert(0,"+repr(mount_root+'/.update_stage/guardian/bootstrap')+");import guardian_boot\n"
    (site/'watchtower_guardian.pth').write_text(line,encoding='utf-8')
    import yaml
    override=root/'docker/docker-compose.override.yml'
    value=yaml.safe_load(override.read_text(encoding='utf-8')) if override.exists() else {}
    if value is None:value={}
    if not isinstance(value,dict):raise ValueError('Existing Compose override is not a mapping')
    if override.exists():shutil.copy2(override,home/'original-compose.override.yml')
    services=value.setdefault('services',{})
    purelib=sysconfig.get_path('purelib');target=purelib+'/watchtower_guardian.pth'
    binding='../.update_stage/guardian/site/watchtower_guardian.pth:'+target+':ro'
    for role in ('web','worker','scheduler'):
        service=services.setdefault(role,{})
        volumes=service.setdefault('volumes',[])
        if not isinstance(volumes,list):raise ValueError('Existing Compose volumes are not a sequence')
        if any(target in str(item) and item!=binding for item in volumes):raise ValueError('Existing guardian mount conflicts with this runtime')
        if binding not in volumes:volumes.append(binding)
        if role in ('worker','scheduler') and 'guardian_runtime.py' in data['files']:
            entry=['python',mount_root+'/.update_stage/guardian/bootstrap/guardian_runtime.py',role]
            old=service.get('entrypoint')
            if old and old!=entry:raise ValueError('Custom background entrypoint requires an explicit process adapter')
            service['entrypoint']=entry
    temporary=override.with_name(override.name+'.guardian-incoming');temporary.write_text(yaml.safe_dump(value,sort_keys=False),encoding='utf-8');os.replace(temporary,override)
    result={'installed':True,'engine_api':1,'generation':generation,'manifest_sha':hashlib.sha256((source/'manifest.json').read_bytes()).hexdigest(),
            'source_version':data['version'],'requires_recreate':True,'cold_boot_mount':target,
            'background_api':1 if 'guardian_runtime.py' in data['files'] else 0}
    write(state,result);return result

def ensure(root):
    """Boot entry; a recreated container reads the persistent mount immediately."""
    if os.name!='posix' or not os.path.exists('/var/run/docker.sock'):return
    # A verified newer carrier may upgrade the installer itself. Otherwise
    # pinning this module would prevent future guardian migration logic.
    source=Path(root)/'sentinel_platform/core/guardian_assets'
    if (source/'manifest.json').is_file():
        data=verify(source);candidate=source/'core/persistent_guardian.py'
        state=Path(root)/'.update_stage/guardian/installation.json'
        from sentinel_platform.core.update_policy import key
        allowed=not state.exists() or key(data['version'])>=key(json.loads(state.read_text())['source_version'])
        if allowed and candidate.is_file() and hashlib.sha256(candidate.read_bytes()).digest()!=hashlib.sha256(Path(__file__).read_bytes()).digest():
            import importlib.util
            spec=importlib.util.spec_from_file_location('watchtower_verified_guardian_installer',candidate)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.ensure(root)
    import fcntl
    folder=Path(root)/'.update_stage/guardian';folder.mkdir(parents=True,exist_ok=True)
    with (folder/'.install.lock').open('a+b') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:return
        result=install(root)
        if not result.get('installed') or not result.get('requires_recreate'):return
        if os.environ.get('SENTINEL_GUARDIAN_GENERATION')==result['generation']:
            result['requires_recreate']=False;write(folder/'installation.json',result);return
        from sentinel_platform.modules.about._updater import _recreate_containers
        ok,message=_recreate_containers(str(Path(root)/'docker'))
        if not ok:raise RuntimeError('Persistent guardian startup migration failed: '+message)
