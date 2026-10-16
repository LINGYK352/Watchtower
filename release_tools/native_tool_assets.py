"""Required Windows program assets, reused by full installers and signed delta assembly."""
from pathlib import Path
import hashlib,json,shutil

UNPACKER={
    'tool':'KillWxapkg','version':'2.4.1','license':'MIT',
    'source':'https://github.com/Ackites/KillWxapkg/releases/download/v2.4.1/KillWxapkg_2.4.1_windows_amd64.exe',
    'sha256':'2df29b47d054f320b48ae0797547c201bb2d7e841ab243ffbbb0318e7319f1b0',
    'bytes':37702656,'member':'runtime/tools/KillWxapkg.exe',
}
SHARED_ASSETS={
    'watchtower-fiber-template.apk':{'bytes':4627316,'sha256':'95940e560a8e2645b14b98c687cf360818cbd43e65e945f63a9909db8251e718'},
    'Watchtower-Link-USB-template.zip':{'bytes':19840839,'sha256':'861cf12487af1484ad8aeaa3114dd242dc8299d1e6957716e5269c85ae8783d5'},
}

def digest(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):value.update(chunk)
    return value.hexdigest()

def install(program,asset_cache,shared_assets=None):
    """Write only declared program members; never inspect or copy account state."""
    program=Path(program).resolve();cache=Path(asset_cache).resolve()
    binary=cache/'KillWxapkg.exe';license_file=cache/'KillWxapkg-LICENSE.txt'
    if not binary.is_file() or binary.stat().st_size!=UNPACKER['bytes'] or digest(binary)!=UNPACKER['sha256']:
        raise RuntimeError('Required Windows unpacker is missing or differs from the pinned component')
    if not license_file.is_file():raise RuntimeError('Required unpacker license is missing')
    files={UNPACKER['member']:binary,'runtime/licenses/KillWxapkg-LICENSE.txt':license_file}
    for name,source in files.items():
        target=program/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.resolve().relative_to(program)
        temporary=target.with_name(target.name+'.incoming')
        shutil.copy2(source,temporary);temporary.replace(target)
    metadata=program/'runtime/tools/KillWxapkg-component.json'
    metadata.write_text(json.dumps(UNPACKER,indent=2)+'\n',encoding='utf-8')
    shared=Path(shared_assets).resolve() if shared_assets else cache
    for name,expected in SHARED_ASSETS.items():
        target=program/'app/dicts/app-link'/name
        if target.is_file() and target.stat().st_size==expected['bytes'] and digest(target)==expected['sha256']:continue
        source=shared/name
        if not source.is_file() or source.stat().st_size!=expected['bytes'] or digest(source)!=expected['sha256']:
            raise RuntimeError('Required shared APP template is missing or differs from its pinned build: '+name)
        target.parent.mkdir(parents=True,exist_ok=True);target.resolve().relative_to(program)
        temporary=target.with_name(target.name+'.incoming');shutil.copy2(source,temporary);temporary.replace(target)
    files.update({'app/dicts/app-link/'+name:shared/name for name in SHARED_ASSETS})
    validate(program)
    return [*files,'runtime/tools/KillWxapkg-component.json']

def validate(program):
    """Assembly must fail rather than release a UI whose core unpacker is absent."""
    program=Path(program);binary=program/UNPACKER['member']
    for member in ['runtime/tools/'+name+'.exe' for name in ('httpx','dnsx','katana','naabu','subfinder','nuclei','mihomo')]+[
            'runtime/mongodb/mongod.exe','runtime/service/NativeService.exe','runtime/python/python.exe']:
        file=program/member
        if not file.is_file():raise RuntimeError('Required Windows runtime component is absent: '+member)
        with file.open('rb') as stream:
            if stream.read(2)!=b'MZ':raise RuntimeError('Windows runtime component is not a native executable: '+member)
    if not (program/'runtime/npoc/launch.py').is_file():raise RuntimeError('Required NPoC launcher is absent')
    browser_metadata=program/'runtime/browser-component.json'
    if not browser_metadata.is_file():raise RuntimeError('Required browser component inventory is absent')
    metadata=json.loads(browser_metadata.read_text(encoding='utf-8'))
    browser=(program/'runtime'/metadata['chromium_executable']).resolve()
    browser.relative_to((program/'runtime').resolve())
    if not browser.is_file():raise RuntimeError('Required persistent browser executable is absent')
    if not binary.is_file() or binary.stat().st_size!=UNPACKER['bytes'] or digest(binary)!=UNPACKER['sha256']:
        raise RuntimeError('Windows program required component check failed: KillWxapkg')
    if not (program/'runtime/licenses/KillWxapkg-LICENSE.txt').is_file():
        raise RuntimeError('Windows unpacker license is absent')
    for name,expected in SHARED_ASSETS.items():
        file=program/'app/dicts/app-link'/name
        if not file.is_file() or file.stat().st_size!=expected['bytes'] or digest(file)!=expected['sha256']:
            raise RuntimeError('Windows required shared template check failed: '+name)
    return True

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--program',required=True);parser.add_argument('--asset-cache');parser.add_argument('--shared-assets')
    args=parser.parse_args()
    if args.asset_cache:members=install(args.program,args.asset_cache,args.shared_assets)
    else:validate(args.program);members=[UNPACKER['member']]
    print(json.dumps({'ok':True,'members':members,'user_state_copied':False}))
