"""Signed file-level desktop updates with side-by-side versions and guarded activation."""
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PRODUCT = 'watchtower-windows-preview'
_VERSION = re.compile(r'^v\d+\.\d+\.\d+(?:-\d+)?-build\d+$')


class UpdateError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1048576), b''): value.update(data)
    return value.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    pending = path.with_name(path.name+'.pending-'+uuid.uuid4().hex)
    pending.write_bytes(canonical(value))
    os.replace(pending, path)


def safe_name(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise UpdateError('更新包包含非法文件路径')
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
        raise UpdateError('更新包文件越界')
    if path.parts[0].lower() in ('state', 'runtime', 'engine', 'versions'):
        raise UpdateError('更新包不能修改运行数据或 Linux 环境')
    if any(part.endswith((' ', '.')) for part in path.parts):
        raise UpdateError('Windows 文件路径不规范')
    return name


def active(root):
    value = json.loads((Path(root)/'active.json').read_text(encoding='utf-8'))
    if not _VERSION.fullmatch(value.get('version', '')):
        raise UpdateError('当前版本记录无效')
    return value


def remove_stage(path, root):
    resolved=Path(path).resolve()
    resolved.relative_to((Path(root)/'versions').resolve())
    if resolved.exists():shutil.rmtree(resolved)


@contextmanager
def update_lock(root):
    lock = Path(root)/'state/desktop-update.lock'
    lock.parent.mkdir(exist_ok=True)
    with lock.open('a+b') as handle:
        handle.write(b'0'); handle.flush(); handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise UpdateError('已有 Windows 更新正在进行') from exc
        try: yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_UN)


def prepare(root, bundle, public_key):
    root = Path(root).resolve()
    before = active(root)
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise UpdateError('更新包包含重复文件')
        manifest = json.loads(archive.read('manifest.json'))
        signature = base64.b64decode(archive.read('manifest.sig'), validate=True)
        try: Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical(manifest))
        except Exception as exc: raise UpdateError('更新包签名无效') from exc
        if manifest.get('schema') != 1 or manifest.get('product') != PRODUCT:
            raise UpdateError('更新包产品或协议不匹配')
        if manifest.get('base') != before['version']:
            raise UpdateError('更新包基线不匹配，需使用对应版本更新包')
        target = manifest.get('target', '')
        if not _VERSION.fullmatch(target) or target == before['version']:
            raise UpdateError('更新包目标版本无效')
        complete, changes = manifest.get('files', {}), manifest.get('changes', {})
        if not isinstance(complete, dict) or not complete or not isinstance(changes, dict):
            raise UpdateError('更新包清单不完整')
        for name, sha in complete.items():
            safe_name(name)
            if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise UpdateError('文件摘要无效')
        if set(changes)-set(complete):raise UpdateError('差异文件不在目标清单内')
        expected={'manifest.json','manifest.sig'} | {'files/'+safe_name(n) for n in changes}
        if set(names) != expected:raise UpdateError('更新包包含未声明文件')
        current = root/'versions'/before['version']
        target_path = root/'versions'/target
        if target_path.exists():
            journal_path=root/'state/desktop-update.json'
            previous=json.loads(journal_path.read_text()) if journal_path.exists() else {}
            if previous.get('base')!=before['version'] or previous.get('target')!=target or previous.get('phase') not in ('prepared','error'):
                raise UpdateError('目标版本目录已存在')
            target_path.resolve().relative_to((root/'versions').resolve())
            os.replace(target_path,target_path.with_name('.recovery-'+uuid.uuid4().hex))
        staging = root/'versions'/('.stage-'+uuid.uuid4().hex)
        try:
            if any(p.is_symlink() for p in current.rglob('*')):raise UpdateError('当前版本含不允许的链接')
            shutil.copytree(current, staging)
            for old in staging.rglob('*'):
                if old.is_file() and old.relative_to(staging).as_posix() not in complete:old.unlink()
            for name, expected_sha in changes.items():
                if expected_sha != complete[name]:raise UpdateError('差异摘要与目标清单不一致')
                info=archive.getinfo('files/'+name)
                if (info.external_attr >> 16) & 0o170000 == 0o120000:raise UpdateError('更新包禁止符号链接')
                dest=staging/name;dest.parent.mkdir(parents=True,exist_ok=True)
                with archive.open(info) as source, dest.open('wb') as output:shutil.copyfileobj(source,output)
            for name, sha in complete.items():
                if digest(staging/name) != sha:raise UpdateError('目标文件校验失败：'+name)
            return before, manifest, staging, target_path
        except Exception:
            remove_stage(staging,root)
            raise


def apply(root, bundle, public_key, health_check, prepared=None):
    root = Path(root).resolve()
    with update_lock(root):
        before, manifest, staging, target = prepare(root,bundle,public_key)
        journal = root/'state/desktop-update.json'
        atomic_json(journal, {'phase':'prepared','base':before['version'],'target':manifest['target']})
        switched=False
        try:
            if prepared:prepared(manifest)
            os.replace(staging,target)
            if not health_check(target,manifest):raise UpdateError('新 Windows 版本启动检查失败')
            # New executable imports are checked before the small active pointer is changed.
            if active(root) != before:raise UpdateError('更新期间当前版本被改变')
            atomic_json(root/'active.json', {'version':manifest['target']})
            switched=True
            atomic_json(journal, {'phase':'done','base':before['version'],'target':manifest['target']})
            return manifest
        except Exception as exc:
            remove_stage(staging,root)
            if switched:atomic_json(root/'active.json',before)
            if target.exists():
                target.resolve().relative_to((root/'versions').resolve())
                os.replace(target,target.with_name('.failed-'+uuid.uuid4().hex))
            # The old version and active pointer remain usable. Keep failed target for diagnosis.
            atomic_json(journal, {'phase':'error','base':before['version'],'target':manifest['target'],
                                  'error':str(exc)[:400]})
            raise
