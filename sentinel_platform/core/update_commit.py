"""Durable source update journal, shared by all Web update worker processes."""
from pathlib import Path
import json
import os
import shutil
import uuid
import hashlib

def sha256(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):result.update(block)
    return result.hexdigest()

def inside(root,name):
    if not name or name.startswith(('/','\\')) or '\\' in name or ':' in name or any(p in ('','.','..') for p in name.split('/')):raise ValueError('Unsafe transaction path')
    root=Path(root).absolute();path=root/name;path.resolve().relative_to(root.resolve())
    for parent in [path,*path.parents]:
        if parent==root:break
        if parent.is_symlink() or parent.exists() and getattr(parent.lstat(),'st_file_attributes',0)&0x400:raise ValueError('Transaction traverses a link')
    return path


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as output:
            json.dump(data, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if os.name != 'nt':
            fd = os.open(path.parent, os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def restore(root, journal):
    backup = inside(root, journal['backup'])
    if not journal['backup'].startswith('.update_backup/'):
        raise ValueError('Invalid update recovery backup')
    for name, existed in reversed(list(journal['operations'].items())):
        target = inside(root, name)
        if existed:
            saved = inside(backup, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(target.name + '.restore-' + uuid.uuid4().hex)
            shutil.copy2(saved, temporary)
            os.replace(temporary, target)
        else:
            target.unlink(missing_ok=True)
    receipt=inside(root,'.update_stage/.release_receipt.json')
    if journal.get('old_receipt') is not None:write(receipt,journal['old_receipt'])
    else:receipt.unlink(missing_ok=True)


def recover(root):
    path = inside(root, '.update_stage/.commit.json')
    if not path.exists():return False
    journal = json.loads(path.read_text(encoding='utf-8'))
    if journal['phase'] != 'committing':return False
    restore(root, journal)
    journal['phase'] = 'recovered'
    write(path, journal)
    return True


def commit(root, staged, removed, backup, target_version, inventory=None):
    """Call under the installation's OS lock. Back up before any mutation."""
    root, backup = Path(root).resolve(), Path(backup).resolve()
    backup.relative_to(root / '.update_backup')
    protected = []
    deletions = []
    for name, expected in removed.items():
        path = inside(root, name)
        if path.is_file():
            if expected and sha256(path) != expected:
                protected.append(name)
            else:
                deletions.append(name)
    operations = {}
    for name in [*staged, *deletions]:
        path = inside(root, name)
        operations[name] = path.is_file()
        if path.is_file():
            saved = inside(backup, name)
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, saved)
            with saved.open('r+b') as handle:os.fsync(handle.fileno())
    receipt=inside(root,'.update_stage/.release_receipt.json')
    old_receipt=json.loads(receipt.read_text()) if receipt.exists() else None
    journal = {'phase': 'committing', 'backup': backup.relative_to(root).as_posix(),'old_receipt':old_receipt,
               'target': target_version, 'operations': operations}
    journal_path = inside(root, '.update_stage/.commit.json')
    write(journal_path, journal)
    try:
        for name in sorted(staged, key=lambda n: (n == 'version.txt', n == 'docker/frontend/index.html', n)):
            path = inside(root, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged[name], path)
            if '/bin/' in name and not name.endswith(('.py', '.txt', '.json', '.yaml', '.yml')):
                os.chmod(path, 0o755)
        for name in deletions:inside(root, name).unlink()
        if inside(root, 'version.txt').read_text(encoding='utf-8').strip() != target_version:
            raise ValueError('Committed version marker differs from target')
        if inventory is not None:write(receipt,{'version':target_version,'files':inventory})
        journal['phase'] = 'done'
        write(journal_path, journal)
    except Exception:
        restore(root, journal)
        journal['phase'] = 'rolled_back'
        write(journal_path, journal)
        raise
    return deletions, protected
