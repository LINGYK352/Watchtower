"""Repair stale image-era changelogs without changing the legacy manifest protocol."""
from pathlib import Path
import json,re,os,tempfile

def _version(value):
    match=re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:-(\d+))?',str(value or ''))
    return (*map(int,match.groups()[:3]),int(match[4]) if match[4] else float('inf')) if match else None

def _read_version(root):
    try:return (Path(root)/'version.txt').read_text(encoding='utf-8').strip()
    except OSError:return ''

def _valid(rows):
    return [row for row in rows if isinstance(row,dict) and _version(row.get('ver')) and isinstance(row.get('summary'),str)] if isinstance(rows,list) else []

def current(root,fetch):
    root=Path(root);version=_read_version(root);target=_version(version);path=root/'changelog.json'
    try:local=_valid(json.loads(path.read_text(encoding='utf-8')))
    except (OSError,ValueError):local=[]
    def compatible(rows):return [row for row in rows if not target or _version(row['ver'])<=target]
    if not version:return local
    if any(row['ver']==version for row in local):return compatible(local)
    try:remote=_valid(fetch())
    except Exception:remote=[]
    selected=compatible(remote)
    if not any(row['ver']==version for row in selected):return compatible(local)
    # Shared file, atomic replace. A concurrent update/rollback supersedes this read.
    temporary=None
    try:
        if _read_version(root)==version:
            with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=root,prefix='.changelog-',suffix='.tmp',delete=False) as handle:
                temporary=handle.name;json.dump(selected,handle,ensure_ascii=False,indent=2)
            if _read_version(root)==version:os.replace(temporary,path);temporary=None
    except OSError:pass
    finally:
        if temporary:
            try:os.unlink(temporary)
            except OSError:pass
    return selected
