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
    root=Path(root);version=_read_version(root);target=_version(version);path=root/'sentinel_platform/release/changelog.json'
    if not path.is_file():path=root/'changelog.json'
    try:local=_valid(json.loads(path.read_text(encoding='utf-8')))
    except (OSError,ValueError):local=[]
    def compatible(rows):return [row for row in rows if not target or _version(row['ver'])<=target]
    if not version:return local
    if any(row['ver']==version for row in local):return compatible(local)
    return compatible(local)
