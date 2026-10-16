"""Repair only the stable launcher from the verified active version directory."""
from pathlib import Path
import json,os,shutil,time,uuid
from windows_preview.signed_download import sha256

def ensure(root,directory):
    root=Path(root);directory=Path(directory)
    meta=json.loads((directory/'desktop.json').read_text(encoding='utf-8'));expected=meta.get('entry_sha256')
    if not expected:return
    source=directory/'WatchtowerEntry.exe';target=root/'Watchtower.exe'
    if sha256(source)!=expected:raise ValueError('入口程序摘要无效')
    if target.is_file() and sha256(target)==expected:return
    pending=root/('.entry-pending-'+uuid.uuid4().hex+'.exe');shutil.copy2(source,pending)
    try:
        for _ in range(60):
            try:os.replace(pending,target);return
            except PermissionError:time.sleep(.25)
        raise RuntimeError('入口程序仍被占用；重新打开程序后将继续修复')
    finally:
        if pending.exists():pending.unlink()
