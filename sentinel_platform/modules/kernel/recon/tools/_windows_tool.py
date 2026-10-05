"""Resolve only runnable native tools; old Linux configuration is not a tool."""
from pathlib import Path
import os,shutil

def executable(tool,configured=''):
    root=Path(os.environ.get('SENTINEL_NATIVE_ROOT',''))
    candidates=[shutil.which(configured) if configured else None,configured,
                root/'runtime/tools'/tool/(tool+'.exe'),root/'runtime/tools'/(tool+'.exe'),shutil.which(tool+'.exe')]
    for value in candidates:
        if not value:continue
        path=Path(value)
        if path.is_file():
            with path.open('rb') as source:
                if source.read(2)==b'MZ':return str(path)
    return ''
