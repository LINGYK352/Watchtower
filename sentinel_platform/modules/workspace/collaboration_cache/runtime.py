"""Use the signed native baseline's existing CPython stdlib, without extra installs."""
import importlib
import os
import sys
from pathlib import Path

_dll_handles = []


def sqlite_module():
    try:
        return importlib.import_module('sqlite3')
    except ModuleNotFoundError as error:
        if error.name not in ('sqlite3', '_sqlite3') or os.name != 'nt' or not getattr(sys, 'frozen', False):
            raise
    # NativeService.exe lives at runtime/service; the same311 ABI is already
    # shipped at runtime/python for tools. No development absolute path exists.
    runtime = Path(sys.executable).resolve().parent.parent / 'python'
    archive = runtime / ('python%d%d.zip' % sys.version_info[:2])
    if not archive.is_file() or not (runtime / '_sqlite3.pyd').is_file() or not (runtime / 'sqlite3.dll').is_file():
        raise RuntimeError('Native baseline standard SQLite runtime is unavailable; repair the existing runtime')
    if hasattr(os, 'add_dll_directory'):
        _dll_handles.append(os.add_dll_directory(str(runtime)))
    for entry in (str(runtime), str(archive)):
        if entry not in sys.path:
            sys.path.append(entry)
    return importlib.import_module('sqlite3')
