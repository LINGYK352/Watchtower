"""Browser deployment paths shared by reconnaissance and AI browser adapters."""
import os
from pathlib import Path

def executable():
    bundled=os.environ.get('SENTINEL_BROWSER_EXECUTABLE','')
    if bundled:
        if not Path(bundled).is_file():raise RuntimeError('Bundled browser component is missing')
        return bundled
    from sentinel_platform.core import get_config
    return str(get_config().section('BROWSER','EXECUTABLE_PATH',default='') or '')

def launch_args(default):
    return ['--disable-gpu','--no-first-run'] if os.name=='nt' else list(default)

def profile_directory(session_id):
    root=os.environ.get('SENTINEL_BROWSER_PROFILES','')
    if not root:return None
    import hashlib
    path=Path(root)/hashlib.sha256(str(session_id).encode()).hexdigest()
    path.mkdir(parents=True,exist_ok=True)
    return str(path)
