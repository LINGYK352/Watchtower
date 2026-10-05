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
    digest=hashlib.sha256(str(session_id).encode()).hexdigest()
    path=Path(root)/(digest[:24] if os.name=='nt' else digest)
    if os.name=='nt':
        # Chromium writes additional temporary names and nested cache paths.
        # Long profiles can save Cookies but silently omit Local State (the
        # encryption key), so encrypted login cookies cannot survive reopening.
        if len(str(path.absolute()).encode('utf-16-le'))//2>180:
            raise RuntimeError('Windows browser profile path is too long; choose a shorter installation folder')
        legacy=Path(root)/digest
        if legacy.exists() and not path.exists():
            legacy.resolve().relative_to(Path(root).resolve())
            if legacy.is_symlink() or getattr(legacy.lstat(),'st_file_attributes',0)&0x400:raise RuntimeError('Browser profile may not be a link')
            legacy.rename(path)
        if path.exists():
            path.resolve().relative_to(Path(root).resolve())
            if path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400:raise RuntimeError('Browser profile may not be a link')
    path.mkdir(parents=True,exist_ok=True)
    return str(path)
