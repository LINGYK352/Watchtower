"""Self-reported product provenance is separate from membership authentication."""
from pathlib import Path
import os,platform
from .paths import project_root

def describe(instance_id):
    root=Path(project_root())
    try:version=(root/'version.txt').read_text(encoding='utf-8').strip()
    except OSError:version='unknown'
    native=bool(os.environ.get('SENTINEL_NATIVE_ROOT'))
    if not native:
        try:
            from .deployment_profile import load
            native=(load(root) or {}).get('runtime_abi','').startswith('windows-')
        except (OSError,ValueError):pass
    return {'instance_id':instance_id,'product':'win' if native else 'web','platform':platform.system().lower(),
            'version':version,'name':'Watchtower '+('Windows' if native else 'Web')}
