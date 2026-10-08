"""Let a signed newer control revision replace an old pinned installer.

Business171 can repair a172 controller without lowering the independent control
revision. The old installer's signature verification remains the trust anchor.
"""
from pathlib import Path
import hashlib,importlib.util,json,os,re

def ensure(root):
    if os.name!='posix' or not os.path.exists('/var/run/docker.sock'):return
    root=Path(root).resolve()
    from sentinel_platform.core import persistent_guardian as pinned
    source=root/'sentinel_platform/core/guardian_assets'
    if not (source/'manifest.json').is_file():return pinned.ensure(root)
    candidate=pinned.verify(source)
    value=candidate.get('engine_revision',1)
    if type(value) is not int or not 1<=value<=10000:raise ValueError('Invalid signed control revision')
    state=root/'.update_stage/guardian/installation.json';old_revision=0
    if state.is_file():
        pointer=json.loads(state.read_text(encoding='utf-8')).get('generation','')
        if not isinstance(pointer,str) or not re.fullmatch('[0-9a-f]{16}',pointer):raise ValueError('Invalid installed control pointer')
        previous=pinned.verify(state.parent/'generations'/pointer)
        old_revision=previous.get('engine_revision',1)
        if type(old_revision) is not int:raise ValueError('Invalid installed control revision')
    path=source/'core/persistent_guardian.py'
    if value>old_revision and 'core/persistent_guardian.py' in candidate['files']:
        # Verification is above; only a member declared by the signed descriptor runs.
        if hashlib.sha256(path.read_bytes()).hexdigest()!=candidate['files']['core/persistent_guardian.py']:raise ValueError('Changed verified installer')
        spec=importlib.util.spec_from_file_location('watchtower_signed_revision_installer',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module.ensure(root)
    return pinned.ensure(root)
