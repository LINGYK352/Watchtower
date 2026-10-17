"""The immutable SDK carries its own copy of the verified TLS contract.

Loading it from assets keeps updates working after rolling the business core
back to a version that predates distribution_tls.py. No runtime source exec or
configuration files are fetched from the network.
"""
from pathlib import Path
import importlib.util
_path=Path(__file__).with_name('assets')/'distribution_tls.py'
_spec=importlib.util.spec_from_file_location('_watchtower_bundled_distribution_tls',_path)
_module=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_module)

class VerifiedOpener:
    def __init__(self,*handlers):self.handlers=handlers
    def open(self,*args,**kwargs):
        return _module.verified_opener(*self.handlers,cafile=Path(__file__).with_name('assets')/'ca-bundle.pem').open(*args,**kwargs)
