"""Workspace control/sync leaf. Runtime secrets remain outside distributed code."""
from __future__ import annotations

import os
from pathlib import Path
import threading
import time

from .control import ControlKeys
from .pairing import Pairings
from .security import LocalSecrets
from .snapshots import Snapshots
from .transfers import Transfers
from .listener import PeerListener


class ControlSyncService:
    def __init__(self, repo, directory=None, clock=time.time, send=None):
        from sentinel_platform.core.paths import project_root
        directory = directory or os.environ.get("WATCHTOWER_CONTROL_SYNC_DIR") or (Path(project_root()) / "shared" / "control-sync")
        self.repo = repo
        self.directory = Path(directory)
        self.secrets = LocalSecrets(self.directory)
        self.control = ControlKeys(repo, clock)
        options = {"send": send} if send else {}
        self.pairing = Pairings(repo, self.secrets, clock, **options)
        self.snapshots = Snapshots(repo, self.directory, clock)
        self.snapshots.recover()
        self.transfers = Transfers(repo, self.pairing, self.snapshots, self.directory, clock)
        self.listener = PeerListener(repo)


_service = None
_lock = threading.Lock()


def get_service():
    global _service
    if _service is None:
        with _lock:
            if _service is None:
                from sentinel_platform.core import get_repo
                _service = ControlSyncService(get_repo())
    return _service
