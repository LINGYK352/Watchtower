"""First installation consent is durable, independent of build and legal display versions.

Keep the original accepted_version/accepted_at as evidence. A valid historical
assent remains accepted across upgrades and rollback. Unknown storage is never
treated as unsigned. Workers read the same configuration-owned file fresh.
"""
from __future__ import annotations
import json, os, tempfile, time
from contextlib import contextmanager
from typing import Any

TERMS_VERSION = "v3"
MARKER = ".disclaimer_accepted"

def _marker_candidates() -> list[str]:
    from sentinel_platform.core.config import _config_candidates, _first_existing
    configs = [p for p in _config_candidates() if p]
    selected = _first_existing(configs) or next((p for p in configs if not p.endswith(".example")), "")
    # This is the same choice as load_config(), not an arbitrary first writable
    # working directory. Native config lives in the installation's state folder.
    canonical = os.path.join(os.path.dirname(selected), MARKER) if selected else os.path.join(os.getcwd(), "config", MARKER)
    paths = [canonical] + [os.path.join(os.path.dirname(p), MARKER) for p in configs]
    # An unqualified global /tmp marker can belong to a different install.
    # Only an application's own former working root is an attributable legacy path.
    cwd = os.path.abspath(os.getcwd())
    app_roots = {os.path.abspath(os.path.dirname(os.path.dirname(p))) for p in configs
                 if os.path.basename(os.path.dirname(p)) in {"config", "state"}}
    if cwd in app_roots: paths.append(os.path.join(cwd, MARKER))
    result, seen = [], set()
    for path in paths:
        path = os.path.abspath(path)
        key = os.path.normcase(path)
        if key not in seen:
            seen.add(key); result.append(path)
    return result

def _read_record(path: str):
    try:
        if os.name == "nt":
            from windows_native.update_state import open_read
            handle = open_read(path)
        else:
            handle = open(path, "r", encoding="utf-8")
        with handle:
            raw = handle.read(16385)
        if len(raw) > 16384:
            raise ValueError("Oversized assent record")
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("accepted"), bool):
            raise ValueError("Invalid assent record")
        if not data["accepted"]:
            return None, False
        version = data.get("accepted_version", "")
        at = data.get("accepted_at", "")
        if not isinstance(version, str) or len(version) > 32 or not isinstance(at, str) or len(at) > 80:
            raise ValueError("Invalid assent metadata")
        return {"accepted": True, "accepted_version": version, "accepted_at": at}, False
    except FileNotFoundError:
        return None, False
    except (OSError, ValueError, UnicodeError):
        return None, True

def _write_record(path: str, payload: dict):
    if os.name == "nt":
        # Reuse the native updater's tested FILE_SHARE_DELETE snapshot and
        # atomic replacement; ordinary CRT readers can otherwise block rename.
        from windows_native.update_state import write
        write(path, payload)
        return
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=MARKER+".", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

@contextmanager
def _record_lock(path: str):
    """An installation file lock also serializes separate workers/processes."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".lock", "a+b") as handle:
        if os.name == "nt":
            import msvcrt
            handle.seek(0, os.SEEK_END)
            if not handle.tell(): handle.write(b"0"); handle.flush()
            deadline = time.monotonic() + 5
            while True:
                try:
                    handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(.05)
            try: yield
            finally:
                handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(handle, fcntl.LOCK_UN)

def _status(record=None, state="unaccepted", persisted=False) -> dict[str, Any]:
    return {**(record or {"accepted": False, "accepted_version": "", "accepted_at": ""}),
            "status": state, "current_version": TERMS_VERSION, "persisted": persisted}

def get_status() -> dict[str, Any]:
    paths = _marker_candidates()
    canonical, unreadable = _read_record(paths[0])
    if canonical:
        return _status(canonical, "accepted", True)
    records = []
    for path in paths[1:]:
        record, failed = _read_record(path)
        unreadable = unreadable or failed
        if record: records.append(record)
    if records:
        record = min(records, key=lambda r: r["accepted_at"] or "9999")
        # Migration never re-signs, upgrades the signed legal version, resets
        # the original timestamp, or overwrites another worker's first assent.
        try:
            with _record_lock(paths[0]):
                fresh, failed = _read_record(paths[0])
                if fresh: return _status(fresh, "accepted", True)
                if not failed: _write_record(paths[0], record)
        except (OSError, ValueError):
            pass  # A valid, durable legacy record is still real assent.
        return _status(record, "accepted", True)
    return _status(state="unavailable" if unreadable else "unaccepted")

def accept(version: str = "") -> dict[str, Any]:
    status = get_status()
    if status["status"] in {"accepted", "unavailable"}:
        return status
    if version != TERMS_VERSION:
        raise ValueError("Unsupported legal version")
    path = _marker_candidates()[0]
    try:
        with _record_lock(path):
            # Fresh read after the OS lock: a concurrent click cannot replace
            # the first signature, even across gunicorn workers.
            record, failed = _read_record(path)
            if record: return _status(record, "accepted", True)
            if failed: return _status(state="unavailable")
            payload = {"accepted": True, "accepted_version": version,
                       "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            _write_record(path, payload)
            return _status(payload, "accepted", True)
    except (OSError, ValueError):
        return _status(state="unavailable")
