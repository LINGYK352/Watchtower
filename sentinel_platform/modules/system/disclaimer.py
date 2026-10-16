"""Installation assent to a substantive legal version, independent of software builds.

The active configuration directory owns one durable record. Legacy paths are
read for migration only; an unavailable record is not an unsigned installation.
Every worker reads fresh. No ROLE, database or browser-cache authority.
"""
from __future__ import annotations
import json, os, re, tempfile, time
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

def _status(record=None, state="unaccepted", persisted=False) -> dict[str, Any]:
    return {**(record or {"accepted": False, "accepted_version": "", "accepted_at": ""}),
            "status": state, "current_version": TERMS_VERSION, "persisted": persisted}

def get_status() -> dict[str, Any]:
    paths = _marker_candidates()
    canonical, unreadable = _read_record(paths[0])
    if canonical and canonical["accepted_version"] == TERMS_VERSION:
        return _status(canonical, "accepted", True)
    records = [canonical] if canonical else []
    for path in paths[1:]:
        record, failed = _read_record(path)
        unreadable = unreadable or failed
        if record: records.append(record)
    matching = [r for r in records if r["accepted_version"] == TERMS_VERSION]
    if matching:
        # Preserve a real historical assent, including its original timestamp.
        record = min(matching, key=lambda r: r["accepted_at"] or "9999")
        # A worker running an older legal version must never downgrade a newer
        # version written during a reload. Legal content changes require review.
        if canonical and re.fullmatch(r"v[0-9]+", canonical["accepted_version"]) and int(canonical["accepted_version"][1:]) > int(TERMS_VERSION[1:]):
            return _status(canonical, "unavailable", True)
        try:
            _write_record(paths[0], record)
            return _status(record, "accepted", True)
        except (OSError, ValueError):
            return _status(record, "unavailable")
    if unreadable:
        return _status(canonical, "unavailable", bool(canonical))
    return _status(canonical or (records[0] if records else None), "unaccepted", bool(canonical))

def accept(version: str = "") -> dict[str, Any]:
    if version != TERMS_VERSION:
        raise ValueError("Unsupported legal version")
    status = get_status()
    if status["status"] == "accepted":
        return status   # Idempotent: an update or duplicate click is not a new assent.
    if status["accepted_version"] and re.fullmatch(r"v[0-9]+", status["accepted_version"]) and int(status["accepted_version"][1:]) > int(TERMS_VERSION[1:]):
        raise ValueError("A newer legal version is already recorded")
    payload = {"accepted": True, "accepted_version": version,
               "accepted_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        _write_record(_marker_candidates()[0], payload)
        return _status(payload, "accepted", True)
    except (OSError, ValueError):
        return _status(state="unavailable")
