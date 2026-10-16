"""Create a missing native content preference before the existing frozen GUI reads it."""
from pathlib import Path
import json, os, tempfile
SOURCE_ROOT = Path(__file__).resolve().parents[3]

def ensure() -> bool:
    if os.name != "nt": return False
    native = os.environ.get("SENTINEL_NATIVE_ROOT", "")
    # Older frozen adapters already expose their persistent state config even
    # when a newer convenience environment name is not in that executable.
    if not native:
        config = Path(os.environ.get("SENTINEL_PLATFORM_CONFIG", ""))
        if config.name != "config.yaml" or config.parent.name != "state": return False
        native = str(config.parent.parent)
    root = Path(native).resolve()
    if SOURCE_ROOT.resolve() != (root / "app").resolve():
        return False
    state = root / "state"
    target = state / "window-preferences.json"
    if target.exists(): return False   # Existing choices, including explicit 1.0, stay intact.
    state.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".window-default-", suffix=".tmp", dir=state)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"zoom": 0.9, "defaults_version": 1}, handle)
            handle.flush(); os.fsync(handle.fileno())
        try:
            # On Windows rename is atomic and refuses an existing destination;
            # a concurrent worker/user preference writer is never overwritten.
            os.rename(temporary, target)
            return True
        except FileExistsError:
            return False
    finally:
        Path(temporary).unlink(missing_ok=True)
