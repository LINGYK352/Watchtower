"""Shared, uncached finding revision. Notification failure never undoes a saved result."""
import uuid
from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

META_ID = '_finding_revision'

def touch_revision():
    try:
        get_repo().collection(Collections.FINDING_IDENTITY).update_one(
            {'_id': META_ID}, {'$inc': {'revision': 1}, '$set': {'stamp': uuid.uuid4().hex}}, upsert=True)
        return True
    except Exception as exc:
        get_logger().warning('Finding live notification deferred: %s', type(exc).__name__)
        return False

def read_revision():
    value = get_repo().collection(Collections.FINDING_IDENTITY).find_one({'_id': META_ID}) or {}
    return {'revision': int(value.get('revision', 0)), 'stamp': str(value.get('stamp', ''))}
