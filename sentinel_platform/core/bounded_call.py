"""Bound optional blocking work without caching authorization or response facts.

Limits are per worker process. A timed-out task keeps its slot until it actually
ends; a hung resolver cannot cause unbounded replacement threads. Callers never
wait for a slot. This is a resource limit, not shared ownership or credential state.
"""
import threading

_lock = threading.Lock()
_slots = {}


def run(name, function, timeout, capacity=2):
    with _lock:
        if name not in _slots:
            _slots[name] = (capacity, threading.BoundedSemaphore(capacity))
        configured, slots = _slots[name]
        if configured != capacity:
            raise ValueError('Bounded call capacity changed for an existing pool')
    if not slots.acquire(blocking=False):
        return None, 'busy'
    done = threading.Event()
    result = {}

    def work():
        try:
            result['value'] = function()
        except Exception as exc:
            result['error'] = type(exc).__name__
        finally:
            slots.release()
            done.set()

    try:
        threading.Thread(target=work, daemon=True, name='bounded-'+name).start()
    except Exception:
        slots.release()
        return None, 'start_failed'
    if not done.wait(timeout):
        return None, 'timeout'
    if 'error' in result:
        return None, result['error']
    return result.get('value'), ''
