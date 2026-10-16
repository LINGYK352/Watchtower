"""Shared reference classification for progress and independent verification."""
import json


def reference_only(name, result):
    # Tool identity cannot be overridden by model arguments or legacy markers.
    if name in ('run_wih', 'collect_js'):
        return True
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (TypeError, ValueError):
            return False
    return isinstance(result, dict) and (result.get('reference_only') is True or
                                        result.get('evidence_source') in ('run_wih', 'collect_js'))
