"""Shared durable session cancellation predicates; no process-local authority."""
from __future__ import annotations
from sentinel_platform.contracts import Collections

CANCELLED = ("stop", "stopped", "cancelled", "canceled", "revoked", "deleted")

def is_cancelled(document):
    return bool(document and (document.get("stop_requested") is True or document.get("status") in CANCELLED))

def writable(session_id):
    # Apply in the Mongo update itself: checking before an LLM call is insufficient.
    return {"_id": session_id, "stop_requested": {"$ne": True}, "status": {"$nin": list(CANCELLED)}}

def reconcile_cancelled(repo):
    """Repair legacy late-write residues without deleting resumable/history data."""
    query={"status":{"$nin":["done","fatal","stopped"]},
           "$or":[{"stop_requested":True},{"status":{"$in":list(CANCELLED)}}]}
    result=repo.collection(Collections.PENTEST_SESSION).update_many(query,
        {"$set":{"status":"stopped","stop_requested":True,"afk_mode":False,
                 "console_running":False,"console_stop_requested":True,"pending_user_msgs":[],
                 "stream_buffer":"","stream_phase":""},
         "$unset":{"active_key":"","console_execution_token":""}})
    return getattr(result,"modified_count",0)
