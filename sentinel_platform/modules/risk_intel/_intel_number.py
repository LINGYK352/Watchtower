"""Stable local intelligence identifiers, allocated with shared Mongo counters and CAS."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import re
from pymongo import ReturnDocument
from sentinel_platform.core import get_repo
from sentinel_platform.contracts import Collections

_CVE = re.compile(r"CVE[-_\s]?(\d{4})[-_\s]?(\d{4,})", re.I)
_WTI = re.compile(r"^WTI-(\d{6})-(\d{6,})$")


def cve(value):
    match = _CVE.search(str(value or ""))
    return "CVE-{}-{}".format(*match.groups()) if match else ""


def beijing_month():
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m")


def month_for(doc):
    if re.fullmatch(r"\d{6}", str(doc.get("number_month", ""))):
        return doc["number_month"]
    # Historical save_date was a local-time string; retain its recorded intake month.
    match = re.match(r"^(\d{4})-(\d{2})-", str(doc.get("save_date", "")))
    if match and 1 <= int(match[2]) <= 12:
        return match[1] + match[2]
    return beijing_month()


def ensure(doc):
    external = cve(doc.get("cve_id"))
    if external:
        return external
    if _WTI.fullmatch(str(doc.get("watchtower_id", ""))):
        return doc["watchtower_id"]
    if "_id" not in doc:
        return ""
    repo = get_repo();coll = repo.collection(Collections.VULN_INTEL)
    counters = repo.collection("vuln_intel_number_sequences")
    month = month_for(doc)
    if not counters.find_one({"_id": month}):
        highest = next(iter(coll.find({"watchtower_id": {"$regex": "^WTI-" + month + "-"}}, {"watchtower_id": 1}).sort("watchtower_id", -1).limit(1)), {})
        match = _WTI.fullmatch(highest.get("watchtower_id", ""))
        counters.update_one({"_id": month}, {"$setOnInsert": {"sequence": int(match[2]) if match else 0}}, upsert=True)
    allocated = counters.find_one_and_update({"_id": month}, {"$inc": {"sequence": 1}}, return_document=ReturnDocument.AFTER)
    number = "WTI-{}-{:06d}".format(month, allocated["sequence"])
    saved = coll.find_one_and_update({"_id": doc["_id"], "$or": [{"watchtower_id": {"$exists": False}}, {"watchtower_id": ""}, {"watchtower_id": None}]},
                                    {"$set": {"watchtower_id": number, "number_month": month}}, return_document=ReturnDocument.AFTER)
    if saved:
        doc.update(watchtower_id=number, number_month=month)
        return number
    existing = coll.find_one({"_id": doc["_id"]}) or {}
    number = cve(existing.get("cve_id")) or existing.get("watchtower_id", "")
    doc["watchtower_id"] = existing.get("watchtower_id", "")
    return number
