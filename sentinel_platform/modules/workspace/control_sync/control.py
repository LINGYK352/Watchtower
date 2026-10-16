"""Administrator-issued, expiring MCP keys delegate to the existing guarded business routes."""
from __future__ import annotations

import re
import secrets
import time

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .security import ControlSyncError, digest, text, ttl


# These are existing application namespaces, not an arbitrary URL/SSRF proxy.
DOMAINS = {
    "system": ("console", "meta/modules", "meta/health", "meta/version"),
    "assets": ("domain", "ip", "site", "url", "cert", "service", "fileleak", "wih", "fingerprint", "asset_scope", "asset_domain", "asset_ip", "asset_site", "asset_wih"),
    "tasks": ("task", "task_fofa", "task_schedule", "github_task", "github_result", "github_scheduler", "github_monitor_result", "scheduler"),
    "pentest": ("pentest/session", "pentest/tools", "miniapp", "app_pentest", "probe"),
    "findings": ("pentest/finding", "vuln", "nuclei_result", "intel/asset", "intel/system", "intel/chain", "intel/vuln_feed"),
    "reports": ("intel/pentest_report", "intel/report", "intel/report_template"),
    "policies": ("policy",),
    "config": ("ai_config", "proxy", "api_keys"),
}
SCOPES = [f"{name}:{right}" for name in DOMAINS for right in ("read", "write") if not (name == "system" and right == "write")]


class ControlKeys:
    def __init__(self, repo, clock=time.time):
        self.repo, self.clock = repo, clock
        self.keys = repo.collection("control_keys")
        self.limits = repo.collection("control_limits")
        self.audit = repo.collection("control_audit")
        self.keys.create_index("hash", unique=True)
        self.limits.create_index("expires", expireAfterSeconds=0)

    def create(self, user: dict, body: dict) -> dict:
        duration = ttl(body.get("expires_in"), 60, 90 * 86400)
        label = text(body.get("name"), 80)
        scopes = body.get("scopes")
        if not isinstance(scopes, list) or not scopes or any(not isinstance(s, str) or s not in SCOPES for s in scopes):
            raise ControlSyncError("至少选择一项有效权限 / Select valid permissions")
        raw = "wt_ctl_" + secrets.token_urlsafe(32)
        now = self.clock()
        doc = {"_id": secrets.token_hex(16), "name": label, "hash": digest(raw), "prefix": raw[:14],
               "owner": user["username"], "scopes": sorted(set(scopes)), "created_at": now,
               "expires_at": now + duration, "revoked": False, "last_used_at": None}
        self.keys.insert_one(doc)
        self.record(doc, "create")
        return {**self.public(doc), "key": raw}

    @staticmethod
    def public(doc):
        return {k: doc.get(k) for k in ("_id", "name", "prefix", "owner", "scopes", "created_at", "expires_at", "revoked", "last_used_at")}

    def list(self):
        return [self.public(d) for d in self.keys.find({}).sort("created_at", -1).limit(200)]

    def revoke(self, key_id):
        doc = self.keys.find_one_and_update({"_id": text(key_id, 32)}, {"$set": {"revoked": True}}, return_document=ReturnDocument.AFTER)
        if not doc:
            raise ControlSyncError("Key不存在 / Key not found", 404)
        self.record(doc, "revoke")
        return self.public(doc)

    def delete(self, key_id):
        doc = self.keys.find_one_and_delete({"_id": text(key_id, 32)})
        if doc:
            self.record(doc, "delete", name=doc.get("name", ""))
        return {"deleted": bool(doc)}

    def authenticate(self, raw):
        if not isinstance(raw, str) or not re.fullmatch(r"wt_ctl_[A-Za-z0-9_-]{43}", raw):
            raise ControlSyncError("控制Key无效或已过期 / Invalid or expired control key", 401)
        doc = self.keys.find_one({"hash": digest(raw), "revoked": False, "expires_at": {"$gt": self.clock()}})
        if not doc:
            raise ControlSyncError("控制Key无效或已过期 / Invalid or expired control key", 401)
        owner = self.repo.collection("user").find_one({"username": doc["owner"]}, {"username": 1, "role": 1, "disabled": 1})
        if doc["owner"] == "master":
            from sentinel_platform.core import get_config
            cfg = get_config()
            master = cfg.section("SENTINEL", "API_KEY", default="") or cfg.section("API_KEY", default="") or cfg.section("ARL", "API_KEY", default="")
            owner = {"username": "master", "role": "admin"} if master else None
        if not owner or owner.get("disabled") or owner.get("role") != "admin":
            raise ControlSyncError("创建者已失去管理员权限 / Key owner is no longer an administrator", 403)
        self.rate_limit(doc)
        fresh = self.keys.find_one_and_update({"_id": doc["_id"], "revoked": False, "expires_at": {"$gt": self.clock()}},
                                             {"$set": {"last_used_at": self.clock()}}, return_document=ReturnDocument.AFTER)
        if not fresh:
            raise ControlSyncError("控制Key已删除、撤销或过期 / Control Key deleted, revoked or expired", 401)
        return doc, {"username": owner["username"], "role": owner["role"], "via": "control_key"}

    def rate_limit(self, doc):
        from datetime import datetime, timezone
        bucket = int(self.clock() // 60)
        ident = f"{doc['_id']}:{bucket}"
        try:
            self.limits.insert_one({"_id": ident, "count": 0, "expires": datetime.fromtimestamp((bucket + 2) * 60, timezone.utc)})
        except DuplicateKeyError:
            pass
        item = self.limits.find_one_and_update({"_id": ident, "count": {"$lt": 120}}, {"$inc": {"count": 1}}, return_document=ReturnDocument.AFTER)
        if not item:
            raise ControlSyncError("控制请求过于频繁 / Control request limit exceeded", 429)

    def record(self, doc, action, **details):
        self.audit.insert_one({"key_id": doc["_id"], "owner": doc.get("owner", ""), "action": action,
                               "at": self.clock(), **details})

    def authorize_operation(self, key: dict, method, path):
        method = text(method, 8).upper()
        path = text(path, 300)
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH") or not re.fullmatch(r"/api/[A-Za-z0-9_./-]+", path) or ".." in path:
            raise ControlSyncError("操作路径或方法无效 / Invalid operation path or method")
        relative = path[5:].rstrip("/")
        # Legacy task stop/resume uses GET for a mutation; never expose it as read-only.
        write = method != "GET" or relative.startswith(("task/stop", "task/resume"))
        right = "write" if write else "read"
        matches = [(len(prefix), domain) for domain, prefixes in DOMAINS.items() for prefix in prefixes
                   if relative == prefix or relative.startswith(prefix + "/")]
        if not matches:
            raise ControlSyncError("该接口未开放给控制Key / Operation is not exposed to control keys", 403)
        domain = max(matches)[1]
        if f"{domain}:{right}" not in key["scopes"]:
            raise ControlSyncError("Key未授权该操作 / Key does not permit this operation", 403)
        return method, path

    def operations(self, key, app):
        out = []
        for rule in app.url_map.iter_rules():
            for method in sorted((rule.methods or set()) - {"OPTIONS", "HEAD"}):
                if "<" in rule.rule:
                    path = re.sub(r"<[^>]+>", "example", rule.rule)
                else:
                    path = rule.rule
                try:
                    self.authorize_operation(key, method, path)
                except ControlSyncError:
                    continue
                out.append({"method": method, "path": rule.rule})
        return sorted(out, key=lambda row: (row["path"], row["method"]))
