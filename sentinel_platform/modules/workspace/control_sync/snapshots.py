"""Portable, selected-category snapshots; staged swaps with a persistent rollback journal."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import threading
import time
import zipfile
from urllib.parse import urlsplit, urlunsplit

from bson import json_util, ObjectId
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from sentinel_platform.contracts import Collections as C
from sentinel_platform.contracts.configuration import overwrite_only, BUILTIN_PROMPT_SCENES, BUILTIN_REPORT_IDS

from .security import ControlSyncError, canonical

COLLECTIONS = {
    "assets": (C.DOMAIN, C.IP, C.SITE, C.URL, C.CERT, C.SERVICE, C.FILELEAK, C.WIH, C.NPOC_SERVICE, C.STAT_FINGER, C.CIP,
               C.INTEL_ASSET, C.INTEL_SYSTEM, C.INTEL_CODE, C.ASSET_SCOPE, C.ASSET_DOMAIN, C.ASSET_IP, C.ASSET_SITE, C.ASSET_WIH),
    "findings": (C.INTEL_FINDING, C.VULN, C.NUCLEI_RESULT, C.FINDING_IDENTITY, C.INTEL_EXPLOIT_CLUE, C.INTEL_ATTACK_CHAIN),
    "reports": (C.PENTEST_REPORT, C.INTEL_REPORT, C.REPORT_TEMPLATE),
    "policies": (C.POLICY,),
    "configuration": (C.AI_CONFIG, C.AI_PROMPT, C.AI_PROVIDER, C.SYSTEM_TAGS, C.PROXY_CONFIG),
    "credentials": (C.API_KEYS, C.AI_PROVIDER, C.PROXY_CUSTOM, C.PROXY_PROFILES, C.PROXY_RULE),
    "task_history": (C.TASK,),
    "session_history": (C.PENTEST_SESSION,),
}
AI_FIELDS = {"_id", "name", "active_provider_id", "max_context_tokens", "max_concurrent_sessions", "timeout", "updated_at"}
PROXY_FIELDS = {"_id", "name", "mode", "auto_select", "test_url", "health_check_url", "health_check_interval", "health_fail_threshold", "doh_endpoints", "updated_at"}
PROVIDER_FIELDS = {"_id", "name", "type", "protocol", "base_url", "model", "enabled", "api_key", "proxy_id", "extra_headers", "extra_body", "created_at", "updated_at", "context_window", "max_context_tokens", "timeout", "exclusive_skill", "model_skill_revision"}
RUNTIME_FIELDS = {"pid", "worker_pid", "browser_pid", "browser_state", "browser_context", "active_key", "celery_id", "celery_task_id", "resource_lease", "console_taken_over", "runtime", "lock", "lock_owner"}
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_RAW = 256 * 1024 * 1024
MAX_ENTRIES = 50000
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
TEMPLATE_EXT = IMAGE_EXT | {".docx", ".pdf", ".xlsx", ".pptx", ".json"}
IDENTITY_FIELDS = {C.POLICY: ("name",), C.AI_PROVIDER: ("name", "protocol", "base_url", "model"),
                   C.ASSET_SCOPE: ("name", "scope_type"), C.PROXY_RULE: ("name",), C.API_KEYS: ("name",),
                   C.AI_CONFIG: ("name",), C.PROXY_CONFIG: ("name",), C.REPORT_TEMPLATE: ("name",),
                   C.INTEL_FINDING: ("point_key",), C.PENTEST_REPORT: ("report_key",),
                   C.INTEL_ASSET:("key",),C.INTEL_SYSTEM:("key",),C.INTEL_EXPLOIT_CLUE:("unit","clue_type","title")}
REFERENCE_FIELDS = {"provider_id": C.AI_PROVIDER, "ai_provider_id": C.AI_PROVIDER, "active_provider_id": C.AI_PROVIDER,
                    "policy_id": C.POLICY, "scope_id": C.ASSET_SCOPE, "proxy_id": C.PROXY_CUSTOM,
                    "proxy_rule_id": C.PROXY_RULE, "template_id": C.REPORT_TEMPLATE,
                    "task_id": C.TASK, "source_task_id": C.TASK, "session_id": C.PENTEST_SESSION,
                    "source_session": C.PENTEST_SESSION, "sessions": C.PENTEST_SESSION,
                    "system_id":C.INTEL_SYSTEM,"asset_id":C.INTEL_ASSET,"asset_ids":C.INTEL_ASSET,
                    "finding_id":C.INTEL_FINDING,"finding_ids":C.INTEL_FINDING,"clue_id":C.INTEL_EXPLOIT_CLUE}


def identity_fields(collection, doc):
    fields = IDENTITY_FIELDS.get(collection, ())
    if not fields or not doc.get(fields[0]):
        return {}
    identity = {k: doc.get(k, "") for k in fields}
    if any(not isinstance(v, (str, int, bool)) for v in identity.values()):
        raise ControlSyncError("数据身份字段无效 / Invalid data identity field")
    if collection == C.AI_PROVIDER:
        url = urlsplit(str(identity.get("base_url", "")))
        host = url.hostname or ""
        host = "[" + host + "]" if ":" in host else host
        if url.port:
            host += ":" + str(url.port)
        identity["base_url"] = urlunsplit((url.scheme, host, url.path.rstrip("/"), "", ""))
    return identity


def selected_collections(selected):
    return sorted({c for category in selected for c in COLLECTIONS[category]})


def guarded_history(doc):
    """Execution choices and grants cannot cross an instance boundary."""
    value=dict(doc)
    value.update(full_authorization=False,full_authorization_acknowledged=False,rule_interception=True,
                 afk_mode=False,console_running=False,console_stop_requested=True,pending_user_msgs=[])
    value.pop('console_execution_token',None)
    return value


def portable(collection, doc, selected):
    value = dict(doc)
    if collection == "ai_config":
        value = {k: v for k, v in value.items() if k in AI_FIELDS}
    elif collection == "proxy_config":
        value = {k: v for k, v in value.items() if k in PROXY_FIELDS}
    elif collection == "ai_provider":
        value = {k: v for k, v in value.items() if k in PROVIDER_FIELDS}
        if "credentials" not in selected:
            value.pop("api_key", None)
            # Custom request headers/body can contain secrets, not just api_key.
            value.pop("extra_headers", None)
            value.pop("extra_body", None)
        if "configuration" not in selected:
            value = {k: v for k, v in value.items() if k in {"_id", "api_key", "extra_headers", "extra_body"}}
    elif collection in (C.TASK, C.PENTEST_SESSION):
        value = {k: v for k, v in value.items() if k not in RUNTIME_FIELDS}
        if collection == C.PENTEST_SESSION:
            value["synced_history"] = True
    return value


def _safe_file(name, selected):
    p = PurePosixPath(name)
    if len(p.parts)>=5 and p.parts[:3]==('files','model_skill','bundles') and 'configuration' in selected:
        if chr(92) in name or ':' in name or p.is_absolute() or any(part in ('','.','..') for part in name.split('/')):return False
        if len(p.parts[3])!=32 or any(c not in '0123456789abcdef' for c in p.parts[3]):return False
        return len(p.parts)==5 and p.parts[4]=='manifest.json' or len(p.parts)>=6 and p.parts[4]=='files'
    if not name or "\\" in name or p.is_absolute() or any(part in ("", ".", "..") or part.startswith(".") for part in p.parts):
        return False
    if len(p.parts) < 3 or p.parts[0] != "files":
        return False
    if p.parts[1] == "image" and any(c in selected for c in ("assets", "findings", "reports")):
        return p.suffix.lower() in IMAGE_EXT
    if p.parts[1] == "template" and "reports" in selected:
        return p.suffix.lower() in TEMPLATE_EXT
    return False



def _notify_finding_change():
    # Across module categories, use the registered FINDING facade, not leaf imports.
    try:
        from sentinel_platform.contracts import get_registry, ROLE
        service = get_registry().get(ROLE.FINDING)
        if service and hasattr(service, 'touch_revision'):
            service.touch_revision()
    except Exception:
        pass  # The UI's bounded reconciliation covers a missed notification.


class Snapshots:
    def __init__(self, repo, directory, clock=time.time, file_roots=None):
        self.repo, self.directory, self.clock = repo, Path(directory), clock
        self.directory.mkdir(parents=True, exist_ok=True)
        self.gate = repo.collection("control_sync_gate")
        self.journals = repo.collection("control_sync_journal")
        self.gate.update_one({"_id": "maintenance"}, {"$setOnInsert": {"closed": False, "leases": {}}}, upsert=True)
        if file_roots is None:
            from sentinel_platform.core import image_dir
            from sentinel_platform.core.paths import template_dir, model_skill_dir
            file_roots = {"image": Path(image_dir()), "template": Path(template_dir()), "model_skill": Path(model_skill_dir())}
        self.file_roots = {k: Path(v) for k, v in file_roots.items()}
        self._local_leases = set()
        self._lease_lock = threading.Lock()
        self._heartbeat_started = False

    def readiness(self):
        # Read shared Mongo on each admission. Paused sessions remain resumable;
        # never stop them or rely on a process-local "idle" cache to copy data.
        from sentinel_platform.core.session_lifecycle import reconcile_cancelled
        reconcile_cancelled(self.repo)
        # resource_pool is registered shared infrastructure, not an AI leaf.
        from sentinel_platform.modules.kernel.resource_pool import cleanup_cancelled_session_reservations
        cleanup_cancelled_session_reservations(self.repo)
        reasons = []
        rules = (("tasks", "task", {"status": {"$nin": ["done", "error", "stop"]}}),
                 ("sessions", C.PENTEST_SESSION, {"status": {"$nin": ["done", "stopped", "fatal"]}}),
                 ("schedules", "task_schedule", {"status": {"$ne": "stopped"}}),
                 ("schedules", "scheduler", {"status": {"$ne": "stop"}}),
                 ("schedules", "github_scheduler", {"enabled": {"$ne": False}}))
        for kind, name, query in rules:
            count = self.repo.collection(name).count_documents(query)
            if count:
                item = {"kind": kind, "count": count}
                if kind == "sessions":
                    item["paused"] = self.repo.collection(name).count_documents({"$and": [query, {"status": {"$regex": "^paused_"}}]})
                reasons.append(item)
        return {"blocked": bool(reasons), "reasons": reasons}

    def active_work(self):
        return self.readiness()["blocked"]

    def require_idle(self):
        state = self.readiness()
        if not state["blocked"]:
            return
        from .security import idle_error
        raise idle_error(state["reasons"])

    def admission(self):
        ident = secrets.token_hex(12)
        item = self.gate.find_one_and_update({"_id": "maintenance", "closed": False}, {"$set": {"leases." + ident: self.clock() + 300}}, return_document=ReturnDocument.AFTER)
        if not item:
            raise ControlSyncError("同步维护中，请稍后再试 / Sync maintenance in progress", 423)
        with self._lease_lock:
            self._local_leases.add(ident)
            if not self._heartbeat_started:
                self._heartbeat_started = True
                threading.Thread(target=self._heartbeat_requests, daemon=True, name="sync-request-leases").start()
        return ident

    def release(self, ident):
        if ident:
            with self._lease_lock:
                self._local_leases.discard(ident)
            self.gate.update_one({"_id": "maintenance"}, {"$unset": {"leases." + ident: ""}})

    def _heartbeat_requests(self):
        while True:
            time.sleep(30)
            with self._lease_lock:
                ids = list(self._local_leases)
            for ident in ids:
                try:
                    self.gate.update_one({"_id": "maintenance", "leases." + ident: {"$exists": True}}, {"$set": {"leases." + ident: self.clock() + 300}})
                except Exception:
                    pass

    def _heartbeat_apply(self, run_id, stopped):
        while not stopped.wait(15):
            try:
                self.gate.update_one({"_id": "maintenance", "closed": True, "run_id": run_id}, {"$set": {"started_at": self.clock()}})
            except Exception:
                pass


    def _sync_available(self):
        return {"_id":"maintenance","closed":False,"$or":[
            {"incremental_run_id":{"$exists":False}},{"incremental_until":{"$lte":self.clock()}}]}

    @contextmanager
    def _incremental_operation(self, run_id):
        # Serialize sync operations only. Business admissions and worker writes
        # remain open; the global maintenance gate is reserved for replacement.
        nonce=secrets.token_hex(16)
        acquired=self.gate.find_one_and_update(self._sync_available(),
            {"$set":{"incremental_run_id":nonce,"incremental_until":self.clock()+300}},return_document=ReturnDocument.AFTER)
        if not acquired:raise ControlSyncError("已有同步正在导出或应用，请稍后重试 / Another sync is exporting or applying",423)
        stopped=threading.Event()
        def check():
            if not self.gate.find_one({"_id":"maintenance","closed":False,"incremental_run_id":nonce,"incremental_until":{"$gt":self.clock()}},{"_id":1}):
                raise ControlSyncError("增量同步租约失效，已保留新增数据，请重试 / Incremental lease expired; added data is retained. Retry",423)
        def heartbeat():
            while not stopped.wait(15):
                try:self.gate.update_one({"_id":"maintenance","closed":False,"incremental_run_id":nonce},{"$set":{"incremental_until":self.clock()+300}})
                except Exception:pass
        threading.Thread(target=heartbeat,daemon=True,name="incremental-sync-lease").start()
        try:yield check
        finally:
            stopped.set()
            self.gate.update_one({"_id":"maintenance","incremental_run_id":nonce},{"$unset":{"incremental_run_id":"","incremental_until":""}})

    def _apply_incremental(self, run_id, raw, selected):
        data,files=self.inspect(raw,selected)
        binding={"mode":"incremental","snapshot_sha256":hashlib.sha256(raw).hexdigest(),"selected":sorted(selected)}
        with self._incremental_operation(run_id) as check:
            old=self.journals.find_one({"_id":run_id})
            if old and old.get('mode') and any(old.get(k)!=v for k,v in binding.items()):
                raise ControlSyncError("同步编号已绑定其他快照 / Sync identifier is bound to another snapshot",409)
            if old and old.get('phase')=='committed':return old['result']
            # Old senders may still include builtin rows. Filter at both ends,
            # before validating their references or publishing any record.
            data={**data,'records':{name:[doc for doc in docs if not overwrite_only(name,doc)] for name,docs in data['records'].items()}}
            records=self._map_identities(data)
            records={name:[doc for doc in docs if not overwrite_only(name,self.repo.collection(name).find_one({'_id':doc['_id']}) or {})] for name,docs in records.items()}
            self._references(records)
            for doc in records.get('ai_provider',[]):
                if 'configuration' not in selected and not self.repo.collection('ai_provider').find_one({'_id':doc['_id']}):
                    raise ControlSyncError("AI凭据缺少对应provider配置，请同时选择配置 / Include provider configuration with its credentials")
            self.journals.update_one({'_id':run_id},{'$set':{**binding,'phase':'incremental_applying','at':self.clock()}},upsert=True)
            # Separate small progress rows avoid a single Mongo16MiB journal
            # limit. Never attach synchronization metadata to business records.
            def progress_id(kind,identity):return 'inci:'+run_id+':'+hashlib.sha256((kind+':'+json_util.dumps(identity,sort_keys=True)).encode()).hexdigest()
            def done(key):return self.journals.find_one({'_id':key,'phase':'incremental_item'})
            def record(key,state):self.journals.replace_one({'_id':key},{'_id':key,'phase':'incremental_item','run_id':run_id,'state':state},upsert=True)
            try:
                # Publish complete attachments before exposing new referring
                # records. Existing files are never replaced, even in a race.
                for member,content in files.items():
                    if PurePosixPath(member).parts[:2]==('files','template') and PurePosixPath(member).parts[2] in BUILTIN_REPORT_IDS:continue
                    key=progress_id('file',member)
                    if done(key):continue
                    check();parts=PurePosixPath(member).parts;root=self.file_roots[parts[1]];path=root.joinpath(*parts[2:]);path.resolve().relative_to(root.resolve())
                    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent!=root.parent):raise ControlSyncError("附件目标包含链接 / Attachment target contains a link")
                    path.parent.mkdir(parents=True,exist_ok=True)
                    if path.exists():
                        record(key,'conflict' if path.read_bytes()!=content else 'existing');continue
                    temp=path.with_name(path.name+'.sync-'+secrets.token_hex(12))
                    try:
                        with temp.open('xb') as handle:handle.write(content);handle.flush();os.fsync(handle.fileno())
                        check()
                        try:os.link(temp,path);state='file_written'
                        except FileExistsError:state='conflict' if path.read_bytes()!=content else 'existing'
                        record(key,state)
                    finally:temp.unlink(missing_ok=True)
                for name,docs in records.items():
                    destination=self.repo.collection(name)
                    for doc in docs:
                        key=progress_id(name,doc['_id'])
                        if done(key):continue
                        check();current=destination.find_one({'_id':doc['_id']})
                        if current is not None:
                            record(key,'conflict' if portable(name,current,selected)!=doc else 'existing');continue
                        value=dict(doc)
                        if name=='ai_provider' and not value.get('api_key'):value['enabled']=False
                        try:destination.insert_one(value);state='inserted'
                        except DuplicateKeyError:
                            current=destination.find_one({'_id':doc['_id']})
                            if current is None:
                                record(key,"conflict");continue
                            state='conflict' if portable(name,current,selected)!=doc else 'existing'
                        record(key,state)
                counts={row['_id']:row['count'] for row in self.journals.aggregate([{'$match':{'run_id':run_id,'phase':'incremental_item'}},{'$group':{'_id':'$state','count':{'$sum':1}}}])}
                stats={'inserted':counts.get('inserted',0),'replaced':0,'conflicts':counts.get('conflict',0),'files_written':counts.get('file_written',0)}
                check();self.journals.update_one({'_id':run_id},{'$set':{'phase':'committed','result':stats,'completed_at':self.clock()},'$unset':{'last_error':''}})
                if 'findings' in selected:_notify_finding_change()
                return stats
            except Exception as error:
                self.journals.update_one({'_id':run_id},{'$set':{'phase':'incremental_pending','last_error':type(error).__name__}})
                raise

    def export(self, selected, mode="overwrite"):
        if mode not in ("incremental","overwrite"):raise ControlSyncError("同步模式无效 / Invalid sync mode")
        if mode=="incremental":
            with self._incremental_operation("export_"+secrets.token_hex(12)):
                return self._export_selected(selected, require_idle=False, include_builtin=False)
        run_id = "export_" + secrets.token_hex(12)
        acquired = self.gate.find_one_and_update(self._sync_available(), {"$set": {"closed": True, "run_id": run_id, "started_at": self.clock()}}, return_document=ReturnDocument.AFTER)
        if not acquired:
            raise ControlSyncError("已有同步维护任务 / Another sync maintenance operation is active", 423)
        stopped = threading.Event()
        threading.Thread(target=self._heartbeat_apply, args=(run_id, stopped), daemon=True, name="sync-export-lease").start()
        try:
            deadline = time.monotonic() + 10
            while True:
                gate = self.gate.find_one({"_id": "maintenance"})
                if not any(expiry > self.clock() for expiry in gate.get("leases", {}).values()):
                    break
                if time.monotonic() >= deadline:
                    raise ControlSyncError("业务请求未结束，请稍后重试 / Wait for in-flight business requests", 409)
                time.sleep(.05)
            return self._export_selected(selected)
        finally:
            stopped.set()
            self.gate.update_one({"_id": "maintenance", "run_id": run_id}, {"$set": {"closed": False}, "$unset": {"run_id": ""}})

    def _export_selected(self, selected, require_idle=True, include_builtin=True):
        if require_idle:self.require_idle()
        records, counts, raw_size = {}, {}, 0
        for name in selected_collections(selected):
            query = {"status": {"$in": ["done", "error", "stop"]}} if name == C.TASK else {"status": {"$in": ["done", "stopped", "fatal"]}} if name == C.PENTEST_SESSION else {}
            docs = []
            for doc in self.repo.collection(name).find(query):
                if not include_builtin and overwrite_only(name,doc):continue
                item = portable(name, doc, selected)
                if name==C.PENTEST_SESSION:item=guarded_history(item)
                if name == C.REPORT_TEMPLATE:
                    root = self.file_roots['template']
                    for key in ('template_path', 'origin_path'):
                        value = item.get(key)
                        if isinstance(value, str) and Path(value).is_absolute():
                            try:
                                item[key] = Path(value).resolve().relative_to(root.resolve()).as_posix()
                            except ValueError:
                                raise ControlSyncError("报告模板位于同步目录外，请先迁入模板目录 / Move report templates into the template directory before syncing") from None
                raw_size += len(json_util.dumps(item).encode())
                if raw_size > MAX_RAW or len(docs) >= 100000:
                    raise ControlSyncError("同步内容过大，请减少选择内容 / Snapshot too large; select fewer categories", 413)
                docs.append(item)
            records[name] = docs
            counts[name] = len(docs)
        # Reference catalogs contain only stable identity fields, never credential values.
        catalogs = {}
        for name in (C.AI_PROVIDER, C.POLICY, C.ASSET_SCOPE, C.PROXY_RULE):
            rows = []
            for doc in self.repo.collection(name).find({}):
                fields = identity_fields(name, doc)
                if fields:
                    rows.append({"_id": doc["_id"], **fields})
            catalogs[name] = rows
        payload = {"schema": 1, "categories": selected, "created_at": self.clock(), "records": records, "catalogs": catalogs}
        stream = io.BytesIO()
        files = 0
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            archive.writestr("snapshot.json", json_util.dumps(payload).encode("utf-8"))
            for name, root in self.file_roots.items():
                enabled = name == "image" and any(c in selected for c in ("assets", "findings", "reports")) or name == "template" and "reports" in selected or name == "model_skill" and "configuration" in selected
                if not enabled or not root.exists():
                    continue
                for path in root.rglob("*"):
                    if not path.is_file() or path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root.parent):
                        continue
                    member = "files/" + name + "/" + path.relative_to(root).as_posix()
                    if not _safe_file(member, selected):
                        continue
                    if not include_builtin and name=='template' and path.relative_to(root).parts[0] in BUILTIN_REPORT_IDS:continue
                    if name=='model_skill':
                        active={r.get('exclusive_skill',{}).get('artifact_id') for r in records.get(C.AI_PROVIDER,[]) if isinstance(r.get('exclusive_skill'),dict)}
                        if path.relative_to(root).parts[1] not in active:continue
                    path.resolve().relative_to(root.resolve())
                    raw_size += path.stat().st_size
                    files += 1
                    if raw_size > MAX_RAW or files > MAX_ENTRIES - 1:
                        raise ControlSyncError("同步附件过大 / Sync attachments too large", 413)
                    # PNG/JPEG/PDF/Office files already compress internally.
                    archive.write(path, member, compress_type=zipfile.ZIP_DEFLATED if path.suffix.lower() == ".json" else zipfile.ZIP_STORED)
        raw = stream.getvalue()
        if len(raw) > MAX_ARCHIVE:
            raise ControlSyncError("同步压缩包过大 / Sync archive too large", 413)
        return raw, {"counts": counts, "files": files, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def inspect(self, raw, selected):
        if not isinstance(raw, bytes) or len(raw) > MAX_ARCHIVE:
            raise ControlSyncError("同步压缩包过大 / Sync archive too large", 413)
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = archive.infolist()
                names = [i.filename for i in entries]
                if len(entries) > MAX_ENTRIES or len(names) != len(set(names)) or sum(i.file_size for i in entries) > MAX_RAW:
                    raise ValueError("archive limits")
                if "snapshot.json" not in names or any(n != "snapshot.json" and not _safe_file(n, selected) for n in names):
                    raise ValueError("unsafe member")
                if any(i.is_dir() or (i.external_attr >> 16) & 0o170000 == 0o120000 for i in entries):
                    raise ValueError("unsafe file type")
                data = json_util.loads(archive.read("snapshot.json").decode("utf-8"))
                if data.get("schema") != 1 or data.get("categories") != selected or set(data.get("records", {})) != set(selected_collections(selected)):
                    raise ValueError("category mismatch")
                for name, docs in data["records"].items():
                    if not isinstance(docs, list) or len(docs) > 100000:
                        raise ValueError("invalid documents")
                    ids = set()
                    for doc in docs:
                        if not isinstance(doc, dict) or not isinstance(doc.get("_id"), (ObjectId, str, int)) or isinstance(doc["_id"], bool):
                            raise ValueError("invalid identity")
                        identity = json_util.dumps(doc["_id"])
                        if identity in ids or portable(name, doc, selected) != doc:
                            raise ValueError("duplicate or nonportable document")
                        ids.add(identity)
                        if name in (C.TASK, C.PENTEST_SESSION) and doc.get("status") not in ("done", "error", "stop", "stopped", "fatal"):
                            raise ValueError("active runtime record")
                        if name == C.REPORT_TEMPLATE:
                            for key in ("template_path", "origin_path"):
                                value = doc.get(key)
                                if isinstance(value, str) and ("\\" in value or PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts or ":" in value):
                                    raise ValueError("nonportable template path")
                if 'configuration' in selected:
                    for provider in data['records'].get(C.AI_PROVIDER,[]):
                        ref=provider.get('exclusive_skill')
                        if not ref:continue
                        if not isinstance(ref,dict) or ref.get('provider_name')!=provider.get('name'):raise ValueError('invalid model SKILL binding')
                        aid=ref.get('artifact_id','');entry=ref.get('entry','')
                        if not isinstance(aid,str) or len(aid)!=32 or any(c not in '0123456789abcdef' for c in aid) or not isinstance(entry,str):raise ValueError('invalid model SKILL reference')
                        prefix='files/model_skill/bundles/'+aid+'/'
                        if prefix+'manifest.json' not in names or prefix+'files/'+entry not in names or not _safe_file(prefix+'files/'+entry,selected):raise ValueError('missing model SKILL assets')
                catalogs = data.get("catalogs", {})
                if not isinstance(catalogs, dict) or set(catalogs) - {C.AI_PROVIDER, C.POLICY, C.ASSET_SCOPE, C.PROXY_RULE}:
                    raise ValueError("invalid reference catalog")
                for name, rows in catalogs.items():
                    if not isinstance(rows, list) or len(rows) > 100000 or any(not isinstance(row, dict) or set(row) - {"_id", *IDENTITY_FIELDS[name]} for row in rows):
                        raise ValueError("invalid reference identity")
                if C.PENTEST_SESSION in data["records"]:
                    data["records"][C.PENTEST_SESSION]=[guarded_history(doc) for doc in data["records"][C.PENTEST_SESSION]]
                return data, {n: archive.read(n) for n in names if n != "snapshot.json"}
        except ControlSyncError:
            raise
        except Exception:
            raise ControlSyncError("同步包校验失败（范围/结构/路径/大小） / Snapshot validation failed", 400) from None

    def _copy_collection(self, source, target):
        db = self.repo.collection(source).database
        if target in db.list_collection_names():
            db.drop_collection(target)
        db.create_collection(target)
        original, destination = db[source], db[target]
        batch = []
        for doc in original.find({}):
            batch.append(doc)
            if len(batch) >= 500:
                destination.insert_many(batch); batch = []
        if batch:
            destination.insert_many(batch)
        for name, index in original.index_information().items():
            if name == "_id_":
                continue
            options = {k: v for k, v in index.items() if k in ("unique", "sparse", "expireAfterSeconds", "partialFilterExpression", "collation")}
            destination.create_index(index["key"], name=name, **options)

    def _references(self, records):
        targets = {"provider_id": "ai_provider", "ai_provider_id": "ai_provider", "active_provider_id": "ai_provider", "policy_id": "policy", "scope_id": "asset_scope", "proxy_id": "proxy_custom"}
        def exists(collection, identity):
            if identity in ("", None, "direct", "smart", "proxy", "subscription", "pool"):
                return True
            variants = [identity]
            if isinstance(identity, str) and ObjectId.is_valid(identity):
                variants.append(ObjectId(identity))
            if any(d.get("_id") in variants for d in records.get(collection, [])):
                return True
            return bool(self.repo.collection(collection).find_one({"_id": {"$in": variants}}, {"_id": 1}))
        def walk(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    if k in targets and isinstance(v, (str, ObjectId)) and not exists(targets[k], v):
                        raise ControlSyncError("配置引用缺失，请同时选择关联配置/凭据或资产 / Missing configuration reference; include related categories")
                    walk(v)
            elif isinstance(value, list):
                for v in value:
                    walk(v)
        for name in ("policy", "ai_config", "ai_prompt", "ai_provider", "proxy_rule"):
            for doc in records.get(name, []):
                walk(doc)


    def _unique_match(self, name, doc, indexes=None):
        """Match only complete scalar business keys from real unique indexes."""
        collection=self.repo.collection(name)
        for index,spec in (indexes if indexes is not None else collection.index_information()).items():
            if index=='_id_' or not spec.get('unique'):continue
            query={}
            for field,direction in spec.get('key',[]):
                value=doc
                for part in field.split('.'):
                    value=value.get(part) if isinstance(value,dict) else None
                if value is None or not isinstance(value,(str,int,float,bool,ObjectId)):break
                query[field]=value
            else:
                if not query:continue
                # Partial indexes need their predicate applied to the candidate;
                # do not infer arbitrary identity from an incomplete key.
                if spec.get('partialFilterExpression'):continue
                options={'collation':spec['collation']} if spec.get('collation') else {}
                current=collection.find_one(query,**options)
                if current is not None:return current
        return None

    def _map_identities(self, data):
        mappings, cached = {}, {}
        catalog_rows = {name: {str(row.get("_id")): row for row in rows} for name, rows in data.get("catalogs", {}).items()}
        for name, rows in data["records"].items():
            catalog_rows.setdefault(name, {}).update({str(row["_id"]): {**catalog_rows.get(name, {}).get(str(row["_id"]), {}), **row} for row in rows})
        for name, rows in catalog_rows.items():
            indexes=self.repo.collection(name).index_information()
            for source_id, doc in rows.items():
                current = self.repo.collection(name).find_one({"_id": doc.get("_id")})
                if current is None and name==C.AI_PROVIDER and doc.get("name"):
                    current=self.repo.collection(name).find_one({"name":doc["name"]})
                fields = identity_fields(name, doc)
                if current is None and fields:
                    cache_key = (name, canonical(fields))
                    if cache_key not in cached:
                        first = IDENTITY_FIELDS[name][0]
                        candidates = self.repo.collection(name).find({first: fields[first]})
                        cached[cache_key] = next((d for d in candidates if identity_fields(name, d) == fields), None)
                    current = cached[cache_key]
                if current is None:current=self._unique_match(name,doc,indexes)
                if current:
                    mappings[(name, source_id)] = current["_id"]
        def mapped(name, value):
            replacement = mappings.get((name, str(value)), value)
            return str(replacement) if isinstance(value, str) and isinstance(replacement, ObjectId) else replacement
        def rewrite(value):
            if isinstance(value, dict):
                out = {}
                for key, val in value.items():
                    name = REFERENCE_FIELDS.get(key)
                    if name and isinstance(val, (str, ObjectId)):
                        val = mapped(name, val)
                    elif name and isinstance(val, list):
                        val = [mapped(name, v) if isinstance(v, (str, ObjectId)) else rewrite(v) for v in val]
                    else:
                        val = rewrite(val)
                    if key == "report_key" and isinstance(val, str) and val.startswith(("task:", "session:")):
                        prefix, identity = val.split(":", 1)
                        val = prefix + ":" + str(mapped(C.TASK if prefix == "task" else C.PENTEST_SESSION, identity))
                    out[key] = val
                return out
            if isinstance(value, list):
                return [rewrite(v) for v in value]
            return value
        result = {}
        for name, rows in data["records"].items():
            docs = []
            for doc in rows:
                new = rewrite(doc)
                new["_id"] = mappings.get((name, str(doc["_id"])), doc["_id"])
                docs.append(new)
            result[name] = docs
        return result

    def apply(self, run_id, raw, selected, mode):
        if mode not in ("incremental", "overwrite"):
            raise ControlSyncError("同步模式无效 / Invalid sync mode")
        if mode=="incremental":return self._apply_incremental(run_id,raw,selected)
        old = self.journals.find_one({"_id": run_id})
        if old and old.get("phase") == "committed":
            return old["result"]  # retry after lost acknowledgement is idempotent
        data, files = self.inspect(raw, selected)
        seen=set()
        for doc in data['records'].get(C.AI_PROMPT,[]):
            builtin=doc.get('scene') in BUILTIN_PROMPT_SCENES
            if builtin and doc['scene'] in seen:
                raise ControlSyncError("源端存在重复内置任务环节，请先清理后覆盖同步 / Remove duplicate builtin stages on the source before replacement sync",409)
            if builtin:seen.add(doc['scene'])
            doc['builtin']=builtin
        acquired = self.gate.find_one_and_update(self._sync_available(), {"$set": {"closed": True, "run_id": run_id, "started_at": self.clock()}}, return_document=ReturnDocument.AFTER)
        if not acquired:
            raise ControlSyncError("已有同步维护任务，请稍后重试 / Another sync is applying", 423)
        heartbeat_stop = threading.Event()
        heartbeat = threading.Thread(target=self._heartbeat_apply, args=(run_id, heartbeat_stop), daemon=True, name="sync-apply-lease")
        heartbeat.start()
        journal = {"_id": run_id, "phase": "preparing", "at": self.clock(), "collections": [], "files": []}
        stats = {"inserted": 0, "replaced": 0, "conflicts": 0, "files_written": 0}
        safe_to_open = False
        try:
            deadline = time.monotonic() + 10
            while True:
                gate = self.gate.find_one({"_id": "maintenance"})
                if not any(expiry > self.clock() for expiry in gate.get("leases", {}).values()):
                    break
                if time.monotonic() >= deadline:
                    raise ControlSyncError("业务请求尚未结束，请稍后同步 / Wait for in-flight business requests", 409)
                time.sleep(.05)
            self.require_idle()
            data["records"] = self._map_identities(data)
            self._references(data["records"])
            self.journals.replace_one({"_id": run_id}, journal, upsert=True)
            db = self.repo.collection("control_sync_journal").database
            existing = set(db.list_collection_names())
            journal["collections"] = [{"name": name, "backup": "csb_" + run_id + "_" + name, "stage": "css_" + run_id + "_" + name, "was_present": name in existing} for name in data["records"]]
            self.journals.update_one({"_id": run_id}, {"$set": {"collections": journal["collections"]}})
            for name, docs in data["records"].items():
                backup, stage = "csb_" + run_id + "_" + name, "css_" + run_id + "_" + name
                self._copy_collection(name, backup)
                self._copy_collection(name, stage)
                destination = db[stage]
                if mode == "overwrite" and name != "ai_provider":
                    destination.delete_many({})
                if mode == "overwrite" and name == "ai_provider" and "configuration" in selected:
                    incoming_ids = [d["_id"] for d in docs]
                    destination.delete_many({"_id": {"$nin": incoming_ids}})
                for doc in docs:
                    current = db[name].find_one({"_id": doc["_id"]})
                    if mode == "incremental" and current:
                        if name == "ai_provider" and "configuration" not in selected:
                            additions = {k: v for k, v in doc.items() if k != "_id" and not current.get(k)}
                            if additions:
                                destination.update_one({"_id": doc["_id"]}, {"$set": additions})
                        elif portable(name, current, selected) != doc:
                            stats["conflicts"] += 1
                        continue
                    if name == "ai_provider" and "configuration" not in selected and not current:
                        raise ControlSyncError("AI凭据缺少对应provider配置，请同时选择配置 / Include provider configuration with its credentials")
                    merged = {**(current or {}), **doc} if name in ("ai_config", "proxy_config", "ai_provider") else doc
                    if name == "ai_provider" and not merged.get("api_key"):
                        merged["enabled"] = False
                    destination.replace_one({"_id": doc["_id"]}, merged, upsert=True)
                    stats["replaced" if current else "inserted"] += 1
            backup_dir = self.directory / "backups" / run_id
            backup_dir.mkdir(parents=True, exist_ok=True)
            for member, content in files.items():
                parts = PurePosixPath(member).parts
                root = self.file_roots[parts[1]]
                path = root.joinpath(*parts[2:])
                path.resolve().relative_to(root.resolve())
                if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root.parent):
                    raise ControlSyncError("附件目标包含链接 / Attachment target contains a link")
                if mode == "incremental" and path.exists():
                    continue
                backup_file = backup_dir.joinpath(*parts[1:])
                if path.exists():
                    backup_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, backup_file)
                journal["files"].append({"member": member, "had_original": path.exists()})
            self.journals.update_one({"_id": run_id}, {"$set": {"files": journal["files"], "phase": "swapping"}})
            journal["phase"] = "swapping"
            # Each rename atomically replaces one collection. The shared maintenance gate
            # prevents readers/writers observing intermediate multi-collection states.
            for item in journal["collections"]:
                db[item["stage"]].rename(item["name"], dropTarget=True)
            for item in journal["files"]:
                parts = PurePosixPath(item["member"]).parts
                path = self.file_roots[parts[1]].joinpath(*parts[2:])
                path.parent.mkdir(parents=True, exist_ok=True)
                temp = path.with_name(path.name + ".sync-" + run_id)
                with temp.open("wb") as handle:
                    handle.write(files[item["member"]]); handle.flush(); os.fsync(handle.fileno())
                os.replace(temp, path)
                stats["files_written"] += 1
            self.journals.update_one({"_id": run_id}, {"$set": {"phase": "committed", "result": stats, "completed_at": self.clock()}})
            safe_to_open = True
            if 'findings' in selected: _notify_finding_change()
            return stats
        except Exception:
            # If recovery itself fails (e.g. disk/DB outage), retain the maintenance gate.
            # Opening it would expose a partially restored multi-collection snapshot.
            self.rollback(journal)
            safe_to_open = True
            raise
        finally:
            heartbeat_stop.set()
            if safe_to_open:
                self.gate.update_one({"_id": "maintenance", "run_id": run_id}, {"$set": {"closed": False}, "$unset": {"run_id": ""}})

    def rollback(self, journal):
        db = self.repo.collection("control_sync_journal").database
        if journal.get("phase") == "swapping":
            for item in journal.get("collections", []):
                if item["was_present"]:
                    self._copy_collection(item["backup"], item["stage"])
                    db[item["stage"]].rename(item["name"], dropTarget=True)
                elif item["name"] in db.list_collection_names():
                    db.drop_collection(item["name"])
            for item in journal.get("files", []):
                parts = PurePosixPath(item["member"]).parts
                target = self.file_roots[parts[1]].joinpath(*parts[2:])
                if item["had_original"]:
                    shutil.copy2(self.directory / "backups" / journal["_id"] / Path(*parts[1:]), target)
                else:
                    target.unlink(missing_ok=True)
        for item in journal.get("collections", []):
            if item["stage"] in db.list_collection_names():
                db.drop_collection(item["stage"])
        self.journals.update_one({"_id": journal["_id"]}, {"$set": {"phase": "rolled_back", "recovered_at": self.clock()}}, upsert=True)

    def recover(self):
        gate = self.gate.find_one({"_id": "maintenance"}) or {}
        if not gate.get("closed"):
            return
        # Startup recovery is only attempted after the old operation lease. Live workers
        # never roll back another process's still-running apply.
        if self.clock() - gate.get("started_at", self.clock()) < 300:
            return
        run_id = gate.get("run_id")
        acquired = self.gate.find_one_and_update({"_id": "maintenance", "closed": True, "run_id": run_id, "started_at": gate.get("started_at")},
                                               {"$set": {"started_at": self.clock()}}, return_document=ReturnDocument.AFTER)
        if not acquired:
            return
        journal = self.journals.find_one({"_id": run_id})
        if journal and journal.get("phase") not in ("committed", "rolled_back"):
            self.rollback(journal)
        self.gate.update_one({"_id": "maintenance", "run_id": run_id}, {"$set": {"closed": False}, "$unset": {"run_id": ""}})
