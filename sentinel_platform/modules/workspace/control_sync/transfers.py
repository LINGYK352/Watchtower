"""Persisted, resumable transfers; both systems approve a concrete direction/mode/category plan."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import threading
import time

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .pairing import categories
from .security import ControlSyncError, b64, text, unb64
from .snapshots import MAX_ARCHIVE

CHUNK_SIZE = 2 * 1024 * 1024
CONFIRMATION_TIMEOUT = "对端30秒内未确认，请重新请求同步 / Peer did not approve within30 seconds; request sync again"


class Transfers:
    def __init__(self, repo, pairing, snapshots, directory, clock=time.time):
        self.repo, self.pairing, self.snapshots, self.clock = repo, pairing, snapshots, clock
        self.directory = Path(directory) / "archives"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.runs = repo.collection("control_sync_runs")
        self.pairing.peer_handler = self.peer

    def _file(self, run_id):
        if len(text(run_id, 32)) != 32 or any(c not in "0123456789abcdef" for c in run_id):
            raise ControlSyncError("同步任务标识无效 / Invalid transfer id")
        return self.directory / (run_id + ".zip")

    def _save(self, run_id, raw):
        path = self._file(run_id)
        tmp = path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, path)

    def public(self, doc):
        out = {k: doc.get(k) for k in ("_id", "link_id", "kind", "flow", "mode", "categories", "state", "created_at", "expires_at", "summary", "result", "error", "stage", "completed_at", "transferred_bytes", "confirm_expires_at")}
        if doc.get("state") not in ("complete", "rejected", "failed") and self.clock() >= doc.get("expires_at", 0):
            out["state"] = "expired"
        return out

    def _part_path(self, run_id, index):
        base = self._file(run_id).with_suffix(".parts")
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < MAX_ARCHIVE // CHUNK_SIZE:
            raise ControlSyncError("数据块索引无效 / Invalid chunk index")
        base.mkdir(exist_ok=True)
        return base / (str(index).zfill(4) + ".bin")

    def _part_put(self, run_id, index, raw, expected_hash):
        if len(raw) > CHUNK_SIZE or hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ControlSyncError("数据块校验失败 / Chunk validation failed")
        path = self._part_path(run_id, index)
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                raise ControlSyncError("重复数据块内容不一致 / Repeated chunk content differs", 409)
            return
        tmp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            # Atomic publication of a complete chunk. A duplicate cannot replace it.
            try:
                os.link(tmp, path)
            except FileExistsError:
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                    raise ControlSyncError("重复数据块内容不一致 / Repeated chunk content differs", 409)
        finally:
            tmp.unlink(missing_ok=True)

    def _parts_present(self, run_id, total):
        count = (total + CHUNK_SIZE - 1) // CHUNK_SIZE
        return [index for index in range(count) if self._part_path(run_id, index).is_file()]

    def _assemble(self, doc):
        total = doc["summary"]["bytes"]
        path = self._file(doc["_id"])
        tmp = path.with_name(path.name + ".assemble.tmp")
        digest = hashlib.sha256()
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        size = 0
        try:
            with os.fdopen(fd, "wb") as handle:
                for index in range((total + CHUNK_SIZE - 1) // CHUNK_SIZE):
                    part = self._part_path(doc["_id"], index)
                    if not part.is_file():
                        raise ControlSyncError("数据块尚未完整接收 / Not all chunks received", 409)
                    raw = part.read_bytes(); size += len(raw); digest.update(raw); handle.write(raw)
                handle.flush(); os.fsync(handle.fileno())
            if size != total or digest.hexdigest() != doc["summary"]["sha256"]:
                raise ControlSyncError("完整快照校验失败 / Complete snapshot checksum failed")
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
        return path

    def expire_confirmations(self):
        now=self.clock()
        self.runs.update_many({'kind':'receiver','state':'preparing','prepare_expires_at':{'$lte':now}}, {'$set':{'state':'failed','stage':'prepare_timeout','error':'快照准备超时，请重试 / Snapshot preparation timed out; retry'}})
        self.runs.update_many({'kind':'receiver','state':'pending','confirm_expires_at':{'$exists':False}}, {'$set':{'confirm_expires_at':now+30}})
        self.runs.update_many({'kind':'receiver','state':'pending','confirm_expires_at':{'$lte':now}}, {'$set':{'state':'rejected','stage':'confirmation_timeout','error':CONFIRMATION_TIMEOUT}})

    def list(self):
        self.expire_confirmations()
        return [self.public(d) for d in self.runs.find({"history_deleted_at":{"$exists":False}}).sort("created_at", -1).limit(100)]

    def history_detail(self,run_id):
        self._file(run_id)  # Validate the identifier even though no file is read.
        doc=self.runs.find_one({'_id':run_id,'history_deleted_at':{'$exists':False}})
        if not doc:raise ControlSyncError('同步记录不存在 / Sync record not found',404)
        return self.public(doc)

    def delete_history(self,run_id,user):
        self._file(run_id)
        if user.get('role')!='admin' or user.get('via')=='control_key':raise ControlSyncError('仅管理员可删除同步记录 / Administrator required',403)
        doc=self.runs.find_one({'_id':run_id})
        if not doc:raise ControlSyncError('同步记录不存在 / Sync record not found',404)
        if doc.get('history_deleted_at'):return {'deleted':True}
        now=self.clock()
        if doc.get('history_action_until',0)>now or doc.get('lease_until',0)>now or doc.get('state') in ('transferring','applying') or (doc.get('state') not in ('complete','rejected','failed') and doc.get('expires_at',0)>now):
            raise ControlSyncError('同步仍在进行或等待确认，结束后可删除记录 / Finish the active or pending sync before deleting its record',409)
        query={'_id':run_id,'state':doc['state'],'$or':[{'lease_until':{'$exists':False}},{'lease_until':{'$lte':now}}]}
        query['$and']=[{'$or':[{'history_action_until':{'$exists':False}},{'history_action_until':{'$lte':now}}]}]
        if doc['state'] not in ('complete','rejected','failed'):query['expires_at']={'$lte':now}
        result=self.runs.update_one(query,{'$set':{'history_deleted_at':now,'history_deleted_by':user['username']}})
        if not result.matched_count:raise ControlSyncError('同步状态已变化，请刷新 / Sync state changed; refresh',409)
        # Keep the protocol receipt/journal for idempotent peer retries. Deleting
        # visible history never removes imported business data or cancels work.
        return {'deleted':True}

    def get(self, run_id, link_id=None):
        self.expire_confirmations()
        query = {"_id": text(run_id, 32)}
        if link_id is not None:
            query["link_id"] = link_id
        doc = self.runs.find_one(query)
        if not doc:
            raise ControlSyncError("同步任务不存在 / Transfer not found", 404)
        if self.public(doc)["state"] == "expired":
            raise ControlSyncError("同步计划已过期，请重新创建 / Transfer plan expired", 410)
        return doc

    def start(self,user,body):
        token=body.get('request_id')
        if token is None:return self._start(user,body)
        if not isinstance(token,str) or len(token)!=32 or any(c not in '0123456789abcdef' for c in token):
            raise ControlSyncError('同步请求编号无效 / Invalid sync request identifier')
        link=self.pairing.require_link(body.get('link_id'),paired=True)
        selected=categories(body.get('categories'))
        run_id=hashlib.sha256((user['username']+':'+link['_id']+':'+token).encode()).hexdigest()[:32]
        def existing():
            row=self.runs.find_one({'_id':run_id})
            if row and (row.get('owner')!=user['username'] or row.get('link_id')!=link['_id'] or row.get('flow')!=body.get('flow') or row.get('mode')!=body.get('mode') or row.get('categories')!=selected):
                raise ControlSyncError('同步请求编号已用于不同计划 / Request identifier belongs to another plan',409)
            return row
        old=existing()
        if old:return self.public(old)
        claims=self.repo.collection('control_sync_request_claims');nonce=secrets.token_hex(16);now=self.clock()
        try:
            claimed=claims.find_one_and_update({'_id':run_id,'$or':[{'lease_until':{'$exists':False}},{'lease_until':{'$lte':now}}]}, {'$set':{'nonce':nonce,'lease_until':now+300}},upsert=True,return_document=ReturnDocument.AFTER)
        except DuplicateKeyError:
            raise ControlSyncError('同一同步请求正在准备，请稍后查看记录 / The same request is being prepared; check its record shortly',409) from None
        try:
            old=existing()
            return self.public(old) if old else self._start(user,body,run_id)
        finally:claims.delete_one({'_id':run_id,'nonce':nonce})

    def _propose(self, link, doc):
        plan={k:doc[k] for k in ('_id','flow','mode','categories','expires_at')}
        # Optional early notification. Old peers reject the unknown action;
        # they still receive the original, fully validated final proposal.
        try:self.pairing.request(link,'prepare',plan)
        except ControlSyncError as error:
            if error.status not in (400,404):raise
        if doc['flow']=='push' and not doc.get('summary'):
            try:raw,summary=self.snapshots.export(doc['categories'],mode=doc['mode'])
            except Exception:
                try:self.pairing.request(link,'cancel_prepare',{'run_id':doc['_id']})
                except Exception:pass
                raise
            self._save(doc['_id'],raw);doc['summary']=summary
            self.runs.update_one({'_id':doc['_id']},{'$set':{'summary':summary}})
        try:return self.pairing.request(link,'propose',{**plan,**({'summary':doc['summary']} if doc.get('summary') else {})})
        except Exception:
            try:self.pairing.request(link,'cancel_prepare',{'run_id':doc['_id']})
            except Exception:pass
            raise

    def _start(self, user, body, run_id=None):
        link = self.pairing.require_link(body.get("link_id"), paired=True)
        if link["kind"] != "initiator":
            raise ControlSyncError("请在发起端选择方向 / Select direction on the initiating system")
        selected = categories(body.get("categories"))
        if not set(selected).issubset(link["categories"]):
            raise ControlSyncError("同步内容超出配对授权 / Categories exceed pairing authorization", 403)
        flow, mode = body.get("flow"), body.get("mode")
        if flow not in ("push", "pull") or mode not in ("incremental", "overwrite"):
            raise ControlSyncError("同步方向或模式无效 / Invalid direction or mode")
        if mode=="overwrite":self.snapshots.require_idle()
        run_id = run_id or secrets.token_hex(16)
        doc = {"_id": run_id, "link_id": link["_id"], "kind": "initiator", "flow": flow, "mode": mode,
               "categories": selected, "owner": user["username"], "state": "pending", "stage": "awaiting_peer_confirmation",
               "created_at": self.clock(), "expires_at": min(self.clock() + 1800, link["connection_expires_at"])}
        self.runs.insert_one(doc)
        try:
            response = self._propose(link,doc)
            self.runs.update_one({"_id": run_id}, {"$set": {"summary": response["run"]["summary"]}})
        except ControlSyncError as exc:
            self.runs.update_one({"_id": run_id}, {"$set": {"state": "failed", "error": str(exc), "stage": "proposal_failed"}})
            raise
        return self.public(self.get(run_id))

    def decide(self, run_id, user, accepted):
        doc = self.get(run_id)
        if doc["kind"] != "receiver":
            raise ControlSyncError("此计划需对端确认 / This plan needs peer confirmation")
        self.pairing.require_link(doc["link_id"], paired=True)
        state = "approved" if accepted is True else "rejected"
        if doc.get("state")=="preparing" and accepted is True:raise ControlSyncError("快照尚未就绪，请等待完整清单 / Wait for the complete snapshot manifest",409)
        if doc.get("state")=="preparing" and accepted is False:
            self.runs.update_one({"_id":run_id,"state":"preparing"},{"$set":{"state":"rejected","stage":"cancelled"}})
            return self.public(self.get(run_id))
        self.runs.update_one({"_id": run_id, "state": "pending", "confirm_expires_at":{"$gt":self.clock()}}, {"$set": {"state": state, "decided_by": user["username"], "stage": "ready" if accepted else "cancelled"}})
        return self.public(self.get(run_id))

    def status(self, run_id):
        doc = self.get(run_id)
        if doc["kind"] == "initiator" and doc["state"] not in ("complete", "rejected", "failed"):
            link = self.pairing.require_link(doc["link_id"], paired=True)
            remote = self.pairing.request(link, "run_status", {"run_id": run_id})["run"]
            if remote["state"] == "rejected":
                self.runs.update_one({"_id": run_id}, {"$set": {"state": "rejected", "stage": "confirmation_timeout" if remote.get("stage")=="confirmation_timeout" else "peer_rejected", "error":CONFIRMATION_TIMEOUT if remote.get("stage")=="confirmation_timeout" else ""}})
            elif remote["state"] in ("approved", "complete") and doc["state"] == "pending":
                self.runs.update_one({"_id": run_id, "state": "pending"}, {"$set": {"state": "ready", "stage": "ready"}})
            elif remote["state"] == "failed":
                self.runs.update_one({"_id": run_id}, {"$set": {"state": "failed", "error": remote.get("error"), "stage": "peer_failed"}})
        return self.public(self.get(run_id))

    def advance(self, run_id):
        nonce=secrets.token_hex(16);now=self.clock()
        claimed=self.runs.find_one_and_update({'_id':run_id,'history_deleted_at':{'$exists':False},'$or':[{'history_action_until':{'$exists':False}},{'history_action_until':{'$lte':now}}]}, {'$set':{'history_action_until':now+180,'history_action_nonce':nonce}})
        if not claimed:raise ControlSyncError('同步记录已删除或正在处理 / Sync record was deleted or is busy',409)
        try:
            doc = self.get(run_id)
            if doc["kind"] != "initiator":
                raise ControlSyncError("请在发起端续更新 / Continue on the initiating system")
            self.pairing.require_link(doc["link_id"], paired=True)
            if doc['state']=='failed' and doc.get('stage')=='proposal_failed':
                link=self.pairing.require_link(doc['link_id'],paired=True)
                response=self._propose(link,doc)
                self.runs.update_one({'_id':run_id,'state':'failed','stage':'proposal_failed'},
                    {'$set':{'summary':response['run']['summary'],'state':'pending','stage':'awaiting_peer_confirmation','error':''}})
                doc=self.get(run_id)
                self.status(run_id)
                doc=self.get(run_id)
                if doc['state'] not in ('ready','transferring'):return self.public(doc)
            if doc["state"] == "failed":
                self.runs.update_one({"_id": run_id}, {"$set": {"state": "ready", "error": ""}})
            else:
                self.status(run_id)
            claimed = self.runs.find_one_and_update({"_id": run_id, "state": {"$in": ["ready", "transferring"]},
                                                    "$or": [{"lease_until": {"$exists": False}}, {"lease_until": {"$lt": self.clock()}}]},
                                                   {"$set": {"state": "transferring", "lease_until": self.clock() + 300, "stage": "transferring"}}, return_document=ReturnDocument.AFTER)
            if claimed:
                threading.Thread(target=self._drive, args=(run_id,), daemon=True, name="watchtower-sync-" + run_id[:8]).start()
            return self.public(self.get(run_id))
        finally:
            self.runs.update_one({'_id':run_id,'history_action_nonce':nonce},{'$unset':{'history_action_until':'','history_action_nonce':''}})

    def _drive(self, run_id):
        stopped = self._keepalive(run_id)
        try:
            doc = self.get(run_id)
            link = self.pairing.require_link(doc["link_id"], paired=True)
            if doc["flow"] == "push":
                path = self._file(run_id)
                if not path.is_file():
                    raise ControlSyncError("待发送快照缺失，请重新创建同步计划 / Snapshot missing; create a new plan")
                if hashlib.sha256(path.read_bytes()).hexdigest() != doc["summary"]["sha256"]:
                    raise ControlSyncError("快照发生变更，请重新创建 / Snapshot changed; create a new plan")
                present = self.pairing.request(link, "chunk_status", {"run_id": run_id})["indices"]
                transferred = 0
                with path.open("rb") as handle:
                    for index in range((doc["summary"]["bytes"] + CHUNK_SIZE - 1) // CHUNK_SIZE):
                        raw = handle.read(CHUNK_SIZE)
                        if index not in present:
                            self.pairing.request(link, "receive_chunk", {"run_id": run_id, "index": index, "data": b64(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                        transferred += len(raw)
                        self.runs.update_one({"_id": run_id}, {"$set": {"transferred_bytes": transferred, "lease_until": self.clock() + 300}})
                result = self.pairing.request(link, "receive_commit", {"run_id": run_id, "sha256": doc["summary"]["sha256"]})["result"]
            else:
                transferred = 0
                for index in range((doc["summary"]["bytes"] + CHUNK_SIZE - 1) // CHUNK_SIZE):
                    part = self._part_path(run_id, index)
                    if not part.is_file():
                        response = self.pairing.request(link, "export_chunk", {"run_id": run_id, "index": index})
                        self._part_put(run_id, index, unb64(response["data"]), response["sha256"])
                    transferred += part.stat().st_size
                    self.runs.update_one({"_id": run_id}, {"$set": {"transferred_bytes": transferred, "lease_until": self.clock() + 300}})
                path = self._assemble(doc)
                self.runs.update_one({"_id": run_id}, {"$set": {"stage": "applying"}})
                with self.pairing.application(doc['link_id'],run_id):
                    result = self.snapshots.apply(run_id, path.read_bytes(), doc["categories"], doc["mode"])
                self.pairing.request(link, "complete", {"run_id": run_id, "result": result})
            self.runs.update_one({"_id": run_id}, {"$set": {"state": "complete", "stage": "complete", "result": result, "completed_at": self.clock()}, "$unset": {"lease_until": ""}})
        except Exception as exc:
            error = str(exc) if isinstance(exc, ControlSyncError) else "同步失败，备份和计划已保留，可重试 / Sync failed; backup and plan retained for retry"
            self.runs.update_one({"_id": run_id}, {"$set": {"state": "failed", "stage": "failed", "error": error}, "$unset": {"lease_until": ""}})
        finally:
            stopped.set()

    def _keepalive(self, run_id):
        stopped = threading.Event()
        def heartbeat():
            while not stopped.wait(15):
                try:
                    self.runs.update_one({"_id": run_id, "state": {"$in": ["transferring", "applying"]}}, {"$set": {"lease_until": self.clock() + 300}})
                    self.pairing.links.update_one({'applying_run':run_id},{'$set':{'applying_until':self.clock()+300}})
                except Exception:
                    pass
        threading.Thread(target=heartbeat, daemon=True, name="sync-transfer-lease").start()
        return stopped

    def peer(self, link, action, body):
        if action in ("prepare","propose"):
            run_id = body.get("_id")
            self._file(run_id)
            selected = categories(body.get("categories"))
            if not set(selected).issubset(link["categories"]):
                raise ControlSyncError("同步内容未获授权 / Categories not authorized", 403)
            flow, mode = body.get("flow"), body.get("mode")
            expiry = body.get("expires_at")
            if flow not in ("push", "pull") or mode not in ("incremental", "overwrite") or not isinstance(expiry, (int, float)) or not self.clock() < expiry <= min(self.clock() + 1801, link["connection_expires_at"]):
                raise ControlSyncError("同步计划无效 / Invalid transfer plan")
            old = self.runs.find_one({"_id": run_id})
            if old:
                if any(old.get(k) != body.get(k) for k in ("flow", "mode", "categories")) or old["link_id"] != link["_id"]:
                    raise ControlSyncError("同步计划重复且不一致 / Transfer id conflict", 409)
                if action=='prepare' and old.get('state')=='failed' and old.get('stage') in ('prepare_failed','prepare_timeout'):
                    self.runs.update_one({'_id':run_id,'state':'failed','stage':old['stage']},{'$set':{'state':'preparing','stage':'preparing_snapshot','prepare_expires_at':min(expiry,self.clock()+120)},'$unset':{'error':'','confirm_expires_at':''}})
                    return {'run':self.public(self.get(run_id,link['_id']))}
                if action=='prepare' or old.get('state')!='preparing':return {"run":self.public(old)}
            if mode=="overwrite":self.snapshots.require_idle()
            if action=='prepare':
                doc={"_id":run_id,"link_id":link['_id'],"kind":"receiver","flow":flow,"mode":mode,"categories":selected,"state":"preparing","stage":"preparing_snapshot","created_at":self.clock(),"expires_at":expiry,"prepare_expires_at":min(expiry,self.clock()+120)}
                try:self.runs.insert_one(doc)
                except DuplicateKeyError:
                    existing=self.get(run_id,link['_id'])
                    if any(existing.get(k)!=doc[k] for k in ('flow','mode','categories')):raise ControlSyncError("同步计划重复且不一致 / Transfer id conflict",409)
                    doc=existing
                return {'run':self.public(doc)}
            summary = body.get("summary")
            if flow == "pull":
                raw, summary = self.snapshots.export(selected, mode=mode)
                self._save(run_id, raw)
            if not isinstance(summary, dict) or not isinstance(summary.get("sha256"), str) or len(summary["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in summary["sha256"]) or isinstance(summary.get("bytes"), bool) or not isinstance(summary.get("bytes"), int) or not 0 < summary["bytes"] <= MAX_ARCHIVE:
                raise ControlSyncError("同步清单无效 / Invalid snapshot summary")
            doc = {"_id": run_id, "link_id": link["_id"], "kind": "receiver", "flow": flow, "mode": mode, "categories": selected,
                   "state": "pending", "stage": "awaiting_local_confirmation", "confirm_expires_at":self.clock()+30, "created_at": self.clock(), "expires_at": expiry, "summary": summary}
            if old and old.get('state')=='preparing':
                updated=self.runs.update_one({'_id':run_id,'link_id':link['_id'],'state':'preparing'},{'$set':doc,'$unset':{'prepare_expires_at':''}})
                if not updated.matched_count:raise ControlSyncError("同步准备已取消，请重新请求 / Preparation cancelled; request again",409)
            else:
                try:self.runs.insert_one(doc)
                except DuplicateKeyError:raise ControlSyncError("同步计划已创建 / Transfer already created",409) from None
            return {"run": self.public(doc)}
        doc = self.get(body.get("run_id"), link["_id"])
        if action=='cancel_prepare':
            self.runs.update_one({'_id':doc['_id'],'state':'preparing'},{'$set':{'state':'failed','stage':'prepare_failed','error':'快照准备未完成，请重试 / Snapshot preparation failed; retry'}})
            return {'ok':True}
        if action == "run_status":
            return {"run": self.public(doc)}
        if doc["state"] == "complete" and action == "receive_commit":
            if body.get("sha256") != doc["summary"]["sha256"]:
                raise ControlSyncError("已完成快照不匹配 / Completed snapshot mismatch", 409)
            return {"result": doc["result"]}
        if doc["state"] not in ("approved", "applying", "complete"):
            raise ControlSyncError("同步计划尚未确认 / Transfer plan not approved", 403)
        if action == "export_chunk" and doc["flow"] == "pull":
            index = body.get("index")
            self._part_path(doc["_id"], index)
            if index * CHUNK_SIZE >= doc["summary"]["bytes"]:
                raise ControlSyncError("数据块超出快照 / Chunk outside snapshot")
            with self._file(doc["_id"]).open("rb") as handle:
                handle.seek(index * CHUNK_SIZE); raw = handle.read(CHUNK_SIZE)
            return {"data": b64(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        if action == "chunk_status" and doc["flow"] == "push":
            return {"indices": self._parts_present(doc["_id"], doc["summary"]["bytes"])}
        if action == "receive_chunk" and doc["flow"] == "push":
            index = body.get("index")
            raw = unb64(body.get("data"), 3 * 1024 * 1024)
            self._part_path(doc["_id"], index)
            expected_size = min(CHUNK_SIZE, doc["summary"]["bytes"] - index * CHUNK_SIZE)
            if len(raw) != expected_size or expected_size <= 0:
                raise ControlSyncError("数据块大小与确认清单不一致 / Chunk size differs from approved plan")
            self._part_put(doc["_id"], index, raw, body.get("sha256"))
            transferred = sum(self._part_path(doc["_id"], i).stat().st_size for i in self._parts_present(doc["_id"], doc["summary"]["bytes"]))
            self.runs.update_one({"_id": doc["_id"]}, {"$set": {"transferred_bytes": transferred, "stage": "transferring"}})
            return {"received_bytes": transferred}
        if action == "complete" and doc["flow"] == "pull":
            result = body.get("result")
            if not isinstance(result, dict) or set(result) - {"inserted", "replaced", "conflicts", "files_written"}:
                raise ControlSyncError("同步结果无效 / Invalid transfer result")
            self.runs.update_one({"_id": doc["_id"]}, {"$set": {"state": "complete", "stage": "complete", "result": result, "completed_at": self.clock()}})
            return {"ok": True}
        if action == "receive_commit" and doc["flow"] == "push":
            if body.get("sha256") != doc["summary"]["sha256"]:
                raise ControlSyncError("同步包与确认的清单不一致 / Snapshot differs from the approved plan")
            claimed = self.runs.find_one_and_update({"_id": doc["_id"], "state": {"$in": ["approved", "applying"]},
                                                    "$or": [{"lease_until": {"$exists": False}}, {"lease_until": {"$lt": self.clock()}}]},
                                                   {"$set": {"state": "applying", "lease_until": self.clock() + 300, "stage": "applying"}}, return_document=ReturnDocument.AFTER)
            if not claimed:
                raise ControlSyncError("同步正在应用，请稍后重试 / Transfer is applying; retry later", 423)
            stopped = self._keepalive(doc["_id"])
            try:
                path = self._assemble(doc)
                with self.pairing.application(doc['link_id'],doc['_id']):
                    result = self.snapshots.apply(doc["_id"], path.read_bytes(), doc["categories"], doc["mode"])
                self.runs.update_one({"_id": doc["_id"]}, {"$set": {"state": "complete", "stage": "complete", "result": result, "completed_at": self.clock()}, "$unset": {"lease_until": ""}})
                return {"result": result}
            except Exception:
                self.runs.update_one({"_id": doc["_id"]}, {"$set": {"state": "approved", "stage": "retry_available"}, "$unset": {"lease_until": ""}})
                raise
            finally:
                stopped.set()
        raise ControlSyncError("同步操作或方向不匹配 / Transfer action/direction mismatch")
