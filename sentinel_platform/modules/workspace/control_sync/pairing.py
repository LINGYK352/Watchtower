"""Receiver-issued, expiring one-use pairing and two independent human approvals."""
from __future__ import annotations
from contextlib import contextmanager
import re

from datetime import datetime, timezone
import http.client
import ipaddress
import json
import platform
from pathlib import Path
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .security import ControlSyncError, canonical, decode_peer, digest, encode_peer, normalize_target, text, ttl
from .peer_poll import refresh_peer

CATEGORIES = ("assets", "findings", "reports", "policies", "configuration", "credentials", "task_history", "session_history")
MAX_PACKET = 8 * 1024 * 1024


def categories(value):
    if not isinstance(value, list) or not value or any(not isinstance(v, str) or v not in CATEGORIES for v in value):
        raise ControlSyncError("请选择有效同步内容 / Select valid sync categories")
    return sorted(set(value))


def transport(target: str, action: str, packet: dict, prefix="/api/control_sync/peer/", timeout_override=None):
    """Resolve, validate and pin the actual connection; never follow redirects or env proxies."""
    target = normalize_target(target)
    u = urlsplit(target)
    try:addresses = socket.getaddrinfo(u.hostname, u.port, type=socket.SOCK_STREAM)
    except OSError:raise ControlSyncError('目标域名无法解析 / Cannot resolve peer host',502) from None
    address = addresses[0][4][0]
    # Validation is repeated on the addresses that will actually be used, not an earlier DNS query.
    for a in addresses:
        ip = ipaddress.ip_address(a[4][0])
        normalize_target(f"{u.scheme}://{'['+str(ip)+']' if ip.version == 6 else str(ip)}:{u.port}")
    cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    timeout = 60 if action in ("receive_commit", "propose") else 5 if action=='status' else 15
    if timeout_override is not None:timeout=timeout_override
    options = {"timeout": timeout}
    if u.scheme == "https":
        options["context"] = ssl.create_default_context()
    connection = cls(u.hostname, u.port, **options)
    connection._create_connection = lambda _addr, timeout=60, source_address=None: socket.create_connection((address, u.port), timeout, source_address)
    try:
        connection.request("POST", prefix + action, body=canonical(packet), headers={"Content-Type": "application/json", "Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_PACKET + 1)
        if len(raw) > MAX_PACKET:
            raise ControlSyncError("同步响应过大 / Sync response too large", 413)
        if response.status != 200:
            # Surface a closed protocol reason, never arbitrary peer text/HTML.
            try: peer_error = json.loads(raw)
            except (ValueError, UnicodeError): peer_error = {}
            if response.status == 409 and isinstance(peer_error, dict) and peer_error.get("reason") == "sync_not_idle":
                from .security import idle_error
                raise idle_error(peer_error.get("blockers"), peer=True)
            status=409 if response.status in (400,401,403,404,409,410) else 502
            raise ControlSyncError(f"对端拒绝请求（HTTP {response.status}）；请检查工作组/连接是否已关闭、凭证期限及版本 / Peer rejected request (HTTP {response.status}); check group/link closure, credential expiry and version",status)
        try:result=json.loads(raw)
        except ValueError:raise ControlSyncError('对端响应不是有效JSON / Peer response is not valid JSON',502) from None
        if not isinstance(result,dict):raise ControlSyncError('对端响应结构无效 / Invalid peer response structure',502)
        return result
    except ControlSyncError:
        raise
    except ssl.SSLCertVerificationError:
        raise ControlSyncError("对端HTTPS证书校验失败，请核对证书链和域名 / Peer HTTPS certificate verification failed; check its chain and hostname", 502) from None
    except (TimeoutError, socket.timeout):
        raise ControlSyncError("连接同步目标超时：请检查接收端监听及防火墙；若Windows无法接收入站连接，可让Windows主动连接VM并拉取数据 / Peer connection timed out. Check receiver and firewall; Windows can instead connect to the VM and pull data", 502, reason="peer_network") from None
    except ConnectionRefusedError:
        raise ControlSyncError("同步目标拒绝连接：接收端口未监听或地址/端口不正确 / Peer connection refused; check the listening port and address", 502, reason="peer_network") from None
    except (OSError, ValueError, http.client.HTTPException):
        raise ControlSyncError("无法连接同步目标，请检查地址、端口和防火墙 / Cannot connect to peer; check address, port and firewall", 502, reason="peer_network") from None
    finally:
        connection.close()


class Pairings:
    def __init__(self, repo, secrets_store, clock=time.time, send=transport):
        self.repo, self.secrets, self.clock, self.send = repo, secrets_store, clock, send
        self.links = repo.collection("control_sync_links")
        self.nonces = repo.collection("control_sync_nonces")
        self.history = repo.collection("control_sync_history")
        self.nonces.create_index("expires", expireAfterSeconds=0)
        self.history.create_index("target", unique=True)
        ident = repo.collection("control_sync_identity")
        ident.update_one({"_id": "local"}, {"$setOnInsert": {"instance_id": secrets.token_hex(16)}}, upsert=True)
        self.instance_id = ident.find_one({"_id": "local"})["instance_id"]
        self.peer_handler = None
        from .node_route import NodeRoutes
        self.node_routes=NodeRoutes(self)

    def identity(self):
        from sentinel_platform.core.client_identity import describe
        return describe(self.instance_id)

    def create(self, user, body):
        pair_ttl = ttl(body.get("expires_in"), 60, 3600)
        connection_ttl = ttl(body.get("connection_expires_in"), 300, 90 * 86400)
        permitted = categories(body.get("categories"))
        label = text(body.get("name", "Watchtower"), 80)
        if self.links.count_documents({"kind": "receiver", "state": {"$in": ["available", "pending"]}, "pair_expires_at": {"$gt": self.clock()}}) >= 20:
            raise ControlSyncError("临时配对Key过多，请先撤销 / Revoke unused pairing keys first", 429)
        public_target=normalize_target(body['public_target'],resolve=False) if body.get('public_target') else ''
        link_id, secret = secrets.token_hex(16), secrets.token_urlsafe(32)
        now = self.clock()
        doc = {"_id": link_id, "kind": "receiver", "name": label, "state": "available", "owner": user["username"],
               "local": self.identity(), "created_at": now, "pair_expires_at": now + pair_ttl,
               "connection_duration": connection_ttl, "connection_expires_at": None, "categories": permitted,
               "pair_hash": digest(secret), "pair_secret": self.secrets.seal(secret, link_id + ":pair"),
               "source_confirmed": False, "receiver_confirmed": False}
        self.links.insert_one(doc)
        if body.get('node') is not None:
            try:
                doc.update(self.node_routes.configure(doc,user,body['node']))
                self.links.update_one({'_id':link_id},{'$set':{k:doc[k] for k in ('route_mode','node_config')}})
            except ControlSyncError as exc:
                self.links.update_one({'_id':link_id},{'$set':{'state':'revoked','node_error':str(exc)},'$unset':{'pair_secret':'','pair_hash':''}})
                raise
        from .. import preferences
        preferences.save(self.repo,user,'sync_target',public_target)
        return {**self.public(doc), "key": f"wt_pair.{link_id}.{secret}"}

    def expire_confirmations(self):
        # Mongo is authoritative across workers and browser refreshes. Older
        # pending links receive one deadline; an established pair is untouched.
        now = self.clock()
        # Never trust a legacy optimistic paired state without both approvals.
        self.links.update_many({"state":"paired","$or":[{"source_confirmed":{"$ne":True}},{"receiver_confirmed":{"$ne":True}}]},
            {"$set":{"state":"pending","confirm_expires_at":now+30},"$unset":{"paired_at":"","connection_expires_at":""}})
        self.links.update_many({'state':'pending','confirm_expires_at':{'$exists':False}},
                               {'$set':{'confirm_expires_at':now+30}})
        self.links.update_many({'state':'pending','confirm_expires_at':{'$lte':now}},
                               {'$set':{'state':'rejected','reject_reason':'confirmation_timeout'}})

    def public(self, doc):
        out = {k: doc.get(k) for k in ("_id", "kind", "name", "state", "owner", "local", "remote", "target", "created_at", "pair_expires_at", "connection_expires_at", "categories", "source_confirmed", "receiver_confirmed", "paired_at", "peer_error", "peer_retry_at", "confirm_expires_at", "reject_reason")}
        if doc.get("state")=="paired" and not (doc.get("source_confirmed") is True and doc.get("receiver_confirmed") is True):
            out["state"]="pending"
        expiry = doc.get("connection_expires_at") if doc.get("state") == "paired" else doc.get("pair_expires_at")
        if expiry is not None and self.clock() >= expiry and doc.get("state") not in ("rejected", "revoked"):
            out["state"] = "expired"
        out['confirmation_remaining']=max(0,min(30,(doc.get('confirm_expires_at') or 0)-self.clock()))
        out['route_mode']=doc.get('route_mode','direct')
        out['node_error']=doc.get('node_error') or ''
        if doc.get('kind')=='receiver' and doc.get('route_mode')=='node' and out['state']=='available':out['node_descriptor']=self.node_routes.descriptor(doc)
        return out

    def list(self):
        self.expire_confirmations()
        return [self.public(d) for d in self.links.find({'deleted_at':{'$exists':False}}).sort("created_at", -1).limit(200)]

    def remember(self, target, label):
        self.history.update_one({"target": target}, {"$set": {"name": label, "last_used_at": self.clock()}}, upsert=True)

    def history_list(self):
        return [{"target": d["target"], "name": d.get("name", ""), "last_used_at": d.get("last_used_at")} for d in self.history.find({}).sort("last_used_at", -1).limit(30)]

    def connect(self, user, body):
        target = normalize_target(body.get("target"))
        raw = text(body.get("key"), 100)
        parts = raw.split(".")
        if len(parts) != 3 or parts[0] != "wt_pair" or len(parts[1]) != 32 or len(parts[2]) != 43:
            raise ControlSyncError("配对Key格式无效 / Invalid pairing key")
        link_id, secret = parts[1:]
        descriptor=self.node_routes.validate(body['node_descriptor'],link_id) if body.get('node_descriptor') else None
        if descriptor:return self.node_routes.connect(user,body,link_id,secret,descriptor)
        if self.links.find_one({"_id": link_id}):
            raise ControlSyncError("该Key已在本机使用，不能重复或连接自己 / Key already used locally; cannot pair with self", 409)
        channel = secrets.token_urlsafe(32)
        payload={"identity": self.identity(), "channel": channel}
        packet = encode_peer(secret, link_id, "pair",payload,self.clock)
        answer=self.send(target,'pair',packet)
        received = decode_peer(secret,answer,"pair:response",self.clock)
        if received.get("error"):
            raise ControlSyncError(received["error"], received.get("status", 400))
        remote = received["link"]
        if remote.get("local", {}).get("instance_id") == self.instance_id:
            raise ControlSyncError("不能同步到当前系统 / Cannot pair with the same system")
        local = {"_id": link_id, "kind": "initiator", "name": text(body.get("name", target), 100), "owner": user["username"],
                 "local": self.identity(), "remote": remote["local"], "target": target,
                 "state": "pending", "created_at": self.clock(), "pair_expires_at": remote["pair_expires_at"],
                 "confirm_expires_at": self.clock()+max(0,min(30,remote.get("confirmation_remaining",30))),
                 "connection_expires_at": None, "categories": remote["categories"], "source_confirmed": False, "receiver_confirmed": False,
                 "channel": self.secrets.seal(channel, link_id + ":channel")}
        try:
            self.links.insert_one(local)
        except DuplicateKeyError:
            raise ControlSyncError("配对已在处理中 / Pairing already in progress", 409) from None
        self.remember(target, local["name"])
        return self.public(local)

    def secret_for(self, doc, pair=False):
        field = "pair_secret" if pair else "channel"
        if field not in doc:
            raise ControlSyncError("配对Key已消费或连接不可用 / Pairing key consumed or link unavailable", 401)
        return self.secrets.open(doc[field], doc["_id"] + (":pair" if pair else ":channel"))

    def require_link(self, link_id, paired=False):
        self.expire_confirmations()
        doc = self.links.find_one({"_id": text(link_id, 32)})
        states = ("paired",) if paired else ("pending", "paired")
        if not doc or doc.get("state") not in states:
            raise ControlSyncError("连接未配对或已撤销 / Link unpaired or revoked", 409)
        self.require_owner(doc)
        expires = doc.get("connection_expires_at") if doc["state"] == "paired" else doc.get("pair_expires_at")
        if not expires or self.clock() >= expires:
            raise ControlSyncError("配对或连接授权已过期 / Pairing or connection authorization expired", 401)
        return doc

    def require_owner(self, doc):
        if doc.get("owner") == "master":
            from sentinel_platform.core import get_config
            cfg = get_config()
            valid = cfg.section("SENTINEL", "API_KEY", default="") or cfg.section("API_KEY", default="") or cfg.section("ARL", "API_KEY", default="")
        else:
            owner = self.repo.collection("user").find_one({"username": doc.get("owner")}, {"role": 1, "disabled": 1})
            valid = owner and owner.get("role") == "admin" and not owner.get("disabled")
        if not valid:
            raise ControlSyncError("连接创建者已失去管理员权限 / Link creator is no longer an administrator", 403)

    def request(self, doc, action, body):
        fresh = self.require_link(doc["_id"], paired=action not in ("status", "confirm", "reject"))
        if fresh["kind"] != "initiator":
            raise ControlSyncError("由发起端操作已配对目标 / Use the initiating system for this operation")
        if fresh.get('route_mode')=='node' and action not in ('status','confirm','reject'):
            route=self.node_routes.link_config(fresh,'node_config') or {}
            if (route.get('grant') or {}).get('claim',{}).get('expires_at',0)<=self.clock():
                self.request(fresh,'status',{})
                fresh=self.require_link(fresh['_id'],paired=True)
        secret = self.secret_for(fresh)
        # Retry only idempotent protocol operations, with a new authenticated
        # nonce each time. Stable run/chunk IDs retain the original receipt.
        attempts=2 if action in ('status','confirm','reject','prepare','cancel_prepare','propose','run_status','chunk_status','export_chunk','receive_chunk','receive_commit') else 1
        for attempt in range(attempts):
            packet=encode_peer(secret,fresh['_id'],action,body,self.clock)
            try:
                answer=self.node_routes.send(fresh,action,packet) if fresh.get('route_mode')=='node' else self.send(fresh['target'],action,packet)
                break
            except ControlSyncError as exc:
                if exc.reason!='peer_network' or attempt+1>=attempts:raise
                time.sleep(.25)
        response = decode_peer(secret,answer,action+':response',self.clock)
        if response.get("error"):
            if response.get("reason") == "sync_not_idle":
                from .security import idle_error
                raise idle_error(response.get("blockers"), peer=True)
            raise ControlSyncError(response["error"], response.get("status", 400))
        if fresh.get('route_mode')=='node':self.node_routes.remember(fresh,response.get('node_config'))
        return response

    def refresh(self, link_id, background=False):
        connecting=self.links.find_one({'_id':link_id,'kind':'initiator','route_mode':'node','state':'connecting','deleted_at':{'$exists':False}})
        if connecting:return self.node_routes.resume(connecting)
        doc = self.require_link(link_id)
        if doc["kind"] == "receiver":
            return self.public(doc)
        def fetch(current):
            status=self.request(current,'status',{})['link']
            return {k:status.get(k) for k in ('state','source_confirmed','receiver_confirmed','connection_expires_at','paired_at','reject_reason')}
        return refresh_peer(self.links,doc,fetch,self.public,self.clock,background)

    def advance(self, link_id):
        self.expire_confirmations()
        now = self.clock()
        doc = self.links.find_one({"_id": link_id})
        if not doc:
            raise ControlSyncError("连接不存在 / Link not found", 404)
        self.links.find_one_and_update({"_id": link_id, "state": "pending", "pair_expires_at": {"$gt": now},
                                       "source_confirmed": True, "receiver_confirmed": True, "confirm_expires_at":{"$gt":now}},
                                      {"$set": {"state": "paired", "paired_at": now, "connection_expires_at": now + doc["connection_duration"]},
                                       "$unset": {"pair_secret": "", "pair_hash": ""}}, return_document=ReturnDocument.AFTER)
        return self.links.find_one({"_id": link_id})

    def confirm(self, link_id, user):
        doc = self.require_link(link_id)
        if doc["kind"] == "initiator":
            status = self.request(doc, "confirm", {})["link"]
            self.links.update_one({"_id": doc["_id"], "state": {"$nin": ["revoked", "rejected"]}}, {"$set": {k: status.get(k) for k in ("state", "source_confirmed", "receiver_confirmed", "connection_expires_at", "paired_at", "reject_reason")}})
        else:
            # This method is reachable only through the logged-in administrator UI route.
            self.links.update_one({"_id": doc["_id"], "state": "pending", "pair_expires_at": {"$gt": self.clock()}, "confirm_expires_at":{"$gt":self.clock()}},
                                  {"$set": {"receiver_confirmed": True, "receiver_confirmed_by": user["username"]}})
            self.advance(doc["_id"])
        return self.public(self.links.find_one({"_id": doc["_id"]}))

    def revoke(self, link_id):
        doc = self.links.find_one({"_id": text(link_id, 32)})
        if not doc:
            raise ControlSyncError("连接不存在 / Link not found", 404)
        if doc["kind"] == "initiator" and self.public(doc)["state"] in ("pending", "paired"):
            try:
                self.request(doc, "reject", {})
            except ControlSyncError:
                pass
        self.links.update_one({"_id": doc["_id"]}, {"$set": {"state": "revoked"}, "$unset": {"pair_secret": "", "pair_hash": "", "channel": ""}})
        self.cancel_plans(doc['_id']);self.node_routes.close(doc)
        return self.public(self.links.find_one({"_id": doc["_id"]}))

    @contextmanager
    def application(self,link_id,run_id):
        """Shared Mongo gate makes deletion and committing business data mutually exclusive."""
        self.require_link(link_id,paired=True)
        claimed=self.links.find_one_and_update({'_id':link_id,'state':'paired','deleted_at':{'$exists':False},
            '$or':[{'applying_until':{'$exists':False}},{'applying_until':{'$lte':self.clock()}}]},
            {'$set':{'applying_run':run_id,'applying_until':self.clock()+300}},return_document=ReturnDocument.AFTER)
        if not claimed:raise ControlSyncError('连接已撤销或数据正在应用 / Link revoked or data application in progress',409)
        try:yield
        finally:self.links.update_one({'_id':link_id,'applying_run':run_id},{'$unset':{'applying_run':'','applying_until':''}})

    def delete(self,link_id,user):
        if user.get('role')!='admin' or user.get('via')=='control_key':raise ControlSyncError('需要管理员登录 / Administrator login required',403)
        link_id=text(link_id,32)
        if not re.fullmatch('[0-9a-f]{32}',link_id):raise ControlSyncError('连接标识无效 / Invalid link id')
        old=self.links.find_one_and_update({'_id':link_id,'deleted_at':{'$exists':False},
            '$or':[{'applying_until':{'$exists':False}},{'applying_until':{'$lte':self.clock()}}]},
            {'$set':{'state':'revoked','deleted_at':self.clock(),'deleted_by':user['username']},'$unset':{'pair_secret':'','pair_hash':'','channel':''}},return_document=ReturnDocument.BEFORE)
        if old is None:
            existing=self.links.find_one({'_id':link_id})
            if not existing:raise ControlSyncError('连接不存在 / Link not found',404)
            if 'deleted_at' not in existing:raise ControlSyncError('数据正在应用，请完成后删除 / Wait for data application to finish',409)
            self.cancel_plans(link_id)
            return {'deleted':True,'peer_notified':None}
        self.cancel_plans(link_id)
        notified=False
        if old.get('kind')=='initiator' and old.get('channel') and self.public(old)['state'] in ('paired','pending'):
            try:
                secret=self.secrets.open(old['channel'],link_id+':channel');packet=encode_peer(secret,link_id,'reject',{},self.clock)
                response=self.node_routes.send(old,'reject',packet,seconds=2) if old.get('route_mode')=='node' else transport(old['target'],'reject',packet,timeout_override=2) if self.send is transport else self.send(old['target'],'reject',packet)
                answer=decode_peer(secret,response,'reject:response',self.clock);notified=not answer.get('error')
            except ControlSyncError:pass
        self.links.update_one({'_id':link_id},{'$set':{'peer_notified':notified}})
        self.node_routes.close(old)
        return {'deleted':True,'peer_notified':notified}

    def cancel_plans(self,link_id):
        # An already started application finishes under its shared gate. Awaiting plans
        # must not survive as confirmation popups after credentials are removed.
        self.repo.collection('control_sync_runs').update_many({'link_id':link_id,
            'state':{'$in':['pending','approved','ready','transferring']},'stage':{'$ne':'applying'}},
            {'$set':{'state':'rejected','stage':'link_revoked','error':'连接已撤销 / Link revoked'}})

    def handle_peer(self, action, packet, via_peer=None):
        self.expire_confirmations()
        pair = action == "pair"
        link_id = text((packet or {}).get("id"), 32)
        doc = self.links.find_one({"_id": link_id, "kind": "receiver"})
        if not doc:
            raise ControlSyncError("同步认证失败 / Sync authentication failed", 401)
        self.require_owner(doc)
        if pair:
            if doc['state'] not in ('available','pending') or self.clock()>=doc['pair_expires_at']:
                raise ControlSyncError("配对Key已过期或已使用 / Pairing key expired or already used", 401)
        elif action not in ("status", "confirm", "reject"):
            doc = self.require_link(link_id, paired=True)
        elif self.public(doc)["state"] == "expired" or doc["state"] not in ("pending", "paired", "rejected", "revoked") or "channel" not in doc:
            raise ControlSyncError("连接已过期或已撤销 / Link expired or revoked", 401)
        secret = self.secret_for(doc, pair=pair)
        body = decode_peer(secret, packet, action, self.clock)
        if doc.get('route_mode')=='node':
            from ..collaboration_cache import crypto
            public=body.get('transport_public') if pair else doc.get('remote_crypto')
            try:valid=bool(via_peer and public and crypto.peer_id(public)==via_peer)
            except ValueError:valid=False
            if not valid:raise ControlSyncError('迁移中转身份不匹配 / Migration relay identity mismatch',403)
        # Reserve only after successful authentication. Unique _id closes cross-worker replay.
        try:
            self.nonces.insert_one({"_id": digest(link_id + ":" + packet["nonce"]), "expires": datetime.fromtimestamp(self.clock() + 300, timezone.utc)})
        except DuplicateKeyError:
            raise ControlSyncError("同步请求已使用 / Sync request already used", 409) from None
        try:
            if pair:
                identity = body.get("identity")
                if not isinstance(identity, dict) or not isinstance(identity.get("instance_id"), str) or len(identity["instance_id"]) != 32 or identity["instance_id"] == self.instance_id:
                    raise ControlSyncError("对端系统标识无效 / Invalid peer identity")
                channel = text(body.get("channel"), 43)
                if doc['state']=='pending':
                    if channel!=self.secret_for(doc) or identity.get('instance_id')!=(doc.get('remote') or {}).get('instance_id') or (doc.get('route_mode')=='node' and (body.get('request_id')!=doc.get('node_pair_request') or body.get('transport_public')!=doc.get('remote_crypto'))):
                        raise ControlSyncError('配对Key已被其它申请消费 / Pairing key consumed by a different request',401)
                    new=doc
                else:new = self.links.find_one_and_update({"_id": link_id, "state": "available", "pair_expires_at": {"$gt": self.clock()}},
                                                     {"$set": {"state": "pending", "confirm_expires_at":self.clock()+30, "remote": {k: identity.get(k) for k in ("instance_id", "platform", "version", "name")},
                                                               **({'remote_crypto':body['transport_public'],'node_pair_request':text(body.get('request_id'),32)} if doc.get('route_mode')=='node' else {}),
                                                               "channel": self.secrets.seal(channel, link_id + ":channel")}}, return_document=ReturnDocument.AFTER)
                if not new:
                    existing=self.links.find_one({'_id':link_id,'state':'pending'})
                    if doc.get('route_mode')=='node' and existing and existing.get('node_pair_request')==body.get('request_id') and existing.get('remote_crypto')==body.get('transport_public') and self.secret_for(existing)==channel:
                        new=existing
                    else:raise ControlSyncError("配对Key已被占用 / Pairing key already claimed", 409)
                result = {"link": self.public(new)}
            elif action == "status":
                result = {"link": self.public(self.links.find_one({"_id": link_id}))}
            elif action == "confirm":
                self.links.update_one({"_id": link_id, "state": "pending", "pair_expires_at": {"$gt": self.clock()}, "confirm_expires_at":{"$gt":self.clock()}}, {"$set": {"source_confirmed": True}})
                result = {"link": self.public(self.advance(link_id))}
            elif action == "reject":
                self.links.update_one({"_id": link_id}, {"$set": {"state": "rejected"}, "$unset": {"pair_secret": "", "pair_hash": ""}})
                self.cancel_plans(link_id)
                self.node_routes.close(doc,defer=True)
                result = {"link": self.public(self.links.find_one({"_id": link_id}))}
            elif self.peer_handler:
                result = self.peer_handler(doc, action, body)
            else:
                raise ControlSyncError("同步操作不支持 / Unsupported sync action", 404)
        except ControlSyncError as exc:
            result = {"error": str(exc), "status": exc.status, **({"reason": exc.reason, "blockers": getattr(exc,"blockers",[])} if exc.reason == "sync_not_idle" else {})}
        if not result.get('error') and doc.get('route_mode')=='node':
            config=self.node_routes.response_config(self.links.find_one({'_id':link_id}))
            if config:result['node_config']=config
        return encode_peer(secret, link_id, action + ":response", result, self.clock)
