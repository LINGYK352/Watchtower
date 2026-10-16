"""system/guard_log —— 智能闸刀拦截日志（capped 环形集合，固定容量 + FIFO 覆盖最早）。

闸刀（AI 渗透出站请求的放行/拦截）是**正常业务事件**，不该塞进 log_monitor（那是 WARNING+
程序报错日志，会被污染）。单独写 `guard_log` 集合，用 MongoDB capped collection 实现
「固定大小 + 满了自动覆盖最早」，无需手写轮转。容量可调（默认 500MB）。

**无 ROLE**（纯业务叶子）：经 registry 以字符串键 `"guard_log_service"` 注册（照
log_service/audit_service 先例），router `endpoints/guard_log.py` + 未来 ai_pentest 闸刀取用。
不放 HTTP 路由。`record` 供闸刀经 registry 调写事件（接口先立，非孤岛）。

迁移来源：app/services/guard_log.py（capped 生命周期 + record + list + stat）。净室重写。
capped 需 db 级命令（create_collection/collMod/collstats），经 `get_repo().collection(x).database`
取 pymongo Database；无 pymongo 的测试环境（fake repo 无 .database）优雅降级——insert/list 仍走 fake。

**禁止硬限制参数**：list `size` 客户端定不砍上限（缺省 30 仅默认）；容量 set_size_mb 只保物理下限
（capped 必须 >0，floor 1MB）不设人为上限（用户自主决定磁盘占用）。
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from sentinel_platform.core import get_repo, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

COLL = Collections.TRAFFIC_LOG
META = Collections.GUARD_LOG_META
DEFAULT_SIZE_MB = 500
MIN_SIZE_MB = 1                         # 物理下限（capped 容量必须 >0），非人为业务限制
DEFAULT_RETENTION_DAYS = 30
# 注：不设 MAX 上限（守禁止硬限制参数——用户自主决定磁盘占用）

_ensured: Dict[str, int] = {"size_bytes": 0}   # 进程内缓存，避免每次插入都查 collstats


def _coll():
    return get_repo().collection(COLL)


def _db():
    """取 pymongo Database（capped 命令用）；fake repo/无 pymongo 时返回 None（降级）。"""
    try:
        return _coll().database
    except Exception:
        return None


def _policy():
    collection=get_repo().collection(META)
    return collection.find_one({'_id':'traffic-storage-policy'}) or collection.find_one({'name':'default'}) or {}


def get_size_mb() -> int:
    """当前 capped 容量配置（MB），下限 1，无上限。库不可用降级默认。"""
    try:
        doc = _policy()
        return max(MIN_SIZE_MB, int(doc.get("size_mb", DEFAULT_SIZE_MB)))
    except (TypeError, ValueError):
        return DEFAULT_SIZE_MB
    except Exception:
        return DEFAULT_SIZE_MB


def get_retention_days():
    try:
        doc=_policy()
        return max(1,int(doc.get('retention_days',DEFAULT_RETENTION_DAYS)))
    except Exception:return DEFAULT_RETENTION_DAYS


def _expire_at(stamp,days=None):
    from datetime import datetime,timedelta
    return datetime.utcfromtimestamp(float(stamp))+timedelta(days=days or get_retention_days())


def maintain():
    """Shared size/age policy; regular TTL collection allows both constraints."""
    db=_db()
    if db is None:return
    days=get_retention_days();cutoff=time.time()-days*86400
    _coll().delete_many({'ts':{'$lt':cutoff}})
    stats=db.command('collstats',COLL)
    budget=get_size_mb()*1024*1024
    while int(stats.get('size') or 0)>budget:
        rows=list(_coll().find({},{'_id':1,'row_bytes':1}).sort([('ts',1),('_id',1)]).limit(100))
        if not rows:break
        chosen=[];released=0
        for row in rows:
            chosen.append(row['_id']);released+=int(row.get('row_bytes') or 256)
            if released>=int(stats.get('size') or 0)-budget:break
        _coll().delete_many({'_id':{'$in':chosen}})
        stats=db.command('collstats',COLL)


def migrate_legacy():
    """Idempotent history import; never drops a store an old worker may still use."""
    db=_db()
    if db is None or Collections.GUARD_LOG not in db.list_collection_names():return
    meta=get_repo().collection(META)
    from pymongo import ReturnDocument,UpdateOne
    token=str(time.time_ns())
    try:
        lease=meta.find_one_and_update({'_id':'traffic-history-migration','$or':[{'until':{'$lt':time.time()}},{'until':{'$exists':False}}]},
          {'$set':{'token':token,'until':time.time()+60}},upsert=True,return_document=ReturnDocument.AFTER)
    except Exception:return
    if not lease or lease.get('token')!=token:return
    try:
        days=get_retention_days();last=lease.get('last_id')
        query={'ts':{'$gte':time.time()-days*86400}}
        if last is not None:query['_id']={'$gt':last}
        rows=list(db[Collections.GUARD_LOG].find(query).sort('_id',1).limit(1000))
        ops=[]
        for row in rows:
            row['expire_at']=_expire_at(row.get('ts',time.time()),days);row['event']='guard';row['source']='legacy_guard'
            ops.append(UpdateOne({'_id':row['_id']},{'$setOnInsert':row},upsert=True))
        if ops:_coll().bulk_write(ops,ordered=False)
        if rows:meta.update_one({'_id':lease['_id'],'token':token},{'$max':{'last_id':rows[-1]['_id']}})
    finally:meta.update_one({'_id':'traffic-history-migration','token':token},{'$set':{'until':0}})


def ensure_capped(size_bytes=None):
    # Compatibility function name; TTL requires a regular collection.
    size_bytes=size_bytes or get_size_mb()*1024*1024
    if _ensured['size_bytes']==size_bytes:return
    db=_db()
    if db is not None:
        _coll().create_index('expire_at',expireAfterSeconds=0)
        _coll().create_index([('session_id',1),('ts',-1)])
        migrate_legacy()
    _ensured['size_bytes']=size_bytes


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class GuardLogServiceImpl:
    """拦截日志能力（无 ROLE，字符串键 guard_log_service 注册）。"""

    def record(self, method: str, url: str, mode: str, allow: bool, level: str,
               reason: str = "", session_id: str = "", site: str = "", **meta) -> None:
        """写一条闸刀事件到拦截日志（capped，满了自动覆盖最早）。**异常吞掉绝不反噬业务**。

        供未来 ai_pentest 闸刀经 `get_registry().get("guard_log_service").record(...)` 调。
        level：safe/danger/ambiguous/ai_safe/ai_danger；mode：src/redteam/conservative。
        """
        try:
            ensure_capped()
            owner=str(meta.get('owner') or '')
            import re
            if not owner and re.fullmatch('[0-9a-fA-F]{24}',session_id or ''):
                from bson import ObjectId
                current=get_repo().collection(Collections.PENTEST_SESSION).find_one({'_id':ObjectId(session_id)},{'owner':1}) or {}
                owner=current.get('owner','')
            row = {
                "owner":owner,
                "expire_at": _expire_at(time.time()), "expiry_revision":int(_policy().get("expiry_revision",0)),
                "request_preview_b64":meta.get('request_preview_b64',''),
                "response_preview_b64":meta.get('response_preview_b64',''),
                "preview_truncated":bool(meta.get('preview_truncated')),
                "truncation_reason":str(meta.get('truncation_reason',''))[:300],
                "capture_note":str(meta.get('capture_note',''))[:300],
                "event": meta.get('event','guard'), "source":str(meta.get('source','guard'))[:80],
                "status_code": meta.get('status_code'),
                "method": (method or "").upper(),
                "url": (url or "")[:500],
                "mode": mode,
                "allow": bool(allow),
                "level": level,
                "reason": (reason or "")[:300],
                "session_id": session_id,
                "site": site,
                "save_date": _now_str(),
                "ts": int(time.time()),
            }
            from bson import BSON,ObjectId
            row['_id']=ObjectId();row['row_bytes']=0;row['row_bytes']=len(BSON.encode(row))
            result = _coll().insert_one(row)
            maintain()
            return str(result.inserted_id)
        except Exception:
            pass    # Traffic audit never breaks the caller.

    def list_logs(self, allow: Any = None, mode: str = "", level: str = "",
                  page: int = 1, size: int = 30, session_id: str = "", owner: Optional[str] = None, metadata_only:bool=False) -> Dict[str, Any]:
        """拦截日志列表（capped $natural 倒序=最新在前 + 过滤 + 分页）。
        size 缺省 30 仅默认，客户端传多大都透传不砍（禁硬限制参数）。库不可用降级空。"""
        try:
            page = max(1, int(page or 1))
            size = max(1, int(size or 30))
        except (TypeError, ValueError):
            page, size = 1, 30
        q: Dict[str, Any] = {'ts':{'$gte':time.time()-get_retention_days()*86400}}
        if owner is not None:q['owner']=owner
        if session_id:q["session_id"] = str(session_id).strip()
        if allow is not None:
            q["allow"] = bool(allow)
        if mode:
            q["mode"] = mode
        if level:
            q["level"] = level
        try:
            ensure_capped()
            migrate_legacy()
            coll = _coll()
            total = coll.count_documents(q)
            items = []
            for d in coll.find(q).sort([('ts',-1),('_id',-1)]).skip((page - 1) * size).limit(size):
                d["_id"] = str(d["_id"])
                d.pop('expire_at',None)
                if metadata_only:
                    d.pop('request_preview_b64',None);d.pop('response_preview_b64',None)
                items.append(d)
            return {"items": items, "total": total, "page": page, "size": size}
        except Exception as exc:
            logger.debug("guard_log: list failed: %s", exc)
            return {"items": [], "total": 0, "page": page, "size": size}

    def read_log(self,identity,owner=None):
        from bson import ObjectId
        try:identifier=ObjectId(identity)
        except Exception:return None
        query={'_id':identifier,'ts':{'$gte':time.time()-get_retention_days()*86400}}
        if owner is not None:query['owner']=owner
        row=_coll().find_one(query)
        if row:row['_id']=str(row['_id']);row.pop('expire_at',None)
        return row

    def stat(self) -> Dict[str, Any]:
        """拦截日志统计：总数/拦截/放行 + 当前容量配置。库不可用降级 0。"""
        try:
            ensure_capped()
            maintain()
            coll = _coll()
            return {
                "total": coll.count_documents({}),
                "blocked": coll.count_documents({"allow": False}),
                "allowed": coll.count_documents({"allow": True}),
                "size_mb": get_size_mb(),
                "default_size_mb": DEFAULT_SIZE_MB, "retention_days":get_retention_days(),
            }
        except Exception as exc:
            logger.debug("guard_log: stat failed: %s", exc)
            return {"total": 0, "blocked": 0, "allowed": 0,
                    "size_mb": get_size_mb(), "default_size_mb": DEFAULT_SIZE_MB}

    def update_preview(self, identity, **meta):
        from bson import ObjectId
        allowed={key:meta[key] for key in ('request_preview_b64','response_preview_b64','preview_truncated','truncation_reason') if key in meta}
        row=_coll().find_one({'_id':ObjectId(identity)})
        if not row:return
        row.update(allowed)
        from bson import BSON
        row['row_bytes']=len(BSON.encode(row));allowed['row_bytes']=row['row_bytes']
        _coll().update_one({'_id':ObjectId(identity)},{'$set':allowed})
        maintain()

    def set_retention_days(self, days):
        if isinstance(days,bool) or float(days)!=int(days) or int(days)<1:raise ValueError('Invalid retention days')
        days=int(days)
        from pymongo import ReturnDocument
        policy=get_repo().collection(META).find_one_and_update({'_id':'traffic-storage-policy'},
            {'$set':{'retention_days':days},'$inc':{'expiry_revision':1},'$setOnInsert':{'name':'traffic-default','size_mb':get_size_mb()}},
            upsert=True,return_document=ReturnDocument.AFTER)
        revision=policy['expiry_revision']
        _coll().update_many({'$or':[{'expiry_revision':{'$lt':revision}},{'expiry_revision':{'$exists':False}}]},
            [{'$set':{'expire_at':{'$toDate':{'$add':[{'$multiply':['$ts',1000]},days*86400000]}},'expiry_revision':revision}}])
        maintain()
        return days

    def set_size_mb(self, mb: Any) -> int:
        """设置拦截日志容量(MB)。运行时生效；改容量可能清空历史。下限 1MB(物理)，无上限(用户自主)。"""
        try:
            mb = max(MIN_SIZE_MB, int(mb))
        except (TypeError, ValueError):
            mb = DEFAULT_SIZE_MB
        try:
            get_repo().collection(META).update_one(
                {'_id':'traffic-storage-policy'}, {'$set':{'size_mb':mb,'update_date':_now_str()},
                 '$setOnInsert':{'name':'traffic-default','retention_days':get_retention_days(),'expiry_revision':0}}, upsert=True)
            _ensured["size_bytes"] = 0      # 强制下次 ensure 重新校准
            ensure_capped(mb * 1024 * 1024)
            maintain()
        except Exception as exc:
            logger.debug("guard_log: set_size failed: %s", exc)
        return get_size_mb()

    def get_size_mb(self) -> int:
        return get_size_mb()


# —— 进程级单例 + registry 接入（字符串键，无 ROLE）——
_service = GuardLogServiceImpl()


def get_service() -> GuardLogServiceImpl:
    return _service

