"""session 端点 e2e —— 真 Flask test_client 走完整链路（网关→端点→registry→信封）。

证明不孤岛：/api/pentest/session* 挂 swagger（与 ai_tools /pentest/tools、vuln_center /pentest/finding 共存）
+ 会话 CRUD 往返 + stop 协作式 + stat/list 分页信封。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemColl:
    def __init__(self):
        self.docs = []
        self._n = 0

    def insert_one(self, doc):
        self._n += 1
        d = dict(doc); d.setdefault("_id", "s%d" % self._n)
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        import re as _re
        out = []
        for d in self.docs:
            if self._doc_ok(d, q or {}):
                out.append(d)
        return out

    def _doc_ok(self, d, q):
        import re as _re
        for k, v in q.items():
            if k == "$or":
                if not any(self._doc_ok(d, sub) for sub in v):
                    return False
            elif isinstance(v, dict) and "$in" in v:
                if d.get(k) not in v["$in"]:
                    return False
            elif isinstance(v, dict) and "$regex" in v:
                flags = _re.I if "i" in (v.get("$options") or "") else 0
                if not _re.search(v["$regex"], str(d.get(k, "")), flags):
                    return False
            elif isinstance(v, dict) and ("$gte" in v or "$lte" in v):
                val = str(d.get(k, ""))
                if "$gte" in v and val < v["$gte"]:
                    return False
                if "$lte" in v and val > v["$lte"]:
                    return False
            elif d.get(k) != v:
                return False
        return True

    def find(self, q=None, proj=None):
        return _Cursor(self._match(q))

    def find_one(self, q):
        m = self._match(q)
        return dict(m[0]) if m else None

    def update_one(self, q, update, upsert=False):
        m = self._match(q)
        if not m:
            return type("R", (), {"matched_count": 0})()
        tgt = next(d for d in self.docs if d.get("_id") == m[0].get("_id"))
        tgt.update(update.get("$set", {}))
        return type("R", (), {"matched_count": 1})()

    def update_many(self, q, update):
        m = self._match(q)
        for x in m:
            next(d for d in self.docs if d.get("_id") == x.get("_id")).update(update.get("$set", {}))
        return type("R", (), {"modified_count": len(m)})()

    def delete_one(self, q):
        before = len(self.docs); m = self._match(q)
        if m:
            self.docs = [d for d in self.docs if d.get("_id") != m[0].get("_id")]
        return type("R", (), {"deleted_count": before - len(self.docs)})()


class _Cursor(list):
    def sort(self, *a, **k):
        return _Cursor(reversed(self))

    def skip(self, n):
        return _Cursor(list(self)[n:])

    def limit(self, n):
        return _Cursor(list(self)[:n])


class _MemRepo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _MemColl())


class ViewAllHelperTest(unittest.TestCase):
    """_can_view_all() / list owner 计算 —— 直接压 flask app context 设 g.current_user 验判定。
    这是多用户归属数据级过滤的端点侧关键逻辑（决定 owner=None 全看 还是 owner=自己 隔离）。"""
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()

    def tearDown(self):
        reset_repo(); reset_registry()

    def _view_all_with(self, current_user):
        from flask import g
        from sentinel_platform.router.endpoints import session as ep
        with self.app.test_request_context("/api/pentest/session"):
            if current_user is not None:
                g.current_user = current_user
            return ep._can_view_all(), ep._current_username()

    def test_auth_off_no_user_sees_all(self):
        va, _ = self._view_all_with(None)             # 无 g.current_user（AUTH 关）
        self.assertTrue(va)

    def test_admin_sees_all(self):
        va, _ = self._view_all_with({"username": "adm", "role": "admin"})
        self.assertTrue(va)

    def test_role_with_view_all_perm_sees_all(self):
        va, _ = self._view_all_with(
            {"username": "lead", "role": "teamlead", "permissions": ["pentest:read", "pentest:view_all"]})
        self.assertTrue(va)

    def test_operator_without_perm_only_own(self):
        va, uname = self._view_all_with(
            {"username": "op1", "role": "operator", "permissions": ["pentest:read", "pentest:write"]})
        self.assertFalse(va)
        self.assertEqual(uname, "op1")               # → 端点会传 owner="op1" 只看自己


class SessionE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        from sentinel_platform.router import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_endpoints_in_swagger(self):
        paths = self.client.get("/api/swagger.json").get_json().get("paths", {})
        self.assertIn("/pentest/session", paths)
        self.assertIn("/pentest/session/stat", paths)
        # 与同 /pentest path 的 ai_tools 共存
        self.assertIn("/pentest/tools", paths)

    def test_console_new_empty_site_paused_manual(self):
        # 会话台新建白板会话：site 可空 → 状态 paused_manual（scheduler 不认领）+ 返 resume_key
        r = self.client.post("/api/pentest/session/console_new",
                             json={"name": "白板作战", "prompt": "只测越权", "mode": "redteam"}).get_json()
        self.assertEqual(r["code"], 200)
        self.assertEqual(r["data"]["status"], "paused_manual")
        self.assertTrue(r["data"]["resume_key"])
        self.assertEqual(r["data"]["site"], "")
        # 能凭 resume_key 载入会话台
        ld = self.client.get("/api/pentest/session/console/%s" % r["data"]["resume_key"]).get_json()
        self.assertEqual(ld["code"], 200)

    def test_list_keyword_and_date_filter(self):
        self.client.post("/api/pentest/session", json={"site": "http://shop.example.com"})
        self.client.post("/api/pentest/session", json={"site": "http://mail.other.org"})
        # keyword 开放匹配 site
        r = self.client.get("/api/pentest/session?keyword=shop").get_json()
        self.assertEqual(r["data"]["total"], 1)
        self.assertIn("shop", r["data"]["items"][0]["site"])
        # 未来日期 date_from → 0 条（save_date 早于它）
        r2 = self.client.get("/api/pentest/session?date_from=2099-01-01").get_json()
        self.assertEqual(r2["data"]["total"], 0)

    def test_create_list_stop_delete_roundtrip(self):
        # 建
        c = self.client.post("/api/pentest/session", json={"site": "http://a.com"}).get_json()
        self.assertEqual(c["code"], 200)
        sid = c["data"]["_id"]
        # 列（分页信封）
        lst = self.client.get("/api/pentest/session").get_json()
        self.assertEqual(lst["code"], 200)
        self.assertEqual(lst["data"]["total"], 1)
        # 停（协作式）
        s = self.client.post("/api/pentest/session/%s/stop" % sid).get_json()
        self.assertEqual(s["code"], 200)
        self.assertEqual(s["data"]["status"], "stopped")
        # 删
        d = self.client.post("/api/pentest/session/%s/delete" % sid).get_json()
        self.assertEqual(d["code"], 200)
        self.assertEqual(self.client.get("/api/pentest/session").get_json()["data"]["total"], 0)

    def test_create_missing_site_400(self):
        body = self.client.post("/api/pentest/session", json={}).get_json()
        self.assertEqual(body["code"], 400)

    def test_stat_envelope(self):
        body = self.client.get("/api/pentest/session/stat").get_json()
        self.assertEqual(body["code"], 200)
        for k in ("total", "running", "active", "total_tokens"):
            self.assertIn(k, body["data"])

    def test_start_engine_registered_no_provider_fatal(self):
        # _engine 已注册但没有可用 Provider：配置缺失是 fatal，不进入 queued/自动重试。
        cr = self.client.post("/api/pentest/session", json={"site": "http://a.com"}).get_json()
        sid = cr["data"]["_id"]
        body = self.client.post("/api/pentest/session/%s/start" % sid).get_json()
        self.assertEqual(body["code"], 400)
        self.assertIn("默认 AI", body["message"])
        self.assertIn("scene=pentest_exec", body["message"])
        # 引擎真跑过的证据：会话详情里 status 被引擎置 fatal
        detail = self.client.get("/api/pentest/session/%s" % sid).get_json()
        self.assertEqual(detail["data"]["status"], "fatal")

    def test_detail_not_found(self):
        body = self.client.get("/api/pentest/session/nope").get_json()
        self.assertEqual(body["code"], 404)

    def test_service_missing_degrades_500(self):
        reset_registry()
        body = self.client.get("/api/pentest/session").get_json()
        self.assertEqual(body["code"], 500)


class SessionStreamTest(unittest.TestCase):
    """只读实时观察 SSE 生成器：增量推 tool_log + meta，终态推 end 后收尾。
    用脚本化 svc（每次 get_session 返回下一状态）验增量游标/终态收尾/不越界。"""

    def _svc(self, snapshots):
        seq = list(snapshots)
        class _Svc:
            def get_session(self, sid, with_messages=False):
                return seq.pop(0) if seq else seq_last[0]
        seq_last = [snapshots[-1]]
        return _Svc()

    def test_incremental_then_end(self):
        from sentinel_platform.router.endpoints.session import _session_event_stream, _STREAM_POLL_SEC
        import sentinel_platform.router.endpoints.session as ep
        ep._STREAM_POLL_SEC = 0        # 测试不真 sleep
        snapshots = [
            {"status": "running", "round": 1, "total_tokens": 10,
             "tool_log": [{"name": "http_request", "arguments": {"url": "u1"}, "result": "r1"}]},
            {"status": "running", "round": 2, "total_tokens": 20,
             "tool_log": [{"name": "http_request", "arguments": {"url": "u1"}, "result": "r1"},
                          {"name": "collect_js", "arguments": {}, "result": "r2"}]},
            {"status": "done", "round": 2, "total_tokens": 25,
             "tool_log": [{"name": "http_request", "arguments": {"url": "u1"}, "result": "r1"},
                          {"name": "collect_js", "arguments": {}, "result": "r2"}]},
        ]
        frames = list(_session_event_stream("s1", self._svc(snapshots)))
        ep._STREAM_POLL_SEC = _STREAM_POLL_SEC
        text = "".join(frames)
        # 两个工具各推一次(不重复)
        self.assertEqual(text.count("event: tool"), 2)
        self.assertIn("http_request", text)
        self.assertIn("collect_js", text)
        # meta 推过 + 终态 end
        self.assertIn("event: meta", text)
        self.assertIn("event: end", text)
        self.assertIn("\"status\": \"done\"", text)

    def test_missing_session_emits_error(self):
        from sentinel_platform.router.endpoints.session import _session_event_stream
        class _Svc:
            def get_session(self, sid, with_messages=False):
                return None
        frames = list(_session_event_stream("nope", _Svc()))
        self.assertIn("event: error", "".join(frames))


if __name__ == "__main__":
    unittest.main()
