"""system/log_monitor 单测 —— core 内存替身 + mock psutil，不连真 Mongo / 不采真资源。

覆盖：日志 record/list(禁硬限 size<=0 全量)/stat/delete/clear、MongoLogHandler 采集、
retention get/set(**无天数上限**，仅 days>=1 floor)、资源 level/sample/query、降级、register 注册。
"""
import logging
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemColl:
    def __init__(self):
        self.docs = []
        self._n = 0

    def insert_one(self, doc):
        self._n += 1
        d = dict(doc); d.setdefault("_id", "id%d" % self._n)
        self.docs.append(d)
        return type("R", (), {"inserted_id": d["_id"]})()

    def count_documents(self, q):
        return len(self._match(q))

    def _match(self, q):
        out = []
        for d in self.docs:
            ok = True
            for k, v in (q or {}).items():
                if isinstance(v, dict):
                    if "$regex" in v:
                        import re
                        if not re.search(v["$regex"], str(d.get(k, "")), re.I):
                            ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out

    def find(self, q):
        return _Cursor(self._match(q))

    def delete_one(self, q):
        before = len(self.docs)
        self.docs = [d for d in self.docs if not all(d.get(k) == v for k, v in q.items())]
        return type("R", (), {"deleted_count": before - len(self.docs)})()

    def delete_many(self, q):
        n = len(self.docs); self.docs = []
        return type("R", (), {"deleted_count": n})()

    def find_one(self, q):
        for d in self.docs:
            if all(d.get(k) == v for k, v in (q or {}).items()):
                return dict(d)
        return None

    def update_one(self, q, update, upsert=False):
        doc = self.find_one(q)
        if doc is None:
            if not upsert:
                return
            doc = dict(q); self.docs.append(doc)
        else:
            doc = next(d for d in self.docs if all(d.get(k) == v for k, v in (q or {}).items()))
        doc.update(update.get("$set", {}))

    def create_index(self, *a, **k):
        return "idx"

    @property
    def database(self):
        # collMod 走异常分支 → 回退 create_index（模拟索引尚不存在）
        return type("DB", (), {"command": lambda *a, **k: (_ for _ in ()).throw(Exception("no collmod"))})()


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


class LogMonitorTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_register_string_key(self):
        from sentinel_platform.modules.system.register import register
        reg = get_registry(); register(reg)
        self.assertIsNotNone(reg.get("log_service"))

    # —— 程序日志 ——
    def test_record_list_stat(self):
        from sentinel_platform.modules.system.log_monitor import record_log, list_logs, stat_logs
        record_log("ERROR", "boom", module="a.py")
        record_log("WARNING", "careful", module="b.py")
        r = list_logs()
        self.assertEqual(r["total"], 2)
        self.assertTrue(all("update_date" not in i for i in r["items"]))   # datetime 不输出
        s = stat_logs()
        self.assertEqual(s["ERROR"], 1)
        self.assertEqual(s["WARNING"], 1)
        self.assertEqual(s["total"], 2)

    def test_list_filter_level_and_message(self):
        from sentinel_platform.modules.system.log_monitor import record_log, list_logs
        record_log("ERROR", "db timeout", module="x")
        record_log("WARNING", "slow query", module="y")
        self.assertEqual(list_logs(level="error")["total"], 1)   # 大小写归一
        self.assertEqual(list_logs(message="timeout")["total"], 1)

    def test_size_zero_returns_all_no_hard_limit(self):
        """禁硬限制参数：size<=0 返全量。"""
        from sentinel_platform.modules.system.log_monitor import record_log, list_logs
        for i in range(30):
            record_log("WARNING", "m%d" % i)
        self.assertEqual(len(list_logs(size=0)["items"]), 30)
        self.assertEqual(len(list_logs(size=9999)["items"]), 30)   # 大 size 不截

    def test_delete_and_clear(self):
        from sentinel_platform.modules.system.log_monitor import record_log, list_logs, delete_logs, clear_logs
        record_log("ERROR", "one")
        rid = list_logs()["items"][0]["_id"]
        self.assertEqual(delete_logs([rid])["deleted"], 1)
        record_log("ERROR", "two"); record_log("ERROR", "three")
        self.assertEqual(clear_logs()["delete_cnt"], 2)

    def test_mongo_log_handler_captures_warning_plus(self):
        from sentinel_platform.modules.system.log_monitor import MongoLogHandler, list_logs
        lg = logging.getLogger("test_capture_%d" % id(self))
        lg.setLevel(logging.DEBUG)
        lg.addHandler(MongoLogHandler(level=logging.WARNING))
        lg.info("ignored")       # < WARNING 不记
        lg.warning("recorded")   # 记
        lg.error("also")         # 记
        self.assertEqual(list_logs()["total"], 2)

    # —— retention（禁硬限制：无上限，仅 days>=1）——
    def test_retention_default(self):
        from sentinel_platform.modules.system.log_monitor import get_retention
        r = get_retention()
        self.assertIn("log_monitor", r)
        self.assertIn("access_log", r)
        self.assertEqual(r["access_log"]["default_days"], 14)

    def test_set_retention_no_upper_cap(self):
        """禁硬限制参数：保留天数无上限（旧代码 MAX_DAYS=365 已去除）。"""
        from sentinel_platform.modules.system.log_monitor import set_retention, get_retention
        set_retention({"access_log": 1000})     # 想留 1000 天随意，不被夹到 365
        self.assertEqual(get_retention()["access_log"]["days"], 1000)

    def test_set_retention_floor_prevents_instant_delete(self):
        """days<1 兜底为 1（防 0 天=即删脚手枪，这是安全 floor 非数据帽）。"""
        from sentinel_platform.modules.system.log_monitor import set_retention, get_retention
        set_retention({"access_log": 0})
        self.assertEqual(get_retention()["access_log"]["days"], 1)

    # —— 资源监控（mock psutil）——
    def test_resource_level(self):
        from sentinel_platform.modules.system import log_monitor as lm
        with mock.patch.object(lm, "get_memory_percent", return_value=95):
            self.assertEqual(lm.get_resource_level(), "critical")
        with mock.patch.object(lm, "get_memory_percent", return_value=50):
            self.assertEqual(lm.get_resource_level(), "relaxed")
        with mock.patch.object(lm, "get_memory_percent", return_value=70):
            self.assertEqual(lm.get_resource_level(), "normal")

    def test_task_slots_resource_aware(self):
        """task_slots 按可用内存×水位系数动态算（废写死档位魔数）；critical恒0；psutil缺失回退。"""
        import sys, types
        from sentinel_platform.modules.system import log_monitor as lm
        def mk_psutil(avail_gb):
            m = types.SimpleNamespace()
            m.virtual_memory = lambda: types.SimpleNamespace(available=int(avail_gb * 1024**3))
            m.swap_memory = lambda: types.SimpleNamespace(free=0)
            return m
        # 6G 可用, 每任务1.5G → base=4: relaxed=4/normal=3/tight=1/critical=0
        with mock.patch.dict(sys.modules, {"psutil": mk_psutil(6)}):
            self.assertEqual(lm._recommend_task_slots("relaxed"), 4)
            self.assertEqual(lm._recommend_task_slots("normal"), 3)
            self.assertEqual(lm._recommend_task_slots("tight"), 1)
            self.assertEqual(lm._recommend_task_slots("critical"), 0)   # 停投恒0
        # 50G 可用 → base=33: 大机器真放开(非旧值恒5)
        with mock.patch.dict(sys.modules, {"psutil": mk_psutil(50)}):
            self.assertEqual(lm._recommend_task_slots("relaxed"), 33)
        # psutil 缺失 → None(调用方回退旧档位)
        import builtins
        orig = builtins.__import__
        def noimp(n, *a, **k):
            if n == "psutil":
                raise ImportError()
            return orig(n, *a, **k)
        builtins.__import__ = noimp
        try:
            self.assertIsNone(lm._recommend_task_slots("normal"))
        finally:
            builtins.__import__ = orig

    def test_sample_and_query_resource(self):
        from sentinel_platform.modules.system import log_monitor as lm
        fake_psutil = mock.MagicMock()
        fake_psutil.cpu_percent.return_value = 10.0
        fake_psutil.virtual_memory.return_value = mock.MagicMock(percent=40.0)
        fake_psutil.disk_usage.return_value = mock.MagicMock(percent=55.0)
        with mock.patch.dict("sys.modules", {"psutil": fake_psutil}):
            s = lm.sample_resource()
        self.assertEqual(s["cpu"], 10.0)
        self.assertEqual(s["memory"], 40.0)
        pts = lm.query_resource_history(days=1)
        self.assertEqual(len(pts), 1)
        self.assertEqual(pts[0]["disk"], 55.0)

    def test_memory_percent_psutil_missing_degrades(self):
        from sentinel_platform.modules.system import log_monitor as lm
        with mock.patch.dict("sys.modules", {"psutil": None}):   # import psutil 失败
            self.assertIsNone(lm.get_memory_percent())
            self.assertEqual(lm.get_resource_level(), "normal")

    def test_log_list_db_failure_degrades(self):
        from sentinel_platform.modules.system import log_monitor as lm

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        self.assertEqual(lm.list_logs()["total"], 0)
        self.assertEqual(lm.stat_logs()["total"], 0)


if __name__ == "__main__":
    unittest.main()
