"""system/log_monitor 单测 —— core 内存替身 + mock psutil，不连真 Mongo / 不采真资源。

覆盖：日志 record/list(禁硬限 size<=0 全量)/stat/delete/clear、MongoLogHandler 采集、
retention get/set(**无天数上限**，仅 days>=1 floor)、资源 level/sample/query、降级、register 注册。
"""
import logging
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo, get_repo
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

    def find_one(self, q, sort=None):
        docs = list(self.docs)
        for field, direction in (sort or []):
            docs.sort(key=lambda d: d.get(field, 0), reverse=direction < 0)
        for d in docs:
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
        """内存维度分级（隔离 CPU/磁盘：置低值不干扰，验证内存单维语义不变）。"""
        from sentinel_platform.modules.system import log_monitor as lm
        with mock.patch.object(lm, "get_cpu_percent", return_value=10), \
             mock.patch.object(lm, "get_disk_percent", return_value=10):
            with mock.patch.object(lm, "get_memory_percent", return_value=95):
                self.assertEqual(lm.get_resource_level(), "critical")
            with mock.patch.object(lm, "get_memory_percent", return_value=50):
                self.assertEqual(lm.get_resource_level(), "relaxed")
            with mock.patch.object(lm, "get_memory_percent", return_value=70):
                self.assertEqual(lm.get_resource_level(), "normal")

    def test_resource_level_multidim_worst(self):
        """综合水位取内存/CPU/磁盘最严重维度：内存空闲但 CPU/磁盘高 → 综合被拉高。"""
        from sentinel_platform.modules.system import log_monitor as lm
        # 内存 relaxed(50)，但 CPU critical(97) → 综合 critical
        with mock.patch.object(lm, "get_memory_percent", return_value=50), \
             mock.patch.object(lm, "get_cpu_percent", return_value=97), \
             mock.patch.object(lm, "get_disk_percent", return_value=10):
            self.assertEqual(lm.get_resource_level(), "critical")
        # 内存 relaxed(50)，磁盘 tight(88) → 综合 tight
        with mock.patch.object(lm, "get_memory_percent", return_value=50), \
             mock.patch.object(lm, "get_cpu_percent", return_value=10), \
             mock.patch.object(lm, "get_disk_percent", return_value=88):
            self.assertEqual(lm.get_resource_level(), "tight")
        # 三维皆空闲 → relaxed（保留向上调度语义）
        with mock.patch.object(lm, "get_memory_percent", return_value=40), \
             mock.patch.object(lm, "get_cpu_percent", return_value=20), \
             mock.patch.object(lm, "get_disk_percent", return_value=30):
            self.assertEqual(lm.get_resource_level(), "relaxed")

    def test_get_resource_alert_dims(self):
        """resource_alert 列出超标维度（tight/critical），normal 维度不进 dims。"""
        from sentinel_platform.modules.system import log_monitor as lm
        with mock.patch.object(lm, "get_memory_percent", return_value=92), \
             mock.patch.object(lm, "get_cpu_percent", return_value=30), \
             mock.patch.object(lm, "get_disk_percent", return_value=88):
            info = lm.get_resource_alert()
        self.assertEqual(info["level"], "critical")   # 内存 92 ≥ 90
        keys = {d["key"]: d["level"] for d in info["dims"]}
        self.assertEqual(keys.get("memory"), "critical")
        self.assertEqual(keys.get("disk"), "tight")   # 磁盘 88 ≥ 85 高
        self.assertNotIn("cpu", keys)                 # CPU 30 正常，不进 dims

    def test_check_and_alert_pushes_and_throttles(self):
        """tight+ 触发推送；同级别 TTL 内去重不重推；回落后清标记能再推。"""
        from sentinel_platform.modules.system import log_monitor as lm
        lm._ALERT_DEDUP["level"] = ""; lm._ALERT_DEDUP["ts"] = 0.0   # 复位
        calls = []
        # 直接 patch 真实 notify 模块的函数——不能用 patch.dict(sys.modules) 换整个 notify：
        # check_and_alert_resource 内 `from ...kernel import notify` 一旦父包 kernel 已导入，
        # 会从 kernel 的属性拿到真实 notify（不查 sys.modules），patch.dict 便失效（跨文件跑时暴露）。
        def _rec(module, msg):
            calls.append((module, msg))
        with mock.patch("sentinel_platform.modules.kernel.notify.notify_critical_log", _rec):
            with mock.patch.object(lm, "get_memory_percent", return_value=97), \
                 mock.patch.object(lm, "get_cpu_percent", return_value=10), \
                 mock.patch.object(lm, "get_disk_percent", return_value=10):
                r1 = lm.check_and_alert_resource()
                self.assertTrue(r1["alerted"])            # 首次 critical → 推送
                r2 = lm.check_and_alert_resource()
                self.assertFalse(r2["alerted"])           # TTL 内同级别 → 去重不推
            self.assertEqual(len(calls), 1)
            # 回落 normal → 清标记
            with mock.patch.object(lm, "get_memory_percent", return_value=50), \
                 mock.patch.object(lm, "get_cpu_percent", return_value=10), \
                 mock.patch.object(lm, "get_disk_percent", return_value=10):
                r3 = lm.check_and_alert_resource()
                self.assertFalse(r3["alerted"])
                self.assertEqual(r3["level"], "relaxed")
            self.assertEqual(lm._ALERT_DEDUP["level"], "")   # 标记已清

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

    def test_cpu_percent_prefers_fresh_sample_no_probe(self):
        """新鲜 resource_history 采样存在 → 直接返回它，绝不做本地 psutil 探测（多 worker 一致 + 无阻塞）。"""
        import time
        from sentinel_platform.modules.system import log_monitor as lm
        set_repo(_MemRepo())
        get_repo().collection(lm.RESOURCE_HISTORY).insert_one(
            {"ts": int(time.time()), "cpu": 12.0, "memory": 40.0, "disk": 55.0})
        boom = mock.MagicMock()
        boom.cpu_percent.side_effect = AssertionError("有新鲜采样时不应调用 psutil.cpu_percent")
        with mock.patch.dict("sys.modules", {"psutil": boom}):
            self.assertEqual(lm.get_cpu_percent(), 12.0)
        boom.cpu_percent.assert_not_called()

    def test_cpu_percent_stale_sample_falls_back_to_blocking_probe(self):
        """采样过期（scheduler 停摆）→ 本地阻塞探测兜底，且 interval 非 0（绝不用冷进程增量口径）。"""
        import time
        from sentinel_platform.modules.system import log_monitor as lm
        set_repo(_MemRepo())
        get_repo().collection(lm.RESOURCE_HISTORY).insert_one(
            {"ts": int(time.time()) - lm._CPU_SAMPLE_MAX_AGE - 10, "cpu": 12.0})
        fake = mock.MagicMock()
        fake.cpu_percent.return_value = 3.0
        with mock.patch.dict("sys.modules", {"psutil": fake}):
            self.assertEqual(lm.get_cpu_percent(), 3.0)
        # 兜底探测必须带真实窗口，绝不 interval=0（假 critical 根因）
        _, kwargs = fake.cpu_percent.call_args
        self.assertEqual(kwargs.get("interval"), lm._CPU_PROBE_INTERVAL)
        self.assertNotEqual(kwargs.get("interval"), 0)

    def test_cpu_percent_no_sample_no_psutil_degrades_none(self):
        """无采样且 psutil 不可用 → None（不参与分级，交由 _cpu_disk_level 走中性 relaxed）。"""
        from sentinel_platform.modules.system import log_monitor as lm
        set_repo(_MemRepo())
        with mock.patch.dict("sys.modules", {"psutil": None}):
            self.assertIsNone(lm.get_cpu_percent())

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
