"""workspace/dashboard 单测 —— core 内存替身，不需真 Mongo；psutil 缺失/存在都覆盖。

覆盖：device_info 扁平字段 + psutil 降级、resource_history 降采样 + 只读集合 + 空降级、
register 以字符串键注册、days 边界钳制。
"""
import time
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _Cursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, key, direction=1):
        self._docs.sort(key=lambda d: d.get(key, 0), reverse=(direction < 0))
        return self

    def __iter__(self):
        return iter(self._docs)


class _Coll:
    def __init__(self, docs=None):
        self.docs = docs or []

    def find(self, query=None):
        since = 0
        if query and "ts" in query and isinstance(query["ts"], dict):
            since = query["ts"].get("$gte", 0)
        return _Cursor([d for d in self.docs if d.get("ts", 0) >= since])


class _Repo(Repository):
    def __init__(self, history=None):
        self._history = history or []

    def collection(self, name):
        return _Coll(self._history)


class DashboardTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()

    def tearDown(self):
        reset_repo()
        reset_registry()

    def _impl(self):
        from sentinel_platform.modules.workspace.dashboard import DashboardServiceImpl
        return DashboardServiceImpl()

    # —— register 字符串键 ——
    def test_register_string_key(self):
        from sentinel_platform.modules.workspace.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get("dashboard_service")
        self.assertIsNotNone(svc)
        self.assertTrue(hasattr(svc, "device_info"))
        self.assertTrue(hasattr(svc, "resource_history"))

    # —— device_info：psutil 存在，扁平字段齐全 ——
    def test_device_info_with_psutil(self):
        fake_ps = mock.MagicMock()
        fake_ps.cpu_percent.return_value = 12.5
        fake_ps.cpu_count.return_value = 4
        fake_ps.virtual_memory.return_value = mock.Mock(percent=48.0, total=8_000_000, used=3_840_000)
        fake_ps.disk_usage.return_value = mock.Mock(percent=60.0, total=100, used=60, free=40)
        fake_ps.boot_time.return_value = time.time() - 3600
        with mock.patch("sentinel_platform.modules.workspace.dashboard._psutil", return_value=fake_ps):
            info = self._impl().device_info()
        self.assertEqual(info["cpu_percent"], 12.5)
        self.assertEqual(info["memory_percent"], 48.0)
        self.assertEqual(info["disk_percent"], 60.0)
        self.assertEqual(info["cpu_count"], 4)
        self.assertTrue(info["uptime_seconds"] >= 3599)
        self.assertTrue(info["psutil"])
        # 扁平字段（旧坑：嵌套 cpu.percent 前端读扁平永远 0）
        for k in ("cpu_percent", "memory_percent", "disk_percent"):
            self.assertNotIsInstance(info[k], dict)

    # —— device_info：psutil 缺失，降级 0 不崩 ——
    def test_device_info_psutil_absent(self):
        with mock.patch("sentinel_platform.modules.workspace.dashboard._psutil", return_value=None):
            info = self._impl().device_info()
        self.assertEqual(info["cpu_percent"], 0.0)
        self.assertFalse(info["psutil"])

    # —— device_info：单项读失败不影响其他字段（部分降级）——
    def test_device_info_partial_failure(self):
        fake_ps = mock.MagicMock()
        fake_ps.cpu_percent.return_value = 10.0
        fake_ps.cpu_count.return_value = 2
        fake_ps.virtual_memory.side_effect = RuntimeError("mem boom")
        fake_ps.disk_usage.return_value = mock.Mock(percent=30.0, total=1, used=1, free=0)
        fake_ps.boot_time.return_value = time.time()
        with mock.patch("sentinel_platform.modules.workspace.dashboard._psutil", return_value=fake_ps):
            info = self._impl().device_info()
        self.assertEqual(info["cpu_percent"], 10.0)      # cpu 正常
        self.assertEqual(info["memory_percent"], 0.0)    # mem 失败降级
        self.assertEqual(info["disk_percent"], 30.0)     # disk 正常

    # —— resource_history：只读集合，降采样 ——
    def test_resource_history_downsample(self):
        now = int(time.time())
        # 造 10 个点，间隔 30s；days=1 step=1min → 相邻<60s 被抽稀
        hist = [{"ts": now - i * 30, "cpu": 10 + i, "memory": 20 + i, "disk": 30 + i} for i in range(10)]
        set_repo(_Repo(history=hist))
        r = self._impl().resource_history(days=1)
        self.assertEqual(r["days"], 1)
        self.assertEqual(r["count"], len(r["points"]))
        # 30s 间隔、step=60s → 大约每隔一个点取一个，点数应 < 10
        self.assertTrue(0 < r["count"] < 10)
        # 时序升序 + 字段齐全
        ts_list = [p["ts"] for p in r["points"]]
        self.assertEqual(ts_list, sorted(ts_list))
        for p in r["points"]:
            self.assertIn("cpu", p)
            self.assertIn("memory", p)
            self.assertIn("disk", p)

    # —— resource_history：空集合降级 ——
    def test_resource_history_empty(self):
        set_repo(_Repo(history=[]))
        r = self._impl().resource_history(days=7)
        self.assertEqual(r["points"], [])
        self.assertEqual(r["count"], 0)

    # —— days 边界钳制 [1,360] + 非法值兜底 ——
    def test_resource_history_days_clamp(self):
        set_repo(_Repo(history=[]))
        im = self._impl()
        self.assertEqual(im.resource_history(days=9999)["days"], 360)
        self.assertEqual(im.resource_history(days=0)["days"], 1)
        self.assertEqual(im.resource_history(days="bad")["days"], 1)


if __name__ == "__main__":
    unittest.main()
