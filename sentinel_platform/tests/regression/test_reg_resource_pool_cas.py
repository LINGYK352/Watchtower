"""回归⑦：资源池 CAS 原子准入 acquire（resource_pool.py:241，AUD-06）。

事故：旧"读预算→判定→独立 $push 登记"三步非原子，多 worker 读同一空账本各自获批→超额预留→OOM。
根治：账本加 rev 版本号，acquire 读 rev→算预算→仅当 rev 未变才 _register_cas 登记($inc rev)，
冲突重采样重试；登记失败绝不返回 holder id。
红线：并发/陈旧 rev 下不得超额登记；免池阈值行为不变。
用回归层自有 _fakes.py（支持 $inc/$setOnInsert/matched_count），不依赖模块 test 内部类。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.modules.kernel import resource_pool as rp
from sentinel_platform.tests.regression._fakes import _FakeRepo


class ResourcePoolCASRegression(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo())
        self._cfg = mock.patch.object(rp, "_cfg", side_effect=lambda k: rp._DEFAULTS[k])
        self._cfg.start()

    def tearDown(self):
        self._cfg.stop()
        reset_repo()

    def test_light_tool_bypasses_pool(self):
        """免池阈值：学习峰值<50MB 轻量工具直接放行、不进账本（hid 空）。"""
        with mock.patch.object(rp, "learned_peak_mb", return_value=10.0):
            r = rp.acquire("http_request", "s1", 0)
        self.assertTrue(r["ok"])
        self.assertTrue(r["light"])
        self.assertEqual(r["hid"], "")

    def test_cas_no_overcommit(self):
        """红线：预算只够 1 个 400MB 工具，第二个申请必被拒（不超额登记）。"""
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=1000.0):
            r1 = rp.acquire("run_nuclei", "a", 5)
            self.assertTrue(r1["ok"])
            r2 = rp.acquire("run_nuclei", "b", 5)
            self.assertFalse(r2["ok"])
            self.assertEqual(r2["status"], "resource_busy")
        holders, rev = rp._read_pool()
        self.assertEqual(len(holders), 1, "超额登记=CAS 失效")
        self.assertGreaterEqual(rev, 1, "rev 应随登记递增(CAS 版本号)")

    def test_stale_rev_register_rejected(self):
        """CAS 语义直证：拿一个陈旧 rev 调 _register_cas → matched_count=0 → 返回 None（不登记）。"""
        rp._ensure_pool_doc()
        _, rev0 = rp._read_pool()
        # 先用当前 rev 成功登记一次，使账本 rev 前进
        hid1 = rp._register_cas("run_nuclei", "a", 5, 400.0, 1.0, rev0)
        self.assertIsNotNone(hid1)
        # 再用已过时的 rev0 登记 → 冲突，返回 None，账本不新增
        hid2 = rp._register_cas("run_nuclei", "b", 5, 400.0, 2.0, rev0)
        self.assertIsNone(hid2, "陈旧 rev 的 CAS 必须失败返回 None，不能超额登记")
        holders, _ = rp._read_pool()
        self.assertEqual(len(holders), 1)

    def test_busy_returns_diagnostics(self):
        """内存不足返 resource_busy + 诊断字段（avail/reserved/headroom），非 error。"""
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=600.0):
            r = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "resource_busy")
        for k in ("avail_mb", "reserved_mb", "headroom_mb"):
            self.assertIn(k, r)


if __name__ == "__main__":
    unittest.main()
