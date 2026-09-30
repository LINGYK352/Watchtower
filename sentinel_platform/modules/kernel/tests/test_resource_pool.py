"""kernel/resource_pool 单测 —— L3 动态内存池（下沉自 ai_pentest，问题11）。

覆盖：轻量工具免池、内存充足放行+登记、内存不足 resource_busy、recon 优先级带被 AI 抢占、
人工抢占低优先、自学习并发污染跳过、超时僵尸清理、release/release_session_all。
用最小 fake collection 支持池用到的 $push/$pull/$slice/$in/$setOnInsert 算子（不连真 Mongo）。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import set_repo, reset_repo
from sentinel_platform.modules.kernel import resource_pool as rp


class _Res:
    """update_one 返回体替身：带 matched_count（CAS 判定用）。"""
    def __init__(self, matched):
        self.matched_count = matched
        self.modified_count = matched


class _FakeColl:
    """最小 Mongo collection 替身：支持 resource_pool 用到的算子。单文档池账本足够。"""
    def __init__(self):
        self.docs = {}   # _id -> doc

    def find_one(self, query, *a, **k):
        return self.docs.get(query.get("_id"))

    def update_one(self, query, update, upsert=False):
        _id = query.get("_id")
        doc = self.docs.get(_id)
        was_absent = doc is None
        if doc is None:
            if not upsert:
                return _Res(0)
            doc = {"_id": _id}
            self.docs[_id] = doc
        # 条件过滤（CAS：rev 匹配 / $exists）——不满足则 matched_count=0，不改文档
        for qk, qv in query.items():
            if qk == "_id":
                continue
            cur = doc.get(qk)
            if isinstance(qv, dict) and "$exists" in qv:
                if bool(qk in doc) != bool(qv["$exists"]):
                    return _Res(0)
            elif cur != qv:
                return _Res(0)   # 如 rev 不匹配 → CAS 冲突
        if "$setOnInsert" in update and was_absent:
            doc.update(update["$setOnInsert"])
        if "$inc" in update:
            for k2, v in update["$inc"].items():
                doc[k2] = doc.get(k2, 0) + v
        if "$set" in update:
            for k2, v in update["$set"].items():
                doc[k2] = v
        if "$push" in update:
            for field, spec in update["$push"].items():
                # 支持点号路径 peaks.<tool>（Mongo 嵌套）
                container, key = doc, field
                if "." in field:
                    parts = field.split(".")
                    container = doc
                    for p in parts[:-1]:
                        container = container.setdefault(p, {})
                    key = parts[-1]
                arr = container.setdefault(key, [])
                if isinstance(spec, dict) and "$each" in spec:
                    arr.extend(spec["$each"])
                    sl = spec.get("$slice")
                    if sl is not None and sl < 0:
                        container[key] = arr[sl:]
                else:
                    arr.append(spec)
        if "$pull" in update:
            for field, cond in update["$pull"].items():
                arr = doc.get(field, [])
                doc[field] = [x for x in arr if not _match_pull(x, cond)]
        return _Res(1)

    def update_many(self, query, update):
        for _id in list(self.docs):
            self.update_one({"_id": _id}, update)


def _match_pull(item, cond):
    """支持 {"hid": {"$in": [...]}} 与 {"session_id": "x"} 两种 $pull 条件。"""
    for key, val in cond.items():
        iv = item.get(key)
        if isinstance(val, dict) and "$in" in val:
            if iv not in val["$in"]:
                return False
        else:
            if iv != val:
                return False
    return True


class _FakeRepo:
    def __init__(self):
        self._colls = {}
    def collection(self, name):
        return self._colls.setdefault(name, _FakeColl())


class ResourcePoolTest(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo())
        # 稳定的配置默认（避免读真 config）
        self._cfg_patch = mock.patch.object(rp, "_cfg", side_effect=lambda k: rp._DEFAULTS[k])
        self._cfg_patch.start()

    def tearDown(self):
        self._cfg_patch.stop()
        reset_repo()

    def test_light_tool_bypasses_pool(self):
        # 轻量工具(学习峰值<50MB)免池直接放行，不查内存
        with mock.patch.object(rp, "learned_peak_mb", return_value=10.0):
            r = rp.acquire("http_request", "s1", 0)
        self.assertTrue(r["ok"])
        self.assertTrue(r["light"])
        self.assertEqual(r["hid"], "")

    def test_grant_when_memory_ample(self):
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=8000.0):
            r = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
        self.assertTrue(r["ok"])
        self.assertFalse(r["light"])
        self.assertTrue(r["hid"])

    def test_resource_busy_when_tight(self):
        # 可用内存刚够 headroom，装不下 400MB 工具 → resource_busy
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=600.0):
            r = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "resource_busy")
        self.assertIn("avail_mb", r)

    def test_cas_no_overcommit_on_concurrent_acquire(self):
        """AUD-06：两个申请者读到同一空账本 rev，第二个 CAS 因 rev 已变而冲突→重采样，
        不会两个都超预算获批。预算只够 1 个 400MB 工具（avail 1000 - headroom），
        模拟并发：第二个申请第一次 CAS 用陈旧 rev（第一个已登记）→ 冲突→重判→内存不足拒绝。"""
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=1000.0):
            r1 = rp.acquire("run_nuclei", "sess_a", 5)     # 第一个：登记 400MB，rev 0→1
            self.assertTrue(r1["ok"])
            # 第二个：此时 reserved=400，budget=1000-400-headroom < 400 → 应被拒（不超额）
            r2 = rp.acquire("run_nuclei", "sess_b", 5)
            self.assertFalse(r2["ok"])
            self.assertEqual(r2["status"], "resource_busy")
        # 账本里只应有 1 个 holder（未超额登记）
        holders, rev = rp._read_pool()
        self.assertEqual(len(holders), 1)
        self.assertGreaterEqual(rev, 1)   # rev 随登记递增

    def test_ai_preempts_recon_band(self):
        # recon 先占预留；AI 自动会话(priority=5)内存不足时抢占 recon 带 → 放行
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=1000.0):
            r1 = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
            self.assertTrue(r1["ok"])
            # 现在 avail 900 - 400 预留 - headroom(512) < 400 → AI 需抢占 recon
            r2 = rp.acquire("run_nuclei", "sess_ai", 5)
        self.assertTrue(r2["ok"], "AI 应抢占 recon 带预留后放行")
        self.assertEqual(r2.get("preempted"), "recon")

    def test_recon_does_not_preempt_ai(self):
        # AI 先占；另一个 recon 内存不足时不能抢 AI（recon 恒让位）→ resource_busy
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=1000.0):
            r1 = rp.acquire("run_nuclei", "sess_ai", 5)
            self.assertTrue(r1["ok"])
            r2 = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
        self.assertFalse(r2["ok"], "recon 不得抢占 AI 预留")
        self.assertEqual(r2["status"], "resource_busy")

    def test_manual_preempts_lower(self):
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=1000.0):
            r1 = rp.acquire("run_nuclei", "sess_ai", 5)   # 自动会话占预留
            self.assertTrue(r1["ok"])
            r2 = rp.acquire("browser_navigate", "console1", rp.PRIORITY_MANUAL)  # 人工抢占
        self.assertTrue(r2["ok"])
        self.assertTrue(r2.get("preempted"))

    def test_release_and_session_all(self):
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=8000.0):
            r = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
            rp.release(r["hid"], tool="recon_screenshot", used_delta_mb=None)
            self.assertEqual(rp._read_holders(), [])
            # release_session_all 清该会话所有 holder
            rp.acquire("recon_screenshot", "recon:t2", rp.PRIORITY_RECON)
            rp.acquire("run_nuclei", "recon:t2", rp.PRIORITY_RECON)
            rp.release_session_all("recon:t2")
        self.assertEqual(rp._read_holders(), [])

    def test_learn_skips_under_concurrency(self):
        # 释放时仍有别的在途 holder → 跳过 record_peak（防并发污染 p95）
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=8000.0):
            r1 = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
            r2 = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
            with mock.patch.object(rp, "record_peak") as rec:
                # 释放 r1 时 r2 仍在途 → 并发>1 → 跳过学习
                rp.release(r1["hid"], tool="recon_screenshot", used_delta_mb=150.0)
                rec.assert_not_called()
                # 释放 r2 时无其他在途 → 记样本
                rp.release(r2["hid"], tool="recon_screenshot", used_delta_mb=150.0)
                rec.assert_called_once()

    def test_record_peak_drops_outlier(self):
        # 离谱样本(> 默认400 × 4 = 1600)丢弃，不进 p95
        rp.record_peak("recon_screenshot", 5000.0)
        doc = rp._peak_doc()
        self.assertNotIn("recon_screenshot", doc.get("peaks", {}))
        # 正常样本记入
        rp.record_peak("recon_screenshot", 150.0)
        self.assertIn(150.0, rp._peak_doc().get("peaks", {}).get("recon_screenshot", []))

    def test_cleanup_stale(self):
        import time
        with mock.patch.object(rp, "learned_peak_mb", return_value=400.0), \
             mock.patch.object(rp, "_available_mb", return_value=8000.0):
            r = rp.acquire("recon_screenshot", "recon:t1", rp.PRIORITY_RECON)
        # 手动把 acquired_at 改成很久以前 → 超时僵尸
        pool = rp._read_holders()
        self.assertEqual(len(pool), 1)
        # 直接改 fake doc 的 acquired_at 模拟僵尸
        from sentinel_platform.core import get_repo
        from sentinel_platform.contracts import Collections
        c = get_repo().collection(Collections.TOOL_RESOURCES)
        c.docs[rp._DEFAULTS["TOOL_MEM_DOC_ID"]]["holders"][0]["acquired_at"] = time.time() - 99999
        n = rp.cleanup_stale_resources()
        self.assertEqual(n, 1)
        self.assertEqual(rp._read_holders(), [])


if __name__ == "__main__":
    unittest.main()
