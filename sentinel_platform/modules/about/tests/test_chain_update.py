"""链式更新（一级一级顺序更新）单测 —— 认领锁自愈 / 卡住看门狗 / 下一跳规划。

覆盖卡死事故根因的三条防线（见修复方案）：
  A) 认领锁带 TTL：被 docker restart 连带杀死的子进程遗留的陈旧锁可被清理自愈（不再永久死锁）。
  B) scheduler 看门狗：progress 停滞非终结相位超 _CHAIN_STALL → 兜底重派下一跳。
  C) 下一跳规划：逐级 156→157→158→159，最终跳标 is_latest。

纯 stdlib + monkeypatch + tempfile，不联网、不碰真实容器。
"""
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from sentinel_platform.modules.about import _updater as up


class _TmpRoot(unittest.TestCase):
    """每例一个临时 current_root，进度文件也重定向到临时路径（隔离，不污染 /tmp 真实进度）。"""
    def setUp(self):
        self._d = tempfile.mkdtemp(prefix="chain_test_")
        self.root = self._d
        os.makedirs(os.path.join(self.root, ".update_stage"), exist_ok=True)
        self._prog = os.path.join(self._d, ".progress.json")
        p = mock.patch.object(up, "PROGRESS_FILE", self._prog)
        p.start(); self.addCleanup(p.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._d, ignore_errors=True)


class TestClaimTTL(_TmpRoot):
    def test_fresh_claim_then_conflict(self):
        # 首次认领成功；同 tag 再认领（锁新鲜）失败——防重复派发
        self.assertTrue(up._claim_once(self.root, "hop-v1.21.158"))
        self.assertFalse(up._claim_once(self.root, "hop-v1.21.158"))

    def test_stale_claim_self_heals(self):
        # 造一个 _CLAIM_TTL+60s 前的陈旧锁（模拟被杀进程遗留）→ 再认领应清旧锁自愈成功
        p = up._claim_path(self.root, "hop-v1.21.158")
        with open(p, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": 99999, "ts": time.time() - up._CLAIM_TTL - 60}))
        self.assertTrue(up._claim_once(self.root, "hop-v1.21.158"))   # 陈旧→清→重建成功

    def test_no_ts_lock_not_treated_stale(self):
        # 无 ts 的锁（异常写入）保守判非陈旧，不误清活锁
        p = up._claim_path(self.root, "spawn-x")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{}")
        self.assertFalse(up._claim_stale(p))
        self.assertFalse(up._claim_once(self.root, "spawn-x"))

    def test_sweep_only_stale(self):
        # _sweep_stale_claims 只清陈旧锁，新鲜锁保留
        stale = up._claim_path(self.root, "hop-old")
        fresh = up._claim_path(self.root, "hop-new")
        with open(stale, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time() - up._CLAIM_TTL - 10}))
        with open(fresh, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time()}))
        swept = up._sweep_stale_claims(self.root)
        self.assertEqual(swept, 1)
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(fresh))


class TestWatchdog(_TmpRoot):
    def test_inactive_noop(self):
        # 无 active 链状态：看门狗零副作用，不派发
        with mock.patch.object(up, "_spawn_chain_step") as spawn:
            r = up.tick_chain_watchdog(self.root)
        self.assertFalse(r["active"])
        spawn.assert_not_called()

    def test_fresh_progress_not_stalled(self):
        # 链 active + progress 刚更新（ts=now）→ 未停滞，不兜底
        up._write_chain_state(self.root, {"active": True, "source_url": "http://up:5080"})
        up.set_progress("applying", msg="正在重启…")   # ts=now
        with mock.patch.object(up, "_spawn_chain_step") as spawn:
            r = up.tick_chain_watchdog(self.root)
        self.assertFalse(r.get("stalled"))
        spawn.assert_not_called()

    def test_stalled_applying_respawns(self):
        # 链 active + progress 停在 applying 且 ts 陈旧 → 判卡住，清陈旧锁 + 兜底重派
        up._write_chain_state(self.root, {"active": True, "source_url": "http://up:5080"})
        # 手写一条 ts 陈旧的 applying 进度
        with open(self._prog, "w", encoding="utf-8") as f:
            f.write(json.dumps({"phase": "applying", "total": 0, "done": 0, "msg": "重启中",
                                "error": "", "ts": time.time() - up._CHAIN_STALL - 30}))
        with mock.patch.object(up, "_spawn_chain_step") as spawn, \
             mock.patch("sentinel_platform.modules.system.activation.read_key", return_value="k"):
            r = up.tick_chain_watchdog(self.root)
        self.assertTrue(r.get("stalled"))
        self.assertEqual(r.get("action"), "respawn")
        spawn.assert_called_once()

    def test_done_phase_no_respawn(self):
        # 链 active 但 progress 已 done（正常收尾窄窗）→ 不干预
        up._write_chain_state(self.root, {"active": True})
        up.set_progress("done", msg="完成")
        with mock.patch.object(up, "_spawn_chain_step") as spawn:
            r = up.tick_chain_watchdog(self.root)
        self.assertEqual(r.get("action"), "none")
        spawn.assert_not_called()

    def test_stalled_no_key_no_respawn(self):
        # 停滞但未激活（无 key）→ 不派发，标 no_key（激活后重试可续）
        up._write_chain_state(self.root, {"active": True, "source_url": "http://up:5080"})
        with open(self._prog, "w", encoding="utf-8") as f:
            f.write(json.dumps({"phase": "applying", "ts": time.time() - up._CHAIN_STALL - 30}))
        with mock.patch.object(up, "_spawn_chain_step") as spawn, \
             mock.patch("sentinel_platform.modules.system.activation.read_key", return_value=""):
            r = up.tick_chain_watchdog(self.root)
        self.assertEqual(r.get("action"), "no_key")
        spawn.assert_not_called()


class TestNextHop(unittest.TestCase):
    """_chain_next_hop 逐级规划：mock server_version + /version + /versions。"""
    def _run(self, local, latest, archived):
        import urllib.request
        def fake_urlopen(req, timeout=0):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            body = {"version": latest} if url.endswith("/version") else \
                   {"versions": [{"version": v} for v in archived]}
            m = mock.MagicMock()
            m.read.return_value = json.dumps(body).encode()
            m.__enter__.return_value = m
            m.__exit__.return_value = False
            return m
        with mock.patch.object(up, "server_version", create=True, return_value=local), \
             mock.patch("sentinel_platform.modules.about.update_check.server_version", return_value=local), \
             mock.patch.object(up, "urlopen", fake_urlopen):
            return up._chain_next_hop("http://up:5080", "k", "")

    def test_single_hop_skips_intermediates(self):
        # v1.21.160 单跳：本地156，最新159，归档有157/158 → 直接单跳到 159（不再逐级落 157/158），is_latest
        target, display, is_latest, err = self._run("v1.21.156", "v1.21.159", ["v1.21.157", "v1.21.158", "v1.21.159"])
        self.assertEqual(display, "v1.21.159")
        self.assertTrue(is_latest)
        self.assertEqual(err, "")
        self.assertEqual(target, "v1.21.159")   # 159 已归档 → 版本仓精确取

    def test_single_hop_latest_unarchived_uses_realtime(self):
        # 最新版未归档（走实时 manifest）：target 为空、display 仍报最新
        target, display, is_latest, err = self._run("v1.21.156", "v1.21.159", ["v1.21.157", "v1.21.158"])
        self.assertEqual(display, "v1.21.159")
        self.assertTrue(is_latest)
        self.assertEqual(target, "")   # 未归档 → 空 target 走实时 manifest

    def test_already_latest(self):
        # 本地=最新 → display 空（无需再更），is_latest True
        target, display, is_latest, err = self._run("v1.21.159", "v1.21.159", ["v1.21.157", "v1.21.158"])
        self.assertEqual(display, "")
        self.assertTrue(is_latest)


class TestFileUrlEncoding(unittest.TestCase):
    """下载 URL 的 path 必须 URL 编码：含 + 空格 中文等特殊字符的文件（如 tzdata GMT+0）
    不编码则服务端 parse_qs 把 + 解成空格 → 404（runtime_libs tzdata 引入后暴露的真实事故）。"""
    def test_plus_in_path_encoded_and_server_decodes(self):
        from urllib.parse import quote, parse_qs
        rel = "runtime_libs/tzdata/zoneinfo/GMT+0"
        # 客户端修复：quote(safe="") 把 / 和 + 都编码
        enc = quote(rel, safe="")
        self.assertIn("%2B", enc)          # + → %2B
        self.assertIn("%2F", enc)          # / → %2F
        # 服务端 parse_qs 正确解回原路径（含 +）
        decoded = parse_qs("path=" + enc).get("path")[0]
        self.assertEqual(decoded, rel)
        # 反证：不编码则 + 被解成空格（旧 bug）
        bad = parse_qs("path=" + rel).get("path")[0]
        self.assertEqual(bad, "runtime_libs/tzdata/zoneinfo/GMT 0")
        self.assertNotEqual(bad, rel)

    def test_chinese_and_space_path(self):
        from urllib.parse import quote, parse_qs
        for rel in ["dicts/报表模板/年度 报告.docx", "a b+c/d.txt"]:
            enc = quote(rel, safe="")
            self.assertEqual(parse_qs("path=" + enc).get("path")[0], rel)


if __name__ == "__main__":
    unittest.main()
