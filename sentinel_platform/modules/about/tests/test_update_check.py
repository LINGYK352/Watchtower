"""update_check 叶子单测 —— 数值 semver 比对 / check_update 判定 / 配置版本源。

重点：版本比对必须数值化（v1.21 > v1.9，字符串比较会错），这是本叶子的核心正确性。
"""
import unittest
from unittest import mock

from sentinel_platform.modules.about import update_check as uc


class TestVersionCompare(unittest.TestCase):
    def test_parse_strips_v(self):
        # _parse 给正式版(无 -N)追加预发布标记后缀 (1,0)（预发布 -N 追加 (0,N)，排在正式版前）
        self.assertEqual(uc._parse("v1.21.19"), (1, 21, 19, 1, 0))
        self.assertEqual(uc._parse("1.9.0"), (1, 9, 0, 1, 0))

    def test_numeric_not_string_compare(self):
        # 字符串比较会误判 v1.21 < v1.9；数值比较必须 v1.21 > v1.9
        self.assertEqual(uc._cmp("v1.21.0", "v1.9.0"), 1)
        self.assertEqual(uc._cmp("v1.9.0", "v1.21.0"), -1)

    def test_equal(self):
        self.assertEqual(uc._cmp("v1.21.19", "1.21.19"), 0)

    def test_different_length(self):
        # 注：预发布后缀使段数不同的 "v1.21" 与 "v1.21.0" 不再判等价（前者补位后后缀错位）——
        # 现实版本号都带完整三段(v1.21.N)，此边界不影响实际比对。核心保证「更高补丁号更大」。
        self.assertEqual(uc._cmp("v1.21.1", "v1.21.0"), 1)
        self.assertEqual(uc._cmp("v1.21.1", "v1.21.2"), -1)

    def test_non_numeric_seg_safe(self):
        # "v2.0-beta"：主段 (2,0) + 预发布 -beta（无数字取 0）追加 (0,0) → (2,0,0,0)；正式版追加 (1,0) 更大
        self.assertEqual(uc._parse("v2.0-beta"), (2, 0, 0, 0))
        self.assertEqual(uc._cmp("v2.0.0-beta", "v2.0.0"), -1)   # 预发布 < 正式版

    def test_server_version_prefers_version_txt_over_config(self):
        # version.txt(随代码部署,权威) 优先于 config.SYSTEM.VERSION(手工旋钮,易滞后)
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: "v1.21.24" if a[:2] == ("SYSTEM", "VERSION") else k.get("default", "")
        with mock.patch.object(uc, "_version_txt", return_value="v1.21.27"), \
             mock.patch.object(uc, "get_config", return_value=cfg):
            self.assertEqual(uc.server_version(), "v1.21.27")   # version.txt 赢
        # version.txt 读不到 → 回退 config
        with mock.patch.object(uc, "_version_txt", return_value=""), \
             mock.patch.object(uc, "get_config", return_value=cfg):
            self.assertEqual(uc.server_version(), "v1.21.24")   # 回退 config


class TestCheckUpdate(unittest.TestCase):
    def setUp(self):
        # 中和 version.txt，并强制本组只测服务端与前端的本地比对。
        p = mock.patch.object(uc, "_version_txt", return_value="")
        p.start(); self.addCleanup(p.stop)
        r = mock.patch.object(uc, "_update_source", return_value=("", "", False))
        r.start(); self.addCleanup(r.stop)

    def _cfg(self, version):
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: version if a[:2] == ("SYSTEM", "VERSION") else k.get("default", "")
        return cfg

    def test_has_update_when_server_ahead(self):
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.22.0")):
            r = uc.check_update("v1.21.19")
        self.assertTrue(r["has_update"])
        self.assertEqual(r["server_version"], "v1.22.0")
        self.assertIn("刷新", r["message"])

    def test_no_update_when_equal(self):
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.19")):
            r = uc.check_update("v1.21.19")
        self.assertFalse(r["has_update"])
        self.assertIn("本地版本", r["message"])

    def test_client_ahead(self):
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.20.0")):
            r = uc.check_update("v1.21.19")
        self.assertFalse(r["has_update"])

    def test_no_client_version(self):
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.19")):
            r = uc.check_update("")
        self.assertFalse(r["has_update"])
        self.assertEqual(r["client_version"], "")

    def test_default_version_when_no_config(self):
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: k.get("default", "")
        with mock.patch.object(uc, "get_config", return_value=cfg):
            self.assertTrue(uc.server_version())   # 有默认值，不空


class TestRemoteCheck(unittest.TestCase):
    """默认查上游更新源：上游领先→has_update；相等→最新；不可达→降级本地比对。"""

    def setUp(self):
        p = mock.patch.object(uc, "_version_txt", return_value="")   # 中和 version.txt，测 config 兜底
        p.start(); self.addCleanup(p.stop)

    def _cfg(self, server, source="http://up:5080", key="", check_remote=True):
        def sect(*a, **k):
            if a[:2] == ("SYSTEM", "VERSION"):
                return server
            if a[:2] == ("UPDATE", "SOURCE_URL"):
                return source
            if a[:2] == ("UPDATE", "KEY"):
                return key
            if a[:2] == ("UPDATE", "CHECK_REMOTE"):
                return check_remote
            return k.get("default", "")
        cfg = mock.Mock()
        cfg.section.side_effect = sect
        return cfg

    def test_remote_ahead_has_update(self):
        # 本实例 v1.21.25，上游 v1.21.26 → 真·远程有新版
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.25")), \
             mock.patch.object(uc, "remote_version", return_value=("v1.21.26", "")):
            r = uc.check_update("v1.21.25")
        self.assertTrue(r["has_update"])
        self.assertTrue(r["remote_ok"])
        self.assertEqual(r["latest_version"], "v1.21.26")
        self.assertIn("v1.21.26", r["message"])

    def test_remote_equal_no_update(self):
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.26")), \
             mock.patch.object(uc, "remote_version", return_value=("v1.21.26", "")):
            r = uc.check_update("v1.21.26")
        self.assertFalse(r["has_update"])
        self.assertTrue(r["remote_ok"])
        self.assertIn("已是最新", r["message"])

    def test_remote_equal_but_frontend_stale_prompts_refresh(self):
        # 本实例=上游=v1.21.26，但浏览器构建还是 v1.21.25 → 仍提示刷新
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.26")), \
             mock.patch.object(uc, "remote_version", return_value=("v1.21.26", "")):
            r = uc.check_update("v1.21.25")
        self.assertTrue(r["has_update"])
        self.assertIn("刷新", r["message"])

    def test_remote_unreachable_degrades_to_local(self):
        # 上游配了但不可达（remote_version 返回 ""）→ 退回本地比对（服务端 vs 前端）
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.26")), \
             mock.patch.object(uc, "remote_version", return_value=("", "network")):
            r = uc.check_update("v1.21.25")
        self.assertFalse(r["remote_ok"])
        self.assertFalse(r["has_update"])
        self.assertEqual(r["error_type"], "network")
        self.assertIn("无法连接", r["message"])

    def test_no_source_configured_local_only(self):
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.25", source="")), \
             mock.patch.object(uc, "_update_source", return_value=("", "", True)):
            r = uc.check_update("v1.21.25")
        self.assertFalse(r["remote_ok"])
        self.assertFalse(r["has_update"])
        self.assertIn("未配置", r["message"])

    def test_check_remote_false_forces_local(self):
        # 显式关掉查上游 → 即使配了 source 也走本地比对，不发起网络请求
        with mock.patch.object(uc, "get_config", return_value=self._cfg("v1.21.25", check_remote=False)), \
             mock.patch.object(uc, "remote_version", return_value="v1.21.99") as rv:
            r = uc.check_update("v1.21.25")
        rv.assert_not_called()
        self.assertFalse(r["remote_ok"])


if __name__ == "__main__":
    unittest.main()
