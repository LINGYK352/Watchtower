"""ext_source 单测 —— 归一化/解析/缓存/降级，不走真网络（mock http_req + 注入 repo）。

覆盖：①FOFA 全角归一化（踩坑根治）②fofa_query 未配 key 降级 + key 日志脱敏 ③crtsh 解析
过滤归属域 ④icp_query Hunter 优先→FOFA 兜底→缓存命中 ⑤外部失败返回空不抛异常。
"""
import unittest
from unittest import mock

from sentinel_platform.modules.kernel import ext_source as ext


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
    def json(self):
        return self._payload


class _FakeColl:
    def __init__(self):
        self.store = {}
    def find_one(self, q):
        return self.store.get(q.get("domain"))
    def update_one(self, q, upd, upsert=False):
        d = q["domain"]
        self.store[d] = {**self.store.get(d, {}), **upd["$set"]}


class _FakeRepo:
    def __init__(self):
        self._c = _FakeColl()
    def collection(self, name):
        return self._c


class TestNormalize(unittest.TestCase):
    def test_fullwidth_to_halfwidth(self):
        q = ext.normalize_fofa_query('domain＝“a.com”＆＆title＝‘系统’')
        self.assertEqual(q, 'domain="a.com"&&title=\'系统\'')

    def test_newline_folded(self):
        self.assertEqual(ext.normalize_fofa_query('a\r\nb'), 'a b')

    def test_multi_space_collapsed(self):
        self.assertEqual(ext.normalize_fofa_query('a   &&   b'), 'a && b')

    def test_none_passthrough(self):
        self.assertIsNone(ext.normalize_fofa_query(None))


class TestFofaQuery(unittest.TestCase):
    def test_no_key_degrades(self):
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: "" if a[:2] == ("FOFA", "KEY") else k.get("default")
        with mock.patch.object(ext, "get_config", return_value=cfg):
            out = ext.fofa_query('domain="a.com"')
        self.assertIsInstance(out, str)
        self.assertIn("FOFA.KEY", out)

    def test_key_masked_on_error(self):
        cfg = mock.Mock()
        vals = {("FOFA", "KEY"): "0123456789SECRETTAIL", ("FOFA", "PAGE_SIZE"): 2000,
                ("FOFA", "MAX_PAGE"): 1, ("FOFA", "URL"): "https://fofa.info"}
        cfg.section.side_effect = lambda *a, **k: vals.get(a[:2], k.get("default"))
        with mock.patch.object(ext, "get_config", return_value=cfg), \
             mock.patch.object(ext, "http_req", return_value=_Resp(200, {"error": True, "errmsg": "bad 0123456789SECRETTAIL"})):
            out = ext.fofa_query('domain="a.com"')
        self.assertIsInstance(out, str)
        self.assertNotIn("SECRETTAIL", out)   # key 尾段被脱敏
        self.assertIn("***", out)

    def test_fallback_log_masks_key(self):
        """安全：next 游标回退的 WARNING 日志不得回显 key 明文（守全局安全边界）。"""
        cfg = mock.Mock()
        vals = {("FOFA", "KEY"): "0123456789SECRETTAIL", ("FOFA", "PAGE_SIZE"): 2000,
                ("FOFA", "MAX_PAGE"): 1, ("FOFA", "URL"): "https://fofa.info"}
        cfg.section.side_effect = lambda *a, **k: vals.get(a[:2], k.get("default"))
        # next 抛含 key 的错 → 回退；page 也抛（返回错误字符串）。断言日志被脱敏。
        with mock.patch.object(ext, "get_config", return_value=cfg), \
             mock.patch.object(ext, "http_req", return_value=_Resp(200, {"error": True, "errmsg": "x 0123456789SECRETTAIL"})), \
             self.assertLogs("sentinel_platform", level="WARNING") as cm:
            ext.fofa_query('domain="a.com"')
        self.assertFalse(any("SECRETTAIL" in line for line in cm.output),
                         "key 尾段泄露到日志: {}".format(cm.output))


class TestCrtsh(unittest.TestCase):
    def test_parse_and_filter(self):
        payload = [{"name_value": "a.example.com\n*.b.example.com\nother.com"}]
        with mock.patch.object(ext, "http_req", return_value=_Resp(200, payload)):
            out = ext.crtsh_search("example.com")
        self.assertIn("a.example.com", out)
        self.assertIn("b.example.com", out)
        self.assertNotIn("other.com", out)    # 不归属 example.com 被过滤

    def test_error_returns_empty(self):
        with mock.patch.object(ext, "http_req", side_effect=Exception("net")):
            self.assertEqual(ext.crtsh_search("x.com"), [])


class TestIcpQuery(unittest.TestCase):
    def setUp(self):
        self.repo = _FakeRepo()

    def _cfg(self, hunter="", fofa=""):
        cfg = mock.Mock()
        vals = {("HUNTER", "KEY"): hunter, ("FOFA", "KEY"): fofa,
                ("HUNTER", "URL"): "https://hunter.qianxin.com", ("FOFA", "URL"): "https://fofa.info"}
        cfg.section.side_effect = lambda *a, **k: vals.get(a[:2], k.get("default"))
        return cfg

    def test_hunter_priority(self):
        hunter_resp = _Resp(200, {"code": 200, "data": {"arr": [{"company": "某某公司", "number": "京ICP备1号"}]}})
        with mock.patch.object(ext, "get_config", return_value=self._cfg(hunter="k")), \
             mock.patch.object(ext, "get_repo", return_value=self.repo), \
             mock.patch.object(ext, "http_req", return_value=hunter_resp):
            out = ext.icp_query("www.a.com")
        self.assertEqual(out["unit"], "某某公司")
        self.assertEqual(out["source"], "hunter")
        # 写入缓存后二次查命中 cache
        with mock.patch.object(ext, "get_config", return_value=self._cfg(hunter="k")), \
             mock.patch.object(ext, "get_repo", return_value=self.repo), \
             mock.patch.object(ext, "http_req", side_effect=AssertionError("不应再发请求")):
            again = ext.icp_query("a.com")
        self.assertEqual(again["unit"], "某某公司")

    def test_no_key_empty_unit(self):
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "get_repo", return_value=self.repo):
            out = ext.icp_query("a.com")
        self.assertEqual(out["unit"], "")

    def test_main_domain_reduces_to_fld(self):
        # 归约到主域：子域/协议/端口都剥掉，映射同一 fld（ICP 按主域备案）
        self.assertEqual(ext._main_domain("https://sub.a.com:8080/path"), "a.com")
        self.assertEqual(ext._main_domain("www.a.com"), "a.com")
        self.assertEqual(ext._main_domain("x.gov.cn"), "x.gov.cn")      # 二级后缀取三段
        self.assertEqual(ext._main_domain("sub.x.com.cn"), "x.com.cn")


if __name__ == "__main__":
    unittest.main()
