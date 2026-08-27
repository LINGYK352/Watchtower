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


class TestFofaCount(unittest.TestCase):
    """fofa_count：只读官方 size + 如实透传 error/errmsg（治"预估0条=会员上限"的误导）。"""

    def _cfg(self, key="0123456789SECRETTAIL"):
        cfg = mock.Mock()
        vals = {("FOFA", "KEY"): key, ("FOFA", "URL"): "https://fofa.info"}
        cfg.section.side_effect = lambda *a, **k: vals.get(a[:2], k.get("default"))
        return cfg

    def test_size_zero_is_not_error(self):
        # domain="gov.cn" 场景：FOFA 返回 size=0 error=False → ok=True size=0（非报错、非上限）
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "_apikey", return_value=""), \
             mock.patch.object(ext, "http_req",
                               return_value=_Resp(200, {"error": False, "size": 0, "results": []})):
            r = ext.fofa_count('domain="gov.cn"')
        self.assertTrue(r["ok"]); self.assertFalse(r["error"]); self.assertEqual(r["size"], 0)

    def test_size_positive(self):
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "_apikey", return_value=""), \
             mock.patch.object(ext, "http_req",
                               return_value=_Resp(200, {"error": False, "size": 19826, "results": [["a"]]})):
            r = ext.fofa_count('cert="gov.cn"')
        self.assertTrue(r["ok"]); self.assertEqual(r["size"], 19826)

    def test_real_error_passthrough_masked(self):
        # 非限流的真实报错（如语法错）→ ok=False + errmsg 原文透传，且 key 尾段脱敏
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "_apikey", return_value=""), \
             mock.patch.object(ext, "http_req",
                               return_value=_Resp(200, {"error": True, "errmsg": "语法错误 0123456789SECRETTAIL"})):
            r = ext.fofa_count('domain="a.com"')
        self.assertFalse(r["ok"]); self.assertTrue(r["error"])
        self.assertIn("语法错误", r["errmsg"])
        self.assertNotIn("SECRETTAIL", r["errmsg"])   # key 脱敏

    def test_ratelimit_retries_then_succeeds(self):
        # 限流(429/速度过快)先失败、重试后成功 → 自愈返回真实 size（不把限流当结果直报）
        seq = [_Resp(429, {}),
               _Resp(200, {"error": True, "errmsg": "[820000] 请求速度过快"}),
               _Resp(200, {"error": False, "size": 1664, "results": [["a"]]})]
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "_apikey", return_value=""), \
             mock.patch.object(ext, "time"), \
             mock.patch.object(ext, "http_req", side_effect=seq):
            r = ext.fofa_count('domain="beijing.gov.cn"')
        self.assertTrue(r["ok"]); self.assertEqual(r["size"], 1664)

    def test_ratelimit_exhausted_friendly_msg(self):
        # 一直限流 → 重试耗尽给"稍后重试"友好提示，而非笼统 429/会员上限
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "_apikey", return_value=""), \
             mock.patch.object(ext, "time"), \
             mock.patch.object(ext, "http_req", return_value=_Resp(429, {})):
            r = ext.fofa_count('domain="a.com"')
        self.assertFalse(r["ok"]); self.assertTrue(r["error"])
        self.assertIn("限流", r["errmsg"])
        self.assertIn("稍后重试", r["errmsg"])

    def test_no_key(self):
        cfg = self._cfg(key="")
        with mock.patch.object(ext, "get_config", return_value=cfg), \
             mock.patch.object(ext, "_apikey", return_value=""):
            r = ext.fofa_count('domain="a.com"')
        self.assertFalse(r["ok"]); self.assertTrue(r["error"])


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
        # 无 key：Hunter 空 → miit 兜底也 mock 空 → FOFA 空 → 空 unit（mock 掉 miit 防打真网络）
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "get_repo", return_value=self.repo), \
             mock.patch.object(ext, "_query_miit", return_value=None):
            out = ext.icp_query("a.com")
        self.assertEqual(out["unit"], "")

    def test_miit_fallback_when_hunter_no_unit(self):
        # Hunter 无 key（返 None）→ 官方 miit 兜底出单位名 → 采用 miit，且写缓存
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "get_repo", return_value=self.repo), \
             mock.patch.object(ext, "_query_miit",
                               return_value={"unit": "官方公司", "icp_no": "京ICP备9号", "source": "miit"}) as mm:
            out = ext.icp_query("b.com")
        self.assertEqual(out["unit"], "官方公司")
        self.assertEqual(out["source"], "miit")
        mm.assert_called_once_with("b.com")
        # 二次查命中缓存，不再调 miit
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "get_repo", return_value=self.repo), \
             mock.patch.object(ext, "_query_miit", side_effect=AssertionError("应命中缓存不再查")):
            again = ext.icp_query("b.com")
        self.assertEqual(again["unit"], "官方公司")

    def test_hunter_unit_skips_miit(self):
        # Hunter 出了单位名 → 不应再调 miit（兜底定位，Hunter 优先省验证码开销）
        hunter_resp = _Resp(200, {"code": 200, "data": {"arr": [{"company": "H公司", "number": "沪ICP备2号"}]}})
        with mock.patch.object(ext, "get_config", return_value=self._cfg(hunter="k")), \
             mock.patch.object(ext, "get_repo", return_value=self.repo), \
             mock.patch.object(ext, "http_req", return_value=hunter_resp), \
             mock.patch.object(ext, "_query_miit", side_effect=AssertionError("Hunter 已出单位名不应调 miit")):
            out = ext.icp_query("c.com")
        self.assertEqual(out["source"], "hunter")

    def test_miit_degrades_on_exception(self):
        # _query_miit 内部异常 → 返回 None，icp_query 不崩、降级空 unit
        with mock.patch.object(ext, "get_config", return_value=self._cfg()), \
             mock.patch.object(ext, "get_repo", return_value=self.repo), \
             mock.patch("sentinel_platform.modules.kernel._icp_miit.query_icp",
                        side_effect=RuntimeError("boom")):
            out = ext.icp_query("d.com")
        self.assertEqual(out["unit"], "")

    def test_main_domain_reduces_to_fld(self):
        # 归约到主域：子域/协议/端口都剥掉，映射同一 fld（ICP 按主域备案）
        self.assertEqual(ext._main_domain("https://sub.a.com:8080/path"), "a.com")
        self.assertEqual(ext._main_domain("www.a.com"), "a.com")
        self.assertEqual(ext._main_domain("x.gov.cn"), "x.gov.cn")      # 二级后缀取三段
        self.assertEqual(ext._main_domain("sub.x.com.cn"), "x.com.cn")


class TestMultiSourceDedup(unittest.TestCase):
    """多源合并去重：域名按 hostname、纯IP按 ip+port，宽进不误删（不解析域名成IP，避免CDN误合并）。"""

    def test_dedup_rows(self):
        rows = [
            {"host": "www.a.gov.cn", "ip": "1.1.1.1", "port": "443"},   # 域名
            {"host": "www.b.gov.cn", "ip": "1.1.1.1", "port": "443"},   # 同IP不同域名(CDN)→都保留
            {"host": "www.a.gov.cn", "ip": "1.1.1.1", "port": "443"},   # 重复域名→合并
            {"host": "", "ip": "2.2.2.2", "port": "8080"},              # 纯IP
            {"host": "", "ip": "2.2.2.2", "port": "8080"},              # 重复IP+port→合并
            {"host": "", "ip": "2.2.2.2", "port": "9090"},              # 同IP不同port→保留
        ]
        targets = ext._dedup_source_rows(rows)
        # www.a / www.b 都在(域名不因同IP合并，避免CDN误合并)；同IP不同端口合并成一次IP任务
        self.assertIn("www.a.gov.cn", targets)
        self.assertIn("www.b.gov.cn", targets)
        self.assertIn("2.2.2.2", targets)
        # a域名 + b域名 + 2.2.2.2(同IP不同端口→一次IP任务，全端口扫) = 3
        self.assertEqual(len(targets), 3)
        self.assertEqual(sorted(set(targets)), sorted(targets))  # 无重复字符串

    def test_multi_source_merge(self):
        from unittest import mock
        # FOFA 返回 [[host,ip,port]]，鹰图返回 {rows:[{host,ip,port}]}
        fake_fofa = [["www.a.gov.cn", "1.1.1.1", "443"], ["www.c.gov.cn", "3.3.3.3", "80"]]
        fake_hunter = {"ok": True, "total": 2, "rows": [
            {"host": "www.a.gov.cn", "ip": "1.1.1.1", "port": "443"},   # 与FOFA重复→合并
            {"host": "www.d.gov.cn", "ip": "4.4.4.4", "port": "443"},   # 鹰图独有→互补
        ], "error": ""}
        with mock.patch.object(ext, "fofa_query", return_value=fake_fofa), \
             mock.patch.object(ext, "hunter_query", return_value=fake_hunter), \
             mock.patch.object(ext, "normalize_fofa_query", side_effect=lambda x: x):
            r = ext.multi_source_targets({"fofa": 'domain="gov.cn"', "hunter": 'domain="gov.cn"'})
        self.assertTrue(r["ok"])
        # a(两源重复→1) + c(FOFA) + d(鹰图) = 3 个互补去重后目标
        self.assertEqual(set(r["targets"]), {"www.a.gov.cn", "www.c.gov.cn", "www.d.gov.cn"})
        self.assertEqual(r["per_source"]["fofa"], 2)
        self.assertEqual(r["per_source"]["hunter"], 2)
        self.assertEqual(r["merged"], 3)


if __name__ == "__main__":
    unittest.main()
