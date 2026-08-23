"""黑名单过滤单测 —— 补净室迁移丢失的数据卫生（check_domain_black/is_black_asset_site）。

覆盖：①域名后缀匹配(blackdomain endswith) ②违规词子串(blackhexie in) ③站点前缀(black_asset_site startswith)
④filter_domains 就地滤 ctx.hosts+domains ⑤filter_sites 滤 ctx.sites ⑥字典缺失降级不崩。
不依赖真字典文件——monkeypatch 缓存注入测试数据（隔离，不受 dicts/ 实际内容影响）。
"""
import unittest

from sentinel_platform.modules.kernel.recon import blacklist as bl


class _Ctx:
    """最小 ReconContext 替身（只需 hosts/domains/sites + options）。"""
    def __init__(self, hosts=None, domains=None, sites=None, options=None):
        self.hosts = list(hosts or [])
        self.domains = list(domains or [])
        self.sites = list(sites or [])
        self.options = options or {}


class _Dom:
    def __init__(self, domain):
        self.domain = domain


class _Site:
    def __init__(self, url, hostname=""):
        self.url = url
        self.hostname = hostname


class TestBlacklist(unittest.TestCase):
    def setUp(self):
        # 直接注入缓存，隔离真字典文件
        bl._black_domain = [".aliyunwaf.com", ".qzone.qq.com"]
        bl._black_word = ["google", "facebook"]
        bl._black_site = ["https://qiangzhan.qq.com"]

    def tearDown(self):
        bl.reset_cache()

    def test_black_domain_suffix(self):
        self.assertTrue(bl.is_black_domain("x.aliyunwaf.com"))     # 后缀命中 WAF
        self.assertTrue(bl.is_black_domain("a.qzone.qq.com"))
        self.assertFalse(bl.is_black_domain("real.target.com"))

    def test_black_domain_word(self):
        self.assertTrue(bl.is_black_domain("www.google.com"))      # 违规词子串
        self.assertTrue(bl.is_black_domain("m.facebook.net"))
        self.assertFalse(bl.is_black_domain("mytarget.cn"))

    def test_black_site_prefix(self):
        self.assertTrue(bl.is_black_site("https://qiangzhan.qq.com/path"))
        self.assertFalse(bl.is_black_site("https://real.target.com"))

    def test_filter_domains_inplace(self):
        ctx = _Ctx(hosts=["real.target.com", "x.aliyunwaf.com", "www.google.com"],
                   domains=[_Dom("real.target.com"), _Dom("x.aliyunwaf.com"), _Dom("www.google.com")])
        dropped = bl.filter_domains(ctx)
        self.assertEqual(dropped, 2)                                # 滤掉 waf + google
        self.assertEqual(ctx.hosts, ["real.target.com"])
        self.assertEqual([d.domain for d in ctx.domains], ["real.target.com"])

    def test_filter_sites_inplace(self):
        ctx = _Ctx(sites=[_Site("https://real.target.com", "real.target.com"),
                          _Site("https://qiangzhan.qq.com", "qiangzhan.qq.com"),
                          _Site("http://y.aliyunwaf.com", "y.aliyunwaf.com")])
        dropped = bl.filter_sites(ctx)
        self.assertEqual(dropped, 2)                                # 滤掉 站点前缀黑 + 域名黑
        self.assertEqual([s.url for s in ctx.sites], ["https://real.target.com"])

    def test_empty_dict_no_filter(self):
        bl._black_domain, bl._black_word, bl._black_site = [], [], []
        self.assertFalse(bl.is_black_domain("anything.com"))
        ctx = _Ctx(hosts=["a.com"], domains=[_Dom("a.com")])
        self.assertEqual(bl.filter_domains(ctx), 0)                 # 空字典=不过滤

    def test_empty_input_safe(self):
        self.assertFalse(bl.is_black_domain(""))
        self.assertFalse(bl.is_black_site(""))


class TestPipelineGating(unittest.TestCase):
    """pipeline 门控：blacklist_filter=false 时不过滤（守禁硬限制精神，可关）。"""
    def setUp(self):
        bl._black_domain = [".aliyunwaf.com"]
        bl._black_word = []
        bl._black_site = []

    def tearDown(self):
        bl.reset_cache()

    def test_gating_off_skips(self):
        from sentinel_platform.modules.kernel.recon import pipeline
        ctx = _Ctx(hosts=["x.aliyunwaf.com"], domains=[_Dom("x.aliyunwaf.com")],
                   options={"blacklist_filter": False})
        self.assertEqual(pipeline._apply_blacklist_domains(ctx), 0)  # 关了不滤
        self.assertEqual(ctx.hosts, ["x.aliyunwaf.com"])

    def test_gating_on_default_filters(self):
        from sentinel_platform.modules.kernel.recon import pipeline
        ctx = _Ctx(hosts=["x.aliyunwaf.com", "real.com"],
                   domains=[_Dom("x.aliyunwaf.com"), _Dom("real.com")], options={})
        self.assertEqual(pipeline._apply_blacklist_domains(ctx), 1)  # 默认开
        self.assertEqual(ctx.hosts, ["real.com"])


if __name__ == "__main__":
    unittest.main()
