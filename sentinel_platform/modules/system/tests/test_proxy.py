"""system/proxy 单测 —— core 内存替身 + mock 出口 IP，不发真网络。

覆盖：接口契约（ProxyService 结构化子类型）、出口决策三档、配置层（默认/校验/持久化）、
健康检测（成功/失败/缓存）、失活告警走 NOTIFY（含缺失降级）、status/detect_exit_ip、register 注册。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.interfaces import ProxyService
from sentinel_platform.contracts.registry import reset_registry


class _MemCollection:
    """极简内存 collection：支持 find_one/insert_one/update_one(upsert)。"""
    def __init__(self):
        self._doc = None

    def find_one(self, query):
        return dict(self._doc) if self._doc else None

    def insert_one(self, doc):
        self._doc = dict(doc)
        self._doc.setdefault("_id", "mem1")
        return type("R", (), {"inserted_id": self._doc["_id"]})()

    def update_one(self, query, update, upsert=False):
        if self._doc is None:
            if upsert:
                self._doc = {"name": "default"}
            else:
                return
        self._doc.update(update.get("$set", {}))


class _MemRepo(Repository):
    def __init__(self, doc=None):
        self._coll = _MemCollection()
        if doc is not None:
            self._coll._doc = dict(doc)

    def collection(self, name):
        return self._coll


def _reset_health():
    from sentinel_platform.modules.system import proxy as p
    p._HEALTH_CACHE.update(ok=False, ts=0.0, fail_streak=0, notified_down=False)


class ProxyTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); _reset_health()

    def tearDown(self):
        reset_repo(); reset_registry(); _reset_health()

    # —— 接口契约 ——
    def test_satisfies_protocol(self):
        from sentinel_platform.modules.system.proxy import ProxyServiceImpl
        self.assertIsInstance(ProxyServiceImpl(), ProxyService)

    def test_register_puts_proxy_into_registry(self):
        from sentinel_platform.modules.system.register import register
        set_repo(_MemRepo())
        reg = get_registry(); register(reg)
        svc = reg.get(ROLE.PROXY)
        self.assertIsNotNone(svc)
        self.assertTrue(hasattr(svc, "resolve_egress") and hasattr(svc, "check_health"))

    # —— 出口决策三档 ——
    def test_resolve_egress_direct(self):
        from sentinel_platform.modules.system.proxy import ProxyServiceImpl
        self.assertEqual(ProxyServiceImpl().resolve_egress("direct"), ("", False))

    def _expected_mihomo_url(self, port=17890):
        # mihomo host 环境相关：容器设 MIHOMO_HOST=mihomo（独立容器架构），本地回退 127.0.0.1。
        # 断言用实际 _mihomo_host() 而非硬编码，避免容器/本地跑出不同结果的假失败。
        from sentinel_platform.modules.system.proxy import _mihomo_host
        return "http://{}:{}".format(_mihomo_host(), port)

    def test_resolve_egress_global_enabled(self):
        # 新4模式：global 需 global_mode_enabled=True + 订阅源，才返回 URL
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890,
                           "global_mode_enabled": True, "global_source": {"type": "subscription", "ref_id": ""}}))
        from sentinel_platform.modules.system.proxy import ProxyServiceImpl
        url, fb = ProxyServiceImpl().resolve_egress("global")
        self.assertEqual(url, self._expected_mihomo_url())
        self.assertFalse(fb)

    def test_resolve_egress_global_disabled_direct(self):
        # global 未开 → 降级直连
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890, "global_mode_enabled": False}))
        from sentinel_platform.modules.system.proxy import ProxyServiceImpl
        self.assertEqual(ProxyServiceImpl().resolve_egress("global"), ("", False))

    def test_resolve_egress_smart_fallback(self):
        # smart → allow_fallback=True（可回退直连），URL 取智能源
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890,
                           "smart_source": {"type": "subscription", "ref_id": ""}}))
        from sentinel_platform.modules.system.proxy import ProxyServiceImpl
        url, fb = ProxyServiceImpl().resolve_egress("smart")
        self.assertEqual(url, self._expected_mihomo_url())
        self.assertTrue(fb)

    def test_resolve_egress_legacy_source_compat(self):
        # 旧调用兼容：recon_bridge 传 (mode, source=subscription) —— proxy+source 直接走该源
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system.proxy import ProxyServiceImpl
        svc = ProxyServiceImpl()
        url, force = svc.resolve_egress("proxy", source="subscription")
        self.assertEqual(url, self._expected_mihomo_url())   # 旧 proxy+source 直接走订阅源
        self.assertTrue(force)                             # 旧 proxy=强制走代理(不回退)
        self.assertEqual(svc.resolve_egress("off"), ("", False))          # off→direct

    def test_resolve_egress_direct_mode(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system.proxy import ProxyServiceImpl
        self.assertEqual(ProxyServiceImpl().resolve_egress("direct"), ("", False))

    # —— 配置层 ——
    def test_get_config_creates_default(self):
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.proxy import get_config
        cfg = get_config()
        self.assertEqual(cfg["mode"], "rule")
        self.assertEqual(cfg["http_port"], 17890)
        self.assertFalse(cfg["enabled"])

    def test_save_config_whitelist_and_validation(self):
        set_repo(_MemRepo({"name": "default", "enabled": False, "mode": "rule"}))
        from sentinel_platform.modules.system.proxy import save_config
        r = save_config({"enabled": True, "mode": "global", "http_port": "18080",
                         "malicious": "x"})  # 非白名单字段应被忽略
        self.assertTrue(r["enabled"])
        self.assertEqual(r["mode"], "global")
        self.assertEqual(r["http_port"], 18080)   # 字符串→int
        self.assertNotIn("malicious", r)

    def test_save_config_bad_mode(self):
        set_repo(_MemRepo({"name": "default"}))
        from sentinel_platform.modules.system.proxy import save_config
        self.assertIn("error", save_config({"mode": "weird"}))

    def test_save_config_doh_string_split(self):
        set_repo(_MemRepo({"name": "default"}))
        from sentinel_platform.modules.system.proxy import save_config
        r = save_config({"doh_endpoints": "https://a/dns, https://b/dns"})
        self.assertEqual(r["doh_endpoints"], ["https://a/dns", "https://b/dns"])

    # —— 代理源结构性校验（选空源应拦保存，只查空不探可达）——
    def test_save_config_rejects_empty_pool_source(self):
        """核心 bug：全局代理选「公共代理」但池空(0可用) → 必须拦保存并给明确错误。"""
        set_repo(_MemRepo({"name": "default", "enabled": True}))
        from sentinel_platform.modules.system import proxy as p
        # 代理池服务返回空池（enabled=0/alive=0）
        fake_pool = type("P", (), {"stats": lambda self: {"total": 0, "alive": 0, "enabled": 0}})()
        get_registry().register("proxy_pool_service", fake_pool)
        r = p.save_config({"global_mode_enabled": True, "global_source": {"type": "pool", "ref_id": ""}})
        self.assertIn("error", r)
        self.assertIn("公共代理", r["error"])

    def test_save_config_accepts_pool_with_alive(self):
        """公共代理池有可用代理 → 放行保存。"""
        set_repo(_MemRepo({"name": "default", "enabled": True}))
        from sentinel_platform.modules.system import proxy as p
        fake_pool = type("P", (), {"stats": lambda self: {"total": 5, "alive": 3, "enabled": 3}})()
        get_registry().register("proxy_pool_service", fake_pool)
        r = p.save_config({"global_mode_enabled": True, "global_source": {"type": "pool", "ref_id": ""}})
        self.assertNotIn("error", r)
        self.assertTrue(r["global_mode_enabled"])

    def test_save_config_rejects_custom_without_ref(self):
        """全局选「自定义」但没选具体条目 → 拦。"""
        set_repo(_MemRepo({"name": "default", "enabled": True}))
        from sentinel_platform.modules.system import proxy as p
        r = p.save_config({"global_mode_enabled": True, "global_source": {"type": "custom", "ref_id": ""}})
        self.assertIn("error", r)
        self.assertIn("自定义", r["error"])

    def test_save_config_rejects_subscription_without_profile(self):
        """智能代理选「内核代理」但无激活订阅(active_profile_id 空) → 拦。"""
        set_repo(_MemRepo({"name": "default", "enabled": True, "active_profile_id": ""}))
        from sentinel_platform.modules.system import proxy as p
        r = p.save_config({"smart_source": {"type": "subscription", "ref_id": "sub1"}})
        self.assertIn("error", r)
        self.assertIn("内核代理", r["error"])

    def test_save_config_smart_default_placeholder_not_validated(self):
        """智能源=订阅空占位(默认直连) → 不校验、不拦（避免误伤直连）。"""
        set_repo(_MemRepo({"name": "default", "enabled": True}))
        from sentinel_platform.modules.system import proxy as p
        r = p.save_config({"smart_source": {"type": "subscription", "ref_id": ""}})
        self.assertNotIn("error", r)

    def test_save_config_direct_switch_not_validated(self):
        """切直连（global 关、源置空占位）→ 不校验源，正常保存。"""
        set_repo(_MemRepo({"name": "default", "enabled": True}))
        from sentinel_platform.modules.system import proxy as p
        r = p.save_config({"global_mode_enabled": False,
                           "global_source": {"type": "subscription", "ref_id": ""},
                           "smart_source": {"type": "subscription", "ref_id": ""}})
        self.assertNotIn("error", r)

    def test_save_config_port_change_skips_source_validation(self):
        """只改端口/DoH（提交不带源字段）→ 不触发源校验（不受空池影响）。"""
        set_repo(_MemRepo({"name": "default", "enabled": True}))
        from sentinel_platform.modules.system import proxy as p
        r = p.save_config({"http_port": 18888})
        self.assertNotIn("error", r)
        self.assertEqual(r["http_port"], 18888)

    # —— 健康检测 ——
    def test_check_health_disabled_false(self):
        set_repo(_MemRepo({"name": "default", "enabled": False}))
        from sentinel_platform.modules.system.proxy import check_health
        self.assertFalse(check_health(use_cache=False))

    def test_check_health_success(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system import proxy as p
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("1.2.3.4", "")):
            self.assertTrue(p.check_health(use_cache=False))

    def test_check_health_failure_notifies_after_threshold(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system import proxy as p
        # 注册一个假的 NOTIFY 记录调用
        calls = []
        fake_notify = type("N", (), {"notify": lambda self, msg, **kw: calls.append((msg, kw)) or {"ok": True}})()
        get_registry().register(ROLE.NOTIFY, fake_notify)
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("", "conn refused")):
            self.assertFalse(p.check_health(use_cache=False))   # 第1次失败：不告警
            self.assertEqual(len(calls), 0)
            self.assertFalse(p.check_health(use_cache=False))   # 第2次(达阈值)：告警一次
            self.assertEqual(len(calls), 1)
            self.assertFalse(p.check_health(use_cache=False))   # 第3次：已 notified_down，不重复
            self.assertEqual(len(calls), 1)

    def test_check_health_notify_missing_degrades(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system import proxy as p
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("", "err")):
            # NOTIFY 未注册：失活告警降级不崩
            p.check_health(use_cache=False)
            self.assertFalse(p.check_health(use_cache=False))   # 不抛异常即通过

    def test_check_health_recovery_resets(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system import proxy as p
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("", "err")):
            p.check_health(use_cache=False); p.check_health(use_cache=False)
        self.assertTrue(p._HEALTH_CACHE["notified_down"])
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("9.9.9.9", "")):
            self.assertTrue(p.check_health(use_cache=False))
        self.assertEqual(p._HEALTH_CACHE["fail_streak"], 0)
        self.assertFalse(p._HEALTH_CACHE["notified_down"])

    # —— status / detect_exit_ip ——
    def test_status_shape(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system.proxy import status
        s = status()
        for k in ("config", "running", "proxy_url", "last_health_ok"):
            self.assertIn(k, s)
        self.assertEqual(s["proxy_url"], self._expected_mihomo_url())

    def test_detect_exit_ip_proxied(self):
        # 4模式架构：仅 enabled:True 不够，须开全局代理(global_mode_enabled)才真走代理探出口。
        # （旧 config 只给 enabled 会被 current_platform_egress 判为 direct→不探代理，是过时写法。）
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890,
                           "global_mode_enabled": True,
                           "global_source": {"type": "subscription", "ref_id": ""}}))
        from sentinel_platform.modules.system import proxy as p
        # 直连返 1.1.1.1，经代理返 2.2.2.2 → proxied True
        seq = [("1.1.1.1", ""), ("2.2.2.2", "")]
        with mock.patch.object(p, "_fetch_exit_ip", side_effect=seq):
            r = p.detect_exit_ip(use_cache=False)
        self.assertEqual(r["direct_ip"], "1.1.1.1")
        self.assertEqual(r["proxy_ip"], "2.2.2.2")
        self.assertTrue(r["proxied"])

    def test_fetch_exit_ip_parallel_beats_head_of_line_block(self):
        """并行探测：首端点被墙(慢+失败)不应饿死后面可达端点。
        回归「国内直连 api.ipify.org 超时吃满预算→ifconfig.me 没机会→直连出口误报空」。"""
        import time as _t
        import requests
        from sentinel_platform.modules.system import proxy as p

        class _Resp:
            def __init__(self, text): self.status_code = 200; self.text = text

        def fake_get(self, url, **kw):
            if "ipify" in url:                 # 首端点：被墙，慢且失败
                _t.sleep(2.0)
                raise OSError("blocked")
            if "ifconfig" in url:              # 可达端点：快速返回合法 IP
                _t.sleep(0.05)
                return _Resp("36.34.8.122")
            _t.sleep(2.0)
            raise OSError("blocked")

        t0 = _t.time()
        with mock.patch.object(requests.Session, "get", fake_get):
            ip, err = p._fetch_exit_ip(None, timeout=4, deadline=_t.time() + 6)
        elapsed = _t.time() - t0
        self.assertEqual(ip, "36.34.8.122")    # 拿到可达端点的 IP（非空）
        self.assertEqual(err, "")
        self.assertLess(elapsed, 1.5)          # 未被 2s 的被墙端点阻塞（并行才可能 <1.5s）

    def test_fetch_exit_ip_direct_bypasses_env_proxy(self):
        """直连探测(proxies=None)必须 trust_env=False，杜绝被环境 *_proxy 劫持走代理。
        回归「直连出口恒空 + 报 Cannot connect to proxy」。"""
        import requests
        from sentinel_platform.modules.system import proxy as p
        seen = {}

        class _Resp:
            status_code = 200; text = "8.8.8.8"

        real_get = requests.Session.get

        def spy_get(self, url, **kw):
            seen["trust_env"] = self.trust_env
            seen["proxies"] = kw.get("proxies")
            return _Resp()

        with mock.patch.object(requests.Session, "get", spy_get):
            ip, err = p._fetch_exit_ip(None, timeout=2, deadline=0)
        self.assertEqual(ip, "8.8.8.8")
        self.assertFalse(seen["trust_env"])    # Session.trust_env 被关，忽略环境代理
        self.assertIsNone(seen["proxies"])     # 直连不传 proxies

    # —— 需求2：健康检测异常文案归一 ——
    def test_friendly_proxy_error_normalizes(self):
        from sentinel_platform.modules.system import proxy as p
        raw = ("HTTPSConnectionPool(host='ifconfig.me', port=443): Max retries exceeded "
               "with url: /ip (Caused by ProxyError('Cannot connect to proxy.', "
               "timeout('_ssl.c:1132: The handshake operation timed out')))")
        self.assertEqual(p._friendly_proxy_error(raw), "代理失效（全部节点不可达）")
        # 非代理连通类错误保持原样，不误伤
        self.assertEqual(p._friendly_proxy_error("proxy not enabled"), "proxy not enabled")
        self.assertEqual(p._friendly_proxy_error(""), "")

    def test_check_health_failure_stores_friendly_error(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system import proxy as p
        raw = "HTTPSConnectionPool ... ProxyError('Cannot connect to proxy')"
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("", raw)):
            self.assertFalse(p.check_health(use_cache=False))
        doc = p.get_config()
        self.assertEqual(doc.get("last_health_error"), "代理失效（全部节点不可达）")

    # —— 需求1：启用代理保存时探可达性，全挂则拦 ——
    def test_save_config_blocks_when_enabled_proxy_unreachable(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890,
                           "active_profile_id": "sub1"}))
        from sentinel_platform.modules.system import proxy as p
        with mock.patch.object(p, "_proxy_reachable", return_value=False):
            r = p.save_config({"global_mode_enabled": True,
                               "global_source": {"type": "subscription", "ref_id": "sub1"}})
        self.assertIn("error", r)
        self.assertIn("代理失效", r["error"])
        # 不可达被拦→未落库启用（global_mode_enabled 仍为旧值/未写入）
        self.assertNotEqual(p.get_config().get("global_mode_enabled"), True)

    def test_save_config_passes_when_enabled_proxy_reachable(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890,
                           "active_profile_id": "sub1"}))
        from sentinel_platform.modules.system import proxy as p
        with mock.patch.object(p, "_proxy_reachable", return_value=True):
            r = p.save_config({"global_mode_enabled": True,
                               "global_source": {"type": "subscription", "ref_id": "sub1"}})
        self.assertNotIn("error", r)
        self.assertTrue(p.get_config().get("global_mode_enabled"))

    def test_save_config_smart_not_blocked_by_reachability(self):
        """smart 模式设计上不可达自动降级直连，保存不因探测失败被拦。"""
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890,
                           "active_profile_id": "sub1"}))
        from sentinel_platform.modules.system import proxy as p
        with mock.patch.object(p, "_proxy_reachable", return_value=False):
            r = p.save_config({"smart_source": {"type": "subscription", "ref_id": "sub1"}})
        self.assertNotIn("error", r)

    # —— 需求3：代理告警推送开关（默认开，可关） ——
    def test_notify_down_gated_off_when_switch_false(self):
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system import proxy as p
        calls = []
        fake_notify = type("N", (), {"notify": lambda self, msg, **kw: calls.append(msg) or {"ok": True}})()
        fake_keys = type("K", (), {"get_key": lambda self, kid: {"proxy_down_notify": False}})()
        get_registry().register(ROLE.NOTIFY, fake_notify)
        get_registry().register("api_keys_service", fake_keys)
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("", "conn refused")):
            p.check_health(use_cache=False); p.check_health(use_cache=False)   # 达阈值本应告警
        self.assertEqual(len(calls), 0, "开关关闭时不推送代理告警")

    def test_notify_down_on_by_default_when_field_absent(self):
        """存量安装未存 proxy_down_notify（get_key 返 '' 或字段缺失）→ 默认开启，仍推送。"""
        set_repo(_MemRepo({"name": "default", "enabled": True, "http_port": 17890}))
        from sentinel_platform.modules.system import proxy as p
        calls = []
        fake_notify = type("N", (), {"notify": lambda self, msg, **kw: calls.append(msg) or {"ok": True}})()
        fake_keys = type("K", (), {"get_key": lambda self, kid: {"proxy_down_notify": ""}})()  # 存量空串
        get_registry().register(ROLE.NOTIFY, fake_notify)
        get_registry().register("api_keys_service", fake_keys)
        with mock.patch.object(p, "_fetch_exit_ip", return_value=("", "conn refused")):
            p.check_health(use_cache=False); p.check_health(use_cache=False)
        self.assertEqual(len(calls), 1, "字段缺失/空串按默认开启，正常推送")


if __name__ == "__main__":
    unittest.main()
