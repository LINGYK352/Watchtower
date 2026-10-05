"""kernel/notify 单测 —— core 内存替身，不需真 Mongo / 不发真网络。

覆盖：接口契约（NotifyService 结构化子类型）、渠道分发、飞书签名 payload、
阈值过滤、日志去重节流+噪音过滤、错误汇总不抛、register 注册。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.interfaces import NotifyService
from sentinel_platform.contracts.registry import reset_registry


class _FakeCollection:
    def __init__(self, doc=None):
        self._doc = doc

    def find_one(self, query):
        return self._doc


class _FakeRepo(Repository):
    """只替 collection()，返回预置 api_keys 文档，不连真库。"""
    def __init__(self, api_keys_doc=None):
        self._doc = api_keys_doc

    def collection(self, name):
        return _FakeCollection(self._doc)


def _reset_notify_caches():
    from sentinel_platform.modules.kernel import notify as n
    n._cfg_cache.update(data=None, ts=0.0)
    n._notify_dedup.clear()


class NotifyTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()
        _reset_notify_caches()

    def tearDown(self):
        reset_repo()
        reset_registry()
        _reset_notify_caches()

    # —— 接口契约 ——
    def test_satisfies_protocol(self):
        from sentinel_platform.modules.kernel.notify import NotifyServiceImpl
        self.assertIsInstance(NotifyServiceImpl(), NotifyService)

    def test_register_puts_notify_into_registry(self):
        from sentinel_platform.modules.kernel.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get(ROLE.NOTIFY)
        self.assertIsNotNone(svc)
        self.assertTrue(hasattr(svc, "notify"))

    # —— 参数校验 ——
    def test_empty_message_returns_error(self):
        from sentinel_platform.modules.kernel.notify import NotifyServiceImpl
        r = NotifyServiceImpl().notify("")
        self.assertFalse(r["ok"])
        self.assertIn("error", r)
        self.assertEqual(r["sent"], [])

    # —— 渠道分发：飞书启用，发送成功 ——
    def test_notify_feishu_success(self):
        set_repo(_FakeRepo({"name": "default",
                            "feishu": {"enabled": True, "webhook": "https://feishu/x"}}))
        from sentinel_platform.modules.kernel.notify import NotifyServiceImpl
        with mock.patch("sentinel_platform.modules.kernel.notify._feishu_send") as m:
            r = NotifyServiceImpl().notify("hello", title="t")
        m.assert_called_once()
        self.assertTrue(r["ok"])
        self.assertEqual(r["sent"], ["feishu"])

    # —— 自动模式：未启用渠道被跳过 ——
    def test_auto_skips_disabled_channel(self):
        set_repo(_FakeRepo({"name": "default", "feishu": {"enabled": False, "webhook": "x"}}))
        from sentinel_platform.modules.kernel.notify import NotifyServiceImpl
        with mock.patch("sentinel_platform.modules.kernel.notify._feishu_send") as m:
            r = NotifyServiceImpl().notify("hi")
        m.assert_not_called()
        self.assertFalse(r["ok"])
        self.assertEqual(r["sent"], [])

    # —— 单渠道失败：汇总 error，不抛 ——
    def test_channel_failure_summarized_not_raised(self):
        set_repo(_FakeRepo({"name": "default",
                            "feishu": {"enabled": True, "webhook": "https://feishu/x"}}))
        from sentinel_platform.modules.kernel.notify import NotifyServiceImpl
        with mock.patch("sentinel_platform.modules.kernel.notify._feishu_send",
                        side_effect=RuntimeError("boom")):
            r = NotifyServiceImpl().notify("hi", channel="feishu")
        self.assertFalse(r["ok"])
        self.assertIn("boom", r["error"])

    def test_unknown_channel(self):
        set_repo(_FakeRepo({}))
        from sentinel_platform.modules.kernel.notify import NotifyServiceImpl
        r = NotifyServiceImpl().notify("hi", channel="telegram")
        self.assertFalse(r["ok"])
        self.assertIn("telegram", r["error"])

    # —— 飞书签名 payload 结构 ——
    def test_feishu_send_builds_signed_payload(self):
        from sentinel_platform.modules.kernel import notify as n
        captured = {}

        class _Resp:
            status_code = 200
            def json(self):
                return {"code": 0}

        def _fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return _Resp()

        with mock.patch.dict("sys.modules", {"requests": mock.MagicMock(post=_fake_post)}):
            n._feishu_send({"webhook": "https://feishu/hook", "secret": "s3cr3t"},
                           "标题", "正文")
        self.assertEqual(captured["url"], "https://feishu/hook")
        self.assertEqual(captured["json"]["msg_type"], "post")
        self.assertIn("sign", captured["json"])
        self.assertIn("timestamp", captured["json"])

    def test_feishu_send_no_webhook_raises(self):
        from sentinel_platform.modules.kernel import notify as n
        with self.assertRaises(ValueError):
            n._feishu_send({}, "t", "c")

    # —— 漏洞阈值 ——
    def test_notify_vuln_below_threshold_skipped(self):
        set_repo(_FakeRepo({"name": "default",
                            "feishu": {"enabled": True, "webhook": "x", "min_severity": "high"}}))
        from sentinel_platform.modules.kernel import notify as n
        with mock.patch.object(n, "_feishu_send") as m:
            r = n.notify_vuln("SQLi", "http://t", "low")
        m.assert_not_called()
        self.assertFalse(r["ok"])

    def test_notify_vuln_meets_threshold_sends(self):
        set_repo(_FakeRepo({"name": "default",
                            "feishu": {"enabled": True, "webhook": "https://f/x",
                                       "min_severity": "medium"}}))
        from sentinel_platform.modules.kernel import notify as n
        with mock.patch.object(n, "_feishu_send") as m:
            r = n.notify_vuln("RCE", "http://t", "critical", cvss_score=9.8, unit="ACME")
        m.assert_called_once()
        self.assertTrue(r["ok"])

    # —— 日志噪音过滤 + 去重节流 ——
    def test_critical_log_noise_filtered(self):
        set_repo(_FakeRepo({"name": "default", "feishu": {"enabled": True, "webhook": "x"}}))
        from sentinel_platform.modules.kernel import notify as n
        with mock.patch.object(n, "_feishu_send") as m:
            r = n.notify_critical_log("scan", "Read timed out on host")
        m.assert_not_called()
        self.assertEqual(r["error"], "noise filtered")

    def test_critical_log_dedup_throttle(self):
        set_repo(_FakeRepo({"name": "default",
                            "feishu": {"enabled": True, "webhook": "https://f/x"}}))
        from sentinel_platform.modules.kernel import notify as n
        with mock.patch.object(n, "_feishu_send") as m:
            r1 = n.notify_critical_log("mod", "some real error happened")
            r2 = n.notify_critical_log("mod", "some real error happened")
        self.assertTrue(r1["ok"])
        self.assertFalse(r2["ok"])
        self.assertEqual(r2["error"], "throttled")
        self.assertEqual(m.call_count, 1)

    # —— 钉钉/企微渠道（设计 §九 写死三渠道，2026-08-02 补齐）——
    def test_dingtalk_send_builds_signed_payload(self):
        from sentinel_platform.modules.kernel import notify as n
        captured = {}

        class _Resp:
            status_code = 200
            def json(self):
                return {"errcode": 0}

        def _fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return _Resp()

        with mock.patch.dict("sys.modules", {"requests": mock.MagicMock(post=_fake_post)}):
            n._dingtalk_send({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=x",
                              "secret": "SEC123"}, "标题", "正文")
        self.assertIn("&timestamp=", captured["url"])   # 加签后 URL 带 timestamp+sign
        self.assertIn("&sign=", captured["url"])
        self.assertEqual(captured["json"]["msgtype"], "text")
        self.assertIn("标题", captured["json"]["text"]["content"])

    def test_dingtalk_no_secret_no_sign(self):
        from sentinel_platform.modules.kernel import notify as n
        captured = {}

        class _Resp:
            status_code = 200
            def json(self):
                return {"errcode": 0}

        with mock.patch.dict("sys.modules", {"requests": mock.MagicMock(
                post=lambda url, json=None, timeout=None: (captured.update(url=url) or _Resp()))}):
            n._dingtalk_send({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=x"},
                             "t", "c")
        self.assertNotIn("&sign=", captured["url"])     # 无 secret 不加签

    def test_dingtalk_no_webhook_raises(self):
        from sentinel_platform.modules.kernel import notify as n
        with self.assertRaises(ValueError):
            n._dingtalk_send({}, "t", "c")

    def test_wework_send_direct_post(self):
        from sentinel_platform.modules.kernel import notify as n
        captured = {}

        class _Resp:
            status_code = 200
            def json(self):
                return {"errcode": 0}

        def _fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return _Resp()

        with mock.patch.dict("sys.modules", {"requests": mock.MagicMock(post=_fake_post)}):
            n._wework_send({"webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x"},
                           "标题", "正文")
        self.assertEqual(captured["url"], "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x")
        self.assertEqual(captured["json"]["msgtype"], "text")   # 企微直接 POST 无签名

    def test_wework_no_webhook_raises(self):
        from sentinel_platform.modules.kernel import notify as n
        with self.assertRaises(ValueError):
            n._wework_send({}, "t", "c")

    def test_three_channels_registered(self):
        """设计 §九：飞书/钉钉/企微三渠道都在注册表（回归防再退化成单渠道）。"""
        from sentinel_platform.modules.kernel import notify as n
        self.assertEqual(set(n._CHANNELS), {"feishu", "dingtalk", "wework"})

    def test_notify_dispatches_to_dingtalk(self):
        """notify(channel='dingtalk') 真分发到钉钉发送函数。"""
        set_repo(_FakeRepo({"name": "default",
                            "dingtalk": {"enabled": True, "webhook": "https://d/x"}}))
        from sentinel_platform.modules.kernel import notify as n
        with mock.patch.object(n, "_dingtalk_send") as m:
            r = n._service.notify("msg", channel="dingtalk")
        m.assert_called_once()
        self.assertIn("dingtalk", r["sent"])


if __name__ == "__main__":
    unittest.main()
