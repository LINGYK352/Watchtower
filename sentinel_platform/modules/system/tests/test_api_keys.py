"""system/api_keys 单测 —— core 内存替身，不连真 Mongo。

覆盖：默认文档、列出掩码、保存（掩码不覆盖/明文覆盖/enabled 切换）、get_key（enabled/禁用/未知）、
register 注册（字符串键 api_keys_service）、库故障降级。
"""
import unittest
from unittest import mock

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry
from sentinel_platform.contracts.registry import reset_registry


class _MemCollection:
    def __init__(self, doc=None):
        self._doc = dict(doc) if doc else None

    def find_one(self, query):
        return dict(self._doc) if self._doc else None

    def insert_one(self, doc):
        self._doc = dict(doc)
        return type("R", (), {"inserted_id": "mem1"})()

    def update_one(self, query, update, upsert=False):
        if self._doc is None:
            self._doc = {"name": "default"}
        self._doc.update(update.get("$set", {}))


class _MemRepo(Repository):
    def __init__(self, doc=None):
        self._coll = _MemCollection(doc)

    def collection(self, name):
        return self._coll


class ApiKeysTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry()
        from sentinel_platform.modules.system import api_keys
        self._validators = mock.patch.dict(
            api_keys._VALIDATORS,
            {name: (lambda _key, _sub: (True, "")) for name in api_keys._VALIDATORS},
            clear=False)
        self._validators.start()

    def tearDown(self):
        self._validators.stop()
        reset_repo(); reset_registry()

    def test_register_string_key(self):
        from sentinel_platform.modules.system.register import register
        set_repo(_MemRepo())
        reg = get_registry(); register(reg)
        svc = reg.get("api_keys_service")
        self.assertIsNotNone(svc)
        self.assertTrue(hasattr(svc, "list_keys") and hasattr(svc, "save_keys") and hasattr(svc, "get_key"))

    def test_default_doc_and_list_masked(self):
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import list_keys
        r = list_keys()
        ids = {i["id"] for i in r["items"]}
        self.assertIn("fofa", ids)
        self.assertIn("feishu", ids)
        # 默认全未启用、密钥未配置
        fofa = next(i for i in r["items"] if i["id"] == "fofa")
        self.assertFalse(fofa["enabled"])
        self.assertFalse(fofa["key_set"])
        # feishu 的 min_severity 有默认 medium
        feishu = next(i for i in r["items"] if i["id"] == "feishu")
        self.assertEqual(feishu["min_severity"], "medium")

    def test_save_then_list_masks_secret(self):
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import save_keys
        r = save_keys({"fofa": {"key": "SECRETKEY123456", "enabled": True}})
        fofa = next(i for i in r["items"] if i["id"] == "fofa")
        self.assertTrue(fofa["enabled"])
        self.assertTrue(fofa["key_set"])
        self.assertTrue(fofa["key"].endswith("3456"))   # 末4位明文
        self.assertIn("*", fofa["key"])                 # 其余掩码
        self.assertNotIn("SECRET", fofa["key"])         # 明文不泄露

    def test_save_masked_value_does_not_overwrite(self):
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import save_keys, get_key
        save_keys({"fofa": {"key": "REALKEY7890", "enabled": True}})
        # 前端把掩码回传（未改）→ 不应覆盖真值
        masked = save_keys({"fofa": {"key": "*******7890", "enabled": True}})
        self.assertEqual(get_key("fofa")["key"], "REALKEY7890")
        # 传新明文 → 覆盖
        save_keys({"fofa": {"key": "NEWKEY4321", "enabled": True}})
        self.assertEqual(get_key("fofa")["key"], "NEWKEY4321")

    def test_get_key_respects_enabled(self):
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import save_keys, get_key
        save_keys({"feishu": {"webhook": "https://feishu/hook", "enabled": True}})
        self.assertEqual(get_key("feishu")["webhook"], "https://feishu/hook")
        # 禁用后 get_key 返空（消费方据此跳过）
        save_keys({"feishu": {"enabled": False}})
        self.assertEqual(get_key("feishu")["webhook"], "")

    def test_bool_switch_fields_roundtrip_false(self):
        """需求3 关联修复：bool 开关字段（vuln_feed_notify/proxy_down_notify）存 False 后
        list_keys 必须原样返 False，绝不被 `or ""` 成空串（否则前端按默认 true 回显→关了又变开）。"""
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import save_keys, list_keys, get_key
        save_keys({"feishu": {"webhook": "https://feishu/hook", "enabled": True,
                              "proxy_down_notify": False, "vuln_feed_notify": False}})
        feishu = next(i for i in list_keys()["items"] if i["id"] == "feishu")
        self.assertIs(feishu["proxy_down_notify"], False)
        self.assertIs(feishu["vuln_feed_notify"], False)
        # 存 True 也如实返回
        save_keys({"feishu": {"proxy_down_notify": True, "enabled": True, "webhook": "https://feishu/hook"}})
        self.assertIs(get_key("feishu")["proxy_down_notify"], True)

    def test_proxy_down_notify_default_true(self):
        """默认文档 proxy_down_notify 应为 True（默认开启）。"""
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import _default_doc
        self.assertIs(_default_doc()["feishu"]["proxy_down_notify"], True)

    def test_get_key_unknown(self):
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import get_key
        self.assertEqual(get_key("nonexistent"), {})

    def test_save_non_dict(self):
        set_repo(_MemRepo())
        from sentinel_platform.modules.system.api_keys import save_keys
        self.assertIn("error", save_keys("notdict"))

    def test_get_doc_db_failure_degrades(self):
        from sentinel_platform.modules.system.api_keys import get_doc

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        doc = get_doc()   # 降级返回内存默认，不抛
        self.assertEqual(doc["name"], "default")


if __name__ == "__main__":
    unittest.main()
