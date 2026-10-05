"""poc 叶子单测 —— 分页/查询构造/清空/同步降级，注入内存 repo，不需真 Mongo。

覆盖：①list_poc 分页信封形状(page/size/total/items) ②文本字段正则模糊 vs 枚举等值
③_id 序列化成 str ④size 上限/非法参数兜底 ⑤clear 返回 delete_cnt ⑥sync 诚实降级。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.risk_intel import poc


class _FakeColl:
    def __init__(self, docs=None):
        self.docs = list(docs or [])
        self._q = {}

    def _match(self, d, q):
        for k, v in q.items():
            if isinstance(v, dict) and "$regex" in v:
                import re
                if not re.search(v["$regex"], str(d.get(k, "")),
                                 re.I if v.get("$options") == "i" else 0):
                    return False
            elif d.get(k) != v:
                return False
        return True

    def count_documents(self, q):
        return sum(1 for d in self.docs if self._match(d, q))

    def find(self, q):
        self._q = q
        self._res = [d for d in self.docs if self._match(d, q)]
        return self

    def skip(self, n):
        self._res = self._res[n:]
        return self

    def limit(self, n):
        self._res = self._res[:n]
        return self

    def __iter__(self):
        return iter(self._res)

    def delete_many(self, q):
        n = len(self.docs)
        self.docs = []
        class _R:
            deleted_count = n
        return _R()

    def insert_many(self, docs):
        self.docs.extend(docs)
        return type("R", (), {"inserted_ids": list(range(len(docs)))})()


class _FakeRepo:
    def __init__(self, docs=None):
        self._c = _FakeColl(docs)

    def collection(self, name):
        return self._c


_SAMPLE = [
    {"_id": "a1", "plugin_name": "weblogic_rce", "app_name": "WebLogic",
     "vul_name": "WebLogic 反序列化", "plugin_type": "poc", "scheme": "http", "category": "rce"},
    {"_id": "a2", "plugin_name": "redis_unauth", "app_name": "Redis",
     "vul_name": "Redis 未授权", "plugin_type": "brute", "scheme": "redis", "category": "unauth"},
    {"_id": "a3", "plugin_name": "weblogic_ssrf", "app_name": "WebLogic",
     "vul_name": "WebLogic SSRF", "plugin_type": "poc", "scheme": "http", "category": "ssrf"},
]


class TestPocList(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo(_SAMPLE))

    def tearDown(self):
        set_repo(None)

    def test_envelope_shape(self):
        r = poc.list_poc({})
        self.assertEqual(set(r), {"page", "size", "total", "items"})
        self.assertEqual(r["total"], 3)
        self.assertEqual(r["page"], 1)

    def test_id_serialized_str(self):
        r = poc.list_poc({})
        self.assertTrue(all(isinstance(it["_id"], str) for it in r["items"]))

    def test_text_field_regex(self):
        r = poc.list_poc({"app_name": "weblogic"})   # 大小写不敏感模糊
        self.assertEqual(r["total"], 2)

    def test_equal_field(self):
        r = poc.list_poc({"plugin_type": "brute"})
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["items"][0]["plugin_name"], "redis_unauth")

    def test_pagination(self):
        r = poc.list_poc({"page": 1, "size": 2})
        self.assertEqual(len(r["items"]), 2)
        self.assertEqual(r["size"], 2)

    def test_bad_params_fallback(self):
        r = poc.list_poc({"page": "x", "size": "y"})
        self.assertEqual((r["page"], r["size"]), (1, 10))

    def test_size_no_hard_cap(self):
        # 禁硬限制参数：size 由调用方决定，不静默截断
        r = poc.list_poc({"size": 99999})
        self.assertEqual(r["size"], 99999)


class TestPocMutations(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo(_SAMPLE))

    def tearDown(self):
        set_repo(None)

    def test_clear_returns_count(self):
        r = poc.clear_poc()
        self.assertEqual(r["delete_cnt"], 3)
        self.assertEqual(poc.list_poc({})["total"], 0)

    def test_sync_plugins(self):
        from unittest import mock
        record = {"plugin_name": "Demo", "app_name": "Demo", "scheme": "http",
                  "vul_name": "Demo", "plugin_type": "poc", "category": "漏洞PoC"}
        with mock.patch.object(poc, "_locate_plugins_dir", return_value="/tmp/plugins"), \
             mock.patch.object(poc, "_scan_plugins", return_value=[record]):
            r = poc.sync_poc()
        self.assertEqual(r.get("plugin_cnt"), 1)
        self.assertEqual(poc.list_poc({})["total"], 1)


if __name__ == "__main__":
    unittest.main()
