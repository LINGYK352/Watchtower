"""fingerprint 叶子单测 —— 规则校验(安全:无 eval)/CRUD/去重/无硬限制，注入内存 repo。

重点：validate_rule 用 ast 白名单——放行合法规则、拒非法字段、**拒注入(函数调用/import)**。
"""
import unittest

from sentinel_platform.core import set_repo
from sentinel_platform.modules.asset import fingerprint as fp


class _FakeColl:
    def __init__(self):
        self.docs = []
    def find_one(self, q):
        for d in self.docs:
            if all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict)):
                return d
        return None
    def count_documents(self, q):
        return len(self._filter(q))
    def _filter(self, q):
        import re
        out = []
        for d in self.docs:
            ok = True
            for k, v in q.items():
                if isinstance(v, dict) and "$regex" in v:
                    if not re.search(v["$regex"], str(d.get(k, "")), re.I):
                        ok = False
                elif d.get(k) != v:
                    ok = False
            if ok:
                out.append(d)
        return out
    def find(self, q):
        self._r = self._filter(q); return self
    def sort(self, *a):
        return self
    def skip(self, n):
        self._r = self._r[n:]; return self
    def limit(self, n):
        self._r = self._r[:n]; return self
    def __iter__(self):
        return iter(self._r)
    def insert_one(self, doc):
        doc["_id"] = "fp{}".format(len(self.docs) + 1); self.docs.append(doc)
    def delete_one(self, q):
        d = self.find_one({"_id": q.get("_id")})
        # 简化：按传入 _id 的 str 匹配
        for x in list(self.docs):
            if str(x.get("_id")) == str(q.get("_id")):
                self.docs.remove(x)
                class _R: deleted_count = 1
                return _R()
        class _R0: deleted_count = 0
        return _R0()


class _FakeRepo:
    def __init__(self):
        self._c = _FakeColl()
    def collection(self, name):
        return self._c


class TestValidateRule(unittest.TestCase):
    def test_valid_simple(self):
        ok, _ = fp.validate_rule('body="Powered by X"')
        self.assertTrue(ok)

    def test_valid_and_or(self):
        ok, _ = fp.validate_rule('body="a" && title="登录" || server="nginx"')
        self.assertTrue(ok)

    def test_valid_neq(self):
        ok, _ = fp.validate_rule('title!="404"')
        self.assertTrue(ok)

    def test_empty_rejected(self):
        ok, msg = fp.validate_rule("")
        self.assertFalse(ok)

    def test_illegal_field(self):
        ok, msg = fp.validate_rule('evil="x"')
        self.assertFalse(ok)
        self.assertIn("非法字段", msg)

    def test_injection_call_rejected(self):
        # 注入尝试：函数调用（旧 eval 的攻击面）→ 必须拒
        ok, msg = fp.validate_rule('body=__import__("os").system("id")')
        self.assertFalse(ok)

    def test_injection_attr_rejected(self):
        ok, _ = fp.validate_rule('body=os.system')
        self.assertFalse(ok)

    def test_syntax_error(self):
        ok, msg = fp.validate_rule('body=="a" &&')
        self.assertFalse(ok)


class TestFingerprintCRUD(unittest.TestCase):
    def setUp(self):
        set_repo(_FakeRepo())

    def tearDown(self):
        set_repo(None)

    def test_add_and_list(self):
        r = fp.add_fingerprint("WebLogic", 'body="WebLogic"')
        self.assertNotIn("error", r)
        lst = fp.list_fingerprint({})
        self.assertEqual(lst["total"], 1)
        self.assertEqual(lst["items"][0]["name"], "WebLogic")
        self.assertIsInstance(lst["items"][0]["_id"], str)

    def test_add_invalid_rule(self):
        self.assertIn("error", fp.add_fingerprint("bad", 'evil="x"'))

    def test_add_dup_rule(self):
        fp.add_fingerprint("A", 'body="dup"')
        self.assertIn("error", fp.add_fingerprint("B", 'body="dup"'))

    def test_add_missing_fields(self):
        self.assertIn("error", fp.add_fingerprint("", 'body="x"'))

    def test_delete(self):
        fp.add_fingerprint("A", 'body="x"')
        fid = fp.list_fingerprint({})["items"][0]["_id"]
        r = fp.delete_fingerprint([fid])
        self.assertEqual(r["deleted"], 1)
        self.assertEqual(fp.list_fingerprint({})["total"], 0)

    def test_delete_empty_ids(self):
        self.assertIn("error", fp.delete_fingerprint([]))

    def test_list_no_hard_size_cap(self):
        r = fp.list_fingerprint({"size": 99999})
        self.assertEqual(r["size"], 99999)      # 禁硬限制参数

    def test_list_name_filter(self):
        fp.add_fingerprint("WebLogic", 'body="a"')
        fp.add_fingerprint("Redis", 'body="b"')
        self.assertEqual(fp.list_fingerprint({"name": "web"})["total"], 1)


if __name__ == "__main__":
    unittest.main()
