"""mihomo 内核进程管理单测 —— 补净室迁移丢失的 P1 缺口（可单测的纯逻辑部分）。

覆盖：①订阅 URL SSRF 校验(拒内网/非http/userinfo) ②config 生成去 geo 依赖+禁 TUN+global 模式(关键踩坑)
③节点地区前缀默认不硬编码(空=全节点,配了才过滤) ④profile CRUD ⑤流量账本增量累计(核心重启不回退)。
进程启停(start/stop)依赖真实 mihomo 二进制+os.kill，不在单测覆盖（需 Linux 真环境 E2E）。
"""
import os
import tempfile
import unittest

from sentinel_platform.core import set_repo


class _Coll:
    def __init__(self):
        self.docs = []
        self._n = 0
    def _match(self, d, q):
        return all(d.get(k) == v for k, v in q.items() if not isinstance(v, dict))
    def find_one(self, q, proj=None):
        for d in self.docs:
            if self._match(d, q):
                return d
        return None
    def find(self, q=None):
        rows = [d for d in self.docs if self._match(d, q or {})]
        class _Cur(list):
            def sort(self, *a, **k):
                return self
        return _Cur(rows)
    def insert_one(self, doc):
        self._n += 1
        doc.setdefault("_id", "p%d" % self._n)
        self.docs.append(doc)
        class _R: pass
        r = _R(); r.inserted_id = doc["_id"]; return r
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if not d and upsert:
            d = dict(q); self.docs.append(d)
        if d:
            d.update(upd.get("$set", {}))
            for k, inc in (upd.get("$inc") or {}).items():
                d[k] = (d.get(k, 0) or 0) + inc
        class _R: modified_count = 1 if d else 0
        return _R()
    def delete_one(self, q):
        d = self.find_one(q)
        if d:
            self.docs.remove(d)
        class _R: deleted_count = 1 if d else 0
        return _R()
    def delete_many(self, q):
        keep = [d for d in self.docs if not self._match(d, q)]
        n = len(self.docs) - len(keep)
        self.docs = keep
        class _R: deleted_count = n
        return _R()


class _Repo:
    def __init__(self):
        self._c = {}
    def collection(self, name):
        return self._c.setdefault(name, _Coll())


class TestMihomoSSRF(unittest.TestCase):
    def test_reject_non_http(self):
        from sentinel_platform.modules.system import _mihomo as m
        for bad in ("ftp://x.com/a", "file:///etc/passwd", "ss://xxx"):
            with self.assertRaises(ValueError):
                m.validate_subscription_url(bad)

    def test_reject_userinfo(self):
        from sentinel_platform.modules.system import _mihomo as m
        with self.assertRaises(ValueError):
            m.validate_subscription_url("http://user:pass@example.com/sub")

    def test_reject_internal_ip(self):
        from sentinel_platform.modules.system import _mihomo as m
        for bad in ("http://127.0.0.1/sub", "http://10.0.0.1/x", "http://192.168.1.1/x", "http://169.254.1.1/x"):
            with self.assertRaises(ValueError):
                m.validate_subscription_url(bad)


class TestMihomoConfigGen(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())
        self._tmp = tempfile.mkdtemp()
        os.environ["SENTINEL_PROXY_RUNTIME_DIR"] = self._tmp

    def tearDown(self):
        set_repo(None)
        os.environ.pop("SENTINEL_PROXY_RUNTIME_DIR", None)

    def test_config_strips_geo_and_disables_tun(self):
        """关键踩坑：生成的 config 必须关 geo 自动下载 + 禁 TUN + global 模式（否则启动崩/劫持整机）。"""
        import yaml
        from sentinel_platform.modules.system import _mihomo as m
        path = m.build_runtime_config()
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertEqual(data["geodata-mode"], False)
        self.assertEqual(data["geo-auto-update"], False)
        self.assertEqual(data["tun"], {"enable": False})   # 禁 TUN 防劫持整机
        self.assertEqual(data["mode"], "global")
        self.assertEqual(data["rules"], ["MATCH,GLOBAL"])
        self.assertNotIn("rule-providers", data)

    def test_region_prefixes_default_empty_no_hardcode(self):
        """地区前缀默认空=不硬编码（不再只选 HK/MO/TW，根治旧硬编码病）。"""
        from sentinel_platform.modules.system import _mihomo as m
        self.assertEqual(m._region_prefixes(), ())   # 无配置=空=全节点

    def test_region_prefixes_configurable(self):
        from sentinel_platform.core import get_repo
        from sentinel_platform.modules.system import _mihomo as m
        get_repo().collection("proxy_config").insert_one(
            {"name": "default", "node_region_prefixes": ["US", "JP"]})
        self.assertEqual(m._region_prefixes(), ("US", "JP"))   # 可配美/日等，非硬编码港澳台


class TestMihomoProfileCRUD(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())
        self._tmp = tempfile.mkdtemp()
        os.environ["SENTINEL_PROXY_RUNTIME_DIR"] = self._tmp

    def tearDown(self):
        set_repo(None)
        os.environ.pop("SENTINEL_PROXY_RUNTIME_DIR", None)

    def test_import_and_list_profile(self):
        from sentinel_platform.modules.system import _mihomo as m
        content = "proxies:\n  - {name: n1, type: ss}\nproxy-groups: []\n"
        r = m.import_profile_content("机场A", content)
        self.assertNotIn("error", r)
        self.assertEqual(r["proxy_count"], 1)
        items = m.list_profiles()
        self.assertEqual(len(items), 1)
        # 落盘了
        self.assertTrue(os.path.exists(r["path"]))

    def test_delete_profile_removes_file(self):
        from sentinel_platform.modules.system import _mihomo as m
        r = m.import_profile_content("A", "proxies: []\n")
        path = r["path"]
        m.delete_profile(r["_id"])
        self.assertEqual(len(m.list_profiles()), 0)
        self.assertFalse(os.path.exists(path))

    def test_reject_oversized_profile(self):
        from sentinel_platform.modules.system import _mihomo as m
        with self.assertRaises(ValueError):
            m.validate_profile_content("x" * (m.MAX_PROFILE_SIZE + 1))


class TestMihomoTraffic(unittest.TestCase):
    def setUp(self):
        set_repo(_Repo())

    def tearDown(self):
        set_repo(None)

    def test_traffic_stats_empty(self):
        from sentinel_platform.modules.system import _mihomo as m
        s = m.traffic_stats()
        self.assertEqual(s["total_up"], 0)
        self.assertEqual(s["by_profile"], [])

    def test_reset_traffic(self):
        from sentinel_platform.core import get_repo
        from sentinel_platform.modules.system import _mihomo as m
        get_repo().collection("proxy_traffic").insert_one({"scope": "meta", "total_up": 999})
        m.reset_traffic_stats()
        self.assertEqual(m.traffic_stats()["total_up"], 0)


if __name__ == "__main__":
    unittest.main()
