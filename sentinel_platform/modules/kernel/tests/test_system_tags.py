"""kernel/system_tags 单测 —— 纯函数为主，find_related 用内存替身，不连真 Mongo。

覆盖：接口契约（SystemTagsService 结构化子类型 + 返回类型）、系统命名（权重/撞名区分/回退空）、
标签抽取（指纹/标题/role/噪音过滤/归一）、加权相似度、相关系统检索、register 注册、降级不抛。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.interfaces import SystemTagsService
from sentinel_platform.contracts.registry import reset_registry


class _FakeCursor(list):
    pass


class _FakeCollection:
    def __init__(self, docs):
        self._docs = docs

    def find(self, query=None):
        return _FakeCursor(self._docs)


class _FakeRepo(Repository):
    def __init__(self, docs=None):
        self._docs = docs or []

    def collection(self, name):
        return _FakeCollection(self._docs)


class SystemTagsTest(unittest.TestCase):
    def setUp(self):
        reset_repo()
        reset_registry()

    def tearDown(self):
        reset_repo()
        reset_registry()

    # —— 接口契约 ——
    def test_satisfies_protocol(self):
        from sentinel_platform.modules.kernel.system_tags import SystemTagsServiceImpl
        self.assertIsInstance(SystemTagsServiceImpl(), SystemTagsService)

    def test_register_puts_system_tags_into_registry(self):
        from sentinel_platform.modules.kernel.register import register
        reg = get_registry()
        register(reg)
        svc = reg.get(ROLE.SYSTEM_TAGS)
        self.assertIsNotNone(svc)
        self.assertTrue(hasattr(svc, "pick_system_name"))
        self.assertTrue(hasattr(svc, "extract_tags"))

    # —— 归一 / 分类 ——
    def test_canonical_name_vendor_alias(self):
        from sentinel_platform.modules.kernel.system_tags import canonical_name
        self.assertEqual(canonical_name("seeyon"), "致远")
        self.assertEqual(canonical_name("致远OA"), "致远")
        self.assertEqual(canonical_name("weaver"), "泛微")
        self.assertEqual(canonical_name("UnknownX"), "unknownx")  # 无别名组→小写原名
        self.assertEqual(canonical_name(""), "")

    def test_classify_tag(self):
        from sentinel_platform.modules.kernel.system_tags import classify_tag
        self.assertEqual(classify_tag("seeyon"), "system")     # 厂商→system
        self.assertEqual(classify_tag("Struts2"), "framework")
        self.assertEqual(classify_tag("nginx"), "tech")
        self.assertEqual(classify_tag("jenkins"), "component")
        self.assertEqual(classify_tag("XX管理系统"), "system")  # 强特征词
        self.assertEqual(classify_tag("weirdthing"), "component")  # 默认

    # —— pick_system_name（契约：dict 入，str 出，空则 ""）——
    def test_pick_system_name_weight_priority(self):
        from sentinel_platform.modules.kernel.system_tags import SystemTagsServiceImpl
        svc = SystemTagsServiceImpl()
        # framework(6) > tech(1)：主名取 spring
        r = svc.pick_system_name({"finger": [{"name": "nginx"}, {"name": "spring"}]})
        self.assertTrue(r.startswith("spring"))

    def test_pick_system_name_collision_suffix(self):
        from sentinel_platform.modules.kernel.system_tags import SystemTagsServiceImpl
        svc = SystemTagsServiceImpl()
        # 两个 tech 同权重 → 主名带次要特征后缀区分
        r = svc.pick_system_name({"finger_names": ["asp", "iis"]})
        self.assertIn("(", r)  # 形如 "asp (iis)"

    def test_pick_system_name_fallback_title_then_empty(self):
        from sentinel_platform.modules.kernel.system_tags import SystemTagsServiceImpl
        svc = SystemTagsServiceImpl()
        self.assertEqual(svc.pick_system_name({"title": "某OA门户"}), "某OA门户")  # 无指纹回退标题
        self.assertEqual(svc.pick_system_name({}), "")                            # 全空→""（契约）
        self.assertEqual(svc.pick_system_name({"finger": [{"name": "alt-svc"}]}), "")  # 全噪音→""

    # —— extract_tags（契约：dict 入，list[str] 出）——
    def test_extract_tags_returns_str_list(self):
        from sentinel_platform.modules.kernel.system_tags import SystemTagsServiceImpl
        svc = SystemTagsServiceImpl()
        tags = svc.extract_tags({"finger": [{"name": "seeyon"}], "title": "OA办公系统"})
        self.assertIsInstance(tags, list)
        self.assertTrue(all(isinstance(t, str) for t in tags))
        self.assertIn("致远", tags)  # 归一后规范名

    def test_extract_tags_empty(self):
        from sentinel_platform.modules.kernel.system_tags import SystemTagsServiceImpl
        self.assertEqual(SystemTagsServiceImpl().extract_tags({}), [])

    def test_extract_tags_detailed_role_and_noise(self):
        from sentinel_platform.modules.kernel.system_tags import extract_tags_detailed
        detailed = extract_tags_detailed({
            "finger": [{"name": "nginx"}, {"name": "alt-svc"}],  # alt-svc 噪音应过滤
            "title": "后台管理", "urls": ["https://x/admin/login"],
        })
        tags = {(d["tag"], d["type"]) for d in detailed}
        self.assertIn(("nginx", "tech"), tags)
        self.assertNotIn(("alt-svc", "tech"), tags)         # 噪音过滤
        self.assertTrue(any(t == "admin" and ty == "role" for t, ty in tags))  # role 推断

    # —— 加权相似度 ——
    def test_tag_similarity_confidence_levels(self):
        from sentinel_platform.modules.kernel.system_tags import tag_similarity
        a = [{"tag": "致远", "type": "system"}]
        self.assertEqual(tag_similarity(a, a)["confidence"], "high")     # 共享 system
        b = [{"tag": "spring", "type": "framework"}]
        self.assertEqual(tag_similarity(b, b)["confidence"], "medium")   # 共享 framework
        c = [{"tag": "nginx", "type": "tech"}]
        self.assertEqual(tag_similarity(c, c)["confidence"], "low")      # 只共享 tech
        self.assertEqual(tag_similarity(a, b)["confidence"], "none")     # 无共享
        self.assertEqual(tag_similarity(a, b)["score"], 0)

    # —— find_related_systems（内存替身）——
    def test_find_related_systems(self):
        from sentinel_platform.modules.kernel.system_tags import find_related_systems
        set_repo(_FakeRepo([
            {"_id": "s1", "name": "致远OA", "units": ["u1", "u2"],
             "tags": [{"tag": "致远", "type": "system"}]},
            {"_id": "s2", "name": "某站", "units": ["u3"],
             "tags": [{"tag": "nginx", "type": "tech"}]},  # 只 tech，score=1 < 3 被过滤
        ]))
        target = [{"tag": "致远", "type": "system"}]
        out = find_related_systems(target)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["system_id"], "s1")
        self.assertEqual(out[0]["units_count"], 2)
        self.assertEqual(out[0]["similarity"]["confidence"], "high")

    def test_find_related_excludes_self(self):
        from sentinel_platform.modules.kernel.system_tags import find_related_systems
        set_repo(_FakeRepo([
            {"_id": "s1", "name": "致远OA", "units": [],
             "tags": [{"tag": "致远", "type": "system"}]},
        ]))
        out = find_related_systems([{"tag": "致远", "type": "system"}], exclude_system_id="s1")
        self.assertEqual(out, [])

    def test_find_related_db_failure_degrades(self):
        from sentinel_platform.modules.kernel.system_tags import find_related_systems

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        self.assertEqual(find_related_systems([{"tag": "致远", "type": "system"}]), [])  # 降级不抛


if __name__ == "__main__":
    unittest.main()
