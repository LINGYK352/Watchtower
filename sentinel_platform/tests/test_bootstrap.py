"""sentinel_platform/bootstrap 单测 —— 装配底座（register_all + ensure_indexes + create_app 委托）。

覆盖：register_all 装配全部类别 + 9 ROLE 齐 + 字符串键服务齐、单类别失败不阻断、
ensure_indexes 幂等/降级、bootstrap 一站式、create_app 委托 router、router 委托 bootstrap 后仍全注册。
"""
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts import get_registry, ROLE
from sentinel_platform.contracts.registry import reset_registry


class _MemColl:
    def __init__(self):
        self.indexes = []

    def create_index(self, keys, **kwargs):
        self.indexes.append((tuple(keys) if isinstance(keys, list) else keys, tuple(sorted(kwargs.items()))))
        return "idx"


class _MemRepo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        return self._colls.setdefault(name, _MemColl())


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())

    def tearDown(self):
        reset_repo(); reset_registry()

    def test_register_all_registers_categories(self):
        from sentinel_platform.bootstrap import register_all, CATEGORY_REGISTERS
        r = register_all()
        # 全部类别成功（无 failed）——所有叶子已完成
        self.assertEqual(r["failed"], {})
        self.assertEqual(len(r["registered"]), len(CATEGORY_REGISTERS))
        for cat in ("kernel", "risk_intel", "system", "asset", "workspace", "task_plan", "ai_pentest"):
            self.assertIn(cat, r["registered"])

    def test_all_roles_registered(self):
        """装配后 9 个冻结 ROLE 全部就绪（跨类别集成体检）。"""
        from sentinel_platform.bootstrap import register_all
        reg = get_registry()
        register_all(reg)
        for role in (ROLE.RECON, ROLE.INTEL, ROLE.FINDING, ROLE.PENTEST_DISPATCH, ROLE.VULN_INTEL,
                     ROLE.PROXY, ROLE.NOTIFY, ROLE.EXPLOIT_CLUE, ROLE.SYSTEM_TAGS, ROLE.USER, ROLE.RBAC):
            self.assertIsNotNone(reg.get(role), "ROLE 未注册: {}".format(role))

    def test_string_key_services_registered(self):
        """字符串键服务（非 ROLE）也全就绪。"""
        from sentinel_platform.bootstrap import register_all
        reg = get_registry()
        register_all(reg)
        for key in ("api_keys_service", "audit_service", "log_service",
                    "asset_search_service", "asset_group_service", "dashboard_service",
                    "policy_service", "task_list_service", "ai_config_service", "ai_tools_service"):
            self.assertIsNotNone(reg.get(key), "字符串键服务未注册: {}".format(key))

    def test_register_all_single_category_failure_not_block(self):
        """单类别 import 失败不阻断其余（缺失降级）。"""
        from sentinel_platform import bootstrap
        orig = list(bootstrap.CATEGORY_REGISTERS)
        try:
            bootstrap.CATEGORY_REGISTERS.append("sentinel_platform.modules.nonexistent.register")
            r = bootstrap.register_all(get_registry())
            self.assertIn("nonexistent", r["failed"])
            self.assertIn("kernel", r["registered"])   # 其余仍注册
        finally:
            bootstrap.CATEGORY_REGISTERS[:] = orig

    def test_ensure_indexes(self):
        from sentinel_platform.bootstrap import ensure_indexes, INDEX_SPECS
        r = ensure_indexes()
        total = sum(len(specs) for _, specs in INDEX_SPECS)
        self.assertEqual(r["created"], total)   # 内存替身全成功
        self.assertEqual(r["skipped"], 0)

    def test_ensure_indexes_degrades_on_db_failure(self):
        from sentinel_platform.bootstrap import ensure_indexes

        class _BoomRepo(Repository):
            def __init__(self): pass
            def collection(self, name):
                raise RuntimeError("db down")

        set_repo(_BoomRepo())
        r = ensure_indexes()   # 不抛
        self.assertEqual(r["created"], 0)
        self.assertGreater(r["skipped"], 0)

    def test_index_specs_use_collections_constants(self):
        """索引对象都是 Collections 里的真集合名（不硬编码错字符串）。"""
        from sentinel_platform.bootstrap import INDEX_SPECS
        from sentinel_platform.contracts import Collections
        valid = {v for k, v in vars(Collections).items() if isinstance(v, str) and not k.startswith("_")}
        for coll_name, _ in INDEX_SPECS:
            self.assertIn(coll_name, valid, "非法集合名: {}".format(coll_name))

    def test_bootstrap_one_shot(self):
        from sentinel_platform.bootstrap import bootstrap
        r = bootstrap(with_indexes=True)
        self.assertEqual(r["failed"], {})
        self.assertIn("indexes", r)

    def test_router_delegates_to_bootstrap(self):
        """router.create_app 走 bootstrap 装配后，registry 里 ROLE 齐（委托生效，非双列表）。"""
        from sentinel_platform.router import create_app
        create_app()
        reg = get_registry()
        self.assertIsNotNone(reg.get(ROLE.PENTEST_DISPATCH))
        self.assertIsNotNone(reg.get(ROLE.INTEL))

    def test_create_app_via_bootstrap(self):
        """bootstrap.create_app 委托 router（gunicorn 统一入口）。"""
        from sentinel_platform.bootstrap import create_app
        app = create_app()
        self.assertTrue(hasattr(app, "test_client"))


if __name__ == "__main__":
    unittest.main()
