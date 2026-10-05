"""端到端：about 更新检测端点经核心路由（公开 + 信封 + 版本比对）。"""
import unittest

from sentinel_platform.core import set_repo


class TestAboutE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        set_repo(None)   # about 不依赖 repo
        from sentinel_platform.router import create_app
        cls.client = create_app().test_client()

    def test_version_public(self):
        body = self.client.get("/api/about/version").get_json()
        self.assertEqual(body["code"], 200)
        self.assertTrue(body["data"]["version"])

    def test_check_with_client(self):
        from unittest import mock
        with mock.patch("sentinel_platform.modules.about.update_check._update_source", return_value=("", "", False)):
            body = self.client.get("/api/about/check?client=v1.0.0").get_json()
        self.assertEqual(body["code"], 200)
        # 服务端默认版本远高于 v1.0.0 → 有更新
        self.assertTrue(body["data"]["has_update"])
        self.assertIn("server_version", body["data"])

    def test_check_no_client(self):
        body = self.client.get("/api/about/check").get_json()
        self.assertEqual(body["code"], 200)
        self.assertFalse(body["data"]["has_update"])

    def test_swagger_includes_about(self):
        spec = self.client.get("/api/swagger.json").get_json()
        self.assertTrue(any("/about/" in p for p in spec["paths"]))

    def test_do_update_refuses_downgrade(self):
        """防降级守卫：远端版本不新于本地 → _do_update 不写任何文件、置 done「不降级」。
        回归「点一键更新把 v1.21.129 刷成分发源旧快照 v1.21.107」。"""
        from unittest import mock
        import io, json as _json
        from sentinel_platform.router.endpoints import about as ab

        # 远端 manifest 里含一个与本地不同 sha 的文件（若无守卫会被覆盖），版本却是很旧的 v1.0.0
        remote = {"version": "v1.0.0", "manifest": {"version.txt": "deadbeef"}}
        class _Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False
        def fake_urlopen(req, timeout=30):
            return _Resp(_json.dumps(remote).encode())

        wrote = {"n": 0}
        real_open = open
        def spy_open(path, mode="r", *a, **k):
            if "w" in mode and "version.txt" in str(path):
                wrote["n"] += 1
            return real_open(path, mode, *a, **k)

        with mock.patch.object(ab, "urlopen", fake_urlopen), \
             mock.patch("sentinel_platform.modules.about.update_check.server_version", return_value="v1.21.129"):
            ab._do_update("http://x:5080", "eyJk.k.k", "/nonexistent-root")
        prog = ab._get_progress()
        self.assertEqual(prog.get("phase"), "done")
        self.assertIn("不降级", prog.get("msg", ""))
        self.assertEqual(wrote["n"], 0)   # 一个文件都没写


if __name__ == "__main__":
    unittest.main()
