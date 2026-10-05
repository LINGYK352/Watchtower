"""image 端点 e2e —— 截图静态服务，解 SiteTab.vue 截图孤岛。

验：真截图文件返图片字节 + Content-Type；不存在返 404；扩展名白名单；路径遍历防护；公开(不带 Token 也 200)。
"""
import os
import shutil
import tempfile
import unittest

from sentinel_platform.core.db import Repository, set_repo, reset_repo
from sentinel_platform.contracts.registry import reset_registry


class _MemRepo(Repository):
    def __init__(self):
        self._colls = {}

    def collection(self, name):
        class _C:
            def find_one(self, q): return None
            def find(self, q=None, proj=None): return []
            def count_documents(self, q): return 0
            def insert_one(self, d): return type("R", (), {"inserted_id": "x"})()
            def update_one(self, *a, **k): return type("R", (), {"matched_count": 0})()
        return self._colls.setdefault(name, _C())


class ImageEndpointE2E(unittest.TestCase):
    def setUp(self):
        reset_repo(); reset_registry(); set_repo(_MemRepo())
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "T1"), exist_ok=True)
        with open(os.path.join(self.tmp, "T1", "shot.png"), "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\nFAKEPNGDATA")
        from sentinel_platform.router.endpoints import image as image_ep
        self._orig = image_ep._screenshot_dir
        image_ep._screenshot_dir = lambda: self.tmp   # 指到临时截图目录
        from sentinel_platform.router import create_app
        self.client = create_app().test_client()

    def tearDown(self):
        from sentinel_platform.router.endpoints import image as image_ep
        image_ep._screenshot_dir = self._orig
        reset_repo(); reset_registry()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_in_swagger(self):
        paths = self.client.get("/api/swagger.json").get_json().get("paths", {})
        self.assertTrue(any("/image/" in p for p in paths))

    def test_serve_real_screenshot(self):
        r = self.client.get("/api/image/T1/shot.png")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Content-Type"], "image/png")
        self.assertIn(b"PNG", r.get_data())

    def test_missing_returns_404(self):
        self.assertEqual(self.client.get("/api/image/T1/nope.png").status_code, 404)

    def test_disallowed_ext_404(self):
        self.assertEqual(self.client.get("/api/image/T1/evil.exe").status_code, 404)

    def test_path_traversal_blocked(self):
        r = self.client.get("/api/image/T1/..%2f..%2fpasswd.png")
        self.assertEqual(r.status_code, 404)

    def test_public_no_token(self):
        self.assertEqual(self.client.get("/api/image/T1/shot.png").status_code, 200)


if __name__ == "__main__":
    unittest.main()
