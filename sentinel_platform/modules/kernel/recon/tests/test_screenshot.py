"""recon/native/screenshot 单测 —— 命令构建 / safe_name / 相对路径 / 降级 / registry。

不需真 phantomjs：available() 依赖二进制，通过注入假路径/mock resolve_binary 验证；
capture 的 subprocess 执行不在单测跑（只测构建与降级路径），避免依赖真二进制/真渲染。
"""
from __future__ import annotations

import os
import tempfile
import unittest

from sentinel_platform.modules.kernel.recon.native.screenshot import (
    Screenshot, safe_name, default_phantomjs, default_rasterize,
    default_image_dir, ROLE_SCREENSHOT,
)


class TestSafeName(unittest.TestCase):
    def test_replaces_scheme_and_illegal(self):
        self.assertEqual(safe_name("http://a.com/x?y=1"), "http_a.com_x_y_1")
        self.assertEqual(safe_name("https://1.2.3.4:8080/"), "https_1.2.3.4_8080_")

    def test_truncate_180(self):
        long = "http://" + ("a" * 300) + ".com"
        self.assertLessEqual(len(safe_name(long)), 180)

    def test_no_path_traversal(self):
        # ../ 里的 / 和 . 被规范：斜杠→_，点保留但无法构成遍历（拼进单一目录）
        n = safe_name("http://x/../../etc/passwd")
        self.assertNotIn("/", n)
        self.assertTrue(n.startswith("http_x"))


class TestDefaults(unittest.TestCase):
    def test_phantomjs_path_points_to_external(self):
        p = default_phantomjs().replace("\\", "/")
        self.assertTrue(p.endswith("external/phantomjs/phantomjs"))

    def test_rasterize_exists_adjacent(self):
        # rasterize.js 应随模块存在
        r = default_rasterize()
        self.assertTrue(r.endswith("rasterize.js"))
        self.assertTrue(os.path.isfile(r))

    def test_image_dir_points_to_root_image(self):
        d = default_image_dir().replace("\\", "/")
        self.assertTrue(d.endswith("/image"))


class TestAvailable(unittest.TestCase):
    def test_unavailable_when_no_binary(self):
        # 指向不存在的 phantomjs → 不可用（降级）
        s = Screenshot(phantomjs_path="/no/such/phantomjs", rasterize_js=default_rasterize(),
                       image_dir="/tmp/img")
        self.assertFalse(s.available())

    def test_unavailable_when_no_rasterize(self):
        # 造一个真实存在的假二进制，但 rasterize 缺失 → 不可用
        with tempfile.NamedTemporaryFile(suffix="_phantomjs", delete=False) as f:
            fake_bin = f.name
        try:
            s = Screenshot(phantomjs_path=fake_bin, rasterize_js="/no/such/rasterize.js",
                           image_dir="/tmp/img")
            self.assertFalse(s.available())
        finally:
            os.unlink(fake_bin)

    def test_unavailable_when_no_image_dir(self):
        # 构造传空 image_dir 会回退默认（有意设计：registry 未配时用根 image/）；
        # 故直接把属性置空验证 available() 的 image_dir 守卫（缺目录不可用）。
        with tempfile.NamedTemporaryFile(suffix="_phantomjs", delete=False) as f:
            fake_bin = f.name
        try:
            s = Screenshot(phantomjs_path=fake_bin, rasterize_js=default_rasterize(),
                           image_dir="/tmp/img")
            self.assertTrue(s.available())      # 有目录 → 可用
            s.image_dir = ""                    # 手动清空触发守卫
            self.assertFalse(s.available())
        finally:
            os.unlink(fake_bin)

    def test_constructor_defaults_image_dir(self):
        # 传空 image_dir → 回退默认根 image/（非"无目录"）
        s = Screenshot(image_dir="")
        self.assertTrue(s.image_dir.replace("\\", "/").endswith("/image"))

    def test_available_when_all_present(self):
        with tempfile.NamedTemporaryFile(suffix="_phantomjs", delete=False) as f:
            fake_bin = f.name
        try:
            s = Screenshot(phantomjs_path=fake_bin, rasterize_js=default_rasterize(),
                           image_dir="/tmp/img")
            self.assertTrue(s.available())
        finally:
            os.unlink(fake_bin)


class TestBuildArgv(unittest.TestCase):
    def test_argv_structure(self):
        s = Screenshot(timeout=30)
        argv = s.build_argv("/bin/phantomjs", "http://a.com", "/img/t/a.jpg")
        self.assertEqual(argv[0], "/bin/phantomjs")
        self.assertIn("--ignore-ssl-errors=true", argv)
        self.assertIn("--ssl-protocol=any", argv)
        self.assertEqual(argv[-3], "http://a.com")
        self.assertEqual(argv[-2], "/img/t/a.jpg")
        self.assertEqual(argv[-1], "30000")   # timeout*1000 ms

    def test_timeout_ms_conversion(self):
        s = Screenshot(timeout=10)
        argv = s.build_argv("pjs", "u", "o")
        self.assertEqual(argv[-1], "10000")


class TestRelUrl(unittest.TestCase):
    def test_default_prefix(self):
        s = Screenshot()
        self.assertEqual(s.rel_url("task1", "a.jpg"), "/image/task1/a.jpg")

    def test_custom_prefix_stripped(self):
        s = Screenshot(url_prefix="/image/")
        self.assertEqual(s.rel_url("t", "x.jpg"), "/image/t/x.jpg")


class TestCaptureDegrade(unittest.TestCase):
    def test_capture_returns_empty_when_unavailable(self):
        # 不可用（无二进制）→ 返 {} 不报错
        s = Screenshot(phantomjs_path="/no/such/phantomjs", image_dir="/tmp/img")
        self.assertEqual(s.capture(["http://a.com"], "task1"), {})

    def test_capture_empty_sites(self):
        with tempfile.NamedTemporaryFile(suffix="_phantomjs", delete=False) as f:
            fake_bin = f.name
        try:
            s = Screenshot(phantomjs_path=fake_bin, rasterize_js=default_rasterize(),
                           image_dir=tempfile.gettempdir())
            self.assertEqual(s.capture([], "task1"), {})
            self.assertEqual(s.capture(None, "task1"), {})
        finally:
            os.unlink(fake_bin)


class TestResolveBinary(unittest.TestCase):
    def test_explicit_path_isfile(self):
        with tempfile.NamedTemporaryFile(suffix="_phantomjs", delete=False) as f:
            fake_bin = f.name
        try:
            s = Screenshot(phantomjs_path=fake_bin)
            self.assertEqual(s.resolve_binary(), fake_bin)
        finally:
            os.unlink(fake_bin)

    def test_explicit_missing_returns_empty(self):
        s = Screenshot(phantomjs_path="/definitely/not/here/phantomjs")
        # which 找不到 + 非文件 → ""
        self.assertEqual(s.resolve_binary(), "")


class TestRegistryIntegration(unittest.TestCase):
    def test_screenshot_registered(self):
        from sentinel_platform.modules.kernel.recon.registry import build_registry, ROLE_SCREENSHOT as RS
        reg = build_registry(None)
        # first() 不判可用性：应能取到候选
        tool = reg.first(RS)
        self.assertIsNotNone(tool)
        self.assertEqual(tool.adapter, "phantomjs_screenshot")

    def test_role_constant(self):
        self.assertEqual(ROLE_SCREENSHOT, "screenshot")


if __name__ == "__main__":
    unittest.main()
