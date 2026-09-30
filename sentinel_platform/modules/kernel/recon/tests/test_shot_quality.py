"""_shot_quality 单测 —— 截图质量门（问题11：黑屏/空白过滤 + md5 去重）。纯本地，不需二进制。"""
import os
import tempfile
import unittest

from sentinel_platform.modules.kernel.recon.native import _shot_quality as sq


class ShotQualityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shotq_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, nbytes):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(b"\x00" * nbytes)
        return p

    def test_missing_file(self):
        r = sq.assess_shot(os.path.join(self.tmp, "nope.jpg"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "missing")

    def test_blank_too_small(self):
        # 实测空白黑屏 16627B < 默认 30000 → blank
        p = self._write("blank.jpg", 16627)
        r = sq.assess_shot(p, min_bytes=30000)
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "blank")

    def test_real_content_passes(self):
        # 真实内容页 280727B > 阈值 → ok
        p = self._write("real.jpg", 280727)
        seen = set()
        r = sq.assess_shot(p, seen_md5=seen, min_bytes=30000)
        self.assertTrue(r["ok"])
        self.assertTrue(r["md5"])

    def test_md5_dedup(self):
        # 两张内容完全相同的大图（同 md5）：第一张 ok，第二张判 dup
        seen = set()
        p1 = self._write("a.jpg", 50000)
        r1 = sq.assess_shot(p1, seen_md5=seen, min_bytes=30000)
        self.assertTrue(r1["ok"])
        seen.add(r1["md5"])
        p2 = self._write("b.jpg", 50000)   # 同为全 \x00 50000 字节 → 同 md5
        r2 = sq.assess_shot(p2, seen_md5=seen, min_bytes=30000)
        self.assertFalse(r2["ok"])
        self.assertEqual(r2["reason"], "dup")

    def test_min_bytes_default_from_config_fallback(self):
        # 不传 min_bytes 时用默认 30000（config 不可用回退）
        p = self._write("mid.jpg", 100)
        r = sq.assess_shot(p)
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "blank")


if __name__ == "__main__":
    unittest.main()
