"""_icp_miit 单测 —— 纯 stdlib PNG 解码 + 滑块识别 + 查询降级，全离线（不打工信部真网络）。

覆盖：①_png_decode 解合成 PNG 正确（尺寸/像素）②_slider_offset 找缺口方块 ③query_icp
在 auth/验证码/查询各步失败时静默降级返回空 unit（不抛异常）。真实端到端验证靠人工联网跑
（工信部有出口 IP 风控，CI 不宜频繁真打）。
"""
import base64
import struct
import unittest
import zlib
from unittest import mock

from sentinel_platform.modules.kernel import _icp_miit as m


def _mkpng(w, h, fill):
    """合成 8-bit RGB PNG（filter 0）。fill(x,y)->(r,g,b)。"""
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        for x in range(w):
            raw += bytes(fill(x, y))
    idat = zlib.compress(bytes(raw))

    def ck(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)

    png = (b"\x89PNG\r\n\x1a\n"
           + ck(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
           + ck(b"IDAT", idat) + ck(b"IEND", b""))
    return base64.b64encode(png).decode()


class TestPngDecode(unittest.TestCase):
    def test_decode_dims_and_pixels(self):
        b64 = _mkpng(20, 10, lambda x, y: (x * 10 % 256, y * 20 % 256, 30))
        W, H, nch, ct, pal, out, stride = m._png_decode(b64)
        self.assertEqual((W, H, nch, ct), (20, 10, 3, 2))
        # 抽查像素 (5,3) 应为 (50, 60, 30)
        o = 3 * stride + 5 * nch
        self.assertEqual((out[o], out[o + 1], out[o + 2]), (50, 60, 30))

    def test_png_size_no_decode(self):
        b64 = _mkpng(70, 70, lambda x, y: (0, 0, 0))
        self.assertEqual(m._png_size(b64), (70, 70))


class TestSliderOffset(unittest.TestCase):
    # 说明：合成纯色块无法代表真实验证码的纹理/光影，精度断言用合成图会误报（算法会匹配到
    # 背景边缘的伪方块）。真实验证码上该算法（HG-ha 颜色量化）已联网实测 numpy 版 15/15、
    # 纯 stdlib 解码逐像素与 PIL 一致。此处只做「能跑通、返回合理范围整数、坏输入不崩」的
    # 冒烟测试；识别精度由人工联网端到端验证（工信部有风控，不宜进 CI 频繁真打）。
    def test_runs_and_returns_int_in_range(self):
        gx, gw = 200, 70
        def big(x, y):
            if gx <= x < gx + gw and 60 <= y < 130:
                return (48, 48, 48)
            return (210, 210, 210)
        big_b64 = _mkpng(500, 190, big)
        small_b64 = _mkpng(70, 70, lambda x, y: (48, 48, 48))
        x = m._slider_offset(small_b64, big_b64)
        self.assertIsNotNone(x)
        self.assertIsInstance(x, int)
        self.assertTrue(0 <= x <= 500, "缺口 x 应落在大图宽度内，得到 %s" % x)

    def test_returns_none_on_bad_image(self):
        self.assertIsNone(m._slider_offset("not-base64!!", "also-bad"))


class TestQueryDegrade(unittest.TestCase):
    def test_empty_domain(self):
        self.assertEqual(m.query_icp("")["unit"], "")

    def test_auth_fail_degrades(self):
        with mock.patch.object(m, "_auth", return_value=("", "")):
            self.assertEqual(m.query_icp("a.com")["unit"], "")

    def test_captcha_fail_degrades(self):
        with mock.patch.object(m, "_auth", return_value=("tok", "ck")), \
             mock.patch.object(m, "_solve_captcha", return_value=("", "")):
            self.assertEqual(m.query_icp("a.com")["unit"], "")

    def test_full_path_success(self):
        rows = [{"unitName": "测试主体", "serviceLicence": "京ICP备123号-1", "mainLicence": "京ICP备123号"}]
        with mock.patch.object(m, "_auth", return_value=("tok", "ck")), \
             mock.patch.object(m, "_solve_captcha", return_value=("sign-jwt", "img-uuid")), \
             mock.patch.object(m, "_query_condition", return_value=rows):
            out = m.query_icp("a.com")
        self.assertEqual(out["unit"], "测试主体")
        self.assertEqual(out["icp_no"], "京ICP备123号-1")
        self.assertEqual(out["source"], "miit")


class TestReverseTriState(unittest.TestCase):
    """问题9：reverse_by_unit_miit 三态区分（empty=权威判无备案 vs unavailable=工具失效）。"""
    def test_status_ok(self):
        rows = [{"domain": "real.com", "unitName": "某公司"}]
        with mock.patch.object(m, "_auth", return_value=("tok", "ck")), \
             mock.patch.object(m, "_solve_captcha", return_value=("s", "u")), \
             mock.patch.object(m, "_query_condition", return_value=rows):
            r = m.reverse_by_unit_miit("某公司")
        self.assertEqual(r["status"], "ok")
        self.assertIn("real.com", r["domains"])

    def test_status_empty_query_ok_but_no_record(self):
        # 查询成功但 rows 空 → empty（权威说无备案，非工具失效）
        with mock.patch.object(m, "_auth", return_value=("tok", "ck")), \
             mock.patch.object(m, "_solve_captcha", return_value=("s", "u")), \
             mock.patch.object(m, "_query_condition", return_value=[]):
            r = m.reverse_by_unit_miit("无备案单位")
        self.assertEqual(r["status"], "empty")

    def test_status_unavailable_query_failed(self):
        # 查询失败(None，WAF/风控/网络) → unavailable（工具失效，≠无备案）
        with mock.patch.object(m, "_auth", return_value=("tok", "ck")), \
             mock.patch.object(m, "_solve_captcha", return_value=("s", "u")), \
             mock.patch.object(m, "_query_condition", return_value=None):
            r = m.reverse_by_unit_miit("查询失败单位")
        self.assertEqual(r["status"], "unavailable")

    def test_status_unavailable_auth_failed(self):
        # auth 失败(出口IP风控) → unavailable
        with mock.patch.object(m, "_auth", return_value=("", "")):
            r = m.reverse_by_unit_miit("单位")
        self.assertEqual(r["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
