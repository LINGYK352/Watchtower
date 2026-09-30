"""回归③：资产去重键 _dedup_key（session.py:708，核心链路 §6.1）。

事故（记忆 dengta-dedup-key-physical-not-inferred，v2.7.34 铁证）：
- 用 system_id/灯塔指纹当去重键 → 某 system_id 组 87 资产横跨 2 单位、20 hostname 被误聚成"一个系统"，
  按它派一篇 = 把整个单位的渗透合并掉 = 危险漏报。
- 正解：键必用物理唯一标识(hostname/ip:port)，不用推断聚类。不同 hostname 的壳页不合并。
红线：键的构成里绝不出现 system_id/fingerprint。
"""
import unittest

from sentinel_platform.modules.ai_pentest.session import _dedup_key


class DedupKeyRegression(unittest.TestCase):
    def test_level1_no_dedup_each_unique(self):
        a = {"key": "https://a.com", "site": "https://a.com"}
        self.assertTrue(_dedup_key(a, level=1).startswith("raw:"))

    def test_key_uses_physical_not_system_id(self):
        """红线：即使资产带 system_id/fingerprint，去重键也不含它们（只用 ip/port/hostname）。"""
        a = {"hostname": "a.com", "ip": "1.2.3.4", "key": "https://a.com:443",
             "system_id": "SYS_SHOULD_NOT_APPEAR", "fingerprint": "FP_SHOULD_NOT_APPEAR"}
        k = _dedup_key(a, level=2)
        self.assertNotIn("SYS_SHOULD_NOT_APPEAR", k)
        self.assertNotIn("FP_SHOULD_NOT_APPEAR", k)
        self.assertIn("1.2.3.4", k)   # 用物理 IP

    def test_different_hostname_4xx_not_merged(self):
        """不同 hostname 的 4xx 壳页(无 IP)严格按 hostname 分开，不合并（守 v2.7.34）。"""
        a = {"hostname": "crm.x.com", "key": "https://crm.x.com", "status": 403}
        b = {"hostname": "msp.x.com", "key": "https://msp.x.com", "status": 403}
        self.assertNotEqual(_dedup_key(a, level=2), _dedup_key(b, level=2))

    def test_pure_ip_key(self):
        a = {"hostname": "1.2.3.4", "ip": "1.2.3.4", "key": "http://1.2.3.4:8080"}
        self.assertEqual(_dedup_key(a, level=2), "p:1.2.3.4|8080")

    def test_same_ip_port_merged_level2(self):
        """同 IP+同 port（非 CDN）= 同站点 → 合并。"""
        a = {"hostname": "a.com", "ip": "9.9.9.9", "key": "https://a.com:443"}
        b = {"hostname": "b.com", "ip": "9.9.9.9", "key": "https://b.com:443"}
        self.assertEqual(_dedup_key(a, level=2), _dedup_key(b, level=2))

    def test_cdn_adds_hostname(self):
        """CDN 资产键里带 hostname（不同子域不因共享 CDN IP 被误合）。"""
        a = {"hostname": "a.com", "ip": "1.1.1.1", "key": "https://a.com:443", "is_cdn": True}
        b = {"hostname": "b.com", "ip": "1.1.1.1", "key": "https://b.com:443", "is_cdn": True}
        self.assertNotEqual(_dedup_key(a, level=2), _dedup_key(b, level=2))

    def test_levels_produce_different_prefixes(self):
        a = {"hostname": "a.com", "ip": "1.2.3.4", "key": "https://a.com:443",
             "status": 200, "title": "Portal", "fld": "x.com", "body_length": 1000}
        self.assertTrue(_dedup_key(a, level=1).startswith("raw:"))
        # level3 x 档对 2xx+有IP+有title 跨子域合并（键以 x: 开头）
        self.assertTrue(_dedup_key(a, level=3).startswith("x:"))


if __name__ == "__main__":
    unittest.main()
