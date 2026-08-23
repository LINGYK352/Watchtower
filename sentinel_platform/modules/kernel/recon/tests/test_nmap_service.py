"""nmap_service 对接单测 —— -oG 解析 / enrich 回填 / 降级，不需真装 nmap（测 parse/enrich）。

nmap -oG 非 JSONL，测静态 parse 与 IPRec 回填逻辑（执行与解析分离，同 weakbrute 范式）。
"""
import unittest

from sentinel_platform.modules.kernel.recon.tools.nmap_service import NmapService
from sentinel_platform.modules.kernel.recon.models import IPRec, PortInfo
from sentinel_platform.modules.kernel.recon.registry import build_registry, ROLE_SERVICE_DETECT

# 真实 nmap -oG 输出样例（含 Ports: 行）
_OG = ("Host: 1.2.3.4 ()\tPorts: "
       "22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu/, "
       "80/open/tcp//http//nginx 1.18.0/, "
       "3306/open/tcp//mysql//MySQL 5.7/\n")


class TestParse(unittest.TestCase):
    def test_parse_services(self):
        r = NmapService.parse(_OG)
        self.assertEqual(set(r), {22, 80, 3306})
        self.assertEqual(r[22].service_name, "ssh")
        self.assertIn("OpenSSH", r[22].version)
        self.assertEqual(r[80].service_name, "http")
        self.assertIsInstance(r[80], PortInfo)

    def test_parse_skips_closed(self):
        og = "Host: x ()\tPorts: 22/closed/tcp//ssh///, 80/open/tcp//http///\n"
        r = NmapService.parse(og)
        self.assertNotIn(22, r)
        self.assertIn(80, r)

    def test_parse_junk_safe(self):
        self.assertEqual(NmapService.parse("no ports line here"), {})
        self.assertEqual(NmapService.parse(""), {})

    def test_parse_malformed_segment(self):
        # 段字段不足 7 → 跳过不崩
        r = NmapService.parse("Host: x ()\tPorts: 22/open/tcp\n")
        self.assertEqual(r, {})


class TestEnrich(unittest.TestCase):
    def test_enrich_fills_ports(self):
        svc = NmapService()
        ip = IPRec(ip="1.2.3.4", ports=[PortInfo(port_id=22), PortInfo(port_id=80)])
        # 直接注入 parse 结果模拟 detect（不跑真 nmap）
        svc.detect = lambda ip_, ports: NmapService.parse(_OG)
        out = svc.enrich(ip)
        p22 = next(p for p in out.ports if p.port_id == 22)
        self.assertEqual(p22.service_name, "ssh")
        self.assertIn("OpenSSH", p22.version)

    def test_enrich_empty_ports_noop(self):
        svc = NmapService()
        ip = IPRec(ip="1.2.3.4", ports=[])
        self.assertIs(svc.enrich(ip), ip)

    def test_detect_no_binary_degrades(self):
        # 强制 locate 返回空（无 nmap）→ detect 返 {}
        svc = NmapService()
        svc.locate = lambda: ""
        self.assertEqual(svc.detect("1.2.3.4", [22, 80]), {})

    def test_detect_no_ports(self):
        svc = NmapService(binary_path="nmap")
        self.assertEqual(svc.detect("1.2.3.4", []), {})


class TestRegistry(unittest.TestCase):
    def test_service_detect_registered(self):
        reg = build_registry()
        self.assertIsNotNone(reg.first(ROLE_SERVICE_DETECT))
        self.assertEqual(reg.first(ROLE_SERVICE_DETECT).adapter, "nmap_service")


if __name__ == "__main__":
    unittest.main()
