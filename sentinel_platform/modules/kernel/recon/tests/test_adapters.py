"""对接层单测 —— 只测解析/结构化，不需真装 external 工具（执行与解析分离）。

覆盖：①每工具 parse_record 把原始输出结构化对齐 models 字段 ②杂行/非法行跳过
③registry 角色降级（工具没装 pick 返回 None）④structure 逐行 JSON 过滤。
"""
import unittest

from sentinel_platform.modules.kernel.recon.tools import Nuclei, Httpx, Naabu, WeakBrute
from sentinel_platform.modules.kernel.recon.models import NucleiRec, SiteRec, IPRec, VulnRec
from sentinel_platform.modules.kernel.recon.registry import (
    build_registry, ToolRegistry, ROLE_VULN_SCAN, ROLE_PORT_SCAN)


class TestNuclei(unittest.TestCase):
    def test_parse_hit(self):
        obj = {"template-id": "CVE-2021-1", "template-url": "http://t/x",
               "info": {"name": "测试漏洞", "severity": "high"},
               "matched-at": "https://a.com/x", "host": "a.com"}
        rec = Nuclei().parse_record(obj)
        self.assertIsInstance(rec, NucleiRec)
        self.assertEqual(rec.target, "a.com")
        self.assertEqual(rec.template_id, "CVE-2021-1")
        self.assertEqual(rec.vuln_name, "测试漏洞")
        self.assertEqual(rec.vuln_severity, "high")

    def test_parse_no_target_dropped(self):
        self.assertIsNone(Nuclei().parse_record({"template-id": "x", "info": {}}))

    def test_info_not_dict_safe(self):
        rec = Nuclei().parse_record({"host": "a.com", "info": "bad"})
        self.assertEqual(rec.vuln_name, "")

    def test_structure_skips_junk(self):
        raw = '\n'.join([
            'not json', '[]', '123',
            '{"host":"a.com","info":{"name":"n","severity":"low"}}',
        ])
        recs = list(Nuclei().structure(raw))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].target, "a.com")


class TestHttpx(unittest.TestCase):
    def test_parse_site(self):
        obj = {"url": "https://a.com", "host": "1.2.3.4", "title": "首页",
               "status_code": 200, "webserver": "nginx", "content_length": 512,
               "tech": ["PHP", "jQuery"], "favicon": "-123", "raw_header": "Server: nginx"}
        rec = Httpx().parse_record(obj)
        self.assertIsInstance(rec, SiteRec)
        self.assertEqual(rec.hostname, "a.com")
        self.assertEqual(rec.ip, "1.2.3.4")
        self.assertEqual(rec.status, 200)
        self.assertEqual(rec.http_server, "nginx")
        self.assertEqual(rec.body_length, 512)
        self.assertEqual([f["name"] for f in rec.finger], ["PHP", "jQuery"])
        self.assertEqual(rec.favicon, {"hash": "-123"})

    def test_ip_equal_hostname_cleared(self):
        rec = Httpx().parse_record({"url": "https://a.com", "host": "a.com"})
        self.assertEqual(rec.ip, "")

    def test_no_url_dropped(self):
        self.assertIsNone(Httpx().parse_record({"title": "x"}))

    def test_bad_status_zero(self):
        rec = Httpx().parse_record({"url": "http://a", "status_code": "bad"})
        self.assertEqual(rec.status, 0)


class TestNaabu(unittest.TestCase):
    def test_parse_port(self):
        ip, port, host = Naabu().parse_record({"ip": "1.2.3.4", "port": 80, "host": "a.com"})
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(port.port_id, 80)
        self.assertEqual(host, "a.com")

    def test_bad_port_dropped(self):
        self.assertIsNone(Naabu().parse_record({"ip": "1.2.3.4", "port": "x"}))
        self.assertIsNone(Naabu().parse_record({"port": 80}))

    def test_scan_aggregates_by_ip(self):
        raw = '\n'.join([
            '{"ip":"1.1.1.1","port":80,"host":"a.com"}',
            '{"ip":"1.1.1.1","port":443,"host":"a.com"}',
            '{"ip":"2.2.2.2","port":22}',
        ])
        naabu = Naabu()
        # 直接喂 structure 模拟工具输出，验证聚合逻辑（不跑真进程）
        rows = list(naabu.structure(raw))
        agg = {}
        for ip, port_rec, host in rows:
            rec = agg.setdefault(ip, IPRec(ip=ip))
            if port_rec.port_id not in {p.port_id for p in rec.ports}:
                rec.ports.append(port_rec)
        self.assertEqual(len(agg), 2)
        self.assertEqual(len(agg["1.1.1.1"].ports), 2)


class TestWeakBrute(unittest.TestCase):
    def test_parse_valid_creds(self):
        out = WeakBrute.parse_output(
            "root:123456 - Valid credentials\n", "1.2.3.4", 22, "ssh", "ssh-brute")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].plg_type, "brute")
        self.assertEqual(out[0].verify_data, "root:123456")
        self.assertEqual(out[0].target, "ssh://1.2.3.4:22")

    def test_parse_unauth_redis(self):
        out = WeakBrute.parse_output(
            "| redis-info: \n|   Server version: 5.0\n", "1.2.3.4", 6379, "redis", "redis-info")
        self.assertTrue(any(r.vul_name.endswith("未授权访问") for r in out))

    def test_redis_with_auth_not_flagged(self):
        out = WeakBrute.parse_output(
            "requirepass set\n", "1.2.3.4", 6379, "redis", "redis-info")
        self.assertEqual(out, [])


class TestRegistry(unittest.TestCase):
    def test_build_has_roles(self):
        reg = build_registry()
        self.assertIsNotNone(reg.first(ROLE_VULN_SCAN))
        self.assertIsNotNone(reg.first(ROLE_PORT_SCAN))

    def test_pick_degrades_when_unavailable(self):
        reg = ToolRegistry()

        class _Dead:
            adapter = "dead"
            def available(self):
                return False
        reg.register("x", _Dead())
        self.assertIsNone(reg.pick("x"))

    def test_report_shape(self):
        rep = build_registry().report()
        self.assertIn(ROLE_VULN_SCAN, rep)


if __name__ == "__main__":
    unittest.main()
