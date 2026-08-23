"""recon pipeline 编排单测 —— 注入假工具（不需真装二进制），验证阶段编排/降级/取消/domain vs ip。

覆盖：全工具缺失→各阶段 skipped 不崩、假工具产出流经 ctx 中间态、domain 有 subdomain/resolve
而 ip 没有、协作式取消在阶段边界抛 stopped、单阶段异常隔离不整体崩、run_pipeline 返回摘要 + records
转 list[dict]、subdomain→resolve→site 数据串联。
"""
import unittest

from sentinel_platform.modules.kernel.recon import pipeline as P
from sentinel_platform.modules.kernel.recon.pipeline import Tools, run_pipeline
from sentinel_platform.modules.kernel.recon.models import DomainRec, IPRec, SiteRec, NucleiRec, PortInfo


class _FakeTool:
    """通用假工具：available() 可控 + 任意方法返回预置记录。"""
    def __init__(self, avail=True, ret=None, raises=False):
        self._avail = avail
        self._ret = ret if ret is not None else []
        self._raises = raises

    def available(self):
        return self._avail

    def _call(self, *a, **k):
        if self._raises:
            raise RuntimeError("boom")
        return list(self._ret)

    # 各工具主方法名都映射到 _call
    enumerate = brute = resolve = scan = probe = crawl = fetch = find = _call

    def detect(self, ip, pids):
        return {}


class PipelineTest(unittest.TestCase):
    # —— 全工具缺失：各阶段 skipped，result=done，产物空 ——
    def test_all_tools_missing_degrade(self):
        tools = Tools(**{k: _FakeTool(avail=False) for k in
                         ("subfinder", "massdns", "dnsx", "naabu", "nmap", "httpx",
                          "katana", "certfetch", "fileleak", "vhost", "nuclei", "weakbrute",
                          "webinfo", "screenshot", "enricher")})
        r = run_pipeline("t1", "domain", "example.com", tools=tools)
        self.assertEqual(r["result"], "done")
        self.assertEqual(r["stages"], [])                 # 全 skipped
        self.assertEqual(len(r["skipped"]), 14)           # domain 14 阶段全跳
        self.assertEqual(r["records"], {})

    # —— 假工具产出流经中间态 ——
    def test_records_flow(self):
        tools = Tools(
            subfinder=_FakeTool(ret=[DomainRec(domain="a.example.com", type="SUBDOMAIN")]),
            dnsx=_FakeTool(ret=[DomainRec(domain="a.example.com", type="A", ips=["1.2.3.4"])]),
            naabu=_FakeTool(ret=[IPRec(ip="1.2.3.4", ports=[PortInfo(port_id=80)])]),
            httpx=_FakeTool(ret=[SiteRec(url="http://a.example.com", ip="1.2.3.4", status=200)]),
            nuclei=_FakeTool(ret=[NucleiRec(target="http://a.example.com", template_id="cve-x",
                                            vuln_name="v", vuln_severity="high")]),
            massdns=_FakeTool(avail=False), dnsx_=None,
            katana=_FakeTool(avail=False), certfetch=_FakeTool(avail=False),
            fileleak=_FakeTool(avail=False), vhost=_FakeTool(avail=False),
            nmap=_FakeTool(avail=False), weakbrute=_FakeTool(avail=False),
        )
        r = run_pipeline("t2", "domain", "example.com", tools=tools)
        self.assertEqual(r["result"], "done")
        self.assertIn("subdomain", r["stages"])
        self.assertIn("resolve", r["stages"])
        self.assertIn("portscan", r["stages"])
        self.assertIn("site", r["stages"])
        self.assertIn("poc", r["stages"])
        # records 转 list[dict]
        self.assertTrue(any(d["domain"] == "a.example.com" for d in r["records"]["domain"]))
        self.assertTrue(any(x["ip"] == "1.2.3.4" for x in r["records"]["ip"]))
        self.assertTrue(r["records"]["nuclei_result"])

    # —— domain vs ip：ip 省 subdomain/resolve ——
    def test_ip_skips_subdomain_resolve(self):
        tools = Tools(naabu=_FakeTool(ret=[IPRec(ip="1.2.3.4", ports=[PortInfo(port_id=443)])]),
                      **{k: _FakeTool(avail=False) for k in
                         ("subfinder", "massdns", "dnsx", "nmap", "httpx", "katana",
                          "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")})
        r = run_pipeline("t3", "ip", "1.2.3.4", tools=tools)
        all_stages = r["stages"] + r["skipped"]
        self.assertNotIn("subdomain", all_stages)         # ip 任务无子域名阶段
        self.assertNotIn("resolve", all_stages)
        self.assertIn("portscan", r["stages"])

    # —— 协作式取消：cancel_check 返 True → stopped，保留已跑产物 ——
    def test_cooperative_cancel(self):
        calls = {"n": 0}

        def cancel():
            calls["n"] += 1
            return calls["n"] >= 2                         # 第 2 个阶段边界停

        tools = Tools(subfinder=_FakeTool(ret=[DomainRec(domain="a.example.com")]),
                      **{k: _FakeTool(avail=False) for k in
                         ("massdns", "dnsx", "naabu", "nmap", "httpx", "katana",
                          "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")})
        r = run_pipeline("t4", "domain", "example.com", tools=tools, cancel_check=cancel)
        self.assertEqual(r["result"], "stopped")
        self.assertIn("subdomain", r["stages"])           # 第 1 阶段跑了
        self.assertNotIn("poc", r["stages"])              # 后续未跑

    # —— 单阶段异常隔离：一个阶段抛异常，不整体崩，其余继续 ——
    # BUG-006（2026-08-07 更新断言）：可选阶段失败 + 仍有资产产出 → 任务算 done（降级），
    # 不再冒泡成 error（§11.4 设计：阶段 skip/降级是正常行为）。原断言 error 是被修掉的旧行为。
    def test_stage_error_isolated(self):
        tools = Tools(
            subfinder=_FakeTool(raises=True),             # subdomain 阶段炸
            naabu=_FakeTool(ret=[IPRec(ip="1.1.1.1", ports=[PortInfo(port_id=80)])]),
            **{k: _FakeTool(avail=False) for k in
               ("massdns", "dnsx", "nmap", "httpx", "katana",
                "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")})
        r = run_pipeline("t5", "domain", "example.com", tools=tools)
        self.assertEqual(r["result"], "done")             # 有资产产出→降级为 done，不误判 error
        self.assertIn("subdomain", r.get("failed_stages", []))  # 失败阶段如实记录（降级告警）
        self.assertTrue(any(x["ip"] == "1.1.1.1" for x in r["records"].get("ip", [])))  # 后续阶段照跑

    # —— 全程零资产 + 阶段失败 → 致命 error（BUG-006：只有一个资产都没产出才判 error）——
    def test_stage_error_no_assets_is_fatal(self):
        tools = Tools(
            subfinder=_FakeTool(raises=True),             # 唯一能产出的阶段炸了
            **{k: _FakeTool(avail=False) for k in
               ("massdns", "dnsx", "naabu", "nmap", "httpx", "katana",
                "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")})
        r = run_pipeline("t5b", "domain", "example.com", tools=tools)
        self.assertEqual(r["result"], "error")            # 零资产 + 有失败阶段 → 真 error
        self.assertIn("subdomain", r.get("failed_stages", []))

    # —— 空目标：不崩，全空 ——
    def test_empty_target(self):
        r = run_pipeline("t6", "domain", "", tools=Tools(
            **{k: _FakeTool(avail=False) for k in
               ("subfinder", "massdns", "dnsx", "naabu", "nmap", "httpx", "katana",
                "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")}))
        self.assertEqual(r["result"], "done")

    # —— nmap 服务识别回填 PortInfo dataclass 属性（防 dict-only 回填漏 PortInfo 的 bug）——
    def test_service_backfill_portinfo(self):
        class _Nmap:
            def available(self):
                return True
            def detect(self, ip, pids):
                return {80: PortInfo(port_id=80, service_name="http", version="1.1", product="nginx")}
        ipr = IPRec(ip="1.2.3.4", ports=[PortInfo(port_id=80)])
        tools = Tools(naabu=_FakeTool(ret=[ipr]), nmap=_Nmap(),
                      **{k: _FakeTool(avail=False) for k in
                         ("subfinder", "massdns", "dnsx", "httpx", "katana",
                          "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")})
        r = run_pipeline("t8", "ip", "1.2.3.4", tools=tools)
        self.assertIn("service", r["stages"])
        self.assertEqual(ipr.ports[0].service_name, "http")   # 回填生效
        self.assertEqual(ipr.ports[0].product, "nginx")

    # —— 端口扫描把 IP 喂给证书/服务阶段（中间态串联）——
    def test_ports_feed_downstream(self):
        tools = Tools(
            naabu=_FakeTool(ret=[IPRec(ip="9.9.9.9", ports=[PortInfo(port_id=443)])]),
            certfetch=_FakeTool(ret=[]),                  # available 但无证书 → skipped(count0)
            **{k: _FakeTool(avail=False) for k in
               ("subfinder", "massdns", "dnsx", "nmap", "httpx", "katana",
                "fileleak", "vhost", "nuclei", "weakbrute")})
        r = run_pipeline("t7", "ip", "9.9.9.9", tools=tools)
        self.assertIn("portscan", r["stages"])
        self.assertEqual(r["counts"]["portscan"], 1)



    # —— 断点续扫：done_steps 里的阶段跳过不重跑 ——
    def test_checkpoint_skips_done_stages(self):
        calls = []
        class _Track(_FakeTool):
            def __init__(self, name, **kw):
                super().__init__(**kw); self._name = name
            def _call(self, *a, **k):
                calls.append(self._name); return super()._call(*a, **k)
            enumerate = brute = resolve = scan = probe = crawl = fetch = find = _call
        tools = Tools(subfinder=_Track("subfinder", ret=[DomainRec(domain="a.example.com")]),
                      dnsx=_Track("dnsx", ret=[DomainRec(domain="a.example.com", ips=["1.2.3.4"])]))
        # subdomain 已完成 → 跳过，dnsx 仍跑
        r = run_pipeline("t", "domain", "example.com", tools=tools, done_steps=["subdomain"])
        self.assertNotIn("subfinder", calls)      # 已完成阶段未再调工具
        self.assertNotIn("subdomain", r["stages"])

    def test_checkpoint_restores_context_for_downstream_stages(self):
        calls = {}

        class _PortScan(_FakeTool):
            def scan(self, targets, **kwargs):
                calls["port_targets"] = list(targets)
                return [IPRec(ip="1.2.3.4", ports=[PortInfo(port_id=80)])]

        class _Http(_FakeTool):
            def probe(self, targets, **kwargs):
                calls["site_targets"] = list(targets)
                return [SiteRec(url="http://a.example.com", hostname="a.example.com", ip="1.2.3.4")]

        tools = Tools(subfinder=_FakeTool(raises=True), dnsx=_FakeTool(raises=True),
                      naabu=_PortScan(), httpx=_Http(),
                      **{k: _FakeTool(avail=False) for k in
                         ("massdns", "nmap", "katana", "certfetch", "fileleak", "vhost",
                          "nuclei", "weakbrute", "webinfo", "screenshot")})
        initial = {"domain": [{"domain": "a.example.com", "type": "A", "ips": ["1.2.3.4"]}]}
        r = run_pipeline("t", "domain", "example.com", tools=tools,
                         done_steps=["subdomain", "resolve"], initial_records=initial)
        self.assertEqual(r["result"], "done")
        self.assertEqual(calls["port_targets"], ["a.example.com"])
        self.assertIn("1.2.3.4:80", calls["site_targets"])
        self.assertTrue(r["records"].get("site"))

    # —— 流式回调：每阶段后 on_stage 被调，站点阶段可触发派发 ——
    def test_on_stage_streaming_callback(self):
        seen = []
        tools = Tools(subfinder=_FakeTool(ret=[DomainRec(domain="a.example.com")]),
                      dnsx=_FakeTool(ret=[DomainRec(domain="a.example.com", ips=["1.2.3.4"])]),
                      httpx=_FakeTool(ret=[SiteRec(url="http://a.example.com", hostname="a.example.com")]))
        def _on(ctx, stage): seen.append(stage)
        run_pipeline("t", "domain", "example.com", tools=tools, on_stage=_on)
        self.assertIn("subdomain", seen)          # 每完成阶段都回调
        self.assertIn("site", seen)

    # —— 水位：io_concurrency 注入 native 工具并发度 ——
    def test_water_level_io_concurrency(self):
        t = Tools(io_concurrency=3)
        self.assertEqual(t.fileleak.concurrency, 3)   # 注入生效
        self.assertEqual(t.vhost.concurrency, 3)
        t2 = Tools()                                   # 未注入 → 类默认(不为3)
        self.assertNotEqual(t2.fileleak.concurrency, 3)

    # —— IP 分桶并行：多 IP vhost 跨 IP 并行不漏（结果与串行一致）——
    def test_vhost_ip_bucketing(self):
        ips = [IPRec(ip="1.1.1.1"), IPRec(ip="2.2.2.2"), IPRec(ip="3.3.3.3")]
        class _Vhost(_FakeTool):
            def find(self, ip, hosts, **k):
                return [SiteRec(url="http://%s" % ip, hostname="h", ip=ip)]
        tools = Tools(naabu=_FakeTool(ret=ips), dnsx=_FakeTool(ret=[DomainRec(domain="h", ips=["1.1.1.1"])]),
                      subfinder=_FakeTool(ret=[DomainRec(domain="h")]), vhost=_Vhost())
        r = run_pipeline("t", "domain", "example.com", tools=tools,
                         options={"scan_parallelism": 3})
        # 3 个 IP 各产 1 站点，并行不漏
        self.assertGreaterEqual(r["counts"].get("vhost", 0), 3)


class CollectModeTest(unittest.TestCase):
    """collect_mode 三档分流（回归:净室迁移曾丢,三档执行完全一样）。"""

    def _tools_tracking(self):
        calls = {"subfinder": 0, "massdns": 0}
        class _Track:
            def __init__(s, name): s.name = name
            def available(s): return True
            def enumerate(s, roots, scope=None):
                calls["subfinder"] += 1
                return [DomainRec(domain="a.example.com")]
            def brute(s, root, words, resolvers=None, scope=None):
                calls["massdns"] += 1
                return [DomainRec(domain="b.example.com")]
        # subfinder+massdns 跟踪；其余工具缺失(不干扰)
        t = Tools(subfinder=_Track("subfinder"), massdns=_Track("massdns"),
                  **{k: _FakeTool(avail=False) for k in
                     ("dnsx", "naabu", "nmap", "httpx", "katana", "certfetch",
                      "fileleak", "vhost", "nuclei", "weakbrute", "webinfo", "screenshot", "enricher")})
        return t, calls

    def _opts(self, mode):
        # massdns 爆破需 brute_words+resolvers 才触发,给上以验证 passive 确实跳过
        return {"collect_mode": mode, "brute_words": ["www", "admin"], "resolvers": "/tmp/r.txt"}

    def test_single_skips_enumeration(self):
        t, calls = self._tools_tracking()
        run_pipeline("t", "domain", "example.com", tools=t, options=self._opts("single"))
        self.assertEqual(calls["subfinder"], 0, "single 不枚举子域名")
        self.assertEqual(calls["massdns"], 0, "single 不爆破")

    def test_multi_passive_no_brute(self):
        t, calls = self._tools_tracking()
        run_pipeline("t", "domain", "example.com", tools=t, options=self._opts("multi_passive"))
        self.assertEqual(calls["subfinder"], 1, "multi_passive 被动枚举")
        self.assertEqual(calls["massdns"], 0, "multi_passive 不爆破")

    def test_multi_brute_both(self):
        t, calls = self._tools_tracking()
        run_pipeline("t", "domain", "example.com", tools=t, options=self._opts("multi_brute"))
        self.assertEqual(calls["subfinder"], 1, "multi_brute 被动枚举")
        self.assertGreaterEqual(calls["massdns"], 1, "multi_brute 爆破")

    def test_default_is_brute(self):
        """缺省(无 collect_mode)= multi_brute 兼容存量。"""
        t, calls = self._tools_tracking()
        run_pipeline("t", "domain", "example.com", tools=t,
                     options={"brute_words": ["www"], "resolvers": "/tmp/r.txt"})
        self.assertEqual(calls["subfinder"], 1)
        self.assertGreaterEqual(calls["massdns"], 1)


if __name__ == "__main__":
    unittest.main()
