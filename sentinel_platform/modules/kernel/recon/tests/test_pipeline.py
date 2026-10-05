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
        # 铜钱重构后：工具全缺仍降级不崩、result=done。但 seed_intake（gate=always）无条件把种子
        # 入线（种子是确定资产，不依赖任何工具）——所以会产出 1 条 domain 记录（种子本身），
        # 这是设计目标（种子不因工具缺失而蒸发），非 bug。其余需工具的阶段全 skip。
        tools = Tools(**{k: _FakeTool(avail=False) for k in
                         ("subfinder", "massdns", "dnsx", "naabu", "nmap", "httpx",
                          "katana", "certfetch", "fileleak", "vhost", "nuclei", "weakbrute",
                          "webinfo", "screenshot", "enricher")})
        r = run_pipeline("t1", "domain", "example.com", tools=tools)
        self.assertEqual(r["result"], "done")
        self.assertEqual(r["stages"], ["seed_intake"])    # 仅种子入线产出（无工具依赖）
        self.assertEqual(r["records"].get("domain"), [{"domain": "example.com", "record": [],
                         "type": "SEED", "ips": [], "source": "seed"}])

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
        # poc 铜钱已全局禁用（主动扫描禁绝）→ 不再串、不再出 nuclei_result（即便注入了 nuclei 替身）
        self.assertNotIn("poc", r["stages"])
        self.assertFalse(r["records"].get("nuclei_result"))
        # records 转 list[dict]
        self.assertTrue(any(d["domain"] == "a.example.com" for d in r["records"]["domain"]))
        self.assertTrue(any(x["ip"] == "1.2.3.4" for x in r["records"]["ip"]))

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
        self.assertIn("seed_intake", r["stages"])         # 第 1 铜钱跑了（重构后 seed_intake 打头）
        self.assertNotIn("poc", r["stages"])              # 后续未跑（取消生效）

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
    # 铜钱重构后：seed_intake（gate=always）无条件入种子，域名任务永远至少有种子产出，故「零资产」
    # 场景改用 **IP 任务**构造（ip 任务无 seed_intake 铜钱，ip_seed 需 targets 是 IP；这里用非法/空
    # 让唯一产出阶段 portscan 炸 → 真零资产）。验证 error 机制本身仍有效（未被重构弱化）。
    def test_stage_error_no_assets_is_fatal(self):
        tools = Tools(
            naabu=_FakeTool(raises=True),                 # IP 任务唯一能产出的 portscan 炸了
            **{k: _FakeTool(avail=False) for k in
               ("subfinder", "massdns", "dnsx", "nmap", "httpx", "katana",
                "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")})
        # 非 IP 目标喂 ip 任务：ip_seed 不入（targets 非合法 IP），portscan 炸 → 零资产
        r = run_pipeline("t5b", "ip", "not-an-ip-target", tools=tools)
        self.assertEqual(r["result"], "error")            # 零资产 + 有失败阶段 → 真 error
        self.assertIn("portscan", r.get("failed_stages", []))

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

    def test_service_resource_degraded_deferred_not_done(self):
        """AUD-11：nmap 因资源门超时降级(返 __degraded__)→ service 阶段 deferred_resource（非终态），
        不进 done_steps，恢复资源后重投会重跑，不把"未执行"误当"执行了无发现"。"""
        class _NmapDegraded:
            def available(self):
                return True
            def detect(self, ip, pids):
                return {"__degraded__": True}   # 模拟资源门超时降级
        ipr = IPRec(ip="1.2.3.4", ports=[PortInfo(port_id=80)])
        tools = Tools(naabu=_FakeTool(ret=[ipr]), nmap=_NmapDegraded(),
                      **{k: _FakeTool(avail=False) for k in
                         ("subfinder", "massdns", "dnsx", "httpx", "katana",
                          "certfetch", "fileleak", "vhost", "nuclei", "weakbrute")})
        r = run_pipeline("t9", "ip", "1.2.3.4", tools=tools)
        # service 阶段状态为 deferred_resource（非 completed_empty），且不算 failed
        self.assertEqual((r["stage_status"].get("service") or {}).get("status"), "deferred_resource")
        self.assertNotIn("service", r.get("failed_stages", []))

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
        # 断点续扫：seed_intake/subdomain/resolve 已完成（种子已在 initial_records 恢复），跳过不重跑
        r = run_pipeline("t", "domain", "example.com", tools=tools,
                         done_steps=["seed_intake", "subdomain", "resolve"], initial_records=initial)
        self.assertEqual(r["result"], "done")
        # 问题5 修复后：resolve_ip_seed 把解析出的 IP(1.2.3.4)灌进 ctx.ips → portscan 扫解析 IP（更正确，
        # 不再回退扫 hostname 让 naabu 重解析）。这也保证 port_scan=false 时解析 IP 仍落 ip 集合。
        self.assertEqual(calls["port_targets"], ["1.2.3.4"])
        self.assertIn("1.2.3.4:80", calls["site_targets"])
        self.assertTrue(r["records"].get("site"))
        # 解析 IP 应保底入 ip 集合（问题5：不受 port_scan 门控）
        self.assertTrue(any(ip.get("ip") == "1.2.3.4" for ip in (r["records"].get("ip") or [])))

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

    def test_site_batch_streaming_dispatch(self):
        """目标级流式：site 分批探测，每批探通即触发 on_stage('site')（emit_batch），
        不等整阶段所有目标探完。多批 → site 回调多次（首会话延迟从'等全部'降到'第一批探通即派'）。"""
        site_events = []

        class _BatchHttp(_FakeTool):
            def probe(self, targets, **kwargs):
                # 每个目标返回一个站点（模拟批内探通）
                return [SiteRec(url="http://{}".format(h), hostname=str(h)) for h in targets]

        # 300 个 host（io_concurrency 默认 100 → batch=max(200,50)=200 → 分 2 批）
        hosts = ["h{}.example.com".format(i) for i in range(300)]
        tools = Tools(subfinder=_FakeTool(ret=[DomainRec(domain=h) for h in hosts]),
                      httpx=_BatchHttp(),
                      **{k: _FakeTool(avail=False) for k in
                         ("massdns", "dnsx", "naabu", "nmap", "katana", "certfetch",
                          "fileleak", "vhost", "nuclei", "weakbrute", "webinfo", "screenshot", "enricher")})

        def _on(ctx, stage):
            if stage == "site":
                site_events.append(len(ctx.sites))
        r = run_pipeline("t", "domain", "example.com", tools=tools,
                         options={"collect_mode": "multi_passive"}, on_stage=_on)
        # site 回调 >=2 次（分批触发）+ 阶段结束 1 次；每次 ctx.sites 递增（增量流式）
        self.assertGreaterEqual(len(site_events), 2, "site 应分批多次触发流式派发")
        self.assertEqual(site_events, sorted(site_events), "每批 ctx.sites 递增（增量）")
        self.assertEqual(r["result"], "done")

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

    def test_single_seed_intake_and_site_no_fallback(self):
        """single 卡死根治核心：single 跳枚举，但种子仍入 ctx.hosts（seed_intake 铜钱），
        site 探测拿到的是「种子 host」而非 fallback 到全量 ctx.targets。旧 bug：single 直接 return
        导致 hosts 空 → site fallback ctx.targets 全量 httpx 探 → 卡死。"""
        probed = {}

        class _Http(_FakeTool):
            def probe(self, targets, **kwargs):
                probed["targets"] = list(targets)
                return [SiteRec(url="http://a.com", hostname="a.com")]

        t = Tools(subfinder=_FakeTool(avail=False), httpx=_Http(),
                  **{k: _FakeTool(avail=False) for k in
                     ("massdns", "dnsx", "naabu", "nmap", "katana", "certfetch",
                      "fileleak", "vhost", "nuclei", "weakbrute", "webinfo", "screenshot", "enricher")})
        r = run_pipeline("t", "domain", "a.com", tools=t, options={"collect_mode": "single"})
        # 种子入线：domain 记录含种子 a.com；site 探测目标是种子 host（经 hosts），非空 fallback
        self.assertTrue(any(d.get("domain") == "a.com" for d in r["records"].get("domain", [])),
                        "single 种子必须入线（根治卡死）")
        self.assertEqual(probed.get("targets"), ["a.com"], "site 探种子 host，不 fallback 全量")
        self.assertEqual(r["result"], "done")

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

    def test_third_party_source_skips_public_enum(self):
        """第三方源有效（API 源/FOFA）时，**跳过 subfinder 公共被动枚举**（卡死元凶），只用第三方源。"""
        observed = {"enumerate_called": False, "sources_called": False}

        class _Subfinder:
            def available(self): return True
            def enumerate(self, roots, scope=None):
                observed["enumerate_called"] = True          # 公共全量枚举——应被跳过
                return [DomainRec(domain="public.example.com")]
            def enumerate_sources(self, roots, credentials, scope=None):
                observed["sources_called"] = True
                observed["credentials"] = credentials
                return [DomainRec(domain="api.example.com")]

        tools = Tools(subfinder=_Subfinder(), **{k: _FakeTool(avail=False) for k in
                      ("massdns", "dnsx", "naabu", "nmap", "httpx", "katana", "certfetch",
                       "fileleak", "vhost", "nuclei", "weakbrute", "webinfo", "screenshot", "enricher")})
        r = run_pipeline("t", "domain", "example.com", tools=tools,
                         options={"collect_mode": "multi_brute", "domain_brute": False,
                                  "_collection_source_credentials": {"hunter": "secret"}})
        domains = {d["domain"] for d in r["records"]["domain"]}
        self.assertFalse(observed["enumerate_called"])       # 红线：公共枚举被跳过
        self.assertNotIn("public.example.com", domains)
        self.assertTrue(observed["sources_called"])          # API 增强源仍跑
        self.assertIn("api.example.com", domains)
        self.assertEqual(observed["credentials"], {"hunter": "secret"})

    def test_fofa_collector_also_skips_public_enum(self):
        """FOFA 原生采集器有效时同样跳过公共枚举（第三方源判据含 _fofa_collector）。"""
        observed = {"enumerate_called": False}

        class _Subfinder:
            def available(self): return True
            def enumerate(self, roots, scope=None):
                observed["enumerate_called"] = True
                return [DomainRec(domain="public.example.com")]

        tools = Tools(subfinder=_Subfinder(), **{k: _FakeTool(avail=False) for k in
                      ("massdns", "dnsx", "naabu", "nmap", "httpx", "katana", "certfetch",
                       "fileleak", "vhost", "nuclei", "weakbrute", "webinfo", "screenshot", "enricher")})
        r = run_pipeline("t", "domain", "example.com", tools=tools,
                         options={"collect_mode": "multi_brute", "domain_brute": False,
                                  "_fofa_collector": lambda roots: ["fofa.example.com"]})
        domains = {d["domain"] for d in r["records"]["domain"]}
        self.assertFalse(observed["enumerate_called"])
        self.assertIn("fofa.example.com", domains)           # FOFA 采集结果保留

    def test_no_third_party_falls_back_to_public_enum(self):
        """无任何第三方源 → 退回 subfinder 公共被动枚举兜底（不丢子域发现能力，向后兼容）。"""
        observed = {"enumerate_called": False}

        class _Subfinder:
            def available(self): return True
            def enumerate(self, roots, scope=None):
                observed["enumerate_called"] = True
                return [DomainRec(domain="public.example.com")]

        tools = Tools(subfinder=_Subfinder(), **{k: _FakeTool(avail=False) for k in
                      ("massdns", "dnsx", "naabu", "nmap", "httpx", "katana", "certfetch",
                       "fileleak", "vhost", "nuclei", "weakbrute", "webinfo", "screenshot", "enricher")})
        r = run_pipeline("t", "domain", "example.com", tools=tools,
                         options={"collect_mode": "multi_brute", "domain_brute": False})
        domains = {d["domain"] for d in r["records"]["domain"]}
        self.assertTrue(observed["enumerate_called"])        # 兜底：公共枚举被调用
        self.assertIn("public.example.com", domains)


class ActiveScanDisabledTest(unittest.TestCase):
    """主动扫描全局禁用（用户明令 2026-08-28）：poc(nuclei)/weakbrute 铜钱无论策略勾选都不串。"""

    class _Ctx:
        task_type = "domain"
        def __init__(self, opts): self.options = opts

    def test_poc_gate_disabled_even_if_policy_on(self):
        # 策略显式勾选 nuclei_scan=True，gate 仍返 False（全局禁）
        spec = next(s for s in P.STAGE_SPECS if s.name == "poc")
        on, reason = spec.gate(self._Ctx({"nuclei_scan": True}))
        self.assertFalse(on)
        self.assertIn("全局禁用", reason)

    def test_weakbrute_gate_disabled_even_if_config(self):
        spec = next(s for s in P.STAGE_SPECS if s.name == "weakbrute")
        on, reason = spec.gate(self._Ctx({"brute_config": ["ssh"]}))
        self.assertFalse(on)
        self.assertIn("全局禁用", reason)

    def test_assemble_excludes_poc_weakbrute(self):
        # 组装出的执行链不含 poc/weakbrute（gate=off 进 disabled 列表）
        ctx = self._Ctx({"nuclei_scan": True, "brute_config": ["ssh"]})
        selected, disabled = P.assemble_stages(ctx)
        names = {s.name for s in selected}
        self.assertNotIn("poc", names)
        self.assertNotIn("weakbrute", names)
        dnames = {n for n, _ in disabled}
        self.assertIn("poc", dnames)
        self.assertIn("weakbrute", dnames)


if __name__ == "__main__":
    unittest.main()
