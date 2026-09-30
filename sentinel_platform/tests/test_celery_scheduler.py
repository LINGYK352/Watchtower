"""celery worker + scheduler 进程入口测试（2026-07-05 Claude-Opus[recon]）。

celery 未装本地（仅 vendor wheel）→ 不真起 broker；测:①scheduler tick 逻辑(投 waiting + 到期计划)
②celery_app 无 celery 时抛 ImportError 而非静默 ③scheduler 到期计划任务翻 WAITING 语义。
均用内存 repo + mock，不依赖真 celery/mongo/broker。
"""
import time
import unittest
from unittest import mock

from sentinel_platform.core import set_repo
from sentinel_platform import scheduler


class _Coll:
    def __init__(self, docs=None):
        self.docs = list(docs or [])
    def find(self, q=None, proj=None):
        q = q or {}
        def _match(d):
            for k, v in q.items():
                if isinstance(v, dict) and "$in" in v:
                    if d.get(k) not in v["$in"]:
                        return False
                elif isinstance(v, dict) and "$ne" in v:
                    if d.get(k) == v["$ne"]:   # 缺字段=None != True → 满足 $ne:True（对齐真 pymongo）
                        return False
                elif d.get(k) != v:
                    return False
            return True
        return [d for d in self.docs if _match(d)]
    def find_one(self, q, sort=None):
        rows = self.find(q)
        if sort:
            for field, direction in reversed(sort):
                rows = sorted(rows, key=lambda d: d.get(field, 0), reverse=(direction < 0))
        return next(iter(rows), None)
    def count_documents(self, q=None):
        return len(self.find(q))
    def update_one(self, q, upd, upsert=False):
        d = self.find_one(q)
        if d:
            d.update(upd.get("$set", {}))
            for k, v in upd.get("$inc", {}).items():
                d[k] = d.get(k, 0) + v
        return type("R", (), {"modified_count": 1 if d else 0})()


class _Repo:
    def __init__(self):
        self.c = {}
    def collection(self, n):
        return self.c.setdefault(n, _Coll())


class TestSchedulerTick(unittest.TestCase):
    def tearDown(self):
        set_repo(None)

    def test_tick_invokes_run_waiting(self):
        repo = _Repo(); set_repo(repo)
        with mock.patch("sentinel_platform.modules.kernel.orchestration.run_waiting_tasks",
                        return_value={"picked": 2, "submitted": 2}) as m:
            r = scheduler.tick()
        m.assert_called_once()
        self.assertEqual(r["waiting"]["submitted"], 2)

    def test_promote_due_schedule(self):
        """v1.21.96 起 _promote_due_schedules 委托 task_schedule_service.run_due 真建扫描任务
        （旧行为只 run_number++ 不建任务，已改）。本测试验证委托：注册假 run_due，断言被调 + 返 ran 数。"""
        from sentinel_platform.contracts import get_registry
        from sentinel_platform.contracts.registry import reset_registry
        reset_registry()
        called = {"n": 0}
        class _FakeSchedSvc:
            def run_due(self):
                called["n"] += 1
                return {"picked": 2, "ran": 1}     # 模拟：2 到期、1 真建成
        get_registry().register("task_schedule_service", _FakeSchedSvc())
        n = scheduler._promote_due_schedules()
        self.assertEqual(called["n"], 1)            # 委托调了 run_due
        self.assertEqual(n, 1)                      # 返 run_due 的 ran 数（真触发数）
        reset_registry()

    def test_promote_due_schedule_no_service_degrades(self):
        """task_schedule_service 未注册 → 降级返 0 不崩（缺失降级铁律）。"""
        from sentinel_platform.contracts.registry import reset_registry
        reset_registry()
        self.assertEqual(scheduler._promote_due_schedules(), 0)

    def test_tick_degrades_no_crash(self):
        set_repo(_Repo())
        with mock.patch("sentinel_platform.modules.kernel.orchestration.run_waiting_tasks",
                        side_effect=Exception("boom")):
            r = scheduler.tick()      # 不抛
        self.assertIn("waiting", r)

    def test_tick_seconds_config(self):
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: 15 if a[:2] == ("SCHEDULE", "TICK_SECONDS") else k.get("default")
        with mock.patch.object(scheduler, "get_config", return_value=cfg):
            self.assertEqual(scheduler._tick_seconds(), 15)


class TestSessionRecovery(unittest.TestCase):
    """会话自愈 tick（§13.5 全自动无人值守：queued促投/paused重投/stalled看门狗）。"""
    def tearDown(self):
        set_repo(None)

    def test_tick_sessions_queued_and_paused(self):
        repo = _Repo(); set_repo(repo)
        sc = repo.collection("intel_pentest_session")
        sc.docs = [
            {"_id": "q1", "status": "queued"},
            {"_id": "p1", "status": "paused_transient", "retry_count": 1},
            {"_id": "pmax", "status": "paused_transient", "retry_count": 12},   # ≥MAX_TRANSIENT_RETRY(12)→降级
        ]
        calls = []
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session",
                        side_effect=lambda sid, **kw: (calls.append(sid) or {"submitted": True})):
            out = scheduler._tick_sessions()
        self.assertEqual(out["queued"], 1)      # q1 促投
        self.assertEqual(out["resumed"], 1)     # p1 重投
        self.assertEqual(out["degraded"], 1)    # pmax 降级
        self.assertIn("q1", calls); self.assertIn("p1", calls)
        # pmax 降级为 manual，不再投
        self.assertEqual(next(d for d in sc.docs if d["_id"]=="pmax")["status"], "paused_manual")
        # retry_count 的原子递增由真实 orchestration.submit_session 完成；本测试 mock 只验证调度选择。
        self.assertEqual(next(d for d in sc.docs if d["_id"]=="p1")["retry_count"], 1)

    def test_tick_sessions_concurrency_cap(self):
        repo = _Repo(); set_repo(repo)
        sc = repo.collection("intel_pentest_session")
        sc.docs = [{"_id":"r","status":"running"}] + [{"_id":"q%d"%i,"status":"queued","priority":i} for i in range(5)]
        calls=[]
        with mock.patch("sentinel_platform.scheduler._session_cap", return_value=3),              mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session",
                        side_effect=lambda sid, **kw: (calls.append(sid) or {"submitted": True})):
            out = scheduler._tick_sessions()
        # cap=3, running=1 → 只促投 2 个 queued
        self.assertEqual(out["queued"], 2)
        self.assertEqual(len(calls), 2)


    def test_tick_sessions_stalled_watchdog(self):
        repo = _Repo(); set_repo(repo)
        sc = repo.collection("intel_pentest_session")
        sc.docs = [{"_id": "r1", "status": "running", "update_date": "2020-01-01 00:00:00"}]  # 远古心跳=死
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session"):
            out = scheduler._tick_sessions()
        self.assertEqual(out["stalled"], 1)
        self.assertEqual(sc.docs[0]["status"], "queued")   # 判死→重排队

    def test_tick_sessions_dispatching_stall_reclaim(self):
        """dispatching 停滞（心跳远古=派发消息丢/worker起转前崩）→ 回 queued 重派 + dispatch_reclaim_count++。
        治「周期 watchdog 此前只管 running，dispatching 卡死只能靠重启 scheduler」。"""
        repo = _Repo(); set_repo(repo)
        sc = repo.collection("intel_pentest_session")
        sc.docs = [{"_id": "d1", "status": "dispatching", "update_date": "2020-01-01 00:00:00"}]
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session",
                        side_effect=lambda sid, **kw: {"submitted": True}):
            out = scheduler._tick_sessions()
        self.assertEqual(out["stalled"], 1)
        self.assertEqual(sc.docs[0]["status"], "queued")           # 卡死 dispatching → 重排队
        self.assertEqual(sc.docs[0]["dispatch_reclaim_count"], 1)  # 计数++（超限才降级）

    def test_tick_sessions_dispatching_reclaim_degrade(self):
        """dispatching 反复停滞回收超 MAX_DISPATCH_RECLAIM(3) 仍起不来 → 降级 paused_manual（延迟自愈），
        不无限 queued↔dispatching 抖动占槽（如 provider 失效/run_agent 起转即崩）。"""
        repo = _Repo(); set_repo(repo)
        sc = repo.collection("intel_pentest_session")
        sc.docs = [{"_id": "d2", "status": "dispatching", "update_date": "2020-01-01 00:00:00",
                    "dispatch_reclaim_count": 3}]
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session"):
            out = scheduler._tick_sessions()
        self.assertEqual(out["degraded"], 1)
        self.assertEqual(sc.docs[0]["status"], "paused_manual")

    def test_tick_sessions_fresh_dispatching_not_reclaimed(self):
        """新鲜 dispatching（心跳=当下，正常刚派发在途）绝不被回收——防 queued↔dispatching 抖动。"""
        repo = _Repo(); set_repo(repo)
        sc = repo.collection("intel_pentest_session")
        sc.docs = [{"_id": "d3", "status": "dispatching",
                    "update_date": time.strftime("%Y-%m-%d %H:%M:%S")}]
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session"):
            out = scheduler._tick_sessions()
        self.assertEqual(out["stalled"], 0)
        self.assertEqual(sc.docs[0]["status"], "dispatching")      # 保持在途，不误回收

    def test_tick_sessions_degrades_no_crash(self):
        set_repo(_Repo())
        out = scheduler._tick_sessions()   # 空库不崩
        self.assertEqual(out["queued"], 0)



class TestCeleryAppEntry(unittest.TestCase):
    def test_import_without_celery_degrades_not_crash(self):
        # celery 未装 → 模块可 import（不崩），celery_app 降级为 None；build() 内 make_celery 仍抛 ImportError
        try:
            import celery  # noqa
            has_celery = True
        except ImportError:
            has_celery = False
        from sentinel_platform import celery_app as _m
        if has_celery:
            self.assertIsNotNone(_m.celery_app)      # 装了 → 真 app
        else:
            self.assertIsNone(_m.celery_app)         # 没装 → 降级 None，不崩
            with self.assertRaises(ImportError):     # 但显式 build() 仍暴露缺 celery（不静默）
                _m.build()

    def test_broker_url_from_config(self):
        from sentinel_platform import celery_app as _m
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: ("amqp://x:y@h:5672//"
                                                   if a[:2] == ("CELERY", "BROKER_URL") else k.get("default"))
        with mock.patch.object(_m, "get_config", return_value=cfg):
            self.assertEqual(_m._broker_url(), "amqp://x:y@h:5672//")

    def test_broker_url_default(self):
        from sentinel_platform import celery_app as _m
        cfg = mock.Mock()
        cfg.section.side_effect = lambda *a, **k: k.get("default")   # 无配置
        with mock.patch.object(_m, "get_config", return_value=cfg):
            self.assertIn("amqp://", _m._broker_url())              # 有默认 broker

    def test_broker_vhost_single_slash_fixed(self):
        # 存量误配单斜杠 /sentinelhost → 自动补双斜杠（治任务永卡 queued，且更新排除 config.yaml 无法靠改配置修）
        from sentinel_platform import celery_app as _m
        self.assertEqual(
            _m._normalize_broker_url("amqp://sentinel:pw@rabbitmq:5672/sentinelhost"),
            "amqp://sentinel:pw@rabbitmq:5672//sentinelhost")

    def test_broker_vhost_double_slash_untouched(self):
        # 已正确的双斜杠 / 默认根 vhost / 自定义 vhost / 空 vhost 一律不动，避免误伤
        from sentinel_platform import celery_app as _m
        for url in ("amqp://sentinel:pw@rabbitmq:5672//sentinelhost",
                    "amqp://guest:guest@127.0.0.1:5672//",
                    "amqp://u:p@h:5672/myvhost",
                    "amqp://u:p@h:5672/"):
            self.assertEqual(_m._normalize_broker_url(url), url)


class TestL2ResourceWatermark(unittest.TestCase):
    """L2 资源水位暂停/恢复（核心链路 §6.4）——防毛刺连续3tick、低优先先砍、高优先先恢复、relaxed也恢复。"""

    def setUp(self):
        scheduler._critical_streak = 0        # 每例重置模块级计数

    def tearDown(self):
        set_repo(None)
        scheduler._critical_streak = 0

    def _set_level(self, level):
        return mock.patch("sentinel_platform.modules.system.log_monitor.get_resource_level",
                          return_value=level)

    def test_anti_jitter_needs_3_consecutive(self):
        """防毛刺：连续 <3 tick critical 不暂停；第 3 个连续 critical 才动手。"""
        repo = _Repo(); set_repo(repo)
        repo.collection("intel_pentest_session").docs.extend([
            {"_id": "s1", "status": "running", "priority": 1},
            {"_id": "s2", "status": "running", "priority": 5},
        ])
        with self._set_level("critical"):
            self.assertEqual(scheduler._check_resource_l2()["paused"], 0)   # tick1
            self.assertEqual(scheduler._check_resource_l2()["paused"], 0)   # tick2
            self.assertEqual(scheduler._check_resource_l2()["paused"], 1)   # tick3 触发

    def test_jitter_resets_streak(self):
        """连续被打断：critical→critical→normal→critical 不触发（重置为连续计数）。"""
        repo = _Repo(); set_repo(repo)
        repo.collection("intel_pentest_session").docs.append(
            {"_id": "s1", "status": "running", "priority": 1})
        with self._set_level("critical"):
            scheduler._check_resource_l2(); scheduler._check_resource_l2()  # streak=2
        with self._set_level("normal"):
            scheduler._check_resource_l2()                                  # 打断→重置0
        with self._set_level("critical"):
            r = scheduler._check_resource_l2()                              # streak=1
        self.assertEqual(r["paused"], 0)   # 未累计到3

    def test_pause_lowest_priority_first(self):
        """低优先级先砍：running 中 priority 最低的先被暂停。"""
        repo = _Repo(); set_repo(repo)
        coll = repo.collection("intel_pentest_session")
        coll.docs.extend([
            {"_id": "hi", "status": "running", "priority": 9},
            {"_id": "lo", "status": "running", "priority": 1},
        ])
        scheduler._critical_streak = 2
        with self._set_level("critical"):
            scheduler._check_resource_l2()   # streak→3 触发暂停一个
        lo = coll.find_one({"_id": "lo"}); hi = coll.find_one({"_id": "hi"})
        self.assertEqual(lo["status"], "paused_resource")   # 低优先被砍
        self.assertEqual(hi["status"], "running")           # 高优先保留

    def test_resume_highest_priority_first_on_normal(self):
        """水位回 normal：高优先级先恢复（经 submit_session）。"""
        repo = _Repo(); set_repo(repo)
        coll = repo.collection("intel_pentest_session")
        coll.docs.extend([
            {"_id": "hi", "status": "paused_resource", "priority": 9},
            {"_id": "lo", "status": "paused_resource", "priority": 1},
        ])
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session",
                        return_value={"ok": True, "submitted": True}) as m:
            with self._set_level("normal"):
                scheduler._check_resource_l2()
        m.assert_called_once_with("hi", from_status="paused_resource")   # 高优先先恢复

    def test_resume_also_on_relaxed(self):
        """relaxed(<60%) 比 normal 更空闲，也应恢复（设计 §6.4 回落<80%）——修复的真 bug。"""
        repo = _Repo(); set_repo(repo)
        repo.collection("intel_pentest_session").docs.append(
            {"_id": "p1", "status": "paused_resource", "priority": 3})
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session",
                        return_value={"ok": True, "submitted": True}) as m:
            with self._set_level("relaxed"):
                scheduler._check_resource_l2()
        m.assert_called_once()   # relaxed 也触发恢复

    def test_tight_does_not_resume(self):
        """tight(80-90%) 仍有压力，不恢复（只重置计数）。"""
        repo = _Repo(); set_repo(repo)
        repo.collection("intel_pentest_session").docs.append(
            {"_id": "p1", "status": "paused_resource", "priority": 3})
        with mock.patch("sentinel_platform.modules.kernel.orchestration.submit_session") as m:
            with self._set_level("tight"):
                scheduler._check_resource_l2()
        m.assert_not_called()   # tight 不恢复

    def test_pause_no_running_no_crash(self):
        """running 全暂停后再触发暂停：返 0 不崩。"""
        repo = _Repo(); set_repo(repo)
        scheduler._critical_streak = 3
        with self._set_level("critical"):
            r = scheduler._check_resource_l2()   # 无 running 会话
        self.assertEqual(r["paused"], 0)


if __name__ == "__main__":
    unittest.main()
