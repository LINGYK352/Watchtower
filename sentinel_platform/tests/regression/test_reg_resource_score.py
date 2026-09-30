"""回归⑥：资源运行可靠性评分 _resource_score（dashboard.py:115）。

事故史（CHANGELOG v1.21.157-37/38/39，记忆 feedback-fix-root-cause-not-remove-signal）：
- 旧线性算法 min(100-cpu%,100-mem%,100-disk%) 磁盘 77% 钉死总分恒 22「告急」，且误报"已收缩并发保命"。
- 第一版修复矫枉过正：直接把磁盘踢出评分 → 磁盘 77.5% 剩 5.9GB 还拿 93「充裕」（负优化：删信号维度）。
- 最终方案：需求导向 + 以水位系统为骨架（headline 档=get_resource_level，磁盘绝对余量只向下拉档）。

本套件是该函数唯一测试覆盖（此前零覆盖，正是我改坏 3 次没被拦住的根因）。
mock 靶点：patch sentinel_platform.contracts.get_registry（源模块，代码是函数内 from..import）+ os.getloadavg(create=True)。
"""
import unittest
from unittest import mock

_GB = 1024 ** 3


def _info(cpu_percent=15.0, mem_percent=20.0, disk_percent=40.0, free_gb=50.0, cpu_count=4):
    return {"cpu_count": cpu_count, "cpu_percent": cpu_percent, "memory_percent": mem_percent,
            "disk_percent": disk_percent, "disk_usage": {"free": int(free_gb * _GB)}}


class ResourceScoreRegression(unittest.TestCase):
    def _score(self, info, wl="normal", slots=4, load1=0.6):
        """注入水位档/slots/loadavg 后算分。patch contracts.get_registry 源模块。"""
        import sentinel_platform.contracts as C
        from sentinel_platform.modules.workspace.dashboard import DashboardServiceImpl
        svc = mock.Mock()
        svc.get_resource_budget.return_value = {"task_slots": slots, "level": wl}
        svc.get_resource_level.return_value = wl
        reg = mock.Mock(); reg.get.return_value = svc
        with mock.patch.object(C, "get_registry", return_value=reg):
            with mock.patch("os.getloadavg", create=True, return_value=(load1, load1, load1)):
                return DashboardServiceImpl()._resource_score(info)

    # —— 治恒 76（v1.21.157-46）：磁盘"够但不宽裕"(5.8GB) 不再双重钉死分数 ——
    def test_score_dynamic_with_cpu_when_disk_ok(self):
        """VM 实况(水位 relaxed + 磁盘 5.8GB/77.8% 够但不宽裕)：分数必须随 CPU 负载变化，
        不再被磁盘钉死恒 76。这是本次修复的核心断言（磁盘双重钉死 → 动态）。"""
        s_idle = self._score(_info(cpu_percent=10, mem_percent=25, disk_percent=77.8, free_gb=5.8),
                             wl="relaxed", slots=4, load1=0.3)["score"]
        s_busy = self._score(_info(cpu_percent=95, mem_percent=25, disk_percent=77.8, free_gb=5.8),
                             wl="relaxed", slots=4, load1=3.5)["score"]
        self.assertGreater(s_idle, s_busy, "CPU 空闲分应高于满载分(修复前恒 76 不动): idle={} busy={}".format(s_idle, s_busy))
        self.assertNotEqual(s_idle, 76, "空闲不该恰好是被钉死的 76")

    def test_disk_tight_reflected_in_total_not_ignored(self):
        """v1.21.157-50 重构：磁盘偏紧(5.8GB/77.8%，>3GB 未见底)**必须拉低总分**、不再被踢出评分。
        修复前 bug：磁盘维算出 ~58 且 disk_note 报"偏紧"，总分却恒 99「充裕」(headline 自相矛盾)。
        新算法三维加权 + 最弱维拖低 → 磁盘偏紧把 idle 机拉到「运行良好」区间(65~84)，disk 维真实反映在总分里。"""
        r = self._score(_info(cpu_percent=10, mem_percent=20, disk_percent=77.8, free_gb=5.8),
                        wl="relaxed", slots=4, load1=0.3)
        self.assertLess(r["score"], 85, "磁盘偏紧不该再是 99「充裕」: {}".format(r["score"]))
        self.assertGreaterEqual(r["score"], 65, "磁盘只是偏紧(未见底)不该跌破良好档")
        self.assertLess(r["dims"]["disk"], 70, "磁盘维应如实偏低")

    def test_score_moves_with_cpu_in_same_band(self):
        """核心诉求「实时动态」：同一水位/磁盘下，CPU 空闲 vs 满载总分必须有可感差异，
        不再被 relaxed 档地板 85 压成 99~100 的死区。"""
        idle = self._score(_info(cpu_percent=5, mem_percent=20, disk_percent=40, free_gb=50),
                           wl="relaxed", slots=5, load1=0.2)["score"]
        busy = self._score(_info(cpu_percent=95, mem_percent=20, disk_percent=40, free_gb=50),
                           wl="relaxed", slots=5, load1=3.6)["score"]
        self.assertGreater(idle - busy, 8, "CPU 空闲/满载总分差应可感(治死区): idle={} busy={}".format(idle, busy))

    # —— 红线：磁盘真见底(<3GB)仍必须拉低分数（守禁删信号维铁律，不因修恒76而忽略磁盘）——
    def test_disk_truly_low_still_pulls_down(self):
        """磁盘真见底：3GB内→偏紧、1.5GB内→告急。信号维度保留，不是删磁盘。"""
        s_50 = self._score(_info(disk_percent=30, free_gb=50), wl="relaxed", slots=5)["score"]
        s_25 = self._score(_info(disk_percent=92, free_gb=2.5), wl="relaxed", slots=4)["score"]
        s_1 = self._score(_info(disk_percent=97, free_gb=1), wl="relaxed", slots=4)["score"]
        self.assertTrue(s_50 > s_25 > s_1, "磁盘真见底越少分越低: {}".format((s_50, s_25, s_1)))
        self.assertGreaterEqual(s_50, 85)   # 磁盘充裕+资源空 → 充裕
        self.assertLess(s_25, 65)           # 剩 2.5GB(<3) → 拉到偏紧档
        self.assertLess(s_1, 40)            # 剩 1GB(<1.5) → 告急档

    # —— 以水位为骨架：headline 档必须跟随真实水位档 ——
    def test_waterlevel_critical_is_alarm_with_shrink_verdict(self):
        """水位 critical(0 slots 停投) → 必「资源告急」+ verdict 含"收缩并发保命"（严格绑真停投）。"""
        r = self._score(_info(mem_percent=93, disk_percent=40, free_gb=30), wl="critical", slots=0, load1=0.5)
        self.assertEqual(r["level_text"], "资源告急")
        self.assertIn("收缩并发保命", r["verdict"])

    def test_disk_absolute_only_pulls_down_not_up(self):
        """水位 normal 但磁盘只剩 1GB → 被磁盘绝对档拉到告急（磁盘只向下拉不向上抬）。"""
        r = self._score(_info(mem_percent=25, disk_percent=97, free_gb=1), wl="normal", slots=3, load1=0.5)
        self.assertEqual(r["level_text"], "资源告急")

    def test_slots_drive_memory_dimension(self):
        """task_slots 3/2/1/0 → memory 维 充裕/良好/偏紧/告急（对齐真实并发闸）。"""
        # 磁盘/CPU 恒充裕，只让 slots 变，观察 memory 维分档
        m3 = self._score(_info(free_gb=50), wl="relaxed", slots=3)["dims"]["memory"]
        m2 = self._score(_info(free_gb=50), wl="normal", slots=2)["dims"]["memory"]
        m1 = self._score(_info(free_gb=50), wl="tight", slots=1)["dims"]["memory"]
        m0 = self._score(_info(free_gb=50), wl="critical", slots=0)["dims"]["memory"]
        self.assertTrue(m3 >= 85 and m2 >= 65 and 30 <= m1 < 65 and m0 < 30,
                        "slots→memory 维分档异常: {}".format((m3, m2, m1, m0)))

    def test_disk_note_present_when_low(self):
        """磁盘偏紧时 disk_note 给「清理」提示（与"减负/并发保命"口径解耦）。"""
        r = self._score(_info(disk_percent=88, free_gb=6), wl="normal", slots=4)
        self.assertTrue(r["disk_note"], "磁盘偏满应有 disk_note 清理提示")
        self.assertIn("清理", r["disk_note"])

    def test_all_ample_is_excellent(self):
        """内存/CPU/磁盘全空 → 资源充裕、高并发。"""
        r = self._score(_info(cpu_percent=5, mem_percent=15, disk_percent=25, free_gb=100), wl="relaxed", slots=5)
        self.assertEqual(r["level_text"], "资源充裕")
        self.assertGreaterEqual(r["score"], 85)


if __name__ == "__main__":
    unittest.main()
