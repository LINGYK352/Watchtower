"""base.ExternalTool 协作式取消穿透测试 —— 修「任务停不掉」（工具卡阻塞→取消到不了阶段边界）。

核心验证：run(cancel_check=…) 用 Popen+轮询，收到取消立即杀子进程抛 ToolCancelled，不干等工具结束；
无 cancel_check 时走原阻塞路径（向后兼容）。真实杀进程树在 Linux（生产/VM）验证——本测试用
可跨平台的假 Popen 验证控制流（不依赖 os.killpg/start_new_session，Windows 亦可跑）。
"""
import sys
import unittest
from unittest import mock

from sentinel_platform.modules.kernel.recon.base import ExternalTool, ToolCancelled, ToolFailed


class _Tool(ExternalTool):
    binary = "faketool"
    adapter = "faketool"

    def build_argv(self, **kwargs):
        return []

    def parse_record(self, obj):
        return obj   # 直接返回，便于断言

    def structure(self, output):
        return [output]  # 简化：整块输出作一条记录


class _FakePopen:
    """假子进程：wait() 前若干次抛 TimeoutExpired（模拟仍在跑），之后正常结束。"""
    def __init__(self, stall_rounds=999, rc=0, out="OK", err=""):
        self.pid = 4242
        self._stall = stall_rounds
        self.returncode = None
        self._rc, self._out, self._err = rc, out, err
        self.killed = False
        self.stdin = mock.Mock()

    def communicate(self, input=None, timeout=None):
        # stall_rounds 大=模拟卡住的工具：communicate 阻塞直到被 kill（_killed 事件），模拟真实卡死。
        # stall_rounds 小=正常快速返回。新实现把 communicate 放线程跑，主线程 join 轮询 + cancel。
        import time as _t
        if self._stall >= 999:
            while not self.killed:                 # 卡住：等主线程 kill（取消/超时触发）
                _t.sleep(0.02)
            raise Exception("Process killed")      # 被杀后 communicate 抛错（真实行为）
        _t.sleep(0.01 * max(self._stall, 0))       # 正常：短暂后返回
        self.returncode = self._rc
        return self._out, self._err

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self.returncode = self.returncode if self.returncode is not None else self._rc
        return self.returncode


class TestCancelPassthrough(unittest.TestCase):
    def _patch_locate(self, tool):
        return mock.patch.object(tool, "locate", return_value="/usr/bin/faketool")

    def test_cancel_kills_process_and_raises(self):
        """cancel_check 返 True → 立即杀进程抛 ToolCancelled，不等工具跑完（核心修复）。"""
        tool = _Tool()
        fake = _FakePopen(stall_rounds=999)   # 永远"仍在跑"（模拟卡死工具）
        calls = {"n": 0}
        def cancel():
            calls["n"] += 1
            return calls["n"] >= 1            # 第一次轮询就要求取消
        with self._patch_locate(tool), \
             mock.patch("sentinel_platform.core.process_control.popen", return_value=fake), \
             mock.patch.object(ExternalTool, "_kill_tree") as kill_tree:
            with self.assertRaises(ToolCancelled):
                tool.run(stdin_lines=["a.com"], cancel_check=cancel)
        kill_tree.assert_called_once()        # 确实杀了进程树

    def test_instance_cancel_check_used_when_not_passed(self):
        """未显式传 cancel_check 时用实例级 self.cancel_check（Tools 注入路径）。"""
        tool = _Tool()
        tool.cancel_check = lambda: True      # 模拟 Tools 注入
        fake = _FakePopen(stall_rounds=999)
        with self._patch_locate(tool), \
             mock.patch("sentinel_platform.core.process_control.popen", return_value=fake), \
             mock.patch.object(ExternalTool, "_kill_tree"):
            with self.assertRaises(ToolCancelled):
                tool.run(stdin_lines=["a.com"])   # 不传 cancel_check，走 self.cancel_check

    def test_no_cancel_normal_finish(self):
        """cancel_check 一直 False → 工具正常跑完返回结果（不误杀）。"""
        tool = _Tool()
        fake = _FakePopen(stall_rounds=2, rc=0, out="RESULT")  # 卡 2 轮后正常结束
        with self._patch_locate(tool), \
             mock.patch("sentinel_platform.core.process_control.popen", return_value=fake):
            out = tool.run(stdin_lines=["a.com"], cancel_check=lambda: False)
        self.assertEqual(out, ["RESULT"])

    def test_no_cancel_check_uses_blocking_path(self):
        """完全不传 cancel_check 且实例无 → 走原 subprocess.run 阻塞路径（向后兼容）。"""
        tool = _Tool()
        completed = mock.Mock(returncode=0, stdout="BLOCK", stderr="")
        with self._patch_locate(tool), \
             mock.patch("sentinel_platform.core.process_control.run", return_value=completed) as srun:
            out = tool.run(stdin_lines=["a.com"])
        srun.assert_called_once()             # 确认走的是阻塞 subprocess.run
        self.assertEqual(out, ["BLOCK"])


if __name__ == "__main__":
    unittest.main()
