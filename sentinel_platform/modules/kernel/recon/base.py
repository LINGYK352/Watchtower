"""外部侦察工具对接底座 —— ExternalTool（防腐层的核心执行器）。

瞭望塔接入铁律（见 云端/docs/LAYOUT.md「接入铁律」）：external/ 里的工具是"生料"，
绝不裸调、绝不让原始输出直接进内核。每个工具经一个对接子类完成三件事：
  ①调用   build_argv() 拼命令行（子类实现「怎么调」）
  ②解析   parse_record() 把一行原始输出转成结构化记录（子类实现「一行怎么转」）
  ③结构化 run() 统一执行 + 收集结构化记录，只把标准 dataclass 交出去

设计要点：
- 执行(run)与解析(parse_record)分离——单测只测 parse_record，不需真装工具。
- 二进制定位：显式路径优先，否则从 PATH 解析；缺失明确报错 ToolMissing，不静默。
- 只认结构化输出：非法/杂行跳过，异常态经受检异常表达，不拖垮调用方。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, Iterable, Iterator, List, Optional


class ToolMissing(RuntimeError):
    """工具二进制未找到（未安装 / 路径配错）。"""


class ToolFailed(RuntimeError):
    """工具进程执行失败（非零退出且无有效输出 / 超时）。"""


class ExternalTool:
    """外部工具对接基类。子类只覆盖 binary / build_argv / parse_record。"""

    #: 子类覆盖：默认二进制名（PATH 解析用）
    binary: str = ""
    #: 子类覆盖：对接名（注册表键 / 日志标识）
    adapter: str = ""

    def __init__(self, binary_path: str = "", timeout: int = 1800):
        self._path = binary_path or ""
        self.timeout = timeout
        if not self.adapter:
            self.adapter = self.binary

    # —— 二进制定位 ————————————————————————————————
    def locate(self) -> str:
        """解析可执行路径：显式路径 > PATH > external/bin/。找不到抛 ToolMissing。"""
        if self._path:
            resolved = shutil.which(self._path) or (self._path if os.path.isfile(self._path) else "")
            if resolved:
                return resolved
            raise ToolMissing("外部工具显式路径不存在: {}".format(self._path))
        found = shutil.which(self.binary)
        if found:
            return found
        # 回退：搜索 external/bin/（Docker 热更新后工具在此，不在 PATH）
        ext_bin = self._find_in_external_bin()
        if ext_bin:
            return ext_bin
        raise ToolMissing(
            "外部工具 '{}' 未找到：PATH 无此命令，也未配置显式路径。".format(self.binary))

    def _find_in_external_bin(self) -> str:
        """在 external/bin/ 目录查找工具（相对于项目根）。"""
        # 从当前文件上溯找项目根（有 sentinel_platform/ 和 external/ 的目录）
        base = os.path.dirname(os.path.abspath(__file__))
        for _ in range(8):
            candidate = os.path.join(base, "external", "bin", self.binary)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            parent = os.path.dirname(base)
            if parent == base:
                break
            base = parent
        return ""

    def available(self) -> bool:
        """工具是否可用（供降级判断，不抛异常）。"""
        try:
            self.locate()
            return True
        except ToolMissing:
            return False

    # —— 子类实现 ————————————————————————————————
    def build_argv(self, **kwargs: Any) -> List[str]:
        """返回不含二进制路径的参数列表（run 会在头部补真实路径）。"""
        raise NotImplementedError

    def parse_record(self, obj: Dict[str, Any]) -> Optional[Any]:
        """把一行解析后的 JSON dict 转成结构化记录；无效返回 None。"""
        raise NotImplementedError

    # —— 执行 ————————————————————————————————————
    def run(self, stdin_lines: Optional[Iterable[str]] = None, **kwargs: Any) -> List[Any]:
        """定位二进制→执行→逐行结构化。stdin_lines 为喂给工具的目标列表。"""
        argv = [self.locate()] + list(self.build_argv(**kwargs))
        stdin_data = None
        if stdin_lines is not None:
            stdin_data = "\n".join(str(x) for x in stdin_lines) + "\n"
        try:
            proc = subprocess.run(
                argv, input=stdin_data, capture_output=True, text=True,
                timeout=self.timeout, encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolFailed("外部工具 {} 执行超时（{}s）".format(self.adapter, self.timeout)) from exc
        except FileNotFoundError as exc:
            raise ToolMissing("外部工具 {} 无法执行：{}".format(self.adapter, exc)) from exc

        if proc.returncode != 0 and not (proc.stdout or "").strip():
            raise ToolFailed("外部工具 {} 退出码 {}：{}".format(
                self.adapter, proc.returncode, (proc.stderr or "")[:500]))
        return list(self.structure(proc.stdout or ""))

    def structure(self, output: str) -> Iterator[Any]:
        """逐行 JSON 解析 + 结构化。杂行/非 dict/None 跳过——只放行干净记录。"""
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(obj, dict):
                continue
            rec = self.parse_record(obj)
            if rec is not None:
                yield rec
