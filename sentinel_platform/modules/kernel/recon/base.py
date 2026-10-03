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
import time
from sentinel_platform.core import process_control
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional


class ToolMissing(RuntimeError):
    """工具二进制未找到（未安装 / 路径配错）。"""


class ToolFailed(RuntimeError):
    """工具进程执行失败（非零退出且无有效输出 / 超时）。"""


class ToolCancelled(RuntimeError):
    """协作式取消：执行中 cancel_check 返回 True，子进程已被杀，中止本次执行。
    调用链（pipeline）应把它转成 stopped，不当失败。"""


#: 取消检查回调：返回 True 表示应立即中止（杀子进程）。base.run 每 _CANCEL_POLL 秒查一次。
_CANCEL_POLL = 1.0


class ExternalTool:
    """外部工具对接基类。子类只覆盖 binary / build_argv / parse_record。"""

    #: 子类覆盖：默认二进制名（PATH 解析用）
    binary: str = ""
    #: 子类覆盖：对接名（注册表键 / 日志标识）
    adapter: str = ""

    #: 是否内存重工具（子类覆盖）：True 才受资源门控（问题11）。默认 False——
    #: httpx/naabu/dnsx/subfinder 等 IO 密集工具不进内存池（只受 L1/L2 并发水位），
    #: 仅 nuclei/nmap/weakbrute 等真吃内存的置 True。
    resource_heavy: bool = False

    def __init__(self, binary_path: str = "", timeout: int = 1800):
        self._path = binary_path or ""
        self.timeout = timeout
        #: 实例级取消回调（pipeline 经 Tools 注入）；run() 未显式传 cancel_check 时用它。
        #: 使 subfinder.enumerate 等不改签名也能被协作式取消穿透中断。
        self.cancel_check: Optional[Callable[[], bool]] = None
        #: 资源门（pipeline 经 Tools 注入的纯 callable / None）；仅 resource_heavy=True 时生效。
        #: 内存重工具执行前经它申请内存额度、让位 AI（问题11）。
        self.resource_gate = None
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
    def run(self, stdin_lines: Optional[Iterable[str]] = None,
            cancel_check: Optional[Callable[[], bool]] = None,
            on_record: Optional[Callable[[Any], None]] = None, **kwargs: Any) -> List[Any]:
        """定位二进制→执行→逐行结构化。stdin_lines 为喂给工具的目标列表。

        cancel_check：可选取消回调（返回 True 即立即中止）。传入时用 Popen+轮询执行——
        每 ~1s 查一次，收到取消立即 kill 子进程树并抛 ToolCancelled（穿透阻塞的外部工具，
        根治「工具卡在网络里→协作式取消到不了阶段边界→任务停不掉」）。**不传时行为完全等价原
        subprocess.run（向后兼容，单测/无编排调用不变）。**"""
        argv = [self.locate()] + list(self.build_argv(**kwargs))
        stdin_data = None
        if stdin_lines is not None:
            stdin_data = "\n".join(str(x) for x in stdin_lines) + "\n"
        cc = cancel_check or self.cancel_check      # 显式传参优先，否则用实例级（Tools 注入）

        def _dispatch():
            if on_record is not None:
                return self._run_streaming(argv, stdin_data, cc, on_record)
            if cc is None:
                return self._run_blocking(argv, stdin_data)
            return self._run_cancellable(argv, stdin_data, cc)

        # 资源门（问题11）：仅内存重工具(resource_heavy)且注入了 gate 时，执行前申请内存、让位 AI。
        gate = getattr(self, "resource_gate", None)
        if self.resource_heavy and gate is not None:
            with gate("recon_" + (self.adapter or self.binary or "tool")) as h:
                if getattr(h, "degraded", False):
                    return []   # 资源等待超时 → 诚实降级跳过本次执行（返空，阶段照常继续）
                return _dispatch()
        return _dispatch()

    def _run_streaming(self, argv, stdin_data, cancel_check, on_record):
        """逐条交付 JSONL；临时文件隔离 stdin/stdout/stderr，避免大输入/输出 PIPE 死锁。

        stdout 写端与读端是独立 open 的文件描述符，读取不会移动子进程写入偏移。
        所有回调在调用线程执行；退出/超时/取消/回调异常均回收进程树与临时文件。
        """
        import tempfile
        records = []
        pending = b""
        proc = None
        deadline = time.monotonic() + self.timeout
        with tempfile.TemporaryDirectory(prefix="watchtower-stream-") as directory:
            input_path = os.path.join(directory, "input")
            output_path = os.path.join(directory, "output")
            error_path = os.path.join(directory, "error")
            with open(input_path, "wb") as stream:
                stream.write((stdin_data or "").encode("utf-8"))
            with open(input_path, "rb") as source, open(output_path, "wb") as output, open(error_path, "wb") as error:
                try:
                    if cancel_check and cancel_check():
                        raise ToolCancelled("外部工具 {} 启动前已取消".format(self.adapter))
                    proc = process_control.popen(argv, stdin=source, stdout=output, stderr=error, start_new_session=True)
                    with open(output_path, "rb") as reader:
                        while True:
                            if cancel_check and cancel_check():
                                raise ToolCancelled("外部工具 {} 被协作式取消".format(self.adapter))
                            if time.monotonic() > deadline:
                                raise ToolFailed("外部工具 {} 执行超时（{}s）".format(self.adapter, self.timeout))
                            ended = proc.poll() is not None
                            pending += reader.read()
                            lines = pending.split(b"\n")
                            pending = lines.pop()
                            if ended and pending:
                                lines.append(pending)
                                pending = b""
                            for line in lines:
                                for record in self.structure(line.decode("utf-8", "replace")):
                                    records.append(record)
                                    on_record(record)
                            if ended:
                                break
                            time.sleep(min(_CANCEL_POLL, 0.05))
                    if proc.returncode and not records:
                        with open(error_path, "rb") as stream:
                            message = stream.read(500).decode("utf-8", "replace")
                        raise ToolFailed("外部工具 {} 退出码 {}：{}".format(self.adapter, proc.returncode, message))
                    return records
                except FileNotFoundError as exc:
                    raise ToolMissing("外部工具 {} 无法执行".format(self.adapter)) from exc
                finally:
                    if proc is not None:
                        if proc.poll() is None:
                            self._kill_tree(proc)
                        proc.wait()
                        process_control.close(proc)

    def _run_blocking(self, argv: List[str], stdin_data: Optional[str]) -> List[Any]:
        """原阻塞执行（无 cancel_check 时；行为与历史一致）。"""
        try:
            proc = process_control.run(
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

    def _run_cancellable(self, argv: List[str], stdin_data: Optional[str],
                         cancel_check: Callable[[], bool]) -> List[Any]:
        """Popen + communicate(timeout) 轮询执行：期间查 cancel_check，收到取消 kill 进程树抛 ToolCancelled。
        **用 communicate 统一处理 stdin 写 + stdout/stderr 读**（内部线程避免 PIPE 缓冲区满死锁）——
        绝不手动分离 wait()+communicate()（会因 stdout PIPE 满阻塞 + 重复操作已关闭管道报
        'I/O operation on closed file'，这正是 dnsx/httpx 大输出下 resolve/site 阶段失败的根因）。
        communicate(timeout) 超时只抛 TimeoutExpired，**不损坏进程/管道状态**，可循环重试直到完成或取消。
        start_new_session=True 使子进程自成进程组，取消时连带杀 spawn 的孙进程（massdns 等）。"""
        try:
            proc = process_control.popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise ToolMissing("外部工具 {} 无法执行：{}".format(self.adapter, exc)) from exc
        # communicate（完整喂 stdin + 读全 stdout/stderr，内部线程防 PIPE 死锁）放独立线程跑，
        # 主线程轮询该线程是否完成 + 查 cancel/超时。这样既保证 stdin 完整喂入 + stdout 完整读出
        # （不因 PIPE 缓冲满而死锁/截断），又能中途取消。是"可中断 + 有大 stdin/stdout"的正确姿势。
        import threading
        box: Dict[str, Any] = {}

        def _do():
            try:
                box["out"], box["err"] = proc.communicate(input=stdin_data)
            except Exception as exc:                     # 进程被 kill 时 communicate 抛错，记下不外泄
                box["exc"] = exc

        worker = threading.Thread(target=_do, daemon=True)
        worker.start()
        deadline = time.time() + self.timeout
        while worker.is_alive():
            worker.join(timeout=_CANCEL_POLL)
            if not worker.is_alive():
                break
            if cancel_check():                           # 收到停止 → 杀进程树，communicate 线程随之结束
                self._kill_tree(proc)
                worker.join(timeout=5)
                raise ToolCancelled("外部工具 {} 被协作式取消（任务停止）".format(self.adapter))
            if time.time() > deadline:                   # subprocess 级兜底超时
                self._kill_tree(proc)
                worker.join(timeout=5)
                raise ToolFailed("外部工具 {} 执行超时（{}s）".format(self.adapter, self.timeout))
        process_control.close(proc)
        out = box.get("out") or ""
        err = box.get("err") or ""
        if proc.returncode not in (0, None) and not out.strip():
            raise ToolFailed("外部工具 {} 退出码 {}：{}".format(
                self.adapter, proc.returncode, (err or "")[:500]))
        return list(self.structure(out))

    @staticmethod
    def _kill_tree(proc: "subprocess.Popen") -> None:
        """杀子进程及其整个进程组（start_new_session 使 pid=pgid），连带 spawn 的孙进程。"""
        process_control.terminate_tree(proc)

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
