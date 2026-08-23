"""npoc 服务级 PoC / 未授权验证对接 —— external/npoc（ARL-NPoC 的 xing CLI）驱动。

填补 `recon_bridge.run_poc` 契约缺口：RECON 契约 `run_poc(plugins, targets)` 本应跑「指定 PoC
插件」验证目标，旧实现却只转 nuclei_scan（丢弃 plugins）。npoc 提供 nuclei 覆盖不到的**服务级
PoC / 未授权访问 / 特定组件验证**（Redis/MongoDB/Solr/Nacos 等未授权、各类 noauth 插件）。

npoc 是独立 CLI（`xing`，源码项目 `external/npoc`，`pip install -e` 后暴露 console_scripts），
**subprocess arm's-length 调用，不 import 进平台包**（守接入铁律 + LAYOUT「npoc CLI 调用不 import」）。
本文件即 npoc 的对接模块（防腐层）：调用 xing + 解析其输出 + 结构化成 `VulnRec`（对齐 vuln 集合）。

两能力：
  - `list_plugins(plugin_type)`：`xing list` 枚举插件（解 poc.py sync「待 recon_bridge 接 npoc」降级）。
  - `run_poc(plugins, targets)`：`xing scan -n <plugin> -t <targets>` 跑验证，读 JSONL 结果 → VulnRec。

xing scan 把结果写 `Conf.SAVE_JSON_RESULT_FILENAME`（默认 cwd 相对 `npoc_result_json.txt`，JSONL），
每行 `{plg_name,plg_type,vul_name,app_name,target,verify_data}` —— 精确对齐 `VulnRec`。故用独立
临时 cwd 运行、读回该文件即结构化（append 模式，独立临时目录避免脏数据）。

缺 `xing`（未 `pip install -e external/npoc`）→ `available()`=False → registry.pick 取不到 → 降级。
**subprocess 调 xing 不 import npoc → 我方无新库要 vendor**（npoc 自身 deps 属其部署侧 pip install）。
参照旧 app/services/npoc.py 的 run_risk_cruising 逻辑净室重写（改 in-process import 为 CLI，字段对齐属数据契约）。
只依赖 core + stdlib(shutil/subprocess/tempfile/json/re/os)，无第三方库。**禁硬限制参数**：plugins/targets 不砍。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from ..models import VulnRec

# registry 角色常量（服务级 PoC 验证）
ROLE_SERVICE_POC = "service_poc"

# xing list 行格式：`[N][type] name | vul_name`（poc/brute） 或 `[N][type-scheme] name`（sniffer）
_LIST_RE = re.compile(r"^\[\d+\]\[([\w\-]+)(?:-[\w]+)?\]\s*([^\s|]+)\s*(?:\|\s*(.*))?$")


class Npoc:
    """ARL-NPoC (xing CLI) 对接。list_plugins() 枚举 + run_poc(plugins, targets) 验证。"""

    adapter = "npoc"

    def __init__(self, binary_path: str = "", timeout: int = 600, concurrency: int = 8):
        self._path = binary_path or ""
        self.timeout = timeout
        self.concurrency = max(1, int(concurrency))     # 下限保护；非上限（不砍 targets）

    def locate(self) -> str:
        """解析 xing 可执行路径：显式路径 > PATH。找不到返 ""。"""
        if self._path:
            return shutil.which(self._path) or (self._path if os.path.isfile(self._path) else "")
        return shutil.which("xing") or ""

    def available(self) -> bool:
        return bool(self.locate())

    # —— 插件枚举（xing list）——————————————————————
    def list_plugins(self, plugin_type: str = "") -> List[Dict[str, str]]:
        """`xing list [-t type]` 枚举插件，解析 stdout → [{plugin_name, plugin_type, vul_name}]。

        plugin_type 可选 poc/sniffer/listener（缺省全部）。工具缺失/失败 → []（降级不抛）。
        """
        binary = self.locate()
        if not binary:
            return []
        argv = [binary, "list", "-n", "*"]
        if plugin_type:
            argv += ["-t", plugin_type]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.timeout, encoding="utf-8", errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []
        return self.parse_list(proc.stdout or "")

    @staticmethod
    def parse_list(text: str) -> List[Dict[str, str]]:
        """解析 xing list 的 stdout 文本（每行 `[N][type] name | vul`）→ 插件信息列表。"""
        out: List[Dict[str, str]] = []
        seen = set()
        for line in (text or "").splitlines():
            line = line.strip()
            m = _LIST_RE.match(line)
            if not m:
                continue
            ptype, name, vul = m.group(1), m.group(2), (m.group(3) or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            out.append({"plugin_name": name, "plugin_type": ptype, "vul_name": vul})
        return out

    # —— PoC 验证（xing scan）————————————————————————
    def run_poc(self, plugins: Any = None, targets: Any = None,
                proxy: str = "", **kwargs: Any) -> List[VulnRec]:
        """对 targets 跑指定 plugins 的 PoC 验证 → List[VulnRec]。

        plugins: 插件名列表（空/None → 全部插件 `*`）；targets: 目标 URL/host:port 列表。
        每个插件一次 `xing scan -n <plugin> -t <targets_file>`，结果 append 到独立临时 cwd 的
        JSONL，跑完统一读回。**禁硬限制**：plugins/targets 数量不砍。工具缺失/无目标 → []（降级）。
        """
        binary = self.locate()
        tgts = [str(t).strip() for t in _as_list(targets) if t and str(t).strip()]
        if not binary or not tgts:
            return []
        plugin_names = [str(p).strip() for p in _as_list(plugins) if p and str(p).strip()]
        # 空 → 全部插件（glob *）；否则逐插件精确跑
        patterns = plugin_names or ["*"]

        results: List[VulnRec] = []
        with tempfile.TemporaryDirectory(prefix="npoc_") as work:
            tgt_file = os.path.join(work, "targets.txt")
            try:
                with open(tgt_file, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(tgts))
            except OSError:
                return []
            result_file = os.path.join(work, "npoc_result_json.txt")  # xing 默认 cwd 相对名
            for pat in patterns:
                argv = [binary, "scan", "-n", pat, "-t", tgt_file,
                        "-c", str(self.concurrency)]
                if proxy:
                    argv += ["-x", proxy]
                try:
                    # cwd=work 让 xing 的默认相对结果文件落到临时目录
                    subprocess.run(argv, capture_output=True, text=True, cwd=work,
                                   timeout=self.timeout, encoding="utf-8", errors="replace")
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    continue
            results = self.parse_results(result_file)
        return results

    @staticmethod
    def parse_results(result_file: str) -> List[VulnRec]:
        """读 xing scan 的 JSONL 结果文件 → List[VulnRec]（对齐 vuln 集合 PoC 结构）。"""
        out: List[VulnRec] = []
        if not result_file or not os.path.isfile(result_file):
            return out
        try:
            with open(result_file, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return out
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(item, dict):
                continue
            verify = item.get("verify_data")
            if not isinstance(verify, str):
                verify = json.dumps(verify, ensure_ascii=False) if verify else ""
            out.append(VulnRec(
                target=str(item.get("target") or ""),
                vul_name=str(item.get("vul_name") or ""),
                plg_name=str(item.get("plg_name") or ""),
                plg_type=str(item.get("plg_type") or "poc"),
                app_name=str(item.get("app_name") or ""),
                verify_data=verify,
            ))
        return out


def _as_list(v: Any) -> List[Any]:
    """归一成 list：None→[]，标量→[标量]，list/tuple→list。"""
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    return [v]

