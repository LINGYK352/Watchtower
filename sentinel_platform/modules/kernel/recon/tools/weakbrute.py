"""弱口令 / 未授权对接 —— 基于Nmap NSE，使用与再分发须按其实际版本许可处理。

对已识别的非 Web 服务（SSH/FTP/MySQL/Redis/MongoDB 等）跑对应 *-brute NSE + 未授权
检测（redis-info/mongodb-info）。命中 → VulnRec(plg_type=brute/poc)。

授权渗透用途：内置小而精弱口令表（可注入），默认 firstonly 资源可控，不自行全表轰炸。
注：非 JSONL 工具，输出为 nmap 文本，故自实现 run，不走 base.structure 的 JSON 逐行解析。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional

from ..models import VulnRec

# scheme -> (NSE 脚本, 是否未授权检测类)
_NSE = {
    "ssh": ("ssh-brute", False), "ftp": ("ftp-brute", False),
    "mysql": ("mysql-brute", False), "postgresql": ("pgsql-brute", False),
    "redis": ("redis-info", True), "mongodb": ("mongodb-info", True),
    "telnet": ("telnet-brute", False), "vnc": ("vnc-brute", False),
    "pop3": ("pop3-brute", False), "imap": ("imap-brute", False),
    "smtp": ("smtp-brute", False), "smb": ("smb-brute", False),
    "microsoft-ds": ("smb-brute", False), "rdp": ("rdp-brute", False),
    "ms-wbt-server": ("rdp-brute", False),
}
_USERS = ["root", "admin", "test", "administrator", "guest", "oracle", "mysql"]
_PASSES = ["123456", "password", "admin", "root", "123456789", "12345678",
           "111111", "admin123", "root123", "test", ""]


class WeakBrute:
    adapter = "nmap_weakbrute"

    def __init__(self, binary_path: str = "", timeout: int = 300,
                 users: Optional[List[str]] = None, passwords: Optional[List[str]] = None):
        self._path = binary_path or ""
        self.timeout = timeout
        self.users = users or _USERS
        self.passwords = passwords or _PASSES
        #: 资源门（pipeline 经 Tools 注入 / None）：NSE 爆破吃内存 → 执行前申请、让位 AI（问题11）。
        self.resource_gate = None
        #: 取消回调（Tools 注入 / None）。
        self.cancel_check = None

    def locate(self) -> str:
        if self._path:
            return shutil.which(self._path) or self._path
        return shutil.which("nmap") or ""

    def available(self) -> bool:
        return bool(self.locate())

    def brute(self, host: str, port: int, scheme: str) -> List[VulnRec]:
        binary = self.locate()
        entry = _NSE.get(scheme.lower())
        if not binary or not entry:
            return []
        script, is_unauth = entry
        tmp = tempfile.mkdtemp(prefix="wb_")
        try:
            argv = [binary, "-Pn", "-p", str(port), "--script", script,
                    "--host-timeout", "{}s".format(self.timeout)]
            if not is_unauth:
                udb, pdb = os.path.join(tmp, "u.lst"), os.path.join(tmp, "p.lst")
                with open(udb, "w") as f:
                    f.write("\n".join(self.users) + "\n")
                with open(pdb, "w") as f:
                    f.write("\n".join(self.passwords) + "\n")
                argv += ["--script-args",
                         "userdb={},passdb={},brute.firstonly=true".format(udb, pdb)]
            argv.append(host)

            def _run():
                try:
                    proc = subprocess.run(argv, capture_output=True, text=True,
                                          timeout=self.timeout + 30, encoding="utf-8", errors="replace")
                except subprocess.TimeoutExpired:
                    return []
                return self.parse_output(proc.stdout or "", host, port, scheme, script)

            # 资源门（问题11）：注入了 gate 则申请内存、让位 AI；超时诚实降级返 []。
            gate = getattr(self, "resource_gate", None)
            if gate is not None:
                with gate("recon_weakbrute") as h:
                    if getattr(h, "degraded", False):
                        return []
                    return _run()
            return _run()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @staticmethod
    def parse_output(output: str, host: str, port: int, scheme: str, script: str) -> List[VulnRec]:
        out: List[VulnRec] = []
        target = "{}://{}:{}".format(scheme, host, port)
        creds = re.findall(r"([^\s:]+):([^\s]+)\s*-\s*Valid credentials", output)
        if not creds:
            creds = re.findall(r"Account:\s*([^\s]+)\s+Password:\s*([^\s]+)", output)
        for user, pwd in creds:
            out.append(VulnRec(
                target=target, vul_name="{} 服务弱口令".format(scheme.upper()),
                plg_name="{}_weak_password".format(scheme), plg_type="brute",
                app_name=scheme, verify_data="{}:{}".format(user, pwd)))
        if script.endswith("-info") and re.search(r"redis-info|mongodb-info|Server version|db_version", output):
            low = output.lower()
            if "requirepass" not in low and "authentication" not in low:
                out.append(VulnRec(
                    target=target, vul_name="{} 未授权访问".format(scheme.upper()),
                    plg_name="{}_unauth".format(scheme), plg_type="poc",
                    app_name=scheme, verify_data=target))
        return out
