"""侦察工具注册表 —— 按角色注册对接，支持多候选降级。

角色 = 侦察能力语义（port_scan / http_probe / vuln_scan / weak_brute）。
recon_bridge 经此取工具，不硬绑具体实现——换工具只改注册、bridge 一行不动。
一个角色可注册多候选，pick() 返回第一个 available() 的（工具没装则降级为 None）。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# 角色常量
ROLE_PORT_SCAN = "port_scan"
ROLE_HTTP_PROBE = "http_probe"
ROLE_VULN_SCAN = "vuln_scan"
ROLE_WEAK_BRUTE = "weak_brute"
ROLE_RESOLVE = "dns_resolve"
ROLE_WEBINFO = "webinfo"
ROLE_CERT_FETCH = "cert_fetch"      # native TLS 证书抓取（certfetch）
ROLE_SERVICE_DETECT = "service_detect"  # nmap -sV 服务/版本识别，回填 naabu 端口（nmap_service）
ROLE_FILE_LEAK = "file_leak"        # native 文件/路径泄漏探测（fileleak）
ROLE_VHOST = "vhost"                 # native Host 头碰撞发现旁站（vhost）
ROLE_SCREENSHOT = "screenshot"       # phantomjs 站点截图（screenshot；依赖二进制，缺则 pick 降级）
ROLE_SERVICE_POC = "service_poc"     # npoc(xing CLI) 服务级 PoC/未授权验证（依赖 xing，缺则 pick 降级）
ROLE_ICMP_PING = "icmp_ping"         # native ICMP/TCP 主机存活探测（恒可用，无 NET_RAW 降级 TCP）


class ToolRegistry:
    def __init__(self) -> None:
        self._roles: Dict[str, List[Any]] = {}

    def register(self, role: str, tool: Any) -> None:
        self._roles.setdefault(role, []).append(tool)

    def pick(self, role: str) -> Optional[Any]:
        """取该角色第一个可用工具；都不可用返回 None（调用方降级）。"""
        for tool in self._roles.get(role, []):
            try:
                if tool.available():
                    return tool
            except Exception:
                continue
        return None

    def first(self, role: str) -> Optional[Any]:
        """取该角色第一个候选（不判可用性，用于单测/文档）。"""
        cands = self._roles.get(role, [])
        return cands[0] if cands else None

    def report(self) -> Dict[str, Dict[str, bool]]:
        """各角色下工具可用性，供健康检查。"""
        out: Dict[str, Dict[str, bool]] = {}
        for role, tools in self._roles.items():
            out[role] = {}
            for t in tools:
                name = getattr(t, "adapter", t.__class__.__name__)
                try:
                    out[role][name] = bool(t.available())
                except Exception:
                    out[role][name] = False
        return out


def build_registry(config: Any = None) -> ToolRegistry:
    """按配置装配默认工具。config 具 *_path / tool_timeout 属性，None 则从 PATH 解析。"""
    from .tools import Nuclei, Httpx, Naabu, WeakBrute, Dnsx, NmapService, Npoc
    from .webinfo import WebInfoHunter
    from .native.certfetch import CertFetcher
    from .native.fileleak import FileLeakScanner
    from .native.vhost import VhostFinder
    from .native.screenshot import Screenshot
    from .native.icmp import IcmpPing

    def _cfg(name: str, default: Any = "") -> Any:
        return getattr(config, name, default) if config is not None else default

    timeout = _cfg("tool_timeout", 1800)
    reg = ToolRegistry()
    reg.register(ROLE_PORT_SCAN, Naabu(_cfg("naabu_path"), timeout=timeout))
    reg.register(ROLE_HTTP_PROBE, Httpx(_cfg("httpx_path"), timeout=timeout))
    reg.register(ROLE_VULN_SCAN, Nuclei(_cfg("nuclei_path"), timeout=timeout))
    reg.register(ROLE_WEAK_BRUTE, WeakBrute(_cfg("nmap_path"), timeout=_cfg("brute_timeout", 300)))
    reg.register(ROLE_RESOLVE, Dnsx(_cfg("dnsx_path"), timeout=timeout))
    reg.register(ROLE_WEBINFO, WebInfoHunter())      # 纯 Python native，恒可用
    reg.register(ROLE_CERT_FETCH, CertFetcher(timeout=_cfg("cert_timeout", 5.0)))  # native 取证，恒可用
    reg.register(ROLE_SERVICE_DETECT, NmapService(_cfg("nmap_path"), timeout=_cfg("service_timeout", 600)))
    reg.register(ROLE_FILE_LEAK, FileLeakScanner(timeout=_cfg("fileleak_timeout", 8.0)))  # native 探测，恒可用
    reg.register(ROLE_VHOST, VhostFinder(timeout=_cfg("vhost_timeout", 8.0)))  # native Host 碰撞，恒可用
    reg.register(ROLE_SCREENSHOT, Screenshot(                                   # phantomjs 截图，缺二进制则 pick 降级
        phantomjs_path=_cfg("phantomjs_path"), image_dir=_cfg("image_dir"),
        timeout=_cfg("screenshot_timeout", 30)))
    reg.register(ROLE_SERVICE_POC, Npoc(_cfg("npoc_path"),                       # xing CLI 服务级 PoC，缺则 pick 降级
        timeout=_cfg("npoc_timeout", 600), concurrency=_cfg("npoc_concurrency", 8)))
    reg.register(ROLE_ICMP_PING, IcmpPing(timeout=_cfg("icmp_timeout", 2.0)))    # native 存活探测，恒可用（降级 TCP）
    return reg
