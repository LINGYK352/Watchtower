"""system/_mihomo —— mihomo 代理内核进程管理（proxy 叶子同类别私有辅助）。

净室重写 app/services/proxy_core.py（读旧逻辑理解流程/踩坑，不抄源码）的**进程生命周期部分**：
mihomo 子进程启停/自愈 + profile(机场订阅档) CRUD + 运行时 config 生成 + controller 节点操作 +
流量账本（proxy.py 主叶子已有的 config/health/resolve_egress 不在此重复）。

**保留的关键踩坑（不可删）**：
  - `_strip_geo_deps`：订阅常带 GeoIP MMDB/rule-providers 需联网下载，服务器连不上 github → mihomo
    启动即 fatal 崩。去 geodata 自动下载 + global 模式 + 清 rules 绕远程依赖。
  - **禁 TUN**：订阅常带 tun.enable=true 会创建虚拟网卡劫持整机流量（与 SSH/系统代理冲突、
    把 pip 等国内流量导向境外节点中断）。代理中心只应通过 HTTP/SOCKS 端口代理扫描流量，绝不接管整机网络。
  - auto_select **默认全节点参与优选，不硬编码地区**（旧 ARL 硬编码只选 HK/MO/TW 是其作者环境假设，
    很多用户用美/日/新等节点会被全排除→"无可用节点"，净室重写根治此硬编码病）。地区偏好可选配置
    `node_region_prefixes`（默认空=不限）。流量账本跨核心重启增量累计不回退；节点验活用真实流量非只测延迟。

只依赖 core（get_repo/get_config/get_logger）+ yaml（vendor 有 cp38 whl）+ requests（controller 本地调）+ stdlib。
自包含读 PROXY_CONFIG 集合（不 import 主叶子 proxy.py，避免循环）。禁硬限制参数。
"""
from __future__ import annotations

import os
import time
import signal
import socket
import ipaddress
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sentinel_platform.core import get_repo, get_config as _pcfg, get_logger
from sentinel_platform.contracts import Collections

logger = get_logger()

# —— 运行时路径（shared/proxy_runtime/，环境变量可覆盖；对齐 ai_extension shared 范式）——
def _project_root() -> str:
    # 从 modules/system/_mihomo.py 上溯 4 层到项目根（sentinel_platform 的父目录）
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _runtime_dir() -> str:
    configured = os.environ.get("SENTINEL_PROXY_RUNTIME_DIR", "")
    return os.path.abspath(configured or os.path.join(_project_root(), "shared", "proxy_runtime"))


def _mihomo_bin() -> str:
    configured = os.environ.get("SENTINEL_MIHOMO_BIN", "")
    return configured or os.path.join(_project_root(), "external", "mihomo", "mihomo-linux-amd64")


def _mihomo_host() -> str:
    """mihomo 服务地址。**容器模式**（compose 设 MIHOMO_HOST=mihomo）：mihomo 是独立容器，
    平台经服务名访问它的 http/controller 端口（不再本进程 spawn）。**本地模式**（未设）：回退
    127.0.0.1 + 平台自 spawn 子进程（兼容非 compose 开发/单机）。见 待办-mihomo独立容器方案.md。"""
    return (os.environ.get("MIHOMO_HOST", "") or "").strip() or "127.0.0.1"


def _is_container_mode() -> bool:
    """mihomo 独立容器模式：MIHOMO_HOST 显式设了非 127.0.0.1 的值（即指向 mihomo 容器）。
    此模式下平台不 spawn/kill mihomo 进程，改为 controller reload + 探活；生命周期交 compose。"""
    return bool((os.environ.get("MIHOMO_HOST", "") or "").strip())


def _paths() -> Dict[str, str]:
    rt = _runtime_dir()
    return {"runtime": rt, "profiles": os.path.join(rt, "profiles"),
            "logs": os.path.join(rt, "logs"), "config": os.path.join(rt, "config.yaml"),
            "pid": os.path.join(rt, "mihomo.pid"), "log": os.path.join(rt, "logs", "mihomo.log")}


def ensure_dirs() -> None:
    p = _paths()
    for d in (p["runtime"], p["profiles"], p["logs"]):
        os.makedirs(d, exist_ok=True)


MAX_PROFILE_SIZE = 2 * 1024 * 1024
MAX_LOG_LINES = 500
# 订阅拉取重试（境外订阅站网络波动自愈；间歇失败重试非缓存）
_PROFILE_FETCH_RETRY = 3
_PROFILE_FETCH_BACKOFF = 1.5
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"


def _region_prefixes() -> tuple:
    """节点地区偏好前缀（可选）。默认空=全节点参与优选，不硬编码地区（禁硬编码目标知识）。
    配置 PROXY_CONFIG.node_region_prefixes（列表/逗号串，如 ['HK','US']）时才按前缀过滤。"""
    raw = _cfg().get("node_region_prefixes") or []
    if isinstance(raw, str):
        raw = [x.strip() for x in raw.replace(",", " ").split() if x.strip()]
    return tuple(raw) if raw else ()
_FORBIDDEN_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10")]


def _cfg() -> Dict[str, Any]:
    """自包含读代理配置（与主叶子 proxy.get_config 读同一集合，数据契约一致，不形成 import 循环）。"""
    try:
        doc = get_repo().collection(Collections.PROXY_CONFIG).find_one({"name": "default"})
        if doc:
            doc["_id"] = str(doc.get("_id", ""))
            return doc
    except Exception as exc:
        logger.debug("_mihomo read config degraded: %s", exc)
    # 兜底内存默认（端口对齐 proxy.default_config）
    return {"enabled": False, "http_port": 17890, "socks_port": 17891, "mixed_port": 17892,
            "controller_host": "127.0.0.1", "controller_port": 19090, "mode": "rule",
            "secret": "", "active_profile_id": "", "test_url": DEFAULT_TEST_URL}


def _oid(v: Any) -> Any:
    if not v:
        return v
    try:
        from bson import ObjectId
        return ObjectId(v)
    except Exception:
        return v


def _is_forbidden_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(ip_obj in net for net in _FORBIDDEN_NETS)


def validate_subscription_url(url: str):
    """订阅 URL SSRF 防护：只允许 http/https、拒内网/环回、拒 userinfo。返回 parsed 或抛 ValueError。"""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("只允许 http/https 订阅 URL")
    if not parsed.hostname:
        raise ValueError("订阅 URL host 为空")
    if parsed.username or parsed.password:
        raise ValueError("订阅 URL 不得含 userinfo")
    try:
        ipaddress.ip_address(parsed.hostname)
        ips = [parsed.hostname]
    except ValueError:
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            ips = list({item[-1][0] for item in socket.getaddrinfo(parsed.hostname, port)})
        except socket.gaierror:
            raise ValueError("订阅 URL host 解析失败")
    if any(_is_forbidden_ip(ip) for ip in ips):
        raise ValueError("订阅 URL 解析到内网地址（SSRF 防护拒绝）")
    return parsed


# ============================ profile（机场订阅档）CRUD ============================

def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _looks_base64_sub(text: str) -> bool:
    """疑似 base64 v2ray 订阅：整体是 base64 字符集、无 YAML 结构特征（无冒号缩进/proxies）。"""
    t = "".join(text.split())
    if not t or "proxies:" in text or "\n" in text.strip() and ":" in text:
        # 有 YAML 结构特征就不当 base64
        if "proxies:" in text or "proxy-groups:" in text or "\nport:" in text:
            return False
    import re as _re
    return bool(t) and len(t) > 24 and _re.fullmatch(r"[A-Za-z0-9+/=_\-]+", t) is not None


def _b64_sub_to_proxies(text: str) -> list:
    """base64 v2ray 订阅 → Clash proxies 列表。解码出 vmess:///vless:///trojan:///ss:// 节点行，
    逐行转成 Clash proxy dict。无法识别的行跳过。仅覆盖常见协议，够导入用。"""
    import base64 as _b64, json as _json, re as _re
    from urllib.parse import urlparse, unquote, parse_qs
    t = "".join(text.split())
    pad = "=" * (-len(t) % 4)
    try:
        decoded = _b64.urlsafe_b64decode(t + pad).decode("utf-8", "replace")
    except Exception:
        try:
            decoded = _b64.b64decode(t + pad).decode("utf-8", "replace")
        except Exception:
            return []
    proxies = []
    for line in decoded.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("vmess://"):
                body = line[8:]
                body += "=" * (-len(body) % 4)
                info = _json.loads(_b64.b64decode(body).decode("utf-8", "replace"))
                p = {"name": info.get("ps") or info.get("add", "vmess"), "type": "vmess",
                     "server": info.get("add", ""), "port": int(info.get("port", 0) or 0),
                     "uuid": info.get("id", ""), "alterId": int(info.get("aid", 0) or 0),
                     "cipher": info.get("scy", "auto") or "auto", "udp": True}
                net = info.get("net")
                if net and net != "tcp":
                    p["network"] = net
                if info.get("tls") == "tls":
                    p["tls"] = True
                if p["server"] and p["port"]:
                    proxies.append(p)
            elif line.startswith("trojan://"):
                u = urlparse(line)
                if u.hostname and u.port:
                    q = parse_qs(u.query)
                    proxies.append({"name": unquote(u.fragment) or u.hostname, "type": "trojan",
                                    "server": u.hostname, "port": int(u.port),
                                    "password": unquote(u.username or ""), "udp": True,
                                    "sni": (q.get("sni") or q.get("peer") or [""])[0]})
            elif line.startswith("vless://"):
                u = urlparse(line)
                if u.hostname and u.port:
                    q = parse_qs(u.query)
                    p = {"name": unquote(u.fragment) or u.hostname, "type": "vless",
                         "server": u.hostname, "port": int(u.port),
                         "uuid": unquote(u.username or ""), "udp": True,
                         "network": (q.get("type") or ["tcp"])[0]}
                    if (q.get("security") or [""])[0] in ("tls", "reality"):
                        p["tls"] = True
                    proxies.append(p)
            elif line.startswith("ss://"):
                body = line[5:]
                frag = ""
                if "#" in body:
                    body, frag = body.split("#", 1)
                if "@" in body:
                    creds, hostport = body.rsplit("@", 1)
                    creds += "=" * (-len(creds) % 4)
                    method, _, pwd = _b64.b64decode(creds).decode("utf-8", "replace").partition(":")
                else:
                    body += "=" * (-len(body) % 4)
                    dec = _b64.b64decode(body).decode("utf-8", "replace")
                    methpwd, _, hostport = dec.rpartition("@")
                    method, _, pwd = methpwd.partition(":")
                host, _, port = hostport.partition(":")
                if host and port:
                    proxies.append({"name": unquote(frag) or host, "type": "ss",
                                    "server": host, "port": int(_re.sub(r"\D", "", port) or 0),
                                    "cipher": method, "password": pwd, "udp": True})
        except Exception:
            continue
    return proxies


def validate_profile_content(content):
    """校验 profile 内容 → (data, text)。支持两种订阅（BUG-002）：
    ① Clash/Mihomo YAML（含 proxies）；② base64 v2ray 订阅——解码转成 Clash proxies 组装成 YAML。"""
    import yaml
    if isinstance(content, str):
        raw, text = content.encode("utf-8"), content
    else:
        raw, text = content, content.decode("utf-8", errors="replace")
    if len(raw) > MAX_PROFILE_SIZE:
        raise ValueError("profile 过大（>2MB）")
    # 先试 YAML（Clash 正常路径）
    try:
        data = yaml.safe_load(text)
    except Exception:
        data = None
    if isinstance(data, dict) and (data.get("proxies") or data.get("proxy-providers")):
        return data, text
    # 非 Clash YAML：尝试 base64 v2ray 订阅解码
    if _looks_base64_sub(text):
        proxies = _b64_sub_to_proxies(text)
        if proxies:
            data = {"proxies": proxies,
                    "proxy-groups": [{"name": "PROXY", "type": "select",
                                      "proxies": [p["name"] for p in proxies]}],
                    "rules": ["MATCH,PROXY"]}
            return data, yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
        raise ValueError("base64 订阅解码后无可用节点（协议不支持或格式异常）")
    if not isinstance(data, dict):
        raise ValueError("非法 YAML profile（既非 Clash YAML，也非可解码的 base64 订阅）")
    return data, text


def import_profile_content(name: str, content, source: str = "upload") -> Dict[str, Any]:
    """导入 profile 内容：存 proxy_profiles 集合 + 落盘 profiles/<id>.yaml。返回 profile dict。"""
    ensure_dirs()
    data, text = validate_profile_content(content)
    item = {"name": name or "profile-{}".format(int(time.time())), "source": source,
            "created_at": _now_str(), "updated_at": _now_str(),
            "proxy_count": len(data.get("proxies", []) or []),
            "group_count": len(data.get("proxy-groups", []) or [])}
    coll = get_repo().collection(Collections.PROXY_PROFILES)
    res = coll.insert_one(item)
    pid = str(getattr(res, "inserted_id", item.get("_id", "")))
    path = os.path.join(_paths()["profiles"], "{}.yaml".format(pid))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    coll.update_one({"_id": _oid(pid)}, {"$set": {"path": path}})
    return get_profile(pid)


def import_profile_url(url: str, name: str = "") -> Dict[str, Any]:
    """从订阅 URL 拉取 profile（SSRF 校验 + 流式限大小）。
    BUG-002：带 Clash 系 User-Agent——多数机场按 UA 分流，Clash UA 才返回 Clash YAML，
    否则返回 base64 v2ray 节点串（由 validate_profile_content 兜底解码）。

    **trust_env=False 铁律（代理出口规范.md §二轨5 / 项目说明 §7.4）**：mihomo 订阅拉取属
    **平台控制流量**，必须真直连——绝不读进程内残留的 `*_proxy` env（否则被劫持走不通的 mihomo，
    正是 §7.4 根因事故）。**重试**：订阅站多为境外，网络偶发波动优先重试自愈（间歇失败重试非缓存，
    见 feedback-retry-not-cache-for-flaky-probe）；确定性错误（SSRF 校验失败）不在此重试。"""
    import requests
    import time as _t
    parsed = validate_subscription_url(url)
    # Clash 系 UA：机场识别后返回 Clash/Mihomo YAML（而非 base64 v2ray 订阅）
    headers = {"User-Agent": "clash-verge/v1.7.0"}
    sess = requests.Session()
    sess.trust_env = False          # 真直连：不读环境 *_proxy，防残留代理劫持控制流量（§7.4 铁律）
    last_err = None
    for attempt in range(_PROFILE_FETCH_RETRY):
        try:
            resp = sess.get(url, timeout=(10, 30), stream=True, allow_redirects=False, headers=headers)
            resp.raise_for_status()
            chunks, total = [], 0
            for chunk in resp.iter_content(8192):
                total += len(chunk)
                if total > MAX_PROFILE_SIZE:
                    raise ValueError("profile 过大（>2MB）")
                chunks.append(chunk)
            return import_profile_content(name or parsed.netloc, b"".join(chunks), source=url)
        except ValueError:
            raise                    # 大小超限=确定性错误，不重试
        except Exception as exc:
            last_err = exc           # 网络类错误：退避重试（境外订阅站波动自愈）
            if attempt < _PROFILE_FETCH_RETRY - 1:
                _t.sleep(_PROFILE_FETCH_BACKOFF * (attempt + 1))
    raise last_err if last_err else RuntimeError("订阅拉取失败")


def get_profile(profile_id: str) -> Optional[Dict[str, Any]]:
    try:
        item = get_repo().collection(Collections.PROXY_PROFILES).find_one({"_id": _oid(profile_id)})
        if item:
            item["_id"] = str(item["_id"])
        return item
    except Exception:
        return None


def list_profiles() -> List[Dict[str, Any]]:
    out = []
    try:
        for item in get_repo().collection(Collections.PROXY_PROFILES).find().sort([("_id", -1)]):
            item["_id"] = str(item["_id"])
            out.append(item)
    except Exception as exc:
        logger.debug("list_profiles degraded: %s", exc)
    return out


def delete_profile(profile_id: str) -> Dict[str, Any]:
    try:
        prof = get_profile(profile_id)
        get_repo().collection(Collections.PROXY_PROFILES).delete_one({"_id": _oid(profile_id)})
        if prof and prof.get("path") and os.path.exists(prof["path"]):
            try:
                os.remove(prof["path"])
            except OSError:
                pass
        return {"deleted": 1, "profile_id": profile_id}
    except Exception as exc:
        return {"error": str(exc), "deleted": 0}


def _strip_geo_deps(data: Dict[str, Any]) -> None:
    """去外网依赖 + 禁 TUN（关键踩坑，见模块头）：防 mihomo 拉 MMDB 启动崩 + 防 TUN 劫持整机。"""
    data["geodata-mode"] = False
    data["geo-auto-update"] = False
    data["geox-url"] = {}
    data["tun"] = {"enable": False}                 # 禁 TUN：绝不接管整机网络
    dns = data.get("dns")
    if isinstance(dns, dict):
        dns.pop("fallback", None)
        dns.pop("fallback-filter", None)
    data["mode"] = "global"                          # 全量走代理，绕远程 rule-providers/geo
    data["rules"] = ["MATCH,GLOBAL"]
    data.pop("rule-providers", None)


def build_runtime_config() -> str:
    """按当前配置 + active profile 生成 mihomo config.yaml（去 geo 依赖 + 禁 TUN）。返回 config 路径。"""
    import yaml
    ensure_dirs()
    cfg = _cfg()
    p = _paths()
    profile = get_profile(cfg.get("active_profile_id")) if cfg.get("active_profile_id") else None
    data: Dict[str, Any] = {}
    if profile:
        path = profile.get("path", "")
        if not os.path.exists(path):   # 路径迁移：旧 release 目录被清 → 修正到当前 profiles 目录
            cand = os.path.join(p["profiles"], os.path.basename(path))
            if os.path.exists(cand):
                path = cand
                get_repo().collection(Collections.PROXY_PROFILES).update_one(
                    {"_id": _oid(profile["_id"])}, {"$set": {"path": cand}})
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
    data["port"] = int(cfg.get("http_port", 17890))
    data["socks-port"] = int(cfg.get("socks_port", 17891))
    data["mixed-port"] = int(cfg.get("mixed_port", 17892))
    data["allow-lan"] = False
    data["log-level"] = data.get("log-level", "info")
    # 容器模式：controller 与 http/socks/mixed 端口须监听 0.0.0.0，让同 compose 网络的业务容器
    # 经服务名连入；allow-lan=True 放行非本机来源。本地模式仍 127.0.0.1（不对外暴露）。
    _ctrl_bind = "0.0.0.0" if _is_container_mode() else cfg.get("controller_host", "127.0.0.1")
    data["external-controller"] = "{}:{}".format(_ctrl_bind, cfg.get("controller_port", 19090))
    if _is_container_mode():
        data["allow-lan"] = True
    data["secret"] = cfg.get("secret", "")
    data.setdefault("proxies", [])
    data.setdefault("proxy-groups", [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}])
    data.setdefault("rules", ["MATCH,PROXY"])
    _strip_geo_deps(data)
    with open(p["config"], "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, default_flow_style=False)
    return p["config"]


# ============================ 进程生命周期 ============================

def _proc_state(pid: int) -> str:
    """读 /proc/<pid>/stat 的进程状态字符（R/S/D/Z/T...）。读不到返 ""（进程已消失/非 Linux）。"""
    try:
        with open("/proc/{}/stat".format(pid), "r") as f:
            data = f.read()
        # stat 格式: pid (comm) state ...  —— comm 可能含空格/括号，取最后一个 ')' 之后
        rest = data[data.rfind(")") + 1:].split()
        return rest[0] if rest else ""
    except Exception:
        return ""


def _pid_running(pid: int) -> bool:
    """PID 是否为**存活**进程。僵尸(Z)不算存活——僵尸对 os.kill(pid,0) 仍返成功（PID 表项还在），
    但它不是能干活的 mihomo，若据此判 is_running=True 会导致「已在跑」误判、真内核起不来。故显式排除 Z。"""
    if os.name=='nt':
        try:
            import psutil
            process=psutil.Process(pid)
            return process.is_running() and process.status() not in (psutil.STATUS_ZOMBIE,psutil.STATUS_DEAD)
        except (psutil.NoSuchProcess,psutil.AccessDenied):return False
    try:
        os.kill(pid, 0)
    except Exception:
        return False
    return _proc_state(pid) != "Z"


def _reap_if_child(pid: int) -> None:
    """若 pid 是本进程的子进程，waitpid 回收其僵尸表项（非子进程会 ECHILD，忽略）。
    治多容器共享 PID 命名空间下 restart 频繁 kill 旧 mihomo 却无人 waitpid→僵尸堆积。"""
    try:
        os.waitpid(pid, os.WNOHANG)
    except Exception:
        pass


def get_pid() -> Optional[int]:
    try:
        with open(_paths()["pid"], "r") as f:
            return int(f.read().strip())
    except Exception:
        return None


def _controller_alive(timeout: int = 3) -> bool:
    """容器模式探活：GET controller /version 通即 mihomo 容器活着（替代跨容器无意义的 PID 探活）。"""
    try:
        import requests
        secret = _cfg().get("secret", "")
        headers = {"Authorization": "Bearer {}".format(secret)} if secret else {}
        r = requests.get(_controller_base() + "/version", headers=headers, timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def is_running() -> bool:
    # 容器模式：mihomo 是独立容器，本进程无其 PID，改用 controller 探活。
    if _is_container_mode():
        return _controller_alive()
    pid = get_pid()
    return bool(pid and _pid_running(pid))


def trim_core_log() -> bool:
    """mihomo 无日志轮转，节点抖动每秒刷 warning 会撑爆磁盘；只留最新 MAX_LOG_LINES 行。"""
    log_path = _paths()["log"]
    try:
        if not os.path.exists(log_path):
            return False
        trigger = MAX_LOG_LINES * 512
        if os.path.getsize(log_path) <= trigger:
            return False
        with open(log_path, "rb") as f:
            f.seek(-min(os.path.getsize(log_path), MAX_LOG_LINES * 4096), os.SEEK_END)
            data = f.read()
        lines = data.split(b"\n")
        if len(lines) <= MAX_LOG_LINES:
            return False
        with open(log_path, "wb") as f:
            f.write(b"[log trimmed]\n" + b"\n".join(lines[-MAX_LOG_LINES:]))
        return True
    except Exception:
        return False


def _spawn_daemonized(binp: str, runtime: str, log_path: str) -> int:
    """双重 fork 起 mihomo，使其 reparent 到 PID 1（容器内 tini/docker-init）自动回收僵尸。
    治「多容器共享 PID 命名空间下，worker A 起、scheduler/其他 worker kill，却无人 waitpid→僵尸堆积」
    （实测积累 4 个 mihomo 表项，仅 1 活 3 僵尸）。中间子进程 setsid+Popen 后立即 _exit → mihomo 成孤儿
    →被 PID1 收养并在其死亡时 waitpid 回收；启动者只 waitpid 回收秒退的中间子进程，两侧都不留僵尸。
    经 pipe 从中间子进程回传 mihomo 的真实 pid。非 POSIX（无 os.fork）降级普通 Popen。"""
    if not hasattr(os, "fork"):                       # 非 Linux（Windows 开发机）降级
        proc = subprocess.Popen([binp, "-d", runtime],
                                stdout=open(log_path, "ab"), stderr=subprocess.STDOUT, close_fds=True)
        return proc.pid
    r_fd, w_fd = os.pipe()
    intermediate = os.fork()
    if intermediate > 0:                              # —— 启动者：回收中间子进程 + 读回 mihomo pid ——
        os.close(w_fd)
        os.waitpid(intermediate, 0)                   # 中间子进程秒退，立即 reap，无僵尸
        try:
            data = os.read(r_fd, 32)
        finally:
            os.close(r_fd)
        try:
            return int((data or b"").strip() or 0)
        except ValueError:
            return 0
    # —— 中间子进程：脱离会话，起 mihomo，回传 pid，随即退出让 mihomo 归 PID1 ——
    try:
        os.close(r_fd)
        os.setsid()
        log = open(log_path, "ab")
        proc = subprocess.Popen([binp, "-d", runtime], stdout=log, stderr=log,
                                stdin=subprocess.DEVNULL, close_fds=True)
        os.write(w_fd, str(proc.pid).encode())
        os.close(w_fd)
    except Exception:
        pass
    finally:
        os._exit(0)                                   # 中间子进程退出→mihomo 孤儿 reparent 到 PID1(tini)


def start_core() -> Dict[str, Any]:
    """启动 mihomo 子进程。已在跑→幂等返回；二进制缺失→抛 FileNotFoundError。
    **跨容器互斥（2026-08-08）**：共享卷文件锁 flock 串行化「检查 is_running→spawn」全过程，杜绝
    web 端点点击启动与 scheduler 自愈在亚秒窗口内都判「没跑」→各起一个→端口打架/进程翻倍。
    **僵尸根治**：经 _spawn_daemonized 双重 fork 让内核归 PID1 自动回收。"""
    ensure_dirs()
    p = _paths()
    # 容器模式：mihomo 是独立容器（compose 管生命周期），平台不 spawn。写 config + controller reload。
    if _is_container_mode():
        try:
            cfg_path = build_runtime_config()
            reloaded = _reload_controller_config(cfg_path)
            return {"running": _controller_alive(), "container": True,
                    "reloaded": reloaded, "message": "reloaded" if reloaded else "config written (mihomo容器未就绪或reload失败)"}
        except Exception as exc:
            logger.warning("mihomo 容器模式 start_core: %s", exc)
            return {"running": _controller_alive(), "container": True, "message": str(exc)}
    binp = _mihomo_bin()
    if not os.path.exists(binp):
        raise FileNotFoundError("mihomo 内核二进制不存在: {}".format(binp))
    lock_file = None
    try:
        lock_file = open(os.path.join(p["runtime"], "start.lock"), "w")
        try:
            import fcntl                              # 仅 Linux；非 POSIX 降级无锁（本就单机跑）
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        except Exception:
            pass
        if is_running():                              # 持锁内复查——真正的互斥点
            return {"running": True, "pid": get_pid(), "message": "already running"}
        build_runtime_config()
        trim_core_log()
        pid = _spawn_daemonized(binp, p["runtime"], p["log"])
        with open(p["pid"], "w") as f:
            f.write(str(pid))
        logger.info("mihomo started pid=%s", pid)
        return {"running": True, "pid": pid, "message": "started"}
    finally:
        if lock_file is not None:
            try:
                lock_file.close()                     # close 即释放 flock
            except Exception:
                pass


def stop_core() -> Dict[str, Any]:
    """停止 mihomo：SIGTERM 优雅退出，2s 内不退再 SIGKILL；退出后 waitpid 回收僵尸表项。
    容器模式：平台停不了独立容器（生命周期归 compose），弱化为"清空 config 走 DIRECT"——
    代理停用靠策略不选节点/mode=direct，而非杀容器。"""
    if _is_container_mode():
        try:
            cfg = _cfg()
            # 写一份仅 DIRECT 的最小 config 并 reload，让 mihomo 出口回落直连（等效"停用代理"）。
            import yaml
            p = _paths()
            data = {"port": int(cfg.get("http_port", 17890)), "socks-port": int(cfg.get("socks_port", 17891)),
                    "mixed-port": int(cfg.get("mixed_port", 17892)), "allow-lan": True,
                    "external-controller": "0.0.0.0:{}".format(cfg.get("controller_port", 19090)),
                    "secret": cfg.get("secret", ""), "mode": "direct",
                    "proxies": [], "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["DIRECT"]}],
                    "rules": ["MATCH,DIRECT"]}
            with open(p["config"], "w", encoding="utf-8") as f:
                yaml.safe_dump(data, f, allow_unicode=True, default_flow_style=False)
            _reload_controller_config(p["config"])
        except Exception as exc:
            logger.debug("container stop_core degrade: %s", exc)
        return {"running": _controller_alive(), "container": True, "message": "代理已切直连(容器模式不停容器)"}
    pid = get_pid()
    if not pid:
        return {"running": False, "message": "not running"}
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for _ in range(20):
        if not _pid_running(pid):
            break
        time.sleep(0.2)
    if _pid_running(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    _reap_if_child(pid)          # 回收僵尸表项（若是本 worker 起的子进程）——治 restart 僵尸堆积
    try:
        os.remove(_paths()["pid"])
    except OSError:
        pass
    logger.info("mihomo stopped pid=%s", pid)
    return {"running": False, "message": "stopped"}


def _port_free(port: int, host: str = "127.0.0.1") -> bool:
    """端口是否已释放（可 bind）。用于 restart 前确认旧实例端口真的放开（BUG-003）。"""
    if not port:
        return True
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _wait_ports_free(timeout: float = 6.0) -> bool:
    """轮询等待 mihomo 关键端口（mixed/http/socks，:53 DNS 另算）释放。超时返回 False（调用方仍尝试启动）。"""
    cfg = _cfg()
    ports = [int(cfg.get("mixed_port", 17892) or 17892),
             int(cfg.get("http_port", 17890) or 17890),
             int(cfg.get("socks_port", 17891) or 17891)]
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all(_port_free(p) for p in ports if p):
            return True
        time.sleep(0.2)
    return False


def restart_core() -> Dict[str, Any]:
    """重启内核：先干净停旧实例并**等端口真正释放**再启动（BUG-003：治 restart 端口清理竞态
    ——旧 mihomo 进程虽退出但 17892/:53 端口未及时释放，新实例 bind 失败→部分监听挂→看门狗
    循环重启抖动）。stop 后轮询端口空闲，最长等 ~6s，端口放开或超时才 start。
    容器模式：无本地进程/端口概念，直接写 config + controller reload（不停端口等待）。"""
    if _is_container_mode():
        return start_core()
    stop_core()
    freed = _wait_ports_free()
    if not freed:
        logger.warning("mihomo restart: 端口未在超时内释放，仍尝试启动（可能短暂 bind 失败由自愈补偿）")
    return start_core()


_last_autostart_ts = 0.0
_MIN_AUTOSTART_INTERVAL = 30.0   # 看门狗自愈最小间隔（秒），防端口清理竞态期内反复拉起抖动（BUG-003）


def ensure_core_running() -> Dict[str, Any]:
    """自愈（scheduler 周期调）：代理启用但内核没跑→自动拉起。覆盖发布重启/崩溃/OOM。不抛异常。
    BUG-003：加最小重启间隔退避——两次自愈拉起至少隔 30s，避免端口尚未释放就反复 restart 形成抖动。"""
    global _last_autostart_ts
    cfg = _cfg()
    if not cfg.get("enabled"):
        return {"action": "none", "reason": "proxy not enabled"}
    if is_running():
        return {"action": "none", "reason": "already running"}
    now = time.time()
    if now - _last_autostart_ts < _MIN_AUTOSTART_INTERVAL:
        return {"action": "backoff", "reason": "restart throttled ({}s min interval)".format(int(_MIN_AUTOSTART_INTERVAL))}
    _last_autostart_ts = now
    try:
        ret = restart_core()
        return {"action": "started", "pid": ret.get("pid")}
    except Exception as e:
        return {"action": "failed", "error": str(e)}


def read_logs(lines: int = 200) -> str:
    log_path = _paths()["log"]
    if not os.path.exists(log_path):
        return ""
    try:
        with open(log_path, "rb") as f:
            data = f.read()[-128 * 1024:]
        return "\n".join(data.decode("utf-8", errors="replace").splitlines()[-int(lines):])
    except Exception:
        return ""


# ============================ controller 节点操作（mihomo external-controller REST）============================

def _controller_base() -> str:
    # 容器模式下 controller 在 mihomo 容器（经服务名 MIHOMO_HOST），本地模式回退 127.0.0.1。
    # controller_host 配置项仅在未设 MIHOMO_HOST 时作兼容兜底（历史单机配置）。
    cfg = _cfg()
    host = _mihomo_host()
    if host == "127.0.0.1":
        host = cfg.get("controller_host", "127.0.0.1") or "127.0.0.1"
    return "http://{}:{}".format(host, cfg.get("controller_port", 19090))


def _controller_request(method: str, path: str, **kwargs):
    import requests
    secret = _cfg().get("secret", "")
    headers = {"Authorization": "Bearer {}".format(secret)} if secret else {}
    return requests.request(method, _controller_base() + path, headers=headers,
                            timeout=kwargs.pop("timeout", 10), **kwargs)


def _reload_controller_config(config_path: str) -> bool:
    """容器模式：让 mihomo 容器热加载新 config（PUT /configs，不重启容器）。成功返 True。
    注意 path 必须是 mihomo 容器内可见的路径——本平台 config 在共享卷 shared/proxy_runtime/config.yaml，
    容器挂载点一致（/opt/sentinel/current/...）。mihomo 未就绪/reload 失败返 False（调用方降级不崩）。"""
    try:
        resp = _controller_request("PUT", "/configs", json={"path": config_path}, timeout=8)
        return resp.status_code in (200, 204)
    except Exception as exc:
        logger.debug("mihomo controller reload config failed: %s", exc)
        return False


def get_proxies() -> Dict[str, Any]:
    resp = _controller_request("GET", "/proxies")
    resp.raise_for_status()
    return resp.json()


def current_node() -> str:
    """GLOBAL 选择器当前指向的真实叶子节点名（DIRECT/组/空 返 ''）。"""
    try:
        data = get_proxies().get("proxies", {})
        groups = {n for n, i in data.items() if i.get("all")}
        now = data.get("GLOBAL", {}).get("now")
        if now and now not in ("DIRECT", "REJECT", "PASS", "COMPATIBLE") and now not in groups:
            return now
    except Exception:
        pass
    return ""


def select_proxy(group: str, name: str) -> Dict[str, Any]:
    resp = _controller_request("PUT", "/proxies/{}".format(group), json={"name": name})
    if resp.status_code not in (200, 204):
        resp.raise_for_status()
    return {"group": group, "name": name, "selected": True}


def delay_proxy(name: str, test_url: str = "", timeout: int = 5000):
    test_url = test_url or _cfg().get("test_url") or DEFAULT_TEST_URL
    resp = _controller_request("GET", "/proxies/{}/delay".format(name),
                               params={"timeout": timeout, "url": test_url}, timeout=(timeout / 1000) + 3)
    resp.raise_for_status()
    return resp.json().get("delay")


def auto_select(group: str = "PROXY", exclude=None) -> Dict[str, Any]:
    """自动优选最快节点。默认全节点参与（不硬编码地区）；配了 node_region_prefixes 才按前缀过滤。
    exclude: failover 时排除的死节点。"""
    exclude = set(exclude or [])
    data = get_proxies().get("proxies", {})
    group_info = data.get(group)
    if not group_info:
        for name, info in data.items():
            if info.get("all"):
                group, group_info = name, info
                break
    if not group_info:
        raise ValueError("找不到可选代理组")
    groups = {n for n, i in data.items() if i.get("all")}
    prefixes = _region_prefixes()   # 空=不限地区
    candidates = [x for x in group_info.get("all", [])
                  if x not in ("DIRECT", "REJECT", "PASS", "COMPATIBLE")
                  and x not in groups and x not in exclude
                  and (not prefixes or any(x.startswith(p) for p in prefixes))]
    # 有界优选（2026-08-08 修）：机场几十个节点逐个测延时(每个最多几秒)会累计超 gunicorn worker
    # 超时(30s)→worker 被杀→core/start 报 502(实为内核已起、卡在选节点)。故：①单节点测速降到 2s
    # ②总墙钟 deadline 18s，到点即止用已测出的最优 ③测到足够快(<800ms)的节点提前收工，不测完全部。
    results = []
    deadline = time.time() + 18
    for name in candidates:
        if time.time() >= deadline:
            break
        try:
            d = delay_proxy(name, timeout=2000)
            results.append({"name": name, "delay": d})
            if isinstance(d, int) and d < 800:   # 已够快，不必测完剩余节点
                break
        except Exception as e:
            results.append({"name": name, "error": str(e)})
    ok = [x for x in results if isinstance(x.get("delay"), int)]
    if not ok:
        raise ValueError("延迟测试后无可用节点（可能无外网出口/节点全不通）")
    best = sorted(ok, key=lambda x: x["delay"])[0]
    select_proxy(group, best["name"])
    return {"group": group, "selected": best, "results": results}


def _proxy_traffic_ok(timeout: int = 8) -> bool:
    """经 mihomo HTTP 端口做真实 HTTPS 请求，确认流量真能过（非只测 mihomo 延迟）。
    容器模式经服务名，本地 127.0.0.1。"""
    import requests
    proxy = "http://{}:{}".format(_mihomo_host(), _cfg().get("http_port", 17890))
    try:
        r = requests.get("https://api.ipify.org", proxies={"http": proxy, "https": proxy},
                         timeout=timeout, allow_redirects=False, verify=False)
        return r.status_code < 400 and bool((r.text or "").strip())
    except Exception:
        return False


def ensure_proxy_selected() -> Dict[str, Any]:
    """确保代理落到真实存活节点（global 模式 GLOBAL 默认 DIRECT，不强选叶子→走代理流量直连泄露真 IP）。
    当前节点真实流量验活；死了 failover 到最快活节点。仅"启用+运行中"时动作，不抛异常。"""
    cfg = _cfg()
    if not cfg.get("enabled") or not is_running():
        return {"action": "none", "reason": "not enabled or core down"}
    try:
        data = get_proxies().get("proxies", {})
    except Exception as e:
        return {"action": "failed", "error": str(e)}
    if "GLOBAL" not in data:
        return {"action": "none", "reason": "no GLOBAL group"}
    groups = {n for n, i in data.items() if i.get("all")}
    now = data.get("GLOBAL", {}).get("now")
    if now and now not in ("DIRECT", "REJECT", "PASS", "COMPATIBLE") and now not in groups:
        alive = False
        try:
            if isinstance(delay_proxy(now), int) and _proxy_traffic_ok():
                alive = True
        except Exception:
            pass
        if alive:
            return {"action": "none", "reason": "node {} alive".format(now)}
        try:
            r = auto_select("GLOBAL", exclude=[now])
            sel = r.get("selected", {}).get("name", "")
            if sel and sel != now:
                logger.warning("代理节点 %s 失效，failover→ %s", now, sel)
                return {"action": "switched", "node": sel}
            return {"action": "failed", "reason": "failover 选回死节点"}
        except Exception as e:
            return {"action": "failed", "error": str(e)}
    try:
        r = auto_select("GLOBAL")
        return {"action": "selected", "node": r.get("selected", {}).get("name")}
    except Exception as e:
        return {"action": "failed", "error": str(e)}


# ============================ 流量账本（跨核心重启增量累计不回退） ============================

def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "{:.1f}{}".format(n, unit)
        n /= 1024
    return "{:.1f}PB".format(n)


def traffic() -> Dict[str, Any]:
    """实时流量（controller /connections 累计上下行 + 当前连接数）。未运行返零值不抛。"""
    cfg = _cfg()
    zero = {"running": False, "upload_total": 0, "download_total": 0, "connections": 0,
            "upload_h": "0B", "download_h": "0B"}
    if not cfg.get("enabled") or not is_running():
        return zero
    try:
        resp = _controller_request("GET", "/connections", timeout=5)
        resp.raise_for_status()
        d = resp.json()
        up, down = int(d.get("uploadTotal", 0) or 0), int(d.get("downloadTotal", 0) or 0)
        return {"running": True, "upload_total": up, "download_total": down,
                "connections": len(d.get("connections", []) or []),
                "upload_h": _human_bytes(up), "download_h": _human_bytes(down)}
    except Exception as e:
        return dict(zero, running=True, error=str(e))


def sample_traffic() -> None:
    """采样增量归账（总量/机场/节点）。核心重启计数清零时增量从当前值起算，绝不回退。scheduler 周期调。"""
    cfg = _cfg()
    if not cfg.get("enabled") or not is_running():
        return
    try:
        resp = _controller_request("GET", "/connections", timeout=5)
        resp.raise_for_status()
        d = resp.json()
        cur_up, cur_down = int(d.get("uploadTotal", 0) or 0), int(d.get("downloadTotal", 0) or 0)
    except Exception:
        return
    try:
        coll = get_repo().collection(Collections.PROXY_TRAFFIC)
        meta = coll.find_one({"scope": "meta"}) or {}
        last_up, last_down = int(meta.get("last_up", 0)), int(meta.get("last_down", 0))
        if cur_up < last_up or cur_down < last_down:      # 核心重启检测→增量从当前值起算
            d_up, d_down = cur_up, cur_down
        else:
            d_up, d_down = cur_up - last_up, cur_down - last_down
        coll.update_one({"scope": "meta"},
                        {"$set": {"last_up": cur_up, "last_down": cur_down, "updated_at": _now_str()},
                         "$inc": {"total_up": max(d_up, 0), "total_down": max(d_down, 0)}}, upsert=True)
        if d_up <= 0 and d_down <= 0:
            return
        pid = cfg.get("active_profile_id") or "unknown"
        pname = (get_profile(pid) or {}).get("name", "") if pid != "unknown" else ""
        coll.update_one({"scope": "profile", "key": pid},
                        {"$set": {"name": pname, "updated_at": _now_str()},
                         "$inc": {"up": d_up, "down": d_down}}, upsert=True)
        node = current_node()
        if node:
            coll.update_one({"scope": "node", "key": "{}|{}".format(pid, node)},
                            {"$set": {"name": node, "profile_id": pid, "profile_name": pname,
                                      "updated_at": _now_str()},
                             "$inc": {"up": d_up, "down": d_down}}, upsert=True)
    except Exception:
        pass


def traffic_stats() -> Dict[str, Any]:
    """持久化流量账本（总量+按机场+按节点，跨重启累计）。供前端展示。"""
    coll = get_repo().collection(Collections.PROXY_TRAFFIC)
    meta = coll.find_one({"scope": "meta"}) or {}
    tu, td = int(meta.get("total_up", 0)), int(meta.get("total_down", 0))
    def _rows(scope):
        out = []
        for x in coll.find({"scope": scope}).sort([("up", -1)]):
            up, down = int(x.get("up", 0)), int(x.get("down", 0))
            out.append({"key": x.get("key"), "name": x.get("name") or x.get("key"),
                        "profile_name": x.get("profile_name", ""),
                        "up": up, "down": down, "up_h": _human_bytes(up), "down_h": _human_bytes(down)})
        return out
    return {"total_up": tu, "total_down": td, "total_up_h": _human_bytes(tu),
            "total_down_h": _human_bytes(td), "by_profile": _rows("profile"), "by_node": _rows("node")}


def reset_traffic_stats(scope: str = "", key: str = "") -> Dict[str, Any]:
    coll = get_repo().collection(Collections.PROXY_TRAFFIC)
    if scope and key:
        coll.delete_one({"scope": scope, "key": key})
    elif scope:
        coll.delete_many({"scope": scope})
    else:
        coll.delete_many({})
    return traffic_stats()
