"""network_check —— 网络检测（system 叶子，纯 Python ICMP ping + DNS 配置）。

系统设置>网络检测的业务能力：
  - DNS 服务器配置（用户自定义优先 → 系统 DNS → 公共 DNS 回退）
  - 纯 Python ICMP ping（raw socket，零外部命令依赖，root 下直接可用）

无 ROLE（字符串键 "network_check_service" 注册）。只依赖 core.db + stdlib(socket/struct/os)。
"""
from __future__ import annotations

import os
import random
import re
import socket
import struct
import time
from typing import Any, Dict, List, Tuple

from sentinel_platform.core import get_logger, get_repo
from sentinel_platform.contracts import get_registry, ROLE

logger = get_logger()

_DNS_COLL = "network_config"


# ======================== DNS 配置 ========================

def get_dns_config() -> Dict[str, Any]:
    """读取用户自定义 DNS 配置。返回 {servers: ["8.8.8.8", ...]}。"""
    try:
        doc = get_repo().collection(_DNS_COLL).find_one({"name": "default"}) or {}
        servers = doc.get("dns_servers") or []
        return {"servers": [s for s in servers if s and isinstance(s, str)]}
    except Exception:
        return {"servers": []}


def save_dns_config(servers: List[str]) -> Dict[str, Any]:
    """保存 DNS 配置。校验格式后写入。"""
    cleaned = []
    for s in (servers or []):
        s = str(s).strip()
        if s and re.match(r'^[0-9\.:]+$', s):
            cleaned.append(s)
    try:
        get_repo().collection(_DNS_COLL).update_one(
            {"name": "default"},
            {"$set": {"name": "default", "dns_servers": cleaned}},
            upsert=True)
        return {"ok": True, "servers": cleaned}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ======================== DNS 解析 ========================

def resolve_host(host: str) -> Tuple[str, str]:
    """解析主机名到 IP。优先级：用户配置 DNS > 系统 DNS > 公共 DNS。
    返回 (ip, error_msg)，成功时 error_msg 为空。"""
    # 已经是 IP 直接返回
    try:
        socket.inet_aton(host)
        return host, ""
    except socket.error:
        pass

    # 用户配置的 DNS
    custom_dns = get_dns_config().get("servers") or []
    for dns_server in custom_dns:
        ip = _dns_query(host, dns_server)
        if ip:
            return ip, ""

    # 系统 DNS
    try:
        ip = socket.gethostbyname(host)
        return ip, ""
    except socket.gaierror:
        pass

    # 公共 DNS 回退
    for dns_server in ("8.8.8.8", "114.114.114.114", "223.5.5.5"):
        if dns_server not in custom_dns:
            ip = _dns_query(host, dns_server)
            if ip:
                return ip, ""

    return "", "DNS 解析失败: {}（自定义/系统/公共 DNS 均无法解析）".format(host)


def _dns_query(host: str, dns_server: str, timeout: float = 3.0) -> str:
    """手动 UDP DNS A 记录查询（纯 socket，零依赖）。返回 IP 或空串。"""
    try:
        txn_id = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txn_id, flags, 1, 0, 0, 0)
        qname = b''
        for part in host.split('.'):
            qname += struct.pack('!B', len(part)) + part.encode()
        qname += b'\x00'
        question = qname + struct.pack('!HH', 1, 1)
        packet = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_server, 53))
        data, _ = sock.recvfrom(512)
        sock.close()

        ancount = struct.unpack('!H', data[6:8])[0]
        if ancount == 0:
            return ""
        offset = 12
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 5
        for _ in range(ancount):
            if offset >= len(data):
                break
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            if rtype == 1 and rdlen == 4:
                return socket.inet_ntoa(data[offset:offset + 4])
            offset += rdlen
        return ""
    except Exception:
        return ""


# ======================== ICMP Ping ========================

def _checksum(data: bytes) -> int:
    """ICMP 校验和。"""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def _ping_once(dest_ip: str, seq: int, timeout: float = 3.0, pid: int = 0) -> Dict[str, Any]:
    """发一个 ICMP echo request 并等回复。返回 {seq, ttl, time_ms} 或 {seq, error}。"""
    ICMP_PROTO = 1
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO)
    except PermissionError:
        return {"seq": seq, "error": "需要 root 权限发送 ICMP"}
    except OSError as e:
        return {"seq": seq, "error": str(e)}

    sock.settimeout(timeout)
    pid = pid & 0xFFFF

    header = struct.pack('!BBHHH', 8, 0, 0, pid, seq)
    payload = struct.pack('!d', time.time()) + b'\x00' * 32
    cksum = _checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, cksum, pid, seq)
    packet = header + payload

    try:
        send_time = time.time()
        sock.sendto(packet, (dest_ip, 0))
        while True:
            data, addr = sock.recvfrom(1024)
            recv_time = time.time()
            ip_header_len = (data[0] & 0x0F) * 4
            ttl = data[8]
            icmp_data = data[ip_header_len:]
            if icmp_data[0] == 0:  # echo reply
                recv_id = struct.unpack('!H', icmp_data[4:6])[0]
                recv_seq = struct.unpack('!H', icmp_data[6:8])[0]
                if recv_id == pid and recv_seq == seq:
                    ms = (recv_time - send_time) * 1000
                    return {"seq": seq, "ttl": ttl, "time_ms": round(ms, 2)}
            if time.time() - send_time > timeout:
                return {"seq": seq, "error": "超时"}
    except socket.timeout:
        return {"seq": seq, "error": "超时"}
    except OSError as e:
        return {"seq": seq, "error": str(e)}
    finally:
        sock.close()


def do_ping(host: str, count: int = 4) -> str:
    """执行 ping 并格式化为终端风格输出。对外能力入口。"""
    ip, err_msg = resolve_host(host)
    if err_msg:
        return err_msg

    lines = ["PING {} ({}): 64 字节数据".format(host, ip)]
    pid = os.getpid() & 0xFFFF
    sent = 0
    received = 0
    times: List[float] = []

    for i in range(count):
        sent += 1
        result = _ping_once(ip, i + 1, timeout=3.0, pid=pid)
        if "error" in result:
            lines.append("请求超时 seq={}: {}".format(result['seq'], result['error']))
        else:
            received += 1
            ms = result["time_ms"]
            times.append(ms)
            lines.append("64 字节来自 {}: icmp_seq={} ttl={} 时间={:.1f} ms".format(
                ip, result['seq'], result.get('ttl', '?'), ms))
        if i < count - 1:
            time.sleep(0.8)

    loss = ((sent - received) / sent * 100) if sent else 0
    lines.append("\n--- {} ping 统计 ---".format(host))
    lines.append("{} 个包已发送, {} 个包已接收, {:.0f}% 丢包".format(sent, received, loss))
    if times:
        lines.append("往返延迟 最小/平均/最大 = {:.1f}/{:.1f}/{:.1f} ms".format(
            min(times), sum(times) / len(times), max(times)))

    return "\n".join(lines)


# ======================== 网络质量检测（v1.21.148-10）========================
# 诊断"网络为什么差"：丢包/抖动、出网稳定性、DNS 健康、关键依赖可达、代理出口质量。
# 全部复用已有基建（_ping_once/_dns_query/resolve_host），HTTP 探测 trust_env=False 真直连（§7.4）。

# 出网稳定性默认探测目标（国内+国外各一，量化"能不能稳定出网"）。可传入覆盖，非硬清单。
_STABILITY_TARGETS = [
    {"name": "国内(百度)", "url": "https://www.baidu.com", "region": "cn"},
    {"name": "国外(GitHub)", "url": "https://github.com", "region": "intl"},
]
# DNS 健康对比用的解析器（系统+主流公共），解析同一域名比成功率/耗时，一眼看出哪个 DNS 挂了。
_DNS_HEALTH_SERVERS = ["223.5.5.5", "114.114.114.114", "8.8.8.8", "1.1.1.1"]


def _grade(loss_pct: float, avg_ms: float) -> str:
    """链路质量分级（渗透视角：丢包/高延迟都影响扫描与出洞）。good/fair/poor/dead。"""
    if loss_pct >= 100:
        return "dead"
    if loss_pct >= 20 or avg_ms >= 800:
        return "poor"
    if loss_pct > 0 or avg_ms >= 300:
        return "fair"
    return "good"


def ping_quality(host: str, count: int = 10) -> Dict[str, Any]:
    """① 链路质量：多次 ping 算丢包率 + RTT 抖动(jitter=相邻 RTT 差均值)。
    单次 ping 看不出波动，多次才暴露"时快时慢/间歇丢包"（本次 VM 波动就是这么发现的）。"""
    ip, err_msg = resolve_host(host)
    if not ip:
        return {"host": host, "error": err_msg or "无法解析主机", "grade": "dead"}
    pid = os.getpid() & 0xFFFF
    times: List[float] = []
    sent = recv = 0
    for i in range(max(1, count)):
        sent += 1
        r = _ping_once(ip, i + 1, timeout=3.0, pid=pid)
        if "error" not in r:
            recv += 1
            times.append(r["time_ms"])
        if i < count - 1:
            time.sleep(0.3)
    loss = round((sent - recv) / sent * 100, 1) if sent else 100.0
    avg = round(sum(times) / len(times), 1) if times else 0.0
    # 抖动：相邻 RTT 差绝对值的均值（越大越不稳，视频/交互式利用受影响）
    jitter = 0.0
    if len(times) >= 2:
        diffs = [abs(times[k] - times[k - 1]) for k in range(1, len(times))]
        jitter = round(sum(diffs) / len(diffs), 1)
    return {"host": host, "ip": ip, "sent": sent, "received": recv, "loss_pct": loss,
            "min_ms": round(min(times), 1) if times else 0, "avg_ms": avg,
            "max_ms": round(max(times), 1) if times else 0, "jitter_ms": jitter,
            "grade": _grade(loss, avg)}


def _http_probe(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """单次 HTTP 探测（trust_env=False 真直连，不读残留代理 env，§7.4）。返回耗时/状态/是否成功。"""
    import requests
    s = requests.Session()
    s.trust_env = False
    t0 = time.time()
    try:
        r = s.get(url, timeout=timeout, allow_redirects=True,
                  headers={"User-Agent": "Mozilla/5.0 (SentinelNetCheck)"})
        return {"ok": True, "status": r.status_code, "ms": round((time.time() - t0) * 1000)}
    except Exception as exc:
        return {"ok": False, "status": 0, "ms": round((time.time() - t0) * 1000),
                "err": type(exc).__name__}


def egress_stability(targets: Any = None, rounds: int = 5) -> Dict[str, Any]:
    """② 出网稳定性：对国内+国外目标各连续 HTTP 探 N 次，统计成功率+平均延迟。
    直接量化"出网稳不稳"（本次连百度都 72ms→25s 超时就是这么暴露的）。"""
    tlist = targets if isinstance(targets, list) and targets else _STABILITY_TARGETS
    out = []
    for t in tlist:
        url = t.get("url") if isinstance(t, dict) else str(t)
        name = t.get("name", url) if isinstance(t, dict) else url
        oks, mss = 0, []
        for _ in range(max(1, rounds)):
            p = _http_probe(url)
            if p["ok"]:
                oks += 1
                mss.append(p["ms"])
            time.sleep(0.2)
        rate = round(oks / max(1, rounds) * 100)
        avg = round(sum(mss) / len(mss)) if mss else 0
        out.append({"name": name, "url": url, "region": t.get("region", "") if isinstance(t, dict) else "",
                    "rounds": rounds, "success": oks, "success_rate": rate, "avg_ms": avg,
                    "grade": "dead" if rate == 0 else ("poor" if rate < 60 or avg >= 3000 else
                             ("fair" if rate < 100 or avg >= 1000 else "good"))})
    return {"targets": out}


def dns_health(host: str = "www.baidu.com") -> Dict[str, Any]:
    """③ DNS 健康：用系统 DNS + 多个公共 DNS 分别解析同一域名，对比成功率+耗时。
    本次 `127.0.0.53 timed out` 就靠这个一眼看出哪个 DNS 挂了、该换哪个。"""
    results = []
    # 系统 DNS（socket 默认解析）
    t0 = time.time()
    sys_ip = ""
    try:
        sys_ip = socket.gethostbyname(host)
    except Exception:
        sys_ip = ""
    results.append({"server": "系统DNS", "ip": sys_ip, "ms": round((time.time() - t0) * 1000),
                    "ok": bool(sys_ip)})
    # 各公共 DNS（复用 _dns_query 纯 socket 查询）
    for dns in _DNS_HEALTH_SERVERS:
        t0 = time.time()
        ip = _dns_query(host, dns, timeout=3.0)
        results.append({"server": dns, "ip": ip, "ms": round((time.time() - t0) * 1000),
                        "ok": bool(ip)})
    ok_cnt = sum(1 for r in results if r["ok"])
    return {"host": host, "servers": results, "ok_count": ok_cnt, "total": len(results),
            "grade": "good" if ok_cnt == len(results) else ("fair" if ok_cnt >= 2 else
                     ("poor" if ok_cnt == 1 else "dead"))}


def _dep_targets() -> List[Dict[str, str]]:
    """动态构建平台关键依赖清单（不硬编码 URL）：LLM 中转站(从 ai_provider 取) + 更新源 +
    固定情报源(FOFA/Hunter/NVD) + GitHub + 已配订阅站。任一取不到只跳过该项，不崩。"""
    deps: List[Dict[str, str]] = []
    # LLM 中转站（AI 渗透命门——本次 lt4net 失效就是靠体检该看出）
    try:
        for p in get_repo().collection("ai_provider").find({"enabled": True}):
            bu = (p.get("base_url") or "").strip()
            if bu:
                deps.append({"name": "LLM·" + (p.get("name") or "provider"), "url": bu, "kind": "llm"})
    except Exception:
        pass
    # 更新/分发源
    try:
        from sentinel_platform.modules.system import activation as _act
        su = _act.source_url()
        if su:
            deps.append({"name": "更新源", "url": su + "/version", "kind": "update"})
    except Exception:
        pass
    # 固定情报/测绘源（这些是 host 固定的资产收集依赖）
    deps += [
        {"name": "情报·FOFA", "url": "https://fofa.info", "kind": "intel"},
        {"name": "情报·鹰图Hunter", "url": "https://hunter.qianxin.com", "kind": "intel"},
        {"name": "漏洞库·NVD", "url": "https://services.nvd.nist.gov", "kind": "intel"},
        {"name": "GitHub", "url": "https://api.github.com", "kind": "intel"},
    ]
    # 已配的代理订阅站（从 proxy_profiles 的 source URL 取）
    try:
        seen = set()
        for pf in get_repo().collection("proxy_profiles").find({}):
            src = (pf.get("source") or "").strip()
            if src.startswith("http") and src not in seen:
                seen.add(src)
                from urllib.parse import urlparse as _up
                deps.append({"name": "代理订阅·" + (_up(src).netloc or "sub"), "url": src, "kind": "sub"})
    except Exception:
        pass
    return deps


def deps_healthcheck() -> Dict[str, Any]:
    """④ 关键依赖一键体检：批量探平台依赖可达性（LLM/更新源/情报源/GitHub/订阅站）。
    本次 LLM 中转站失效、订阅站波动——一屏看清哪些依赖不通、哪个功能(AI渗透/情报/更新)会瘫。"""
    deps = _dep_targets()
    out = []
    for d in deps:
        p = _http_probe(d["url"], timeout=8.0)
        # 依赖可达判定：连得上就算通（4xx/401/403 也算 host 可达，只是要鉴权）；0/超时=不可达
        reachable = p["ok"] or (p.get("status", 0) > 0)
        out.append({"name": d["name"], "url": d["url"], "kind": d.get("kind", ""),
                    "reachable": reachable, "status": p.get("status", 0), "ms": p.get("ms", 0),
                    "err": p.get("err", "") if not reachable else ""})
    down = [x["name"] for x in out if not x["reachable"]]
    return {"deps": out, "total": len(out), "down_count": len(down), "down": down}


def proxy_egress_quality() -> Dict[str, Any]:
    """⑤ 代理出口质量：经当前代理测出口 IP + 延迟，对比直连（复用 PROXY.detect_exit_ip）。
    量化代理到底能不能用、绕出去慢多少（本次代理节点连不通就靠这个暴露）。"""
    try:
        svc = get_registry().get(ROLE.PROXY)
        if not (svc and hasattr(svc, "detect_exit_ip")):
            return {"available": False, "note": "代理服务未就绪"}
        r = svc.detect_exit_ip(use_cache=False) if callable(getattr(svc, "detect_exit_ip", None)) else {}
        proxy_ip = r.get("proxy_ip", "")
        direct_ip = r.get("direct_ip", "")
        proxied = bool(r.get("proxied"))
        err = r.get("error", "")
        enabled = err != "proxy not enabled"
        # 判定：未启用=n/a；启用但探不到=代理不可用；探到且改变出口=生效；相同=未改变出口
        if not enabled:
            grade, note = "na", "代理未启用（走直连）"
        elif not proxy_ip:
            grade, note = "dead", "代理已启用但探不到出口——代理不可用/节点连不通/网络异常"
        elif proxied:
            grade, note = "good", "代理生效，出口已改变"
        else:
            grade, note = "fair", "经代理出口与直连相同——代理未改变出口（可能选中DIRECT节点）"
        return {"available": True, "enabled": enabled, "proxy_ip": proxy_ip, "direct_ip": direct_ip,
                "proxied": proxied, "grade": grade, "note": note, "error": err}
    except Exception as exc:
        return {"available": False, "note": "代理出口探测异常: {}".format(str(exc)[:80])}


# ======================== 综合评估（总分/总评级）========================
# grade → 分数映射（渗透视角：能不能稳定干活）。na(代理未启用)不计入。
_GRADE_SCORE = {"good": 100, "fair": 70, "poor": 40, "dead": 0}
# 各维度权重（关键依赖最重——LLM/情报断=AI渗透/情报直接瘫；出网稳定性次之；代理未启用不参与）。
_DIM_WEIGHT = {"deps": 0.35, "stability": 0.30, "ping": 0.15, "dns": 0.15, "proxy": 0.05}


def _deps_grade(deps: Dict[str, Any]) -> str:
    """关键依赖体检没有单项 grade，按可达比例折算：全通=good / 断1个=fair / 断多个=poor / 全断=dead。"""
    total = deps.get("total", 0) or 0
    down = deps.get("down_count", 0) or 0
    if total == 0:
        return "fair"
    if down == 0:
        return "good"
    if down >= total:
        return "dead"
    return "fair" if down == 1 else "poor"


def overall_assessment(ping: Any, stability: Any, dns: Any, deps: Any, proxy: Any) -> Dict[str, Any]:
    """综合评估：把5项 grade 加权聚合成总分(0-100)+总评级(优/良/一般/差/严重)+一句诊断。
    **就低不就高**：任一关键维度(依赖/出网)为 dead → 总评级封顶到"差"（避免其他项good掩盖硬伤）。
    代理未启用(na)不计入权重（未启用是正常状态，不拉低总分）。"""
    dims = {}
    if isinstance(ping, dict) and ping.get("grade"):
        dims["ping"] = ping["grade"]
    if isinstance(stability, dict) and stability.get("targets"):
        # 出网稳定性取多目标里最差的（就低）
        gs = [t.get("grade", "fair") for t in stability["targets"]]
        worst = min(gs, key=lambda g: _GRADE_SCORE.get(g, 70)) if gs else "fair"
        dims["stability"] = worst
    if isinstance(dns, dict) and dns.get("grade"):
        dims["dns"] = dns["grade"]
    if isinstance(deps, dict) and "total" in deps:
        dims["deps"] = _deps_grade(deps)
    if isinstance(proxy, dict) and proxy.get("grade") and proxy.get("grade") != "na":
        dims["proxy"] = proxy["grade"]

    if not dims:
        return {"score": 0, "level": "unknown", "level_text": "未知", "summary": "无有效检测数据",
                "dims": {}}
    # 加权平均（只对参与的维度按其权重归一化）
    tw = sum(_DIM_WEIGHT.get(k, 0.1) for k in dims)
    score = sum(_GRADE_SCORE.get(g, 70) * _DIM_WEIGHT.get(k, 0.1) for k, g in dims.items()) / (tw or 1)
    score = round(score)
    # 关键维度 dead → 封顶（就低不就高）
    key_dead = dims.get("deps") == "dead" or dims.get("stability") == "dead"
    # 评级：优(≥90)/良(≥75)/一般(≥55)/差(≥30)/严重(<30)；关键维度dead时封顶到"差"
    if key_dead:
        score = min(score, 45)
    if score >= 90:
        level, text = "excellent", "优"
    elif score >= 75:
        level, text = "good", "良"
    elif score >= 55:
        level, text = "fair", "一般"
    elif score >= 30:
        level, text = "poor", "差"
    else:
        level, text = "critical", "严重"
    # 一句诊断：点出最短板
    weak = [k for k, g in dims.items() if g in ("dead", "poor")]
    _label = {"deps": "平台依赖不可达", "stability": "出网不稳定", "ping": "链路质量差",
              "dns": "DNS解析异常", "proxy": "代理出口异常"}
    if not weak:
        summary = "网络环境良好，各项检测正常" if score >= 90 else "网络环境基本可用，无明显短板"
    else:
        summary = "主要问题：" + "、".join(_label.get(w, w) for w in weak)
    return {"score": score, "level": level, "level_text": text, "summary": summary, "dims": dims}


# ======================== 体检结果持久化 + 定时跑（v1.21.148-12）========================
_NETCHECK_COLL = "netcheck_result"   # 只存最新一条(name=latest)，定时监测/态势总览读它


def run_and_save_quality(ping_host: str = "scanme.nmap.org") -> Dict[str, Any]:
    """跑完整5项体检 + 综合总评，落库最新结果（供定时监测/态势总览/体检页读缓存）。
    串行跑（定时后台线程调用，不占 gunicorn 请求）；任一项异常降级不中断整体。"""
    import time as _t
    def _safe(fn, *a):
        try:
            return fn(*a)
        except Exception as exc:
            logger.debug("netcheck item degraded: %s", exc)
            return None
    ping = _safe(ping_quality, ping_host, 10)
    stability = _safe(egress_stability, None, 5)
    dns = _safe(dns_health, "www.baidu.com")
    deps = _safe(deps_healthcheck)
    proxy = _safe(proxy_egress_quality)
    return save_quality_result(ping, stability, dns, deps, proxy)


def save_quality_result(ping: Any, stability: Any, dns: Any, deps: Any, proxy: Any) -> Dict[str, Any]:
    """把一组体检结果算总评 + 落库最新（定时监测和前端手动体检共用此落库逻辑）。"""
    import time as _t
    assess = overall_assessment(ping, stability, dns, deps, proxy)
    doc = {"name": "latest", "checked_at": _t.strftime("%Y-%m-%d %H:%M:%S"),
           "checked_ts": _t.time(), "assess": assess,
           "ping": ping, "stability": stability, "dns": dns, "deps": deps, "proxy": proxy}
    try:
        get_repo().collection(_NETCHECK_COLL).update_one(
            {"name": "latest"}, {"$set": doc}, upsert=True)
    except Exception as exc:
        logger.debug("save netcheck result degraded: %s", exc)
    return doc


def get_latest_quality() -> Dict[str, Any]:
    """读最新落库的体检结果（态势总览/体检页进页展示用）。无数据返回 {has_data:False}。"""
    try:
        doc = get_repo().collection(_NETCHECK_COLL).find_one({"name": "latest"})
        if not doc:
            return {"has_data": False}
        doc.pop("_id", None)
        doc["has_data"] = True
        return doc
    except Exception as exc:
        logger.debug("get latest netcheck degraded: %s", exc)
        return {"has_data": False}


# ======================== 服务门面 ========================

class NetworkCheckServiceImpl:
    """网络检测能力（无 ROLE，字符串键 network_check_service 注册）。"""

    def get_dns_config(self) -> Dict[str, Any]:
        return get_dns_config()

    def save_dns_config(self, servers: List[str]) -> Dict[str, Any]:
        return save_dns_config(servers)

    def ping(self, host: str, count: int = 4) -> str:
        return do_ping(host, count)

    # —— 网络质量检测（v1.21.148-10）——
    def ping_quality(self, host: str, count: int = 10) -> Dict[str, Any]:
        return ping_quality(host, count)

    def egress_stability(self, targets: Any = None, rounds: int = 5) -> Dict[str, Any]:
        return egress_stability(targets, rounds)

    def dns_health(self, host: str = "www.baidu.com") -> Dict[str, Any]:
        return dns_health(host)

    def deps_healthcheck(self) -> Dict[str, Any]:
        return deps_healthcheck()

    def proxy_egress_quality(self) -> Dict[str, Any]:
        return proxy_egress_quality()

    def overall_assessment(self, ping: Any, stability: Any, dns: Any, deps: Any, proxy: Any) -> Dict[str, Any]:
        return overall_assessment(ping, stability, dns, deps, proxy)

    def run_and_save_quality(self, ping_host: str = "scanme.nmap.org") -> Dict[str, Any]:
        return run_and_save_quality(ping_host)

    def save_quality_result(self, ping: Any, stability: Any, dns: Any, deps: Any, proxy: Any) -> Dict[str, Any]:
        return save_quality_result(ping, stability, dns, deps, proxy)

    def get_latest_quality(self) -> Dict[str, Any]:
        return get_latest_quality()


_service = NetworkCheckServiceImpl()


def get_service() -> NetworkCheckServiceImpl:
    return _service
