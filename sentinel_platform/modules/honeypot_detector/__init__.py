"""honeypot_detector —— 蜜罐检测模块（集成 honeydet）。

职责：
  - 在 AI 渗透前检测目标是否为蜜罐
  - 集成 honeydet（Golang 开源工具）进行通用蜜罐检测（支持 SSH/HTTP/其他协议）
  - 补充自研检测逻辑（honeydet 未覆盖的特征）
  - 综合威胁情报（Shodan、GreyNoise 等）
  - 生成蜜罐检测报告，提前预警 AI

honeydet 能力：
  - 基于签名的多协议检测（TCP/UDP）
  - 支持多步骤、高交互分析
  - 支持 hex、string、regex 检测
  - 可检测 SSH、HTTP/Web、其他网络服务蜜罐

对外接口：
  - detect_honeypot(target) -> HoneypotReport
  - is_honeypot_detected(target) -> bool
  - get_detection_confidence(target) -> float

使用场景：
  - 策略配置中勾选"蜜罐检测"（默认勾选）
  - AI 渗透会话派发前自动检测
  - 检测到蜜罐时给 AI 预警，AI 判断是否继续
  - 确认是蜜罐的会话标记"蜜罐"标签
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from sentinel_platform.core import get_logger

logger = get_logger()


class HoneypotReport:
    """蜜罐检测报告"""

    def __init__(self):
        self.target: str = ""
        self.is_honeypot: bool = False
        self.confidence: float = 0.0  # 0-1，置信度
        self.detected_type: Optional[str] = None  # Cowrie, Kippo, Web Honeypot, etc.
        self.indicators: list[Dict[str, Any]] = []
        self.recommendation: str = ""
        self.detection_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "is_honeypot": self.is_honeypot,
            "confidence": self.confidence,
            "detected_type": self.detected_type,
            "indicators": self.indicators,
            "recommendation": self.recommendation,
            "detection_time": self.detection_time,
        }

    def __repr__(self) -> str:
        return f"<HoneypotReport {self.target} honeypot={self.is_honeypot} confidence={self.confidence:.2f}>"


def detect_honeypot(target: str, ports: Optional[list[int]] = None, timeout: int = 30) -> HoneypotReport:
    """检测目标是否为蜜罐（使用 honeydet + 自研补充）。

    参数:
        target: 目标地址（IP 或域名）
        ports: 要检测的端口列表（默认自动探测常见端口：22, 80, 443, 3306, 6379）
        timeout: 检测超时时间（秒）

    返回:
        HoneypotReport 对象
    """
    start_time = time.time()
    report = HoneypotReport()
    report.target = target

    # 默认检测常见端口
    if not ports:
        ports = [22, 80, 443, 3306, 6379]  # SSH, HTTP, HTTPS, MySQL, Redis

    try:
        # 1. 使用 honeydet 进行主要检测（支持多协议）
        honeydet_result = _detect_with_honeydet(target, ports, timeout)
        if honeydet_result:
            report.indicators.extend(honeydet_result.get("indicators", []))
            if honeydet_result.get("is_honeypot"):
                report.is_honeypot = True
                report.detected_type = honeydet_result.get("detected_type", "Unknown Honeypot")
                report.confidence = max(report.confidence, honeydet_result.get("confidence", 0.0))

        # 2. 自研补充检测（honeydet 未覆盖的特征）
        # 这里可以添加一些 honeydet 没有的检测逻辑，如：
        # - 网络拓扑异常（同 C 段大量相似主机）
        # - 响应时间特征分析
        # - 特定的 HTTP 行为模式
        supplementary_result = _supplementary_detection(target, ports, timeout)
        if supplementary_result:
            report.indicators.extend(supplementary_result.get("indicators", []))
            if supplementary_result.get("is_honeypot"):
                report.is_honeypot = True
                if not report.detected_type:
                    report.detected_type = supplementary_result.get("detected_type", "Unknown")
                # 综合两种检测的置信度（取最大值）
                report.confidence = max(report.confidence, supplementary_result.get("confidence", 0.0))

        # 3. 生成建议
        if report.is_honeypot:
            if report.confidence >= 0.8:
                report.recommendation = "高度疑似蜜罐，强烈建议停止渗透测试"
            elif report.confidence >= 0.5:
                report.recommendation = "疑似蜜罐，建议谨慎进行渗透测试，避免使用真实 IP"
            else:
                report.recommendation = "可能是蜜罐，建议进行进一步验证"
        else:
            report.recommendation = "未检测到明显蜜罐特征，可以继续渗透测试"

    except Exception as exc:
        logger.error(f"蜜罐检测异常: {exc}", exc_info=True)
        report.recommendation = "蜜罐检测失败，建议谨慎进行渗透测试"

    report.detection_time = time.time() - start_time
    logger.info(f"蜜罐检测完成: {report}")

    return report


def _detect_with_honeydet(target: str, ports: list[int], timeout: int) -> Optional[Dict[str, Any]]:
    """使用 honeydet 进行蜜罐检测（支持多协议：SSH、HTTP、其他服务）。

    honeydet 特性：
      - 基于签名的检测
      - 支持多步骤、高交互分析
      - 支持 TCP/UDP 协议
      - 可检测多种蜜罐类型

    返回:
        {
            "is_honeypot": bool,
            "confidence": float,
            "detected_type": str,
            "indicators": [{"type": str, "detail": str, "score": float}]
        }
    """
    honeydet_path = _get_honeydet_path()
    if not honeydet_path:
        logger.warning("honeydet 未安装，跳过 honeydet 检测")
        return None

    try:
        # honeydet 支持多端口检测
        # 根据 honeydet 的文档，可以传入多个端口进行检测
        all_indicators = []
        detected_types = []
        max_confidence = 0.0

        for port in ports:
            # 调用 honeydet 检测单个端口
            cmd = [
                honeydet_path,
                "-target", target,
                "-port", str(port),
                "-timeout", str(timeout),
                "-json"  # 输出 JSON 格式
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False
            )

            if result.returncode != 0:
                logger.debug(f"honeydet 检测端口 {port} 失败: {result.stderr}")
                continue

            # 解析 honeydet 输出
            output = result.stdout.strip()
            if not output:
                continue

            try:
                data = json.loads(output)

                # 提取检测结果
                is_honeypot = data.get("is_honeypot", False) or data.get("detected", False)
                if is_honeypot:
                    confidence = float(data.get("confidence", 0.0))
                    max_confidence = max(max_confidence, confidence)

                    detected_type = data.get("honeypot_type") or data.get("type")
                    if detected_type:
                        detected_types.append(f"{detected_type} (port {port})")

                    # 提取检测指标
                    for check in data.get("checks", []):
                        if check.get("detected"):
                            all_indicators.append({
                                "type": f"port_{port}_" + check.get("name", "unknown"),
                                "detail": check.get("description", ""),
                                "score": float(check.get("score", 0.0))
                            })
            except json.JSONDecodeError:
                logger.debug(f"honeydet 输出解析失败: {output}")
                continue

        # 综合所有端口的检测结果
        if all_indicators:
            return {
                "is_honeypot": True,
                "confidence": max_confidence,
                "detected_type": ", ".join(detected_types) if detected_types else "Unknown Honeypot",
                "indicators": all_indicators
            }

        return {"is_honeypot": False, "confidence": 0.0, "indicators": []}

    except subprocess.TimeoutExpired:
        logger.warning(f"honeydet 检测超时: {target}")
        return None
    except Exception as exc:
        logger.error(f"honeydet 检测异常: {exc}", exc_info=True)
        return None


def _supplementary_detection(target: str, ports: list[int], timeout: int) -> Optional[Dict[str, Any]]:
    """自研补充检测逻辑（honeydet 未覆盖的特征）。

    检测策略：
      1. HTTP/Web 特征（如果开放 80/443）
         - 404 页面过于简单
         - 静态资源缺失
         - 响应时间异常稳定
      2. 网络拓扑异常（未实现，需要网络扫描）
      3. 其他协议特征

    注意：这里只补充 honeydet 未覆盖的检测逻辑
    """
    indicators = []
    total_score = 0.0

    # 只对 HTTP/HTTPS 端口进行 Web 特征检测
    web_ports = [p for p in ports if p in (80, 443, 8080, 8443)]
    if not web_ports:
        return None

    try:
        import requests
    except ImportError:
        logger.warning("requests 未安装，跳过补充 Web 检测")
        return None

    # 尝试 HTTPS 优先，失败则 HTTP
    base_url = None
    for port in web_ports:
        proto = "https" if port in (443, 8443) else "http"
        url = f"{proto}://{target}:{port}" if port not in (80, 443) else f"{proto}://{target}"

        try:
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            if resp.status_code < 500:
                base_url = url
                break
        except Exception:
            continue

    if not base_url:
        return None

    try:
        # 检测1：404 页面特征
        import uuid
        resp_404 = requests.get(f"{base_url}/nonexistent-{uuid.uuid4()}",
                                timeout=5, verify=False, allow_redirects=False)
        if resp_404.status_code == 404 and len(resp_404.text) < 500:
            indicators.append({
                "type": "web_simple_404",
                "detail": f"404 页面过于简单（{len(resp_404.text)} 字节），真实网站通常有自定义 404 页面",
                "score": 0.15
            })
            total_score += 0.15

        # 检测2：响应时间异常稳定
        if _has_timing_anomaly(base_url):
            indicators.append({
                "type": "web_timing_anomaly",
                "detail": "多次请求响应时间过于稳定，缺少真实服务器的缓存/负载特征",
                "score": 0.15
            })
            total_score += 0.15

        # 检测3：静态资源缺失
        home_resp = requests.get(base_url, timeout=5, verify=False)
        if _has_missing_assets(home_resp.text, base_url):
            indicators.append({
                "type": "web_missing_assets",
                "detail": "页面引用的 CSS/JS 资源不存在，可能是伪造的网站",
                "score": 0.2
            })
            total_score += 0.2

    except Exception as exc:
        logger.warning(f"补充 Web 检测异常: {exc}")

    # 置信度阈值：补充检测较保守，只有总分 >= 0.4 才判定为蜜罐
    if total_score >= 0.4:
        return {
            "is_honeypot": True,
            "confidence": min(total_score, 0.7),  # 补充检测最高 0.7，主要依赖 honeydet
            "detected_type": "Web Honeypot",
            "indicators": indicators
        }

    return {"is_honeypot": False, "confidence": 0.0, "indicators": indicators}


def _has_missing_assets(html: str, base_url: str) -> bool:
    """检测页面引用的静态资源是否存在。"""
    try:
        import re
        import requests

        # 提取 CSS/JS 引用
        css_pattern = r'<link[^>]+href=["\'](.*?\.css)["\']'
        js_pattern = r'<script[^>]+src=["\'](.*?\.js)["\']'

        assets = re.findall(css_pattern, html) + re.findall(js_pattern, html)
        if not assets:
            return False  # 没有资源引用，不能判断

        # 检查前 3 个资源
        missing_count = 0
        for asset in assets[:3]:
            if asset.startswith("http"):
                url = asset
            elif asset.startswith("/"):
                url = base_url + asset
            else:
                url = base_url + "/" + asset

            try:
                resp = requests.head(url, timeout=3, verify=False, allow_redirects=True)
                if resp.status_code >= 400:
                    missing_count += 1
            except Exception:
                missing_count += 1

        return missing_count >= 2  # 至少 2 个资源缺失

    except Exception:
        return False


def _has_timing_anomaly(base_url: str) -> bool:
    """检测响应时间是否异常稳定（蜜罐缺少真实缓存机制）。"""
    try:
        import requests
        import statistics

        times = []
        for _ in range(5):
            start = time.time()
            requests.get(base_url, timeout=5, verify=False)
            times.append(time.time() - start)
            time.sleep(0.5)

        # 计算标准差
        std_dev = statistics.stdev(times)

        # 真实服务器的响应时间波动较大（缓存、负载等因素）
        # 蜜罐的响应时间过于稳定
        return std_dev < 0.05  # 标准差小于 50ms 认为异常

    except Exception:
        return False


def _get_honeydet_path() -> Optional[str]:
    """获取 honeydet 可执行文件路径。

    查找顺序：
      1. 环境变量 HONEYDET_PATH
      2. /usr/local/bin/honeydet
      3. /usr/bin/honeydet
      4. ./tools/honeydet
    """
    # 1. 环境变量
    env_path = os.environ.get("HONEYDET_PATH")
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    # 2. 系统路径
    system_paths = [
        "/usr/local/bin/honeydet",
        "/usr/bin/honeydet",
        "/opt/honeydet/honeydet"
    ]

    for path in system_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # 3. 相对路径（开发环境）
    relative_paths = [
        "./tools/honeydet",
        "../tools/honeydet",
        "../../tools/honeydet"
    ]

    for path in relative_paths:
        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path) and os.access(abs_path, os.X_OK):
            return abs_path

    # 4. which 命令查找
    try:
        result = subprocess.run(["which", "honeydet"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    return None


def is_honeypot_available() -> bool:
    """检查蜜罐检测功能是否可用（honeydet 是否已安装）。"""
    return _get_honeydet_path() is not None


def get_honeydet_version() -> Optional[str]:
    """获取 honeydet 版本信息。"""
    honeydet_path = _get_honeydet_path()
    if not honeydet_path:
        return None

    try:
        result = subprocess.run(
            [honeydet_path, "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception:
        return None

