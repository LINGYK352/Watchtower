"""侦察结构化记录 —— 对接模块的"成品"数据模型（防腐层输出）。

纯 dataclass，零存储/框架依赖：只表达"侦察发现了什么"，怎么落库是消费方（intel/
storage）的事。字段命名对齐生产 Mongo 集合（数据契约见 云端/docs/INTERFACES.md §一），
保证平台层零改动消费；但模型本身不含 to_document，不被 Mongo 字段形状绑架。

约定：查询/动作返回这些 dataclass 的 list；消费方用 dataclasses.asdict() 落库或直接读属性。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PortInfo:
    """单个开放端口及服务识别（对齐 ip.port_info[] 元素）。"""
    port_id: int
    service_name: str = ""
    version: str = ""
    protocol: str = "tcp"
    product: str = ""


@dataclass
class DomainRec:
    """一条域名解析记录（对齐 domain 集合）。"""
    domain: str
    record: List[str] = field(default_factory=list)
    type: str = "A"
    ips: List[str] = field(default_factory=list)
    source: str = "recon"


@dataclass
class IPRec:
    """一个 IP 及其开放端口（对齐 ip 集合；geo/cdn 由富化回填）。"""
    ip: str
    ports: List[PortInfo] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)


@dataclass
class SiteRec:
    """一个存活站点（对齐 site 集合；tag/screenshot 由平台/截图回填）。"""
    url: str
    hostname: str = ""
    ip: str = ""
    title: str = ""
    status: int = 0
    headers: str = ""
    http_server: str = ""
    body_length: int = 0
    finger: List[Dict[str, Any]] = field(default_factory=list)
    favicon: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NucleiRec:
    """一个 nuclei 模板命中（对齐 nuclei_result 集合）。"""
    target: str
    template_id: str = ""
    template_url: str = ""
    vuln_name: str = ""
    vuln_severity: str = ""
    vuln_url: str = ""


@dataclass
class VulnRec:
    """一个 PoC/弱口令/未授权发现（对齐 vuln 集合 PoC 结构）。"""
    target: str
    vul_name: str = ""
    plg_name: str = ""
    plg_type: str = "poc"          # poc / brute
    app_name: str = ""
    verify_data: str = ""


@dataclass
class WihRec:
    """一条 JS 挖掘发现（对齐 wih 集合：域名/接口/密钥/IP/手机/邮箱）。"""
    record_type: str               # domain / url / ip / ip_port / mail / mobile / secret
    content: str
    site: str = ""
    source: str = "webinfohunter"


@dataclass
class CertRec:
    """一张 TLS 证书（对齐 cert 集合）。task_id 由消费方/pipeline 落库时补，本模型不含。"""
    ip: str
    port: int
    cert: str = ""                 # PEM 编码证书文本


@dataclass
class FileLeakRec:
    """一条文件/路径泄漏命中（对齐 fileleak 集合）。task_id 由消费方落库时补。"""
    site: str
    url: str
    title: str = ""
    status_code: int = 0
    content_length: int = 0


@dataclass
class UrlRec:
    """一条爬虫发现的 URL（对齐 url 集合）。task_id/fld 由消费方落库时补。"""
    site: str
    url: str
    title: str = ""
    status_code: int = 0
    content_length: int = 0
    source: str = "site_spider"
