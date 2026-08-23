"""recon/enrich —— 侦察富化层（autotag 站点打标 + IP 富化 ip_type/CDN/GeoIP）。

**定位**：不是扫描能力（tools/ 是 external 工具、native/ 是纯 Py 探测），而是 pipeline
在 http/端口阶段**之后**对已发现记录的**后处理富化**。产出对齐生产 Mongo schema
（见 云端/docs/INTERFACES.md §一）的富化字段：
  - `ip` 集合：`ip_type`(PUBLIC/PRIVATE) / `cdn_name` / `geo_asn` / `geo_city`
  - `site` 集合：`tag[]`(入口/无效 自动打标) / `fld`(一级域名 eTLD+1)

**在 dict 层富化（关键设计）**：recon/models 的 IPRec/SiteRec 是冻结的结构化记录，
故意不含富化字段；pipeline 把记录 `dataclasses.asdict()` 后、落库前调用本层就地补字段。
本层因此不 import、不依赖 models（也不改共享的 models.py / registry.py），
纯操作 dict —— 换记录形状不影响富化，加富化维度不动扫描层。

**GeoIP 惰性降级**：读 external/geolite2 的 GeoLite2-City.mmdb / GeoLite2-ASN.mmdb。
`maxminddb` 库惰性 import（对齐 core/db.py 惰性 pymongo），未装库 / 无 mmdb 文件 →
不填 geo_* 字段、不报错（honest degrade）。单测 mock reader 不需真库/真数据。

参照旧引擎 sentinel_engine/enrich/{autotag,enricher}.py 逻辑净室重写（字段对齐属数据契约，非抄源码）。
供 recon pipeline(P1) 的富化阶段直接 import 消费：`from .enrich import build_enricher`。
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any, Dict, List, Optional

# —— autotag：默认容器/占位标题（命中判"无效"站点）——————————————
_INVALID_TITLE_MARKERS = (
    "welcome to nginx", "iis windows", "apache tomcat", "test page",
    "index of /", "403 forbidden", "404 not found", "400 bad request",
    "500 internal", "502 bad gateway", "503 service", "504 gateway",
    "default web site", "it works", "coming soon", "under construction",
    "openresty", "welcome to your", "http server test page",
)

# —— CDN CNAME/hostname 特征片段（命中即标 CDN；小集，数据驱动可扩充）——————
_CDN_MARKERS = (
    "cloudflare", "akamai", "fastly", "cdn", "cloudfront", "edgekey",
    "edgesuite", "azureedge", "aliyuncs", "qcloud", "wscdns", "chinacache",
    "incapdns", "cdngslb", "kunlun", "bsclink", "lxdns", "cdnhwc",
    "dnsv1", "tbcache", "yunjiasu", "ourwebcdn", "cachefly",
)

# 一级域名（eTLD+1）启发式：双级后缀集（数据驱动，可扩充）
_TWO_LEVEL_SUFFIX = frozenset((
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.uk", "org.uk", "gov.uk", "com.hk", "org.hk", "com.tw",
    "co.jp", "com.au", "net.au", "com.sg", "com.my",
))

# RFC 6598 CGNAT（运营商级 NAT）网段，跨 py 版本显式兜底 PRIVATE
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


# ============ 纯函数辅助（无副作用，单测友好，不依赖任何库）============

def classify_ip(ip: str) -> str:
    """判定 IP 归属：PUBLIC / PRIVATE / ""(非 IP)。

    用 stdlib ipaddress（比手写网段判定更健壮：覆盖 IPv6、loopback、link-local、
    保留段等）。私网/环回/链路本地/保留/多播/未指定 → PRIVATE，全球可路由 → PUBLIC。
    另显式兜底 RFC 6598 CGNAT 段 100.64.0.0/10（运营商级 NAT，不可直接路由，等同内网）——
    Python <3.11.4 的 is_private 未纳入此段，显式判定保证跨版本一致。
    """
    if not ip or not isinstance(ip, str):
        return ""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return ""
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return "PRIVATE"
    if addr.is_multicast or addr.is_unspecified:
        return "PRIVATE"
    if addr in _CGNAT_NET:                       # RFC 6598 运营商级 NAT，跨 py 版本兜底
        return "PRIVATE"
    return "PUBLIC"


def extract_fld(host: str) -> str:
    """粗略提取一级域名 (eTLD+1)。IP / 空 原样返回。

    启发式降级实现（不引 tldextract/PSL）：保证 fld 非空且对多数常见域名正确。
    双级后缀（com.cn/co.uk 等）取三段，其余取末两段。
    """
    if not host or not isinstance(host, str):
        return ""
    host = host.strip().strip(".").lower()
    if not host:
        return ""
    # IP 原样返回（IPv4/IPv6 都不做域名切分）
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _TWO_LEVEL_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def auto_tag(site: Dict[str, Any]) -> List[str]:
    """站点自动打标 → ["入口"] 或 ["无效"]。site 为 dict（对齐 site 集合字段）。

    规则（对齐 ARL AutoTag 启发式，净室重写）：
    - 4xx/5xx 状态 → 无效
    - 默认容器/占位标题 → 无效
    - body 过小且无标题 → 无效
    - 其余有实质内容 → 入口
    """
    try:
        status = int(site.get("status") or 0)
    except (ValueError, TypeError):
        status = 0
    title = str(site.get("title") or "").strip().lower()
    try:
        body_len = int(site.get("body_length") or 0)
    except (ValueError, TypeError):
        body_len = 0

    if status and 400 <= status < 600:
        return ["无效"]
    if title and any(m in title for m in _INVALID_TITLE_MARKERS):
        return ["无效"]
    if body_len < 300 and not title:
        return ["无效"]
    return ["入口"]


def detect_cdn(hostnames: List[str]) -> str:
    """据关联域名/CNAME 的特征片段判 CDN，返回命中的 marker（无则 ""）。"""
    for host in hostnames or []:
        low = str(host or "").lower()
        for marker in _CDN_MARKERS:
            if marker in low:
                return marker
    return ""


def default_geolite_dir() -> str:
    """external/geolite2 默认目录（从本文件向上定位仓库根 → external/geolite2）。

    本文件在 sentinel_platform/modules/kernel/recon/enrich.py，向上 5 层到仓库根。
    """
    here = os.path.abspath(__file__)
    # recon -> kernel -> modules -> sentinel_platform -> <root>
    root = here
    for _ in range(5):
        root = os.path.dirname(root)
    return os.path.join(root, "external", "geolite2")


# ============ GeoIP 读取（惰性 maxminddb，缺库/缺文件降级）============

class GeoIPResolver:
    """读 GeoLite2 mmdb 的惰性封装：City（国家/城市）+ ASN（自治域号/组织）。

    - maxminddb 库惰性 import（首次查询才 open），未装 → 全降级返回 {}。
    - mmdb 文件路径可显式传入，否则默认 external/geolite2/GeoLite2-{City,ASN}.mmdb。
    - reader 打开失败（文件缺失/损坏）→ 该库降级，不影响另一库、不报错。
    - 单测通过注入 _city_reader / _asn_reader（鸭子类型 .get(ip)）即可 mock，不需真库/真数据。
    """

    def __init__(self, city_db: str = "", asn_db: str = ""):
        base = default_geolite_dir()
        self.city_db = city_db or os.path.join(base, "GeoLite2-City.mmdb")
        self.asn_db = asn_db or os.path.join(base, "GeoLite2-ASN.mmdb")
        self._city_reader: Any = None
        self._asn_reader: Any = None
        self._city_tried = False
        self._asn_tried = False

    def _open(self, path: str) -> Any:
        if not path or not os.path.isfile(path):
            return None
        try:
            import maxminddb  # 惰性；未装则降级
        except Exception:
            return None
        # 先试默认（Linux ASCII 路径下走 C 扩展 mmap，最快最省内存：demand-paged 页共享）；
        # 失败降级 MODE_FILE（纯 Python seek 读，不载入全文件=低内存，且避开 C 扩展对
        # 非 ASCII 绝对路径的 FileNotFoundError bug——Windows 中文路径实测触发）。
        try:
            return maxminddb.open_database(path)
        except Exception:
            pass
        try:
            return maxminddb.open_database(path, maxminddb.MODE_FILE)
        except Exception:
            return None

    def _get_city_reader(self) -> Any:
        if not self._city_tried:
            self._city_tried = True
            self._city_reader = self._open(self.city_db)
        return self._city_reader

    def _get_asn_reader(self) -> Any:
        if not self._asn_tried:
            self._asn_tried = True
            self._asn_reader = self._open(self.asn_db)
        return self._asn_reader

    def city(self, ip: str) -> Dict[str, Any]:
        """→ {country, city}（英文名）。查不到/降级 → {}。"""
        reader = self._get_city_reader()
        if reader is None:
            return {}
        try:
            rec = reader.get(ip)
            if not rec:
                return {}
            country = ((rec.get("country") or {}).get("names") or {}).get("en", "")
            city = ((rec.get("city") or {}).get("names") or {}).get("en", "")
            out: Dict[str, Any] = {}
            if country:
                out["country"] = country
            if city:
                out["city"] = city
            return out
        except Exception:
            return {}

    def asn(self, ip: str) -> Dict[str, Any]:
        """→ {number, org}（自治域号 + 组织名）。查不到/降级 → {}。"""
        reader = self._get_asn_reader()
        if reader is None:
            return {}
        try:
            rec = reader.get(ip)
            if not rec:
                return {}
            out: Dict[str, Any] = {}
            num = rec.get("autonomous_system_number")
            org = rec.get("autonomous_system_organization")
            if num is not None:
                out["number"] = num
            if org:
                out["org"] = org
            return out
        except Exception:
            return {}

    def close(self) -> None:
        for r in (self._city_reader, self._asn_reader):
            try:
                if r is not None:
                    r.close()
            except Exception:
                pass


# ============ Enricher：pipeline 消费的富化入口 ============

class Enricher:
    """侦察富化器：就地补 IP / 站点记录（dict）的富化字段。

    用法（pipeline 富化阶段）：
        enr = build_enricher(config)
        enr.enrich_ips(ip_dicts, cdn_hint={ip: [cname,...]})   # 就地填 ip_type/cdn_name/geo_*
        enr.enrich_sites(site_dicts)                            # 就地填 tag/fld

    **禁硬限制参数**：不对记录数量设上限，全量遍历富化（GeoIP 只对 PUBLIC 且未填的查）。
    """

    def __init__(self, geoip: Optional[GeoIPResolver] = None):
        self.geoip = geoip

    # —— IP 富化 ————————————————————————————————
    def enrich_ip(self, rec: Dict[str, Any], cdn_hint: Optional[List[str]] = None) -> Dict[str, Any]:
        """就地富化单条 IP dict，返回同一 dict。

        - ip_type：未填才判（PUBLIC/PRIVATE）
        - cdn_name：未填才判，据 cdn_hint（CNAME 列表，DNS 阶段更准）+ 关联 domain 兜底
        - geo_asn / geo_city：仅 PUBLIC 且未填、且 GeoIP 就绪时查
        """
        ip = str(rec.get("ip") or "").strip()
        if not rec.get("ip_type"):
            rec["ip_type"] = classify_ip(ip)
        if not rec.get("cdn_name"):
            hosts = list(cdn_hint or []) + list(rec.get("domain") or rec.get("domains") or [])
            cdn = detect_cdn(hosts)
            if cdn:
                rec["cdn_name"] = cdn
        if self.geoip is not None and rec.get("ip_type") == "PUBLIC":
            if not rec.get("geo_city"):
                city = self.geoip.city(ip)
                if city:
                    rec["geo_city"] = city
            if not rec.get("geo_asn"):
                asn = self.geoip.asn(ip)
                if asn:
                    rec["geo_asn"] = asn
        return rec

    def enrich_ips(self, recs: List[Dict[str, Any]],
                   cdn_hint: Optional[Dict[str, List[str]]] = None) -> List[Dict[str, Any]]:
        """批量就地富化 IP dict 列表。cdn_hint: {ip: [cname,...]} 可选。"""
        hint = cdn_hint or {}
        for r in recs or []:
            self.enrich_ip(r, cdn_hint=hint.get(str(r.get("ip") or "").strip()))
        return recs

    # —— 站点富化 ————————————————————————————————
    def enrich_site(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """就地富化单条站点 dict：tag（未填才打）+ fld（未填才补，据 hostname/site）。"""
        if not rec.get("tag"):
            rec["tag"] = auto_tag(rec)
        if not rec.get("fld"):
            host = rec.get("hostname") or _host_from_url(rec.get("site") or rec.get("url") or "")
            fld = extract_fld(host)
            if fld:
                rec["fld"] = fld
        return rec

    def enrich_sites(self, recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量就地富化站点 dict 列表。"""
        for r in recs or []:
            self.enrich_site(r)
        return recs


def _host_from_url(url: str) -> str:
    """从 url 取 hostname（无 scheme 也兼容）。仅用于 fld 兜底，失败返 ""。"""
    if not url or not isinstance(url, str):
        return ""
    from urllib.parse import urlsplit
    u = url.strip()
    if "://" not in u:
        u = "//" + u
    try:
        return (urlsplit(u).hostname or "").lower()
    except Exception:
        return ""


def build_enricher(config: Any = None) -> Enricher:
    """按配置装配富化器。config 具属性 geolite_city_db / geolite_asn_db / geolite_dir 时优先，
    否则用 external/geolite2 默认路径。GeoIP 缺库/缺文件时 Enricher 仍可用（只跳 geo_*）。
    """
    def _cfg(name: str, default: Any = "") -> Any:
        return getattr(config, name, default) if config is not None else default

    city = _cfg("geolite_city_db")
    asn = _cfg("geolite_asn_db")
    gdir = _cfg("geolite_dir")
    if gdir and not city:
        city = os.path.join(gdir, "GeoLite2-City.mmdb")
    if gdir and not asn:
        asn = os.path.join(gdir, "GeoLite2-ASN.mmdb")
    return Enricher(geoip=GeoIPResolver(city_db=city, asn_db=asn))

