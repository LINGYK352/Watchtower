"""subfinder 对接 —— 子域名**被动枚举**（MIT / ProjectDiscovery）。

域名任务第一步、扫描能力最关键缺口：从被动源（证书透明日志/DNS 聚合/搜索引擎等）枚举子域名，
不主动发包解析。原始输出 `-silent -json`（一行一发现）→ 结构化 DomainRec（对齐 domain 集合）。

被动枚举**不解析 IP**（那是 dnsx/T2 massdns 的活）：故 DomainRec.record/ips 空、type="SUBDOMAIN"
（区别 dnsx 的 A/CNAME），source="subfinder"，供后续 pipeline 把这些子域名喂给 dnsx 解析。

**归属过滤**（防越界）：subfinder 偶因 CNAME/通配返回不属查询主域的名字；只放行以 `.<root>` 结尾
或等于 root 的 host（root 取 JSON 的 input，或调用方传 scope）。
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set

from ..base import ExternalTool
from ..models import DomainRec


def _belongs(host: str, root: str) -> bool:
    """host 是否属于 root（等于 root 或其子域）。root 空则不限（放行）。"""
    if not root:
        return True
    host = host.strip(".").lower()
    root = root.strip(".").lower()
    return host == root or host.endswith("." + root)


class Subfinder(ExternalTool):
    binary = "subfinder"
    adapter = "subfinder"

    def __init__(self, binary_path: str = "", timeout: int = 1800,
                 max_time: int = 3, source_timeout: int = 15):
        """max_time: subfinder 整体枚举上限(分钟,默认3;subfinder 默认10太长,多域名串行会累积到十几分钟);
        source_timeout: 单个被动源等待上限(秒,默认15;subfinder 默认30)。二者都可配,非硬 cap 业务量——
        只是给"境外源 DNS 高并发解析慢/不通"的枚举一个可控时间上限(见 subfinder DNS misbehaving 排查)。"""
        super().__init__(binary_path=binary_path, timeout=timeout)
        self.max_time = int(max_time)
        self.source_timeout = int(source_timeout)

    def build_argv(self, all_sources: bool = False, sources: Optional[List[str]] = None,
                   provider_config: str = "", **kwargs: Any) -> List[str]:
        # -silent 只出结果不出 banner；-json 结构化；-all 用全部源（更全但更慢，默认关，由调用方按需开）
        # -max-time/-timeout 给枚举可控时间上限（默认值偏长，多域名串行会卡十几分钟，见排查记录）。
        argv = ["-silent", "-json"]
        if self.max_time > 0:
            argv += ["-max-time", str(self.max_time)]
        if self.source_timeout > 0:
            argv += ["-timeout", str(self.source_timeout)]
        if all_sources:
            argv.append("-all")
        if sources:
            argv += ["-s", ",".join(s for s in sources if s)]
        if provider_config:
            argv += ["-pc", provider_config]
        return argv

    def parse_record(self, obj: Dict[str, Any]) -> Optional[DomainRec]:
        host = obj.get("host")
        if not isinstance(host, str) or not host.strip():
            return None
        host = host.strip().lower().rstrip(".")
        root = obj.get("input")                       # subfinder 回填被查询的主域
        if isinstance(root, str) and root and not _belongs(host, root):
            return None                               # 越界子域名丢弃（归属过滤）
        return DomainRec(domain=host, record=[], type="SUBDOMAIN", ips=[], source="subfinder")

    def enumerate(self, domains: Iterable[str], all_sources: bool = False,
                  scope: Optional[Set[str]] = None) -> List[DomainRec]:
        """被动枚举一批主域的子域名。scope 传入则额外按其过滤（多主域任务防串域）；去重同名。"""
        recs = self.run(stdin_lines=domains, all_sources=all_sources)
        return self._filter_records(recs, scope)

    def enumerate_sources(self, domains: Iterable[str], credentials: Dict[str, str],
                          scope: Optional[Set[str]] = None) -> List[DomainRec]:
        """仅运行策略选中的、已配置凭据的 API 来源。

        subfinder 只接受 provider-config 文件，因此凭据写入 0600 临时文件；调用结束无论成功失败
        都删除。不复用 HOME 全局配置，避免并发任务互相覆盖来源选择或把密钥留在热更新目录。
        """
        creds = {str(k).strip(): str(v).strip() for k, v in (credentials or {}).items()
                 if str(k).strip() and str(v).strip()}
        if not creds:
            return []
        path = ""
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml",
                                             prefix="watchtower-subfinder-", delete=False) as fp:
                path = fp.name
                for source, credential in creds.items():
                    # JSON 字符串是合法 YAML 标量，可安全承载冒号/@ 等复合凭据字符。
                    fp.write("{}:\n  - {}\n".format(source, json.dumps(credential, ensure_ascii=False)))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            recs = self.run(stdin_lines=domains, sources=list(creds), provider_config=path)
            return self._filter_records(recs, scope)
        finally:
            if path:
                try:
                    os.remove(path)
                except OSError:
                    pass

    @staticmethod
    def _filter_records(recs: Iterable[DomainRec], scope: Optional[Set[str]]) -> List[DomainRec]:
        """统一去重 + scope 过滤，供公共源和选定 API 源共用。"""
        out: List[DomainRec] = []
        seen: Set[str] = set()
        for r in recs:
            if r.domain in seen:
                continue
            if scope and not any(_belongs(r.domain, s) for s in scope):
                continue
            seen.add(r.domain)
            out.append(r)
        return out
