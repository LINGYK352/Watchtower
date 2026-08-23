"""nuclei 对接 —— 模板化漏洞扫描（external/nuclei，MIT / ProjectDiscovery）。

输入：目标 URL 列表（stdin）。原始输出 JSONL，形如：
  {"template-id":"CVE-..","template-url":"..","info":{"name":"..","severity":"high"},
   "matched-at":"https://a/x","host":"a.com"}
结构化 → NucleiRec（字段对齐 nuclei_result 集合）。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..base import ExternalTool
from ..models import NucleiRec


class Nuclei(ExternalTool):
    binary = "nuclei"
    adapter = "nuclei"

    def build_argv(self, concurrency: int = 25, **kwargs: Any) -> List[str]:
        return ["-silent", "-jsonl", "-c", str(concurrency)]

    def parse_record(self, obj: Dict[str, Any]) -> Optional[NucleiRec]:
        info = obj.get("info")
        if not isinstance(info, dict):
            info = {}
        target = obj.get("host") or obj.get("matched-at") or ""
        if not target:
            return None
        return NucleiRec(
            target=target,
            template_id=obj.get("template-id", ""),
            template_url=obj.get("template-url", ""),
            vuln_name=info.get("name", ""),
            vuln_severity=info.get("severity", ""),
            vuln_url=obj.get("matched-at", ""),
        )

    def scan(self, targets: Iterable[str], concurrency: int = 25) -> List[NucleiRec]:
        return self.run(stdin_lines=targets, concurrency=concurrency)
