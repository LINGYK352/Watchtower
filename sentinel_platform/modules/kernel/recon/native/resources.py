"""PhantomJS 动态资源适配：捕获页面真实加载资源/XHR 与最终 DOM，输出结构化字典。"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List
from urllib.parse import urlparse

from .screenshot import default_phantomjs


def default_script() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources.js")


class DynamicResources:
    adapter = "phantomjs_resources"

    def __init__(self, phantomjs_path: str = "", script_path: str = "", timeout: int = 40):
        self.phantomjs_path = phantomjs_path or default_phantomjs()
        self.script_path = script_path or default_script()
        self.timeout = int(timeout or 40)

    def available(self) -> bool:
        return os.path.isfile(self.phantomjs_path) and os.path.isfile(self.script_path)

    def capture(self, site: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"site": site, "available": self.available(), "resources": [],
                               "js": [], "apis": [], "dom": "", "degraded": False}
        if not self.available():
            out["degraded"] = True
            out["reason"] = "phantomjs unavailable"
            return out
        try:
            proc = subprocess.run(
                [self.phantomjs_path, "--ignore-ssl-errors=true", "--ssl-protocol=any",
                 self.script_path, site, str(self.timeout * 1000)],
                capture_output=True, text=True, timeout=self.timeout + 10, check=False)
            base_host = (urlparse(site).hostname or "").lower()
            seen = set()
            for line in (proc.stdout or "").splitlines():
                try:
                    item = json.loads(line)
                except (TypeError, ValueError):
                    continue
                if item.get("type") == "dom":
                    out["dom"] = item.get("content", "")
                    continue
                url = item.get("url", "")
                if not url or url in seen:
                    continue
                seen.add(url); out["resources"].append(url)
                path = urlparse(url).path.lower()
                if path.endswith(".js") or ".js?" in url.lower():
                    out["js"].append(url)
                elif (urlparse(url).hostname or "").lower() == base_host:
                    out["apis"].append(url)
            out["ok"] = proc.returncode == 0
            return out
        except Exception as exc:
            out.update({"degraded": True, "reason": str(exc), "ok": False})
            return out
