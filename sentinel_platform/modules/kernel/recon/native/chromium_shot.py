"""chromium_shot —— 站点截图（Playwright/Chromium 引擎，问题11 取代 phantomjs 黑屏）。

**为何存在**：PhantomJS 老 WebKit 不支持 ES6（Object.assign/Promise/箭头函数），现代 SPA 首屏 JS 崩→
DOM 渲不出→输出纯黑画布（实测坐实）。Chromium 支持 ES6，能正常渲染 SPA。本类与 phantomjs `Screenshot`
**同接口**（available/capture/adapter/rel_url），registry/pipeline chromium-first→phantomjs 兜底→skip。

**引擎机制**：Playwright CLI 子进程 `python -m playwright screenshot --browser chromium <url> <out>`
在 ThreadPoolExecutor 内 per-site 跑——规避 Playwright sync API 跨线程限制（见 ai_pentest/_browser_session
docstring）+ 进程级内存隔离（每个 chromium 独立 PID，内存池独立 gate）。**不 import playwright 进本模块**
（接入铁律：external 工具经对接模块 subprocess 调用，本文件即 chromium 的对接模块）。

**内存门控**：ThreadPool 宽度只是天花板（config，非内存限流）；每 _shot 经注入的 resource_gate
（recon_bridge 注入，守 recon 自包含）申请内存额度——内存不足则阻塞等待、让位 AI（问题11）。
**质量门**：截图后经 _shot_quality.assess_shot 过滤纯色/黑屏 + md5 去重（引擎无关）。
**禁硬限制参数**：sites 数量不砍，并发度只是线程池宽度 + 内存池实际限流。
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Tuple

from sentinel_platform.core import get_logger
from . import _shot_quality
from .screenshot import safe_name, default_image_dir

logger = get_logger()

ROLE_SCREENSHOT = "screenshot"


class ChromiumShot:
    """Playwright/Chromium 站点截图器。capture(sites, task_id) → {site_url: /image/task_id/xx.jpg}。
    同 phantomjs Screenshot 接口，可在 registry/pipeline 作 chromium-first 候选。"""

    adapter = "chromium_screenshot"

    def __init__(self, image_dir: str = "", url_prefix: str = "/image",
                 timeout: int = 30, concurrency: int = 2):
        self.image_dir = image_dir or default_image_dir()
        self.url_prefix = (url_prefix or "/image").rstrip("/")
        self.timeout = timeout
        # chromium 比 phantomjs 重，默认并发更低（天花板，真限流靠内存池）；下限保护，非上限。
        self.concurrency = max(1, int(concurrency))
        #: 注入点（recon_bridge 注入的纯 callable / None）：内存重工具执行前经它申请内存额度、让位 AI。
        self.resource_gate = None
        #: 协作式取消回调（Tools 注入 / None）。
        self.cancel_check = None
        self._exec_ok = None   # available() 执行探测结果缓存

    def available(self) -> bool:
        """playwright 可导入 + chromium 可执行文件在盘 + `playwright --version` 能跑，才可用。
        缺任一 → 不可用（pipeline chromium-first 取不到 → 降级 phantomjs → 都不行则 skip，诚实降级）。"""
        if self._exec_ok is not None:
            return self._exec_ok
        try:
            import importlib.util
            if importlib.util.find_spec("playwright") is None:
                self._exec_ok = False
                return False
            # chromium 可执行文件在盘（对齐 ai_pentest/_browser.available 的判据）
            from playwright.sync_api import sync_playwright  # noqa: F401 —— 仅探测可导入
            r = subprocess.run([sys.executable, "-m", "playwright", "--version"],
                               capture_output=True, timeout=20)
            self._exec_ok = (r.returncode == 0)
            if not self._exec_ok:
                err = (r.stderr or b"").decode("utf-8", "replace")[:200]
                logger.warning("playwright 存在但无法执行（截图降级 phantomjs）：%s", err)
        except Exception as exc:
            self._exec_ok = False
            logger.warning("chromium 截图不可用（降级 phantomjs），playwright/chromium 未就绪：%s", exc)
        return bool(self._exec_ok)

    def rel_url(self, task_id: str, fname: str) -> str:
        """截图相对路径（写入 site.screenshot；前端拼 /api → /api/image/task_id/fname）。"""
        return "{}/{}/{}".format(self.url_prefix, task_id, fname)

    def _cancelled(self) -> bool:
        if self.cancel_check is None:
            return False
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    def _build_argv(self, url: str, out_path: str) -> List[str]:
        """Playwright CLI 截图命令：chromium 无头，给页面渲染时间后截首屏，导航超时毫秒。
        只截首屏（默认非 full-page，对齐 phantomjs viewport，避免超长页巨图）。"""
        return [sys.executable, "-m", "playwright", "screenshot",
                "--browser", "chromium",
                "--wait-for-timeout", "1500",
                "--timeout", str(self.timeout * 1000),
                url, out_path]

    def capture(self, sites: Iterable[str], task_id: str) -> Dict[str, str]:
        """对 sites 截图，返回 {site_url: 相对路径}。不可用 → {} 降级。
        每站点经 resource_gate 申请内存（让位 AI），截后过质量门（纯色/黑屏/重复不入库）。
        **禁硬限制**：sites 不砍，并发度=线程池宽度 + 内存池实际限流。"""
        if not self.available():
            return {}
        out_dir = os.path.join(self.image_dir, str(task_id))
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            return {}
        targets = [s for s in (sites or []) if s and str(s).strip()]
        if not targets:
            return {}

        seen_md5 = set()
        seen_lock = threading.Lock()

        def _shot(site: str) -> Optional[Tuple[str, str]]:
            if self._cancelled():
                return None
            fname = safe_name(site) + ".jpg"
            fpath = os.path.join(out_dir, fname)
            argv = self._build_argv(site, fpath)
            gate = getattr(self, "resource_gate", None)
            try:
                if gate is not None:
                    with gate("recon_screenshot") as h:
                        if getattr(h, "degraded", False):
                            return None   # 资源等待超时 → 诚实跳过本站截图
                        subprocess.run(argv, capture_output=True, timeout=self.timeout + 20)
                else:
                    subprocess.run(argv, capture_output=True, timeout=self.timeout + 20)
            except Exception:
                return None
            # 质量门：过滤纯色/黑屏（尺寸）+ md5 去重（跨站点相同空白页只存一份）
            with seen_lock:
                q = _shot_quality.assess_shot(fpath, seen_md5=seen_md5)
                if not q.get("ok"):
                    return None
                if q.get("md5"):
                    seen_md5.add(q["md5"])
            return (site, self.rel_url(task_id, fname))

        result: Dict[str, str] = {}
        workers = min(self.concurrency, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for r in pool.map(_shot, targets):
                if r:
                    result[r[0]] = r[1]
        return result
