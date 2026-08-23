"""screenshot —— 站点截图（phantomjs 二进制驱动，进程边界 arm's-length 调用）。

对站点用 phantomjs 渲染 rasterize.js 截图，存 `{image_dir}/{task_id}/{safe_name}.jpg`，
返回 `{site_url: 相对路径 /image/{task_id}/xxx.jpg}`。相对路径写入 `site.screenshot`
（对齐 site 集合字段）；前端 SiteTab.vue 读 screenshot（以 `/` 开头）拼 `/api` 前缀经
`/api/image/<task_id>/<file>` 静态服务直连 `<img>`（endpoints/image.py 已挂，非孤岛）。

**区别于纯 Py native（certfetch/fileleak/vhost 恒可用）**：本能力依赖 phantomjs 二进制 +
rasterize.js + image_dir，三者齐备才 `available()`；缺 phantomjs（未装/路径错）→ 不可用，
pipeline 截图阶段 `registry.pick` 取不到 → honest degrade（site.screenshot 保持空，schema 不受影响）。
phantomjs 是独立 CLI（external/phantomjs/），subprocess 调用不 import 进平台包（接入铁律：
external 工具经对接模块结构化才进内核；本文件即 phantomjs 的对接模块）。

二进制定位：显式 config 路径 > external/phantomjs/phantomjs > PATH。**无第三方库、无需 vendor**
（phantomjs 二进制归档在 external/，rasterize.js 随本模块）。线程池并发、单页超时。
**禁止硬限制参数**：sites 数量不砍，并发度只是线程池宽度。
参照旧引擎 sentinel_engine/capabilities/native/screenshot.py 逻辑净室重写（字段/路径对齐属数据契约）。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Tuple

from sentinel_platform.core import get_logger

logger = get_logger()

# registry 角色常量（站点截图）
ROLE_SCREENSHOT = "screenshot"


def _module_root() -> str:
    """项目根：本文件 native → recon → kernel → modules → sentinel_platform → <root>（上 6 层）。"""
    root = os.path.abspath(__file__)
    for _ in range(6):
        root = os.path.dirname(root)
    return root


def default_phantomjs() -> str:
    """external/phantomjs/phantomjs 默认路径（归档二进制）。"""
    return os.path.join(_module_root(), "external", "phantomjs", "phantomjs")


def default_rasterize() -> str:
    """rasterize.js 默认路径（随本模块，native/ 同目录）。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rasterize.js")
    return p if os.path.isfile(p) else ""


def default_image_dir() -> str:
    """截图输出根：统一走 core.image_dir（config SCREENSHOT.DIR 优先，默认项目根 image/），
    与 endpoints/image.py 静态服务同一入口——避免"截图落盘目录 ≠ 静态服务目录"的不一致。
    core 不可用时降级本地项目根 image/（保侦察内核可脱离平台单测）。"""
    try:
        from sentinel_platform.core import image_dir
        return image_dir()
    except Exception:
        return os.path.join(_module_root(), "image")


class Screenshot:
    """phantomjs 站点截图器。capture(sites, task_id) → {site_url: /image/task_id/xx.jpg}。"""

    adapter = "phantomjs_screenshot"

    def __init__(self, phantomjs_path: str = "", rasterize_js: str = "",
                 image_dir: str = "", url_prefix: str = "/image",
                 timeout: int = 30, concurrency: int = 3):
        self._phantomjs = phantomjs_path or ""
        self._rasterize = rasterize_js or default_rasterize()
        self.image_dir = image_dir or default_image_dir()
        self.url_prefix = (url_prefix or "/image").rstrip("/")
        self.timeout = timeout
        self.concurrency = max(1, int(concurrency))       # 下限保护；非上限（不砍 sites）

    # —— 二进制定位：显式路径 > external/phantomjs > PATH ————————
    def resolve_binary(self) -> str:
        if self._phantomjs:
            return shutil.which(self._phantomjs) or (self._phantomjs if os.path.isfile(self._phantomjs) else "")
        dflt = default_phantomjs()
        if os.path.isfile(dflt):
            return dflt
        return shutil.which("phantomjs") or ""

    def available(self) -> bool:
        """phantomjs 二进制 + rasterize.js + image_dir 齐备 **且二进制能真正执行** 才可用。

        改进（2026-08-10 截图 bug 复盘）：原来只查 `os.path.isfile(binary)`——但 phantomjs 缺共享库
        (libfontconfig.so.1/libfreetype.so.6) 时文件在却跑不起来，available 误判为 True → 截图静默
        全失败(site.screenshot 恒空)，且无任何日志线索。现补一次 `--version` 执行探测(结果缓存，
        探测失败记 warning 暴露缺库原因)，让不可用能被真实发现而非静默降级。"""
        b = self.resolve_binary()
        base_ok = bool(b and os.path.isfile(b)
                       and self._rasterize and os.path.isfile(self._rasterize)
                       and self.image_dir)
        if not base_ok:
            return False
        # 执行探测（缓存到实例，避免每次截图前都 fork 一次）
        if getattr(self, "_exec_ok", None) is None:
            try:
                r = subprocess.run([b, "--version"], capture_output=True, timeout=15)
                self._exec_ok = (r.returncode == 0)
                if not self._exec_ok:
                    err = (r.stderr or b"").decode("utf-8", "replace")[:200]
                    logger.warning("phantomjs 存在但无法执行（截图将降级）：%s", err)
            except Exception as exc:
                self._exec_ok = False
                logger.warning("phantomjs 执行探测失败（截图将降级），可能缺共享库"
                               "(libfontconfig/libfreetype)：%s", exc)
        return bool(self._exec_ok)

    # —— 命令构建（与执行分离，单测只测构建/命名不需真 phantomjs）——————
    def build_argv(self, binary: str, url: str, out_path: str) -> List[str]:
        """拼 phantomjs 命令行：忽略 SSL 错误 + 任意协议 + rasterize.js url out timeoutMs。"""
        return [binary, "--ignore-ssl-errors=true", "--ssl-protocol=any",
                self._rasterize, url, out_path, str(self.timeout * 1000)]

    def rel_url(self, task_id: str, fname: str) -> str:
        """截图相对路径（写入 site.screenshot；前端拼 /api → /api/image/task_id/fname）。"""
        return "{}/{}/{}".format(self.url_prefix, task_id, fname)

    def capture(self, sites: Iterable[str], task_id: str) -> Dict[str, str]:
        """对 sites 截图，返回 {site_url: 相对路径}。不可用 → {} 降级。

        **禁止硬限制参数**：sites 数量不砍，全量并发截（并发度只是线程池宽度）。
        截图失败/空文件的站点跳过（不进结果，site.screenshot 保持空）。
        """
        binary = self.resolve_binary()
        if not self.available():
            return {}
        # 二进制可执行位（迁移/解压后常丢 +x）
        try:
            if not os.access(binary, os.X_OK):
                os.chmod(binary, 0o755)
        except Exception:
            pass
        out_dir = os.path.join(self.image_dir, str(task_id))
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            return {}

        targets = [s for s in (sites or []) if s and str(s).strip()]
        if not targets:
            return {}

        def _shot(site: str) -> Optional[Tuple[str, str]]:
            fname = safe_name(site) + ".jpg"
            fpath = os.path.join(out_dir, fname)
            argv = self.build_argv(binary, site, fpath)
            try:
                subprocess.run(argv, capture_output=True, timeout=self.timeout + 15)
            except Exception:
                return None
            if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
                return (site, self.rel_url(task_id, fname))
            return None

        result: Dict[str, str] = {}
        workers = min(self.concurrency, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for r in pool.map(_shot, targets):
                if r:
                    result[r[0]] = r[1]
        return result


def safe_name(site: str) -> str:
    """站点 URL → 安全文件名（非 \\w\\-. 全替 _，截断 180，防路径遍历/非法字符）。"""
    return re.sub(r"[^\w\-.]", "_", str(site).replace("://", "_"))[:180]

