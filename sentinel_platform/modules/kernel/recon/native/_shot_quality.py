"""_shot_quality —— 截图质量门（引擎无关，phantomjs / chromium 都调，问题11）。

**根因**：PhantomJS 对现代 SPA/非200 页面渲染失败→输出纯黑画布；同一张纯黑图被几十个站点重复存
（实测 md5 相同、尺寸恒 16627B）。截图阶段原本只判 size>0 就存，黑图照存、误导展示 + 浪费存储。

**质量门（纯标准库，不引入 Pillow——守零依赖/线上容器无 numpy/Pillow 约束，用户 2026-09-12 定调）**：
  1. 尺寸下限：纯色（全黑/全白）JPEG 编码后极小（实测空白16627B vs 真实内容280727B，区分度高）。
     < min_bytes 判为无效（疑似渲染失败黑屏）。min_bytes 可配（SCREENSHOT.MIN_BYTES），物理意义非裸魔数。
  2. md5 去重：同一次运行内跨站点重复 md5 = 通用空白/错误页，留首张、后续判重复不重复存。

判定用于「标记不存」而非「删数据」——容错高：极少数"小但有内容"的轻页被误判也只是不展示截图，
不影响挖洞。site.screenshot 留空 → 前端显"无有效截图"而非黑屏。
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Optional, Set

from sentinel_platform.core import get_logger

logger = get_logger()

# 尺寸下限默认（字节）：低于此视为疑似纯色/空白图。物理意义——纯色 JPEG 恒小，真实内容页远大于此。
_DEFAULT_MIN_BYTES = 30000


def _min_bytes() -> int:
    """读 SCREENSHOT.MIN_BYTES，缺失/异常回退默认。"""
    try:
        from sentinel_platform.core import get_config
        v = get_config().section("SCREENSHOT", "MIN_BYTES")
        if v is not None:
            return max(1, int(v))
    except Exception:
        pass
    return _DEFAULT_MIN_BYTES


def file_md5(path: str) -> str:
    """算文件 md5（去重用）。读不到返空串。"""
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def assess_shot(path: str, seen_md5: Optional[Set[str]] = None,
                min_bytes: Optional[int] = None) -> Dict[str, Any]:
    """评估一张截图是否有效。返回 {ok, reason, md5}。
      ok=True  → 有效，可写 site.screenshot（并把 md5 记进 seen_md5 供后续去重）
      ok=False → 无效（blank=纯色空白/黑屏 / dup=重复空白页 / missing=文件缺失），不写 screenshot
    seen_md5：本次运行已见 md5 集合（跨站点去重）；min_bytes：尺寸下限（不传读 config）。
    """
    if not path or not os.path.isfile(path):
        return {"ok": False, "reason": "missing", "md5": ""}
    try:
        size = os.path.getsize(path)
    except Exception:
        return {"ok": False, "reason": "missing", "md5": ""}
    thr = int(min_bytes if min_bytes is not None else _min_bytes())
    md5 = file_md5(path)
    if seen_md5 is not None and md5 and md5 in seen_md5:
        return {"ok": False, "reason": "dup", "md5": md5}     # 与已存截图完全相同=通用空白/错误页
    if size >= thr:
        return {"ok": True, "reason": "", "md5": md5}
    # 字节数小 ≠ 空白：浅色/简洁但有效的页面(登录页/API页/example.com 15528B<30000)压出的 JPEG
    # 就是小，甚至比黑屏空白页(≈16627B)还小 → 纯 byte-size 无法区分(用户 2026-09-26 反馈资产检索无图)。
    # 改用内容丰富度：颜色足够丰富(非近纯色/全黑全白)即视为有效截图；只有近纯色才真判 blank。
    if _has_content(path):
        return {"ok": True, "reason": "small_but_content", "md5": md5}
    return {"ok": False, "reason": "blank", "md5": md5}   # 近纯色/黑屏（内容判定也判空）


def _has_content(path: str) -> bool:
    """小图内容判定：下采样 + 颜色量化后统计不同颜色数——近纯色(全黑/全白/单色)极少，
    有文字/图形则多。PIL 缺失/异常时保守返 True(不误杀，重复空白仍由 md5 去重兜底)。"""
    try:
        from PIL import Image
        with Image.open(path) as im:
            im = im.convert("RGB")
            im.thumbnail((120, 120))
            q = im.point(lambda v: v & 0xF8)            # 每通道量化到高 5 bit，压掉 JPEG 噪点
            colors = q.getcolors(maxcolors=200000) or []
            return len(colors) >= 8                     # ≥8 种不同色 = 有内容(近纯色只有 1~3 种)
    except Exception:
        return True
