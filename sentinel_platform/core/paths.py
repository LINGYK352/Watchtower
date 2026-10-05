"""core/paths —— 平台级路径约定（项目根 / 截图目录等跨模块共享常量）。

**为什么在 core**：项目根、截图输出根这类"目录约定"是多个类别（kernel 侦察截图、
ai_pentest 浏览器定格、router/image 静态服务）都要对齐的**共享常量**，不是某个叶子的业务能力。
按 MODULES.md 铁律，跨模块业务能力走 registry；但共享常量/路径约定应下沉本层（core），
避免各处硬编码不一致，也避免叶子间为拿一个路径而直连对方私有文件。

只依赖 stdlib + 同层 core.config（不 import 本包其他层，守 core 冻结层规则）。
"""
from __future__ import annotations

import os

from .config import get_config


def project_root() -> str:
    """项目根目录：core/paths.py → core → sentinel_platform → <项目根>（本文件上三级）。

    项目根 = 含 image/ frontend/ external/ dicts/ 等的顶层目录（见 LAYOUT.md），
    截图等资源产出落 <项目根>/image/。注意：不是 sentinel_platform 层，是它的上一级。
    """
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def image_dir() -> str:
    """截图/图片输出根：config `SCREENSHOT.DIR`（或 `SCREENSHOT_DIR`）优先，默认项目根 `image/`。

    统一入口——引擎 phantomjs 截图、AI 浏览器定格截图、router/image 静态服务三处共用同一根，
    保证截图落盘目录与静态服务目录一致（此前 screenshot.py 硬编码项目根/image、
    image.py 支持 config 覆盖，二者在配了 SCREENSHOT.DIR 时会不一致——本函数收口）。
    """
    try:
        cfg = get_config()
        d = cfg.section("SCREENSHOT", "DIR", default="") or cfg.section("SCREENSHOT_DIR", default="")
        if d:
            return d
    except Exception:
        pass
    return os.path.join(project_root(), "image")


def template_dir() -> str:
    """报告模板输出根：config `TEMPLATE.DIR`（或 `TEMPLATE_DIR`）优先，默认项目根 `template/`。

    仿 image_dir()：报告模板学习产物（注入占位符后的 template.docx、原件备份 origin.docx、
    按需截图、人工上传补充图、生成的报告 docx）统一落此根，host 卷持久（compose 整个项目根挂载 rw，
    web/worker/scheduler 各进程共享同一目录）。缺 config 降级项目根 template/。
    """
    try:
        cfg = get_config()
        d = cfg.section("TEMPLATE", "DIR", default="") or cfg.section("TEMPLATE_DIR", default="")
        if d:
            return d
    except Exception:
        pass
    return os.path.join(project_root(), "template")
