"""image 端点 —— 截图静态服务（挂 /api/image/<task_id>/<file_name>），解前端截图孤岛。

前端 `imageUrl(taskId, fileName)` → `/api/image/{taskId}/{fileName}`，SiteTab.vue 用 `<img src>` 直连加载。
**返图片字节，非 JSON 信封**（二进制资产端点，不适用统一信封/分页规约）。
**必须公开**（gateway PUBLIC_PREFIXES 已含 /api/image）：`<img>` 标签带不了 Token 头，鉴权会 401 全挂
（旧 access_log 注释印证"截图 <img> 直连、无 Token 归属"）。

截图目录：config `SCREENSHOT.DIR`（或 `SCREENSHOT_DIR`），默认根 `image/`（引擎 phantomjs 产出落此）。
安全：`secure_filename` + 白名单扩展 + 路径规范化防目录遍历（旧 ARL 同款加固）。文件不存在返占位/404。
迁移来源：app/routes/image.py。仅 stdlib + flask，无新 vendor。
"""
from __future__ import annotations

import os

from flask import make_response
from flask_restx import Namespace, Resource
from werkzeug.utils import secure_filename

from sentinel_platform.core import image_dir, get_logger

logger = get_logger()

ns = Namespace("image", path="/image", description="站点截图静态服务")

_ALLOWED_EXT = ("jpg", "jpeg", "png", "gif", "webp")
_CTYPE = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
          "gif": "image/gif", "webp": "image/webp"}


def _screenshot_dir() -> str:
    """截图根目录：统一走 core.image_dir（config SCREENSHOT.DIR / SCREENSHOT_DIR 优先，
    默认项目根 image/）——与引擎截图、AI 浏览器定格截图同一入口，保证静态服务目录与落盘目录一致。"""
    return image_dir()


def _allowed(name: str) -> bool:
    return "." in name and name.rsplit(".", 1)[1].lower() in _ALLOWED_EXT


@ns.route("/<string:task_id>/<string:file_name>")
class Image(Resource):
    @ns.doc(security=None, description="截图静态服务（公开，<img> 直连；无 Token）")
    def get(self, task_id, file_name):
        """按 task_id + 文件名取站点截图（图片字节）"""
        task_id = secure_filename(task_id)
        file_name = secure_filename(file_name)
        if not _allowed(file_name):
            return make_response(b"", 404)
        base = _screenshot_dir()
        path = os.path.join(base, task_id, file_name)
        # 路径规范化防遍历：解析后必须仍在 base 下
        real_base = os.path.realpath(base)
        real_path = os.path.realpath(path)
        if not real_path.startswith(real_base + os.sep):
            return make_response(b"", 404)
        if not os.path.isfile(real_path):
            return make_response(b"", 404)
        try:
            with open(real_path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            logger.debug("image read failed %s: %s", real_path, exc)
            return make_response(b"", 404)
        ext = file_name.rsplit(".", 1)[1].lower()
        resp = make_response(data)
        resp.headers["Content-Type"] = _CTYPE.get(ext, "application/octet-stream")
        resp.headers["Cache-Control"] = "public, max-age=86400"
        return resp
