"""ai_tools 端点 —— AI 工具目录的对外 REST（挂 /api/pentest/tools）。

**独立成文件**：ai_pentest 类别的 endpoints/ai_pentest.py 被 ai_config（ns ai_config）占用；ai_tools 单独成文件。
Namespace path `/pentest`、route `/tools`——与 session 的 `/pentest/session/*`、vuln_center 的 `/pentest/finding/*`
同 `/pentest` path 共存不冲突（Flask-RESTX 允许多 Namespace 同 path，路由不重叠）。

对齐前端 api/pentest.ts 的 `tools()`（`/api/pentest/tools` → {tools:[{name,category,summary,description,params}], total}）+ pages/ai/AiTools.vue。
范式：经 get_registry().get("ai_tools_service") 调门面（不 import 叶子内部，缺失降级 500）+ env 信封。
权限：读 pentest:read（工具目录只读展示）。**禁硬限制参数**：返全量工具目录。
"""
from __future__ import annotations

from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_ERROR

logger = get_logger()

ns = Namespace("ai_tools", path="/pentest", description="AI 渗透工具目录")
try:
    from ..openapi import register_envelope_models
    register_envelope_models(ns)
except Exception:
    pass


def _svc():
    """取 AI 工具目录服务（字符串键 "ai_tools_service"，非 ROLE）；未注册 None（降级 500）。"""
    return get_registry().get("ai_tools_service")


@ns.route("/tools")
class AiToolsList(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self):
        """AI 渗透工具目录（分类/摘要/参数，供工具菜单展示）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "AI 工具目录服务未就绪")
        return ok(svc.list_tools())
