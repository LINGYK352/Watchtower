"""api_keys 端点 —— 统一密钥中心的对外 REST（挂 /api/api_keys/）。

**独立成文件的原因**：system 类别的 `endpoints/system.py` 已被 user_manage 作者(recon)占用（user/user_manage
两个 Namespace，明确「勿动 user 部分」）。为零撞车，api_keys 单独成文件、单独挂载（router 按 (module, ns_attr)
挂 Namespace，文件粒度不影响；一类别多 AI 并行时按叶子拆文件比挤同一文件更安全）。

对齐前端 frontend/src/api/apiKeys.ts + pages/settings/ApiKeys.vue：
  GET  /api/api_keys/   列出（密钥掩码 + 分组元数据）
  POST /api/api_keys/   保存（掩码回传值不覆盖原密钥）
路径/形状锁定，勿改。

范式（照 endpoints/risk_intel.py）：Namespace + docstring 首行=summary + @ns.doc(security) +
经 get_registry().get("api_keys_service") 调叶子门面（**不 import 叶子内部**，守解耦，服务缺失降级 500）+ env 信封。
权限（RBAC，网关据 rbac_service 校验；未建降级放行，权限点写 docstring）：读=`apikey:read`；写=`apikey:write`。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("api_keys", path="/api_keys", description="统一 API 密钥中心（FOFA/鹰图/GitHub/飞书等）")
_models = register_envelope_models(ns)

_save_req = ns.model("ApiKeysSaveReq", {})   # body 宽松 {fofa:{key,enabled},...}；掩码值不覆盖原密钥


def _svc():
    """取密钥中心服务（字符串键 "api_keys_service"，照 gateway user_service/rbac_service 先例，非 ROLE）。
    未注册返回 None（端点降级 500，不崩）。"""
    return get_registry().get("api_keys_service")


@ns.route("/")
class ApiKeys(Resource):
    @ns.doc(security="token", description="需权限 apikey:write")
    def get(self):
        """API 密钥列表（密钥字段掩码 + 分组元数据）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "密钥中心服务未就绪")
        return ok(svc.list_keys())

    @ns.doc(security="token", description="需权限 apikey:write")
    @ns.expect(_save_req)
    def post(self):
        """保存 API 密钥（掩码回传值不覆盖原密钥）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "密钥中心服务未就绪")
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return err(CODE_BAD_REQUEST, "请求体必须为 JSON 对象")
        result = svc.save_keys(data)
        if isinstance(result, dict) and result.get("error"):
            return err(CODE_ERROR, result["error"])
        return ok(result)


@ns.route("/options")
class ApiKeyOptions(Resource):
    @ns.doc(security="token", description="任务/策略选择器，仅返回来源名称及配置状态")
    def get(self):
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "密钥中心服务未就绪")
        items = []
        for item in svc.list_keys().get("items", []):
            row = {k: item.get(k) for k in ("id", "label", "group", "fields", "enabled")}
            for field in item.get("fields", []):
                row[field + "_set"] = bool(item.get(field + "_set"))
            items.append(row)
        return ok({"items": items})
