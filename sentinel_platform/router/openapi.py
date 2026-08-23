"""OpenAPI 装配 —— Api 实例 + 安全方案 + 统一信封/错误体 model（§5 规约）。

Flask-RESTX 声明式产出 Swagger 2.0（= OpenAPI 2.0），UI 挂 /api/doc，机读 /api/swagger.json。
安全方案：Token 头（apiKey in header）。信封/分页/错误体在此定义为可复用 model，
各 endpoints `@ns.marshal_with` 引用，保证 swagger 里出参 schema 完整。
"""
from __future__ import annotations

from typing import Any

# Token 头安全方案（OpenAPI securityDefinitions）
AUTHORIZATIONS = {
    "token": {"type": "apiKey", "in": "header", "name": "Token"}
}


def build_api(app: Any = None):
    """建 flask_restx.Api：挂 /api，文档 /api/doc，全局 Token 安全方案。"""
    from flask_restx import Api
    api = Api(
        title="哨兵 Sentinel API",
        version="1.0",
        description="哨兵平台对外 REST API（统一信封 {code,message,data}，Token 头鉴权）",
        doc="/api/doc",
        prefix="/api",
        authorizations=AUTHORIZATIONS,
        security="token",
    )
    if app is not None:
        api.init_app(app)
    return api


def register_envelope_models(ns) -> dict:
    """在给定 Namespace 上注册通用 model：信封 / 分页 / 错误体。返回 {名: model} 供复用。

    注：flask_restx 的 model 绑定在 Namespace/Api 上，各 ns 需各自注册（或共享 Api 级 model）。
    endpoints 用法：`@ns.marshal_with(models['envelope'])` 或自定义 data 字段的具体 model。
    """
    from flask_restx import fields
    envelope_model = ns.model("Envelope", {
        "code": fields.Integer(description="业务码(200/400/401/403/404/500)", example=200),
        "message": fields.String(description="人读说明", example="ok"),
        "data": fields.Raw(description="载荷(对象/分页/动作摘要)"),
    })
    page_model = ns.model("Page", {
        "page": fields.Integer(description="页码"),
        "size": fields.Integer(description="每页条数"),
        "total": fields.Integer(description="总条数"),
        "items": fields.List(fields.Raw, description="数据列表"),
    })
    error_model = ns.model("Error", {
        "code": fields.Integer(description="错误码"),
        "message": fields.String(description="错误说明"),
        "data": fields.Raw(description="附加信息(可空)"),
    })
    return {"envelope": envelope_model, "page": page_model, "error": error_model}
