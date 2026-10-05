"""统一响应信封 —— 全项目对外 HTTP 响应的唯一出口形态。

前端 `frontend/src/api/request.ts` 硬依赖 `{code, message, data}`：按 `data.code===200`
判成功、取 `data.data` 作载荷、`data.message` 显错误、`code===401/403` 特殊处理。
故所有端点响应必须经本模块包装，禁裸返回载荷（否则前端 data.data 取不到 = 孤岛）。

纯函数，零 flask 依赖，可独立单测。endpoints 只产出载荷，调 ok()/err() 包装。
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

# 业务码语义（与 HTTP 状态码一致，前端两者都认）
CODE_OK = 200
CODE_BAD_REQUEST = 400
CODE_UNAUTHORIZED = 401
CODE_ACTIVATION_REQUIRED = 402   # 系统未激活/激活已过期：核心业务端点被网关硬拦（区别于 401 登录失效）
CODE_FORBIDDEN = 403
CODE_NOT_FOUND = 404
CODE_ERROR = 500

_DEFAULT_MSG = {
    CODE_OK: "ok",
    CODE_BAD_REQUEST: "请求参数错误",
    CODE_UNAUTHORIZED: "未认证或登录失效",
    CODE_ACTIVATION_REQUIRED: "系统未激活或激活已过期，请先激活后再使用该功能",
    CODE_FORBIDDEN: "无权限执行此操作",
    CODE_NOT_FOUND: "资源不存在",
    CODE_ERROR: "服务端异常",
}


def envelope(data: Any = None, code: int = CODE_OK, message: str = "") -> Dict[str, Any]:
    """包装成 {code, message, data}。message 为空取该 code 的默认文案。"""
    return {"code": code, "message": message or _DEFAULT_MSG.get(code, ""),
            "data": data if data is not None else {}}


def ok(data: Any = None, message: str = "") -> Dict[str, Any]:
    """成功响应。data 为载荷（对象/分页/动作摘要）。"""
    return envelope(data, CODE_OK, message)


def err(code: int, message: str = "", data: Any = None) -> Tuple[Dict[str, Any], int]:
    """错误响应。返回 (信封, http_status)——http 码与业务 code 一致，前端两者都认。"""
    return envelope(data, code, message), code


def page(items, total: int, page_no: int = 1, size: int = 10, message: str = "") -> Dict[str, Any]:
    """分页成功响应：data = {page,size,total,items}（对齐 BaseResource.build_data）。"""
    return ok({"page": int(page_no), "size": int(size), "total": int(total),
               "items": list(items)}, message)
