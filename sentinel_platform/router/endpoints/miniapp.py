"""小程序渗透 REST API（/api/miniapp/*）—— wxapkg 解包 + 攻击面提取。

纯 HTTP 编解层：接收「选文件夹上传」的多文件 → 落工作区 → 经 registry 调 miniapp_service
解包提接口。业务逻辑在 modules/ai_pentest/miniapp.py，解包对接在 _wxapkg.py（KillWxapkg）。

上传约定：前端 <input webkitdirectory> 把文件夹内每个文件带相对路径上传，文件夹名=AppID(wxid)。
后端从表单 wxid + 多个 file 落盘到 shared/miniapp/<wxid>/pkgs/，再交叶子解包。
权限（RBAC）：写操作 = pentest:write（rbac.PERM_RULES 加 /api/miniapp）。
"""
from __future__ import annotations

import os

from flask import request, g
from flask_restx import Namespace, Resource

from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR

ns = Namespace("miniapp", path="/miniapp", description="小程序渗透：wxapkg 解包 + 提接口")


def _svc():
    return get_registry().get("miniapp_service")


def _username():
    return (getattr(g, "current_user", None) or {}).get("username", "")


def _bad_service():
    return err(CODE_ERROR, "小程序渗透服务未就绪")


@ns.route("/status")
class Status(Resource):
    @ns.doc(security="token", description="解包工具(KillWxapkg)是否就绪")
    def get(self):
        svc = _svc()
        if not svc:
            return _bad_service()
        return ok(svc.tool_available())


@ns.route("/unpack")
class Unpack(Resource):
    @ns.doc(security="token", description="需权限 pentest:write；multipart 上传小程序文件夹(名=AppID)，自动解包提接口")
    def post(self):
        svc = _svc()
        if not svc:
            return _bad_service()
        # wxid 优先取表单；否则从上传文件的相对路径首段推断（文件夹名=AppID）
        wxid = (request.form.get("wxid") or "").strip()
        name = (request.form.get("name") or "").strip()
        files = request.files.getlist("files") or request.files.getlist("file")
        if not files:
            return err(CODE_BAD_REQUEST, "未收到上传文件（multipart files）")
        # 相对路径（webkitRelativePath 前端放 filename，形如 wxABC.../pkg/__APP__.wxapkg）
        if not wxid:
            first = files[0].filename or ""
            seg = first.replace("\\", "/").split("/")
            if len(seg) > 1:
                wxid = seg[0].strip()
        if not wxid:
            return err(CODE_BAD_REQUEST, "无法确定 AppID：请上传以 wxXXXX 命名的小程序文件夹")

        # 落盘到工作区（复用叶子的工作区根，避免路径逻辑重复：经服务侧解包，这里只存原始包）
        from sentinel_platform.modules.ai_pentest.miniapp import _workspace_root, _valid_wxid
        if not _valid_wxid(wxid):
            return err(CODE_BAD_REQUEST, "无效 AppID（应为 wx 开头的小程序 AppID）")
        pkg_dir = os.path.join(_workspace_root(), wxid, "pkgs")
        os.makedirs(pkg_dir, exist_ok=True)
        saved = []
        for f in files:
            fn = (f.filename or "").replace("\\", "/").split("/")[-1]
            if not fn.lower().endswith(".wxapkg"):
                continue   # 只存 wxapkg，忽略文件夹里的其他文件
            dst = os.path.join(pkg_dir, os.path.basename(fn))
            try:
                f.save(dst)
                saved.append(dst)
            except Exception as exc:
                return err(CODE_ERROR, "保存上传文件失败: {}".format(str(exc)[:120]))
        if not saved:
            return err(CODE_BAD_REQUEST, "上传的文件夹内未找到 .wxapkg 文件")

        result = svc.unpack_uploaded(wxid, saved, name=name)
        if not result.get("ok"):
            return err(CODE_BAD_REQUEST, result.get("error", "解包失败"))
        return ok(result)


@ns.route("/launch")
class Launch(Resource):
    @ns.doc(security="token", description="需权限 pentest:write；对勾选的小程序包发起 AI 渗透(一包一会话，选模式+模型)")
    def post(self):
        svc = _svc()
        if not svc or not hasattr(svc, "launch_pentest"):
            return _bad_service()
        b = request.get_json(silent=True) or {}
        # wxids(数组，勾选的包)；兼容旧字段 wxid(单个)
        wxids = b.get("wxids")
        if not wxids and b.get("wxid"):
            wxids = [b.get("wxid")]
        mode = (b.get("mode") or "src").strip()
        provider_id = (b.get("provider_id") or "").strip()
        if not isinstance(wxids, list) or not wxids:
            return err(CODE_BAD_REQUEST, "wxids(数组) 必填")
        r = svc.launch_pentest(wxids, mode=mode, provider_id=provider_id, owner=_username())
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "发起失败"))


@ns.route("/history")
class History(Resource):
    @ns.doc(security="token", description="已处理小程序历史（AppID 列表，倒序）")
    def get(self):
        svc = _svc()
        if not svc:
            return _bad_service()
        return ok({"items": svc.list_history()})


@ns.route("/result/<string:wxid>")
class Result(Resource):
    @ns.doc(security="token", description="读某 AppID 的完整解包结果（回看）")
    def get(self, wxid):
        svc = _svc()
        if not svc:
            return _bad_service()
        r = svc.get_result(wxid)
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "无记录"))


@ns.route("/<string:wxid>")
class Delete(Resource):
    @ns.doc(security="token", description="需权限 pentest:write；删除某 AppID 记录+工作区")
    def delete(self, wxid):
        svc = _svc()
        if not svc:
            return _bad_service()
        r = svc.delete(wxid)
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "删除失败"))
