"""AI 扩展管理 REST API。"""
from __future__ import annotations

import os
import tempfile

from flask import request, g
from flask_restx import Namespace, Resource, fields

from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND

ns = Namespace("ai_extension", path="/pentest/extensions", description="AI 扩展管理与扩展商店")
_toggle = ns.model("AiExtensionToggle", {"username": fields.String(description="操作人")})
_store_install = ns.model("AiExtensionStoreInstall", {
    "extension_id": fields.String(required=True), "version": fields.String(required=True),
    "sha256": fields.String(required=False)})


def _svc(): return get_registry().get("ai_extension_service")
def _username(): return (getattr(g, "current_user", None) or {}).get("username", "")
def _bad_service(): return err(CODE_ERROR, "AI 扩展服务未就绪")

@ns.route('/cloud-code')
class CloudUploadCode(Resource):
    def post(self):
        if not request.content_length or request.content_length>4096:return err(CODE_BAD_REQUEST,'请求大小无效 / Invalid request size')
        body=request.get_json(silent=True)
        if not isinstance(body,dict):return err(CODE_BAD_REQUEST,'Invalid request body')
        from sentinel_platform.modules.ai_pentest._extension_store import cloud_code
        result=cloud_code(body.get('email',''),body.get('locale','zh-CN'))
        if result.get('ok'):return ok(result)
        return {'code':CODE_BAD_REQUEST,'message':result.get('error','验证码请求失败 / Code request failed'),'data':{'retry_after':result.get('retry_after',0)}}

@ns.route('/prepare')
class PrepareUpload(Resource):
    def post(self):
        svc=_svc()
        if not svc:return _bad_service()
        if not request.content_length or request.content_length>300*1024*1024+65536:return err(CODE_BAD_REQUEST,'ZIP超过300MiB / ZIP exceeds 300 MiB')
        f=request.files.get('file')
        if not f or not (f.filename or '').lower().endswith('.zip'):return err(CODE_BAD_REQUEST,'程序主体必须为ZIP / Program body must be a ZIP')
        fd,path=tempfile.mkstemp(prefix='watchtower-ext-prepare-',suffix='.zip');os.close(fd)
        try:
            f.save(path)
            return ok(svc.prepare_upload(path,_username(),request.form.get('target',''),request.form.get('platform','')))
        except (ValueError,TypeError) as exc:return err(CODE_BAD_REQUEST,str(exc))
        finally:
            try:os.unlink(path)
            except OSError:pass

@ns.route('/body/start')
class StartUploadBody(Resource):
    def post(self):
        if not request.content_length or request.content_length>4096:return err(CODE_BAD_REQUEST,'Invalid request size')
        from sentinel_platform.modules.ai_pentest._extension_upload import start_body
        try:return ok(start_body(_username(),request.get_json(silent=True)))
        except (ValueError,TypeError) as exc:return err(CODE_BAD_REQUEST,str(exc))

@ns.route('/body/<string:upload_id>/chunk')
class AppendUploadBody(Resource):
    def post(self,upload_id):
        if not request.content_length or request.content_length>8*1024*1024:return err(CODE_BAD_REQUEST,'数据块最大8MiB / Maximum chunk size is 8 MiB')
        from sentinel_platform.modules.ai_pentest._extension_upload import append_body
        try:return ok(append_body(upload_id,_username(),int(request.headers.get('X-Upload-Offset','-1')),request.get_data()))
        except (ValueError,TypeError) as exc:return err(CODE_BAD_REQUEST,str(exc))

@ns.route('/body/<string:upload_id>/prepare')
class PrepareUploadBody(Resource):
    def post(self,upload_id):
        from sentinel_platform.modules.ai_pentest._extension_upload import prepare_body
        try:return ok(prepare_body(upload_id,_username()))
        except (ValueError,TypeError) as exc:return err(CODE_BAD_REQUEST,str(exc))

@ns.route('/prepared/<string:upload_id>/finish')
class FinishUpload(Resource):
    def post(self,upload_id):
        svc=_svc()
        if not svc:return _bad_service()
        if not request.content_length or request.content_length>65536:return err(CODE_BAD_REQUEST,'上传配置过大 / Upload settings too large')
        try:return ok(svc.finish_upload(upload_id,_username(),request.get_json(silent=True)))
        except (ValueError,TypeError) as exc:return err(CODE_BAD_REQUEST,str(exc))

@ns.route('/prepared/<string:upload_id>/discard')
class DiscardUpload(Resource):
    def post(self,upload_id):
        svc=_svc()
        if not svc:return _bad_service()
        try:return ok(svc.discard_upload(upload_id,_username()))
        except ValueError as exc:return err(CODE_BAD_REQUEST,str(exc))


@ns.route("")
class ExtensionList(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:read；ext_type=ai/feature 过滤大类")
    def get(self):
        svc = _svc()
        if not svc: return _bad_service()
        return ok(svc.list_extensions(source=request.args.get("source", ""),
                                      ext_type=request.args.get("ext_type", "")))


@ns.route("/builtin")
class BuiltinList(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:read")
    def get(self):
        tools = get_registry().get("ai_tools_service")
        if not tools: return err(CODE_ERROR, "AI 工具目录未就绪")
        method = getattr(tools, "list_catalog_with_status", tools.list_tools)
        return ok(method())


@ns.route("/builtin_kernel")
class BuiltinKernelList(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:read；内核内置工具（内核扫描用，全局禁用于 AI）")
    def get(self):
        tools = get_registry().get("ai_tools_service")
        if not tools: return err(CODE_ERROR, "AI 工具目录未就绪")
        method = getattr(tools, "list_kernel_builtin", None)
        if not method: return ok({"tools": [], "total": 0, "implemented": 0})
        return ok(method())


@ns.route("/categories")
class Categories(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:read")
    def get(self):
        svc = _svc(); tools = get_registry().get("ai_tools_service")
        if not svc or not tools: return _bad_service()
        cats = set(tools.categories() or [])
        for item in svc.list_extensions().get("items", []):
            if item.get("category"): cats.add(item["category"])
        return ok({"items": sorted(cats)})


@ns.route("/upload")
class Upload(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:manage；multipart file；上传即授予主机代码执行能力")
    def post(self):
        svc = _svc()
        if not svc: return _bad_service()
        f = request.files.get("file")
        if not f: return err(CODE_BAD_REQUEST, "file 必填(multipart)")
        name = (f.filename or "").lower()
        if name.endswith((".tar.gz", ".tgz")): suffix = ".tar.gz"
        elif name.endswith(".zip"): suffix = ".zip"
        else: return err(CODE_BAD_REQUEST, "仅支持 .tar.gz/.tgz/.zip 扩展包")
        fd, path = tempfile.mkstemp(prefix="sentinel-ext-upload-", suffix=suffix); os.close(fd)
        try:
            f.save(path)
            result = svc.install_archive(path, source="local", username=_username())
            return ok(result) if result.get("ok") else err(CODE_BAD_REQUEST, result.get("error", "安装失败"))
        except Exception as exc:
            try: os.unlink(path)
            except OSError: pass
            return err(CODE_BAD_REQUEST, str(exc))


@ns.route("/submit")
class Submit(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:manage；multipart file；深校验清单后转发云端商店审核（不本地安装）")
    def post(self):
        svc = _svc()
        if not svc: return _bad_service()
        f = request.files.get("file")
        if not f: return err(CODE_BAD_REQUEST, "file 必填(multipart)")
        name = (f.filename or "").lower()
        if name.endswith((".tar.gz", ".tgz")): suffix = ".tar.gz"
        elif name.endswith(".zip"): suffix = ".zip"
        else: return err(CODE_BAD_REQUEST, "仅支持 .tar.gz/.tgz/.zip 扩展包")
        fd, path = tempfile.mkstemp(prefix="sentinel-ext-submit-", suffix=suffix); os.close(fd)
        try:
            f.save(path)
            result = svc.submit_to_store(path, _username())
            return ok(result) if result.get("ok") else err(CODE_BAD_REQUEST, result.get("error", "提交失败"))
        except Exception as exc:
            try: os.unlink(path)
            except OSError: pass
            return err(CODE_BAD_REQUEST, str(exc))


@ns.route("/<string:extension_id>/enable")
class Enable(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:manage")
    def post(self, extension_id):
        svc = _svc(); result = svc.set_enabled(extension_id, True, _username()) if svc else {"error": "服务未就绪"}
        return ok(result) if not result.get("error") else err(CODE_BAD_REQUEST, result["error"])


@ns.route("/<string:extension_id>/disable")
class Disable(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:manage")
    def post(self, extension_id):
        svc = _svc(); result = svc.set_enabled(extension_id, False, _username()) if svc else {"error": "服务未就绪"}
        return ok(result) if not result.get("error") else err(CODE_BAD_REQUEST, result["error"])


@ns.route("/<string:extension_id>/check")
class Check(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:manage")
    def post(self, extension_id):
        svc = _svc(); result = svc.check_extension(extension_id) if svc else {"error": "服务未就绪"}
        return ok(result) if not result.get("error") else err(CODE_NOT_FOUND, result["error"])


@ns.route("/<string:extension_id>/delete")
class Delete(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:manage")
    def post(self, extension_id):
        svc = _svc()
        if not svc: return _bad_service()
        return ok(svc.delete_extension(extension_id, _username()))


@ns.route("/store")
class Store(Resource):
    @ns.doc(security="token", description="需平台登录和统一 JWT 激活凭证")
    def get(self):
        svc = _svc()
        if not svc: return _bad_service()
        return ok(svc.store_catalog())


@ns.route("/store/install")
class StoreInstall(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:manage + 统一 JWT")
    @ns.expect(_store_install, validate=True)
    def post(self):
        svc = _svc()
        if not svc: return _bad_service()
        body = request.get_json(silent=True) or {}
        result = svc.install_from_store(body.get("extension_id", ""), body.get("version", ""),
                                        body.get("sha256", ""), _username())
        return ok(result) if result.get("ok") else err(CODE_BAD_REQUEST, result.get("error", "安装失败"))


@ns.route("/logs")
class Logs(Resource):
    @ns.doc(security="token", description="需权限 ai_extension:read")
    def get(self):
        svc = _svc()
        if not svc: return _bad_service()
        return ok(svc.list_logs(page=request.args.get("page", 1), size=request.args.get("size", 20),
                                extension_id=request.args.get("extension_id", ""), status=request.args.get("status", "")))
