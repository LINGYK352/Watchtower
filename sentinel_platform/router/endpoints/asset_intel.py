"""asset_intel 端点 —— 资产情报中心的对外 REST（挂 /api/intel/）。

**独立成文件**：risk_intel 类别的 endpoints/risk_intel.py 已被 vuln_intel(ns intel/vuln_feed)+vuln_center(ns_finding)
占用；asset_intel 单独成文件、单独挂载（一类别多 AI 并行按叶子拆文件避撞车）。
注意：Namespace `intel` 的 `/vuln_feed/*` 归 vuln_intel（risk_intel.py 的 ns），本文件用**另一 Namespace（tag intel_asset, path /intel）**
只挂资产情报路由（stat/asset/system/code/report/collect/match/context/resolve_icp）；chain/*、units/* 归 attack_chain、unit_view 叶子。

对齐前端 api/intel.ts（路径/形状锁定）：
  GET  /api/intel/stat/         总览统计       GET /api/intel/asset|system|code|report/  各集合分页
  POST /api/intel/collect/      手动归集(task_id)
  GET  /api/intel/match/        渗透前去重(?site)     GET /api/intel/context/ 渗透档案(?asset_key)
  POST /api/intel/resolve_icp/  域名→备案单位

范式：经 get_registry().get(ROLE.INTEL) 调门面（**不 import 叶子内部**，缺失降级 500）+ env 信封。
权限：读 intel:read（stat/list/match/context）/ 写 intel:write（collect/resolve_icp）。**禁硬限制参数**：list size 透传不砍。
"""
from __future__ import annotations

import re

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry, ROLE
from ..envelope import ok, err, page as env_page, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND

logger = get_logger()

ns = Namespace("intel_asset", path="/intel", description="资产情报中心：归集/资产/系统/报告")
try:
    from ..openapi import register_envelope_models
    register_envelope_models(ns)
except Exception:
    pass

_collect_req = ns.model("IntelCollectReq", {})
_icp_req = ns.model("IntelResolveIcpReq", {})


def _svc():
    """取 INTEL 服务（ROLE.INTEL，asset_intel 实现）；未注册 None（降级 500）。"""
    return get_registry().get(ROLE.INTEL)


def _int(v, d):
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


@ns.route("/stat/")
class IntelStat(Resource):
    @ns.doc(security="token", description="需权限 intel:read")
    def get(self):
        """情报中心总览统计"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        return ok(svc.stat())


def _make_list_resource(coll_name: str):
    @ns.route("/{}/".format(coll_name.split("_", 1)[1] if coll_name.startswith("intel_") else coll_name))
    class _IntelList(Resource):
        @ns.doc(security="token", description="需权限 intel:read")
        def get(self):
            """{} 分页列表""".format(coll_name)
            svc = _svc()
            if not svc:
                return err(CODE_ERROR, "情报服务未就绪")
            a = request.args
            r = svc.list_collection(coll_name, page=_int(a.get("page"), 1), size=_int(a.get("size"), 10),
                                    unit=a.get("unit") or "", system_id=a.get("system_id") or "",
                                    pentest_status=a.get("pentest_status") or "", keyword=a.get("keyword") or "",
                                    report_type=a.get("report_type") or "")
            return env_page(r["items"], r["total"], r["page"], r["size"])
    return _IntelList


# /api/intel/{asset,system,code,report}/
IntelAssetList = _make_list_resource("intel_asset")
IntelSystemList = _make_list_resource("intel_system")
IntelCodeList = _make_list_resource("intel_code")
IntelReportList = _make_list_resource("intel_report")


@ns.route("/report_tree/")
class IntelReportTree(Resource):
    @ns.doc(security="token", description="需权限 intel:read：渗透报告三级目录树（任务>单位>资产）")
    def get(self):
        """渗透报告三级目录（BUG-014：前端「三级目录」默认视图数据源）"""
        svc = _svc()
        if not (svc and hasattr(svc, "report_tree")):
            return err(CODE_ERROR, "情报服务未就绪")
        return ok(svc.report_tree())


@ns.route("/report/<string:report_id>")
class IntelReportDetail(Resource):
    @ns.doc(security="token", description="需权限 intel:read：渗透报告详情")
    def get(self, report_id):
        """渗透报告详情（#4：前端点报告查看，原缺此端点→404）"""
        svc = _svc()
        if not (svc and hasattr(svc, "get_report")):
            return err(CODE_ERROR, "情报服务未就绪")
        d = svc.get_report(report_id)
        if d is None:
            return err(CODE_NOT_FOUND, "报告不存在")
        return ok(d)

    @ns.doc(security="token", description="[deprecated] 编辑报告；报告编辑处已改走 PUT /pentest_report/<id>")
    def put(self, report_id):
        """[deprecated] 编辑报告——报告编辑处已切到 /pentest_report/<id>（写 pentest_report 成品集合）。
        本端点 update_report 现指向 pentest_report，无前端调用方，保留仅为兼容。"""
        svc = _svc()
        if not (svc and hasattr(svc, "update_report")):
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.update_report(report_id, content=body.get("content"), title=body.get("title"))
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report/generate")
class IntelReportGenerate(Resource):
    @ns.doc(security="token", description="[deprecated] 生成报告；报告编辑处已改走 POST /pentest_report/generate")
    def post(self):
        """[deprecated] 生成报告——报告编辑处已切到 /pentest_report/generate（写 pentest_report 成品集合）。
        底层 build_task_report/regenerate_session_report 现落 pentest_report，无前端调用方，保留仅为兼容。
        body {type:'task'|'session', task_id|session_id, use_llm?}"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        rtype = (body.get("type") or "").strip()
        if rtype == "task":
            tid = (body.get("task_id") or "").strip()
            if not tid:
                return err(CODE_BAD_REQUEST, "task_id 必填")
            if not hasattr(svc, "build_task_report"):
                return err(CODE_ERROR, "报告服务未就绪")
            r = svc.build_task_report(tid, bool(body.get("use_llm", True)))
        elif rtype == "session":
            sid = (body.get("session_id") or "").strip()
            if not sid:
                return err(CODE_BAD_REQUEST, "session_id 必填")
            if not hasattr(svc, "regenerate_session_report"):
                return err(CODE_ERROR, "报告服务未就绪")
            r = svc.regenerate_session_report(sid)
        else:
            return err(CODE_BAD_REQUEST, "type 须为 task 或 session")
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report/<string:report_id>/export.docx")
class IntelReportExportDocx(Resource):
    @ns.doc(security="token", description="需权限 intel:read：导出报告为 docx 文件下载")
    def get(self, report_id):
        """导出 docx（#4：md→docx 文件流下载）"""
        from flask import Response
        svc = _svc()
        if not (svc and hasattr(svc, "export_report_docx")):
            return err(CODE_ERROR, "情报服务未就绪")
        r = svc.export_report_docx(report_id)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        from urllib.parse import quote
        fn = quote(r.get("filename") or "report.docx")
        return Response(
            r["data"],
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "attachment; filename*=UTF-8''{}".format(fn)})


# ========== 人看成品报告 /api/intel/pentest_report/*（与 intel_report 情报报告物理隔离）==========
# 报告编辑处（ReportEdit.vue）专用：列表/详情/编辑/生成/导出全部指向 pentest_report 集合。
# 会话收尾自动写的 intel_report（AI 情报，供往期借鉴）不经这组端点，也不出现在报告编辑处。
# 写操作权限 pentest:write（见 rbac.py：/api/intel/pentest_report）。
# 列表：_make_list_resource("pentest_report") → /api/intel/pentest_report/（名不以 intel_ 开头取全名）。
IntelPentestReportList = _make_list_resource("pentest_report")


@ns.route("/pentest_report/<string:report_id>")
class PentestReportDetail(Resource):
    @ns.doc(security="token", description="需权限 intel:read：人看成品报告详情")
    def get(self, report_id):
        """成品报告详情（pentest_report）"""
        svc = _svc()
        if not (svc and hasattr(svc, "get_report")):
            return err(CODE_ERROR, "情报服务未就绪")
        d = svc.get_report(report_id, collection="pentest_report")
        if d is None:
            return err(CODE_NOT_FOUND, "报告不存在")
        if d.get("gen_mode") == "template":
            from sentinel_platform.modules.risk_intel.report_template import editor_data
            d["report_data"] = editor_data(d)
        return ok(d)

    @ns.doc(security="token", description="需权限 pentest:write：编辑成品报告正文/标题（人工修订）")
    def put(self, report_id):
        """编辑成品报告；模板报告保存结构化数据并重渲染。"""
        svc = _svc()
        if not (svc and hasattr(svc, "update_report")):
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.update_report(report_id, content=body.get("content"), title=body.get("title"),
                              report_data=body.get("report_data"))
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/pentest_report/generate")
class PentestReportGenerate(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：生成成品报告（task 任务级 / session 会话级重生成）")
    def post(self):
        """生成成品报告：body {type:'task'|'session', task_id|session_id, use_llm?}"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        rtype = (body.get("type") or "").strip()
        if rtype == "task":
            tid = (body.get("task_id") or "").strip()
            if not tid:
                return err(CODE_BAD_REQUEST, "task_id 必填")
            if not hasattr(svc, "build_task_report"):
                return err(CODE_ERROR, "报告服务未就绪")
            r = svc.build_task_report(tid, bool(body.get("use_llm", True)))
        elif rtype == "session":
            sid = (body.get("session_id") or "").strip()
            if not sid:
                return err(CODE_BAD_REQUEST, "session_id 必填")
            if not hasattr(svc, "regenerate_session_report"):
                return err(CODE_ERROR, "报告服务未就绪")
            r = svc.regenerate_session_report(sid)
        else:
            return err(CODE_BAD_REQUEST, "type 须为 task 或 session")
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/pentest_report/<string:report_id>/assist")
class PentestReportAssist(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：AI 提出报告文字修订，不自动保存")
    def post(self, report_id):
        svc = _svc()
        if not (svc and hasattr(svc, "assist_report")):
            return err(CODE_ERROR, "报告辅助服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.assist_report(report_id, draft=body.get("report_data"),
            instruction=body.get("instruction", ""), provider_id=body.get("provider_id", ""),
            only_empty=body.get("only_empty", True) is not False)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/pentest_report/<string:report_id>/export.docx")
class PentestReportExportDocx(Resource):
    @ns.doc(security="token", description="需权限 intel:read：导出成品报告为 docx 文件下载")
    def get(self, report_id):
        """导出成品报告 docx。模板生成的报告(gen_mode=template)直接下发预生成的 docx 文件；
        普通 md 报告走 md→docx 渲染。"""
        from flask import Response
        from urllib.parse import quote
        svc = _svc()
        if not (svc and hasattr(svc, "export_report_docx")):
            return err(CODE_ERROR, "情报服务未就绪")
        # 模板报告：读文档拿 docx_path 直接下发预生成文件（防遍历用 realpath 限定在 template_dir 内）
        d = svc.get_report(report_id, collection="pentest_report") if hasattr(svc, "get_report") else None
        if d and d.get("gen_mode") == "template" and d.get("docx_path"):
            import os as _os
            from sentinel_platform.core import template_dir as _tdir
            base = _os.path.realpath(_tdir())
            full = _os.path.realpath(_os.path.join(base, d["docx_path"]))
            if not full.startswith(base + _os.sep):
                return err(CODE_BAD_REQUEST, "非法路径")
            if not _os.path.isfile(full):
                return err(CODE_NOT_FOUND, "报告文件缺失（可能已删除，请重新生成）")
            with open(full, "rb") as fh:
                data = fh.read()
            fn = quote((d.get("title") or "report") + ".docx")
            return Response(
                data,
                mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": "attachment; filename*=UTF-8''{}".format(fn)})
        r = svc.export_report_docx(report_id, collection="pentest_report")
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        fn = quote(r.get("filename") or "report.docx")
        return Response(
            r["data"],
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "attachment; filename*=UTF-8''{}".format(fn)})


@ns.route("/delete/")
class IntelDelete(Resource):
    @ns.doc(security="token", description="需权限 intel:write：删除情报记录（asset/system/code/report/pentest_report）")
    def post(self):
        """批量删除情报记录（#5：前端点选删除，原缺此端点→404）。body:{collection,_id:[...]}"""
        svc = _svc()
        if not (svc and hasattr(svc, "delete_records")):
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        collection = (body.get("collection") or "").strip()
        ids = body.get("_id") or []
        if not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "_id(非空数组) 必填")
        r = svc.delete_records(collection, ids)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok({"deleted": r.get("deleted", 0)})


@ns.route("/collect/")
class IntelCollect(Resource):
    @ns.doc(security="token", description="需权限 intel:write：手动归集某任务的 site 结果")
    @ns.expect(_collect_req)
    def post(self):
        """手动归集任务资产"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        task_id = (body.get("task_id") or "").strip()
        if not task_id:
            return err(CODE_BAD_REQUEST, "task_id 必填")
        r = svc.collect_from_task(task_id)
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/match/")
class IntelMatch(Resource):
    @ns.doc(security="token", description="需权限 intel:read：渗透前查资产是否已存在/已渗透")
    def get(self):
        """按 site 匹配资产实例"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        asset = svc.match_asset(request.args.get("site", ""))
        return ok({"matched": bool(asset), "asset": asset})


@ns.route("/check_overlap/")
class IntelCheckOverlap(Resource):
    @ns.doc(security="token", description="需权限 intel:read：发起/重启任务前查同资产是否已有渗透会话或历史报告")
    def post(self):
        """检测同资产重复渗透（活跃会话 + 历史报告），供前端确认弹窗"""
        svc = _svc()
        if not svc or not hasattr(svc, "check_pentest_overlap"):
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        targets = body.get("targets") or ([] if not body.get("target") else [body.get("target")])
        if isinstance(targets, str):
            targets = [t for t in re.split(r"[,;\s]+", targets) if t.strip()]
        # within_days>0：只把距今<N天的历史报告计入（控制台侧「近期已渗透」5天阈值弹窗用）；
        # 缺省 0=任务侧全展示（零回归）。控制台前端传 within_days=5（或由后端配置默认）。
        try:
            within_days = int(body.get("within_days") or 0)
        except (TypeError, ValueError):
            within_days = 0
        return ok(svc.check_pentest_overlap(targets=targets, unit=body.get("unit", ""),
                                            within_days=within_days))


@ns.route("/context/")
class IntelContext(Resource):
    @ns.doc(security="token", description="需权限 intel:read：AI 渗透前情报档案")
    def get(self):
        """按 asset_key 装配渗透情报档案"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        return ok(svc.build_pentest_context(request.args.get("asset_key", "")))


@ns.route("/resolve_icp/")
class IntelResolveIcp(Resource):
    @ns.doc(security="token", description="需权限 intel:write：域名→备案单位（经 ext_source，未建降级空）")
    @ns.expect(_icp_req)
    def post(self):
        """域名反查备案单位"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        return ok(svc.resolve_icp((body.get("domain") or "").strip()))


# ========== 报告模板学习 /api/intel/report_template/*（人看成品报告用模板批量生成，省 token）==========
# 上传 docx → AI 一次性学成模板 → 用模板确定性填充生成报告。写权限 pentest:write（见 rbac.py）。

import os as _os
import tempfile as _tempfile


@ns.route("/report_template/upload")
class ReportTemplateUpload(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：上传报告模板 docx 并触发 AI 学习")
    def post(self):
        """上传模板（multipart file + name）→ 学习成可复用模板。只收 .docx。"""
        svc = _svc()
        if not (svc and hasattr(svc, "learn_template")):
            return err(CODE_ERROR, "情报服务未就绪")
        f = request.files.get("file")
        if not f or not (f.filename or ""):
            return err(CODE_BAD_REQUEST, "未收到上传文件（multipart file）")
        fname = f.filename or ""
        if not fname.lower().endswith(".docx"):
            return err(CODE_BAD_REQUEST, "仅支持 .docx 模板；.wps/.doc 请在 WPS/Word 中「另存为 .docx」后上传")
        name = (request.form.get("name") or "").strip() or _os.path.splitext(_os.path.basename(fname))[0]
        created_by = (request.headers.get("X-User") or "").strip()
        provider_id = (request.form.get("provider_id") or "").strip()   # 空=跟随全局默认/template_learn 场景
        # 需人工复核：**默认 True**（学成落 review 待确认）；仅显式传假值(0/false/no/off)才直接 ready。
        _nr = str(request.form.get("need_review") if request.form.get("need_review") is not None else "1").strip().lower()
        need_review = _nr not in ("0", "false", "no", "off", "")
        fd, tmp = _tempfile.mkstemp(prefix="sentinel-tpl-", suffix=".docx")
        _os.close(fd)
        try:
            f.save(tmp)
            r = svc.learn_template(name, tmp, source_filename=fname, created_by=created_by,
                                   provider_id=provider_id, need_review=need_review)
        finally:
            try:
                _os.remove(tmp)
            except Exception:
                pass
        if not r.get("ok"):
            return err(CODE_BAD_REQUEST, r.get("error", "学习失败"))
        return ok(r)


@ns.route("/report_template/")
class ReportTemplateList(Resource):
    @ns.doc(security="token", description="需权限 intel:read：报告模板列表")
    def get(self):
        """模板列表（不含大 schema）"""
        svc = _svc()
        if not (svc and hasattr(svc, "list_templates")):
            return err(CODE_ERROR, "情报服务未就绪")
        a = request.args
        try:
            pg = int(a.get("page") or 1); sz = int(a.get("size") or 20)
        except (TypeError, ValueError):
            pg, sz = 1, 20
        r = svc.list_templates(page=pg, size=sz, scope=a.get("scope") or "")
        return env_page(r["items"], r["total"], r["page"], r["size"])


@ns.route("/report_template/<string:template_id>")
class ReportTemplateDetail(Resource):
    @ns.doc(security="token", description="需权限 intel:read：模板详情（含学习出的 schema，供人工校对）")
    def get(self, template_id):
        svc = _svc()
        if not (svc and hasattr(svc, "get_template")):
            return err(CODE_ERROR, "情报服务未就绪")
        d = svc.get_template(template_id)
        if d is None:
            return err(CODE_NOT_FOUND, "模板不存在")
        return ok(d)

    @ns.doc(security="token", description="需权限 pentest:write：删除模板（连带删磁盘目录）")
    def delete(self, template_id):
        svc = _svc()
        if not (svc and hasattr(svc, "delete_template")):
            return err(CODE_ERROR, "情报服务未就绪")
        r = svc.delete_template(template_id)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report_template/generate")
class ReportTemplateGenerate(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：用模板生成报告 docx")
    def post(self):
        """body {template_id, type:'task'|'session'|'finding', task_id|session_id|finding_id, options?}"""
        svc = _svc()
        if not (svc and hasattr(svc, "generate_from_template")):
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        tid = (body.get("template_id") or "").strip()
        rtype = (body.get("type") or "").strip()
        if not tid:
            return err(CODE_BAD_REQUEST, "template_id 必填")
        if rtype == "task":
            sid = (body.get("task_id") or "").strip()
        elif rtype == "session":
            sid = (body.get("session_id") or "").strip()
        elif rtype == "finding":
            sid = (body.get("finding_id") or "").strip()
        else:
            return err(CODE_BAD_REQUEST, "type 须为 task / session / finding")
        if not sid:
            return err(CODE_BAD_REQUEST, "task_id/session_id/finding_id 必填")
        r = svc.generate_from_template(tid, rtype, sid, body.get("options") or {})
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report_template/<string:template_id>/manual_shot")
class ReportTemplateManualShot(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：上传人工补充截图，绑定某漏洞条目")
    def post(self, template_id):
        """multipart file + finding_id。"""
        svc = _svc()
        if not (svc and hasattr(svc, "save_manual_shot")):
            return err(CODE_ERROR, "情报服务未就绪")
        f = request.files.get("file")
        fid = (request.form.get("finding_id") or "").strip()
        if not f or not fid:
            return err(CODE_BAD_REQUEST, "file 与 finding_id 必填")
        ext = _os.path.splitext(f.filename or "")[1].lstrip(".") or "png"
        r = svc.save_manual_shot(template_id, fid, f.read(), ext=ext)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


# ===== 漏洞证据截图（按 finding_id 全局绑定；上传后生成报告自动嵌入证据/复现区）=====
@ns.route("/finding_shot/<string:finding_id>")
class FindingShotList(Resource):
    @ns.doc(security="token", description="需权限 intel:read：列某漏洞的证据截图（url 走公开 /api/image 直连预览）")
    def get(self, finding_id):
        svc = _svc()
        if not (svc and hasattr(svc, "list_finding_shots")):
            return err(CODE_ERROR, "情报服务未就绪")
        return ok({"shots": svc.list_finding_shots(finding_id)})

    @ns.doc(security="token", description="需权限 pentest:write：上传证据截图（multipart file）")
    def post(self, finding_id):
        svc = _svc()
        if not (svc and hasattr(svc, "save_finding_shot")):
            return err(CODE_ERROR, "情报服务未就绪")
        f = request.files.get("file")
        if not f or not (f.filename or ""):
            return err(CODE_BAD_REQUEST, "未收到上传文件（multipart file）")
        ext = _os.path.splitext(f.filename or "")[1].lstrip(".") or "png"
        r = svc.save_finding_shot(finding_id, f.read(), ext=ext)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/finding_shot/<string:finding_id>/<string:name>")
class FindingShotDelete(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：删除某张证据截图")
    def delete(self, finding_id, name):
        svc = _svc()
        if not (svc and hasattr(svc, "delete_finding_shot")):
            return err(CODE_ERROR, "情报服务未就绪")
        r = svc.delete_finding_shot(finding_id, name)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report_template/<string:template_id>/refine")
class ReportTemplateRefine(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：人在回路重学（可换模型 + 带纠正意见），仍落 review 态")
    def post(self, template_id):
        """body {provider_id?, feedback?}。复用已归档 origin.docx 重新学，反复直到用户满意。"""
        svc = _svc()
        if not (svc and hasattr(svc, "refine_template")):
            return err(CODE_ERROR, "情报服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.refine_template(template_id, provider_id=(body.get("provider_id") or "").strip(),
                                feedback=(body.get("feedback") or "").strip())
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report_template/<string:template_id>/confirm")
class ReportTemplateConfirm(Resource):
    @ns.doc(security="token", description="需权限 pentest:write：确认定稿 review→ready（之后才可生成）")
    def post(self, template_id):
        svc = _svc()
        if not (svc and hasattr(svc, "confirm_template")):
            return err(CODE_ERROR, "情报服务未就绪")
        r = svc.confirm_template(template_id)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report_template/<string:template_id>/diff")
class ReportTemplateDiff(Resource):
    @ns.doc(security="token", description="需权限 intel:read：在线并排对比（origin 原文 vs schema 判定），供复核")
    def get(self, template_id):
        svc = _svc()
        if not (svc and hasattr(svc, "template_diff")):
            return err(CODE_ERROR, "情报服务未就绪")
        r = svc.template_diff(template_id)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/report_template/<string:template_id>/docx")
class ReportTemplateDocx(Resource):
    @ns.doc(security="token", description="需权限 intel:read：取模板原始 docx 字节（which=origin 原报告 / template 打标记模板），供前端 mammoth 在线对比渲染")
    def get(self, template_id):
        """which=origin（origin.docx 原报告）/ template（template.docx 打标记的模板）。
        realpath 防遍历限定 template_dir 内；返回 docx 字节流供前端 mammoth.js 转 HTML 并排对比。"""
        from flask import Response
        from urllib.parse import quote
        svc = _svc()
        if not (svc and hasattr(svc, "get_template_docx")):
            return err(CODE_ERROR, "情报服务未就绪")
        which = (request.args.get("which") or "origin").strip()
        if which not in ("origin", "template"):
            return err(CODE_BAD_REQUEST, "which 须为 origin 或 template")
        r = svc.get_template_docx(template_id, which=which)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        from sentinel_platform.core import template_dir as _tdir
        base = _os.path.realpath(_tdir())
        full = _os.path.realpath(r["path"])
        if not full.startswith(base + _os.sep):
            return err(CODE_BAD_REQUEST, "非法路径")
        if not _os.path.isfile(full):
            return err(CODE_NOT_FOUND, "docx 文件缺失")
        with open(full, "rb") as fh:
            data = fh.read()
        fn = quote("{}_{}.docx".format(which, template_id))
        # inline：前端 fetch 拿 arraybuffer 交 mammoth，不触发浏览器下载
        return Response(
            data,
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "inline; filename*=UTF-8''{}".format(fn)})
