"""risk_intel 类别端点 —— 漏洞与情报的对外 REST（挂 /api/intel/...）。

本文件是 risk_intel 类别的 endpoints 汇总（一类别一 endpoints 文件）。当前已挂：
  vuln_intel 漏洞情报 → /api/intel/vuln_feed/{stat,status,list,query,run,interval}
    （对齐前端 frontend/src/api/vulnIntel.ts + pages/intel/VulnIntel.vue，路径/形状锁定，勿改）。

范式（照 endpoints/meta.py）：Namespace + docstring 首行=summary + @ns.doc(security) +
RequestParser 声明入参 + 经 get_registry().get(ROLE.X) 调叶子门面 + env.ok/err 信封。
**端点不 import 叶子内部实现**，只经 registry 取 ROLE.VULN_INTEL 服务（守解耦，服务缺失降级 503）。

权限（RBAC，网关据 rbac_service 校验；未建时降级放行，权限点写在 docstring/@ns.doc）：
  读（stat/status/list/query）= `vuln:read`；写（run/interval）= `vuln:write`。

后续 risk_intel 叶子（asset_intel/unit_view/attack_chain 等，同 /api/intel 根）在本文件
追加 Resource 到 `ns`；根不同的叶子（如 vuln_center 的 /api/vuln）另加 Namespace + 挂载行。
"""
from __future__ import annotations

import threading

from flask import request, Response
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry, ROLE
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND
from ..openapi import register_envelope_models

logger = get_logger()

ns = Namespace("intel", path="/intel", description="情报中心：漏洞情报库 / 资产情报 / 单位视图")
_models = register_envelope_models(ns)


def _svc():
    """取 VULN_INTEL 服务门面；未注册返回 None（端点降级 503，不崩）。"""
    return get_registry().get(ROLE.VULN_INTEL)


def _bool_arg(v):
    """query 布尔参数：空→None（不过滤）；'1'/'true'/'True'→True，其余→False。"""
    if v in (None, ""):
        return None
    return v in ("1", "true", "True", True)


# —— 入参声明（进 swagger）——
_list_parser = ns.parser()
_list_parser.add_argument("severity", type=str, location="args", help="等级过滤 critical/high/medium/low")
_list_parser.add_argument("source", type=str, location="args", help="来源过滤(源名)")
_list_parser.add_argument("in_kev", type=str, location="args", help="仅在野利用: 1/true")
_list_parser.add_argument("executable", type=str, location="args", help="仅本地可执行: 1/true")
_list_parser.add_argument("keyword", type=str, location="args", help="关键词(cve/标题/组件)")
_list_parser.add_argument("sort", type=str, location="args", help="排序: default/exposure(曝光时间)")
_list_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_list_parser.add_argument("size", type=int, location="args", help="每页条数, 默认20")

_query_parser = ns.parser()
_query_parser.add_argument("component", type=str, required=True, location="args", help="组件名/关键词(必填)")

_run_req = ns.model("VulnFeedRunReq", {})       # body 可选 {sources:[...]}，宽松不强校验
_interval_req = ns.model("VulnFeedIntervalReq", {})


@ns.route("/vuln_feed/stat/")
class VulnFeedStat(Resource):
    @ns.doc(security="token", description="需权限 vuln:read")
    def get(self):
        """漏洞情报库统计（总数/在野/可执行/按等级/按来源）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "漏洞情报服务未就绪")
        return ok(svc.stat())


@ns.route("/vuln_feed/status/")
class VulnFeedStatus(Resource):
    @ns.doc(security="token", description="需权限 vuln:read")
    def get(self):
        """情报源拉取状态（上次拉取/各源健康/间隔）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "漏洞情报服务未就绪")
        return ok(svc.feed_status())


@ns.route("/vuln_feed/list/")
class VulnFeedList(Resource):
    @ns.doc(security="token", description="需权限 vuln:read")
    @ns.expect(_list_parser)
    def get(self):
        """漏洞情报列表（分页 + 等级/来源/在野/可执行/关键词过滤）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "漏洞情报服务未就绪")
        a = _list_parser.parse_args()
        try:
            page, size = int(a.get("page") or 1), int(a.get("size") or 20)
        except (TypeError, ValueError):
            page, size = 1, 20
        data = svc.list_vulns(
            severity=a.get("severity") or None, source=a.get("source") or None,
            in_kev=_bool_arg(a.get("in_kev")), executable=_bool_arg(a.get("executable")),
            keyword=a.get("keyword") or None, sort=a.get("sort") or None, page=page, size=size)
        return ok(data)


@ns.route("/vuln_feed/query/")
class VulnFeedQuery(Resource):
    @ns.doc(security="token", description="需权限 vuln:read")
    @ns.expect(_query_parser)
    def get(self):
        """按组件查漏洞情报（AI 渗透同款，别名扩展+双向模糊）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "漏洞情报服务未就绪")
        component = (request.args.get("component") or "").strip()
        if not component:
            return err(CODE_BAD_REQUEST, "component 必填")
        return ok(svc.query_by_component(component))


@ns.route("/vuln_feed/run/")
class VulnFeedRun(Resource):
    @ns.doc(security="token", description="需权限 vuln:write")
    @ns.expect(_run_req)
    def post(self):
        """立即拉取情报源（异步后台线程，不阻塞；常态由编排层定时拉）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "漏洞情报服务未就绪")
        body = request.get_json(silent=True) or {}
        sources = body.get("sources") or None

        def _bg():
            try:
                svc.run_feed(sources)
            except Exception as e:
                logger.warning("vuln_feed run bg failed: %s", e)

        threading.Thread(target=_bg, daemon=True).start()
        return ok({"status": "submitted", "note": "已提交异步拉取，结果见漏洞情报页"})


@ns.route("/vuln_feed/interval/")
class VulnFeedInterval(Resource):
    @ns.doc(security="token", description="需权限 vuln:write")
    @ns.expect(_interval_req)
    def post(self):
        """设置情报源自动拉取间隔（秒，下限 600）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "漏洞情报服务未就绪")
        body = request.get_json(silent=True) or {}
        seconds = body.get("seconds")
        if not seconds:
            return err(CODE_BAD_REQUEST, "seconds 必填")
        return ok({"interval_seconds": svc.set_feed_interval(seconds)})


# =========================================================================
# 漏洞中心（vuln_center 叶子 / ROLE.FINDING）端点 —— 挂 /api/pentest/finding/*
# 前端 api/pentest.ts + pages/risk/VulnCenter.vue 锁定路径（对齐旧 routes/pentest.py unified）。
# 独立 namespace `ns_finding`（path /pentest），与未来 ai_pentest 的 /pentest/session/* 同根
# 不同路由，无冲突。经 get_registry().get(ROLE.FINDING) 调门面（不 import 叶子内部）。
# 权限：读(stat/unified/detail)=vuln:read；写(delete/mark)=vuln:write。
# =========================================================================
ns_finding = Namespace("pentest_finding", path="/pentest",
                       description="漏洞中心：AI渗透/PoC/Nuclei 三来源混排")
register_envelope_models(ns_finding)


def _finding_svc():
    """取 FINDING 服务门面；未注册返回 None（端点降级 503）。"""
    return get_registry().get(ROLE.FINDING)


def _poc_svc():
    """取 poc 服务门面（字符串键 "poc_service"，无 ROLE）；未注册降级。"""
    return get_registry().get("poc_service")


def _unit_view_svc():
    """取 unit_view 服务门面（字符串键 "unit_view_service"，无 ROLE）；未注册降级。"""
    return get_registry().get("unit_view_service")


def _tri_bool(v):
    """三态布尔：'1'/'true'→True，'0'/'false'→False，其余→None（不过滤）。"""
    if v in ("1", "true", "True"):
        return True
    if v in ("0", "false", "False"):
        return False
    return None


_unified_parser = ns_finding.parser()
_unified_parser.add_argument("unit", type=str, location="args", help="单位过滤")
_unified_parser.add_argument("severity", type=str, location="args", help="等级精确过滤 critical/high/medium/low/info")
_unified_parser.add_argument("min_severity", type=str, location="args", help="最低等级阈值(默认前端传 low，隐藏 info 噪声)")
_unified_parser.add_argument("source", type=str, location="args", help="来源 ai/poc/nuclei，不传=全部")
_unified_parser.add_argument("keyword", type=str, location="args", help="关键词(名称/目标)")
_unified_parser.add_argument("verified", type=str, location="args", help="仅已验证 1/true")
_unified_parser.add_argument("handle_status", type=str, location="args", help="处理状态 ''/submitted/false_positive")
_unified_parser.add_argument("date_from", type=str, location="args", help="起始日期")
_unified_parser.add_argument("date_to", type=str, location="args", help="截止日期")
_unified_parser.add_argument("page", type=int, location="args", help="页码, 默认1")
_unified_parser.add_argument("size", type=int, location="args", help="每页条数, 默认20")
_unified_parser.add_argument("dedup", type=str, location="args",
                             help="漏洞去重：默认1(同漏洞点只留最新一条,隐藏重复)；传0=全部漏洞(含重复)")

_detail_parser = ns_finding.parser()
_detail_parser.add_argument("source", type=str, required=True, location="args", help="来源 ai/poc/nuclei")
_detail_parser.add_argument("id", type=str, required=True, location="args", help="记录 _id")

_del_req = ns_finding.model("FindingDeleteReq", {})     # {source, ids:[]}
_mark_req = ns_finding.model("FindingMarkReq", {})       # {source, ids:[], handle_status}


@ns_finding.route("/finding/stat")
class PentestFindingStat(Resource):
    @ns_finding.doc(security="token", description="需权限 vuln:read")
    def get(self):
        """漏洞统计（AI 已验证/线索 + PoC/Nuclei 合计，可按单位）"""
        svc = _finding_svc()
        if not svc:
            return err(CODE_ERROR, "漏洞中心服务未就绪")
        return ok(svc.finding_stat(unit=request.args.get("unit") or None))


@ns_finding.route("/finding/unified")
class PentestFindingUnified(Resource):
    @ns_finding.doc(security="token", description="需权限 vuln:read")
    @ns_finding.expect(_unified_parser)
    def get(self):
        """统一漏洞中心列表（AI/PoC/Nuclei 三来源混排 + 过滤分页，默认只放已验证真漏洞）"""
        svc = _finding_svc()
        if not svc:
            return err(CODE_ERROR, "漏洞中心服务未就绪")
        a = _unified_parser.parse_args()
        try:
            page, size = int(a.get("page") or 1), int(a.get("size") or 20)
        except (TypeError, ValueError):
            page, size = 1, 20
        data = svc.list_unified_findings(
            unit=a.get("unit") or None, severity=a.get("severity") or None,
            # 默认最低等级 low（隐藏 info 噪声）——服务端强制默认，老前端/API 无需传即生效；
            # 显式传 min_severity=info 可查看全部（新前端「全部(含INFO)」选项）。
            min_severity=a.get("min_severity") or "low",
            source=a.get("source") or None, keyword=a.get("keyword") or None,
            verified=_tri_bool(a.get("verified")), handle_status=a.get("handle_status") or None,
            date_from=a.get("date_from") or None, date_to=a.get("date_to") or None,
            # dedup 默认 True（漏洞去重，隐藏重复）；显式传 "0"/"false" = 全部漏洞（含重复条目）
            dedup=_tri_bool(a.get("dedup")) is not False,
            page=page, size=size)
        return ok(data)


@ns_finding.route("/finding/unified/detail")
class PentestFindingUnifiedDetail(Resource):
    @ns_finding.doc(security="token", description="需权限 vuln:read")
    @ns_finding.expect(_detail_parser)
    def get(self):
        """按来源+id 拉漏洞完整记录（详情抽屉：AI 的 CVSS/证据、PoC/Nuclei 原字段）"""
        svc = _finding_svc()
        if not svc:
            return err(CODE_ERROR, "漏洞中心服务未就绪")
        source = (request.args.get("source") or "").strip()
        _id = (request.args.get("id") or "").strip()
        if not source or not _id:
            return err(CODE_BAD_REQUEST, "source 与 id 必填")
        doc = svc.unified_detail(source, _id)
        if doc is None:
            return err(CODE_NOT_FOUND, "漏洞记录不存在")
        return ok(doc)


@ns_finding.route("/finding/unified/delete")
class PentestFindingUnifiedDelete(Resource):
    @ns_finding.doc(security="token", description="需权限 vuln:write")
    @ns_finding.expect(_del_req)
    def post(self):
        """漏洞中心批量删除（按来源删对应集合）"""
        svc = _finding_svc()
        if not svc:
            return err(CODE_ERROR, "漏洞中心服务未就绪")
        body = request.get_json(silent=True) or {}
        source = (body.get("source") or "").strip()
        ids = body.get("ids") or []
        if not source or not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "source 与 ids(非空数组) 必填")
        return ok({"deleted": svc.delete_unified(source, ids)})


@ns_finding.route("/finding/unified/mark")
class PentestFindingUnifiedMark(Resource):
    @ns_finding.doc(security="token", description="需权限 vuln:write")
    @ns_finding.expect(_mark_req)
    def post(self):
        """漏洞中心批量标记处理状态（''重置/submitted/false_positive，记审计）"""
        svc = _finding_svc()
        if not svc:
            return err(CODE_ERROR, "漏洞中心服务未就绪")
        body = request.get_json(silent=True) or {}
        source = (body.get("source") or "").strip()
        ids = body.get("ids") or []
        handle_status = body.get("handle_status", "")
        if not source or not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "source 与 ids(非空数组) 必填")
        from flask import g
        handle_by = getattr(g, "current_user", {}).get("username", "") if hasattr(g, "current_user") else ""
        try:
            n = svc.mark_unified(source, ids, handle_status, handle_by=handle_by)
        except ValueError as e:
            return err(CODE_BAD_REQUEST, str(e))
        return ok({"modified": n})


@ns_finding.route("/finding/unified/downgrade")
class PentestFindingUnifiedDowngrade(Resource):
    @ns_finding.doc(security="token", description="需权限 vuln:write：人工降低漏洞危害等级（只降不升，仅 AI 漏洞）")
    def post(self):
        """漏洞中心人工降级危害等级。body {source:'ai', ids:[], target_severity:'info|low|medium'}。"""
        svc = _finding_svc()
        if not svc or not hasattr(svc, "downgrade_severity"):
            return err(CODE_ERROR, "漏洞中心服务未就绪")
        body = request.get_json(silent=True) or {}
        source = (body.get("source") or "").strip()
        ids = body.get("ids") or []
        target_severity = (body.get("target_severity") or "").strip()
        if not source or not isinstance(ids, list) or not ids or not target_severity:
            return err(CODE_BAD_REQUEST, "source / ids(非空数组) / target_severity 必填")
        from flask import g
        handle_by = getattr(g, "current_user", {}).get("username", "") if hasattr(g, "current_user") else ""
        r = svc.downgrade_severity(source, ids, target_severity, handle_by=handle_by)
        if r.get("error"):
            return err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


# —— PoC 信息（/api/poc/*，Claude-Opus[recon] 2026-07-05）——
# poc 是无 ROLE 的"核心路由暴露"叶子（同 search/dashboard 等），endpoint 直调叶子函数
# （router→leaf 暴露路径，非 module→module 跨模块，故不违背解耦；无跨模块消费者，不占 ROLE）。
# 数据 API 规范：list 走统一分页信封 env.page（{code,message,data:{page,size,total,items}}）。
# 权限：GET list = vuln:read（默认放行读）；POST sync/clear = vuln:write（网关按 rbac 规则拦）。
ns_poc = Namespace("poc", path="/poc", description="PoC 插件信息：查询/同步/清空")
_poc_list_parser = ns_poc.parser()
_poc_list_parser.add_argument("plugin_name", type=str, location="args", help="PoC 名称(模糊)")
_poc_list_parser.add_argument("app_name", type=str, location="args", help="应用名(模糊)")
_poc_list_parser.add_argument("vul_name", type=str, location="args", help="漏洞名(模糊)")
_poc_list_parser.add_argument("plugin_type", type=str, location="args", help="插件类别 poc/brute")
_poc_list_parser.add_argument("scheme", type=str, location="args", help="协议")
_poc_list_parser.add_argument("category", type=str, location="args", help="分类(模糊)")
_poc_list_parser.add_argument("page", type=int, location="args", help="页码,默认1")
_poc_list_parser.add_argument("size", type=int, location="args", help="每页条数,默认10")


@ns_poc.route("/")
class PocList(Resource):
    @ns_poc.doc(security="token")
    @ns_poc.expect(_poc_list_parser)
    def get(self):
        """PoC 信息查询（分页）"""
        poc = _poc_svc()
        if not poc:
            return err(CODE_ERROR, "PoC 服务未就绪")
        from ..envelope import page as _page
        args = _poc_list_parser.parse_args()
        data = poc.list_poc(args)
        return _page(data["items"], data["total"], data["page"], data["size"])


@ns_poc.route("/sync/")
class PocSync(Resource):
    @ns_poc.doc(security="token")
    def post(self):
        """同步 PoC 信息（需 vuln:write）"""
        poc = _poc_svc()
        if not poc:
            return err(CODE_ERROR, "PoC 服务未就绪")
        r = poc.sync_poc()
        return err(CODE_ERROR, r["error"]) if r.get("error") else ok(r)


@ns_poc.route("/delete/")
class PocDelete(Resource):
    @ns_poc.doc(security="token")
    def post(self):
        """清空 PoC 信息（需 vuln:write）"""
        poc = _poc_svc()
        if not poc:
            return err(CODE_ERROR, "PoC 服务未就绪")
        r = poc.clear_poc()
        return err(CODE_ERROR, r["error"]) if r.get("error") else ok(r)


@ns_poc.route("/import/")
class PocImport(Resource):
    @ns_poc.doc(security="token", description="导入单个 .py POC（需 vuln:write）。npoc 结构自动进内核扫描，其他进 AI 脚本库")
    def post(self):
        """导入单个 .py POC。multipart file 或 JSON {filename, content, overwrite}"""
        poc = _poc_svc()
        if not poc:
            return err(CODE_ERROR, "PoC 服务未就绪")
        f = request.files.get("file")
        if f is not None:
            try:
                content = f.read().decode("utf-8", "ignore")
            except Exception as exc:
                return err(CODE_BAD_REQUEST, "文件读取失败: {}".format(exc))
            r = poc.import_poc(f.filename, content, overwrite=_truthy(request.form.get("overwrite")))
        else:
            b = request.get_json(silent=True) or {}
            if not b.get("filename") or not b.get("content"):
                return err(CODE_BAD_REQUEST, "filename 与 content 必填（或用 multipart file）")
            r = poc.import_poc(b["filename"], b["content"], overwrite=bool(b.get("overwrite")))
        return err(CODE_BAD_REQUEST, r["error"]) if not r.get("ok") else ok(r)


@ns_poc.route("/batch_import/")
class PocBatchImport(Resource):
    @ns_poc.doc(security="token", description="批量导入 zip 内所有 .py POC（需 vuln:write）")
    def post(self):
        """批量导入（multipart file=zip）"""
        poc = _poc_svc()
        if not poc:
            return err(CODE_ERROR, "PoC 服务未就绪")
        f = request.files.get("file")
        if f is None:
            return err(CODE_BAD_REQUEST, "file 必填（multipart zip）")
        try:
            data = f.read()
        except Exception as exc:
            return err(CODE_BAD_REQUEST, "文件读取失败: {}".format(exc))
        r = poc.batch_import_poc(data, overwrite=_truthy(request.form.get("overwrite")))
        return err(CODE_BAD_REQUEST, r["error"]) if not r.get("ok") else ok(r)


@ns_poc.route("/template/")
class PocTemplate(Resource):
    @ns_poc.doc(security="token", description="下载批量导入 .py POC 模板（需 vuln:read）")
    def get(self):
        """POC 模板下载（.py 文件）"""
        import time as _t
        poc = _poc_svc()
        if not poc:
            return err(CODE_ERROR, "PoC 服务未就绪")
        text = poc.import_template()
        resp = Response(text, mimetype="application/octet-stream")
        resp.headers["Content-Disposition"] = "attachment; filename=poc_template_{}.py".format(int(_t.time()))
        resp.headers["Access-Control-Expose-Headers"] = "Content-Disposition"
        return resp


@ns_poc.route("/remove/")
class PocRemove(Resource):
    @ns_poc.doc(security="token", description="按 _id 删除导入的 POC + 物理文件（需 vuln:write）")
    def post(self):
        """删除导入的 POC（按 _id 列表；仅删 imported 来源文件，内置不动）"""
        poc = _poc_svc()
        if not poc:
            return err(CODE_ERROR, "PoC 服务未就绪")
        b = request.get_json(silent=True) or {}
        ids = b.get("_id") or b.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "_id(非空数组) 必填")
        r = poc.delete_poc(ids)
        return err(CODE_BAD_REQUEST, r["error"]) if not r.get("ok") else ok(r)


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


# ============ 单位视图（/api/intel/units|unit|resolve_icp，Claude-Opus[recon] 2026-07-05）============
# unit_view 无 ROLE，核心路由暴露：endpoint 直调叶子函数。同 /api/intel 根，Resource 加到既有 ns。
# resolve_icp 复用 kernel/ext_source.icp_query（跨模块经暴露层：router→leaf 允许，ext_source 无 ROLE）。
# 权限：GET units/detail=intel:read（默认放行）；POST unit/delete=user:manage（级联删高危，fail-closed）。
@ns.route("/units/")
class _Units(Resource):
    @ns.doc(security="token", description="需权限 intel:read")
    def get(self):
        """单位卡片列表（按单位聚合资产/漏洞/报告/攻击链）"""
        unit_view = _unit_view_svc()
        if not unit_view:
            return err(CODE_ERROR, "单位视图服务未就绪")
        return ok({"units": unit_view.unit_overview()})


@ns.route("/unit/<string:unit>")
class _UnitDetail(Resource):
    @ns.doc(security="token", description="需权限 intel:read")
    def get(self, unit):
        """单位详情（漏洞/子域名/系统/报告/攻击链明细）"""
        from urllib.parse import unquote
        unit_view = _unit_view_svc()
        if not unit_view:
            return err(CODE_ERROR, "单位视图服务未就绪")
        r = unit_view.unit_detail(unquote(unit or ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/unit/delete/")
class _UnitDelete(Resource):
    @ns.doc(security="token", description="需权限 user:manage（级联删除高危）")
    def post(self):
        """级联删除单位数据（高危：清该单位 asset/finding/report/session/clue/chain）"""
        unit_view = _unit_view_svc()
        if not unit_view:
            return err(CODE_ERROR, "单位视图服务未就绪")
        body = request.get_json(silent=True) or {}
        r = unit_view.delete_unit(body.get("unit", ""))
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)

# 注：POST /api/intel/resolve_icp/ 由 endpoints/asset_intel.py 的 IntelResolveIcp 统一提供
# （走 INTEL.resolve_icp 门面，权限 intel:write，带参数校验）。此前 unit_view 侧曾重复定义一份
# _ResolveIcp（同路径 /intel + /resolve_icp/），因 asset_intel 的 ns 后加载被覆盖、从不生效，
# 且权限点不一致（read vs write），已于 2026-08-19 删除以消除路由冲突。
