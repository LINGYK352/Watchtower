"""proxy 端点 —— 代理中心的对外 REST（挂 /api/proxy/），解前端 ProxySetting.vue 孤岛。

对齐前端 api/proxy.ts（路径/形状锁定）。全部真挂（2026-08-02 补齐 mihomo 生命周期，此前 core/profiles/
proxies/logs/traffic 是 phase-2 桩 + import_url/upload/activate/select/auto_select/traffic_reset 端点缺失致前端 404）：
  ① 契约核心：status / config / exit_ip / health。
  ② mihomo 内核：core 启停 / profiles+profile 增删激活 / proxies+select+auto_select 节点操作 / logs / traffic
     （委托 system/_mihomo 进程管理，经 ROLE.PROXY 门面调）。
  ③ 公开代理池：pool/*（system/_pool）。

范式：经 get_registry().get(ROLE.PROXY) 调门面（不 import 叶子内部，缺失降级 500）+ env 信封。
权限：读 proxy:read（status/config-get/exit_ip/logs/traffic/pool-list）/ 写 proxy:write（config-save/core/profile/pool-改）。
**禁硬限制参数**：pool 列表 size 透传不砍。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry, ROLE
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR

logger = get_logger()

ns = Namespace("proxy", path="/proxy", description="代理中心：出口配置/健康/节点/流量/公开池")
try:
    from ..openapi import register_envelope_models
    register_envelope_models(ns)
except Exception:
    pass

_cfg_req = ns.model("ProxyConfigReq", {})


def _svc():
    """取 PROXY 服务（ROLE.PROXY，system/proxy 实现）；未注册 None（降级 500）。"""
    return get_registry().get(ROLE.PROXY)


def _pool():
    """取公开代理池服务（字符串键 proxy_pool_service，system/_pool 实现）；未注册 None 降级。"""
    return get_registry().get("proxy_pool_service")


# ========== ① 契约核心（真挂）==========

@ns.route("/status")
class ProxyStatus(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def get(self):
        """代理中心状态（配置/运行态/出口URL/最近健康）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        return ok(svc.status())


@ns.route("/config")
class ProxyConfig(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def get(self):
        """读代理配置"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        return ok(svc.get_config())

    @ns.doc(security="token", description="需权限 proxy:write")
    @ns.expect(_cfg_req)
    def post(self):
        """保存代理配置（端口/模式/健康检测阈值/DoH 等）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return err(CODE_BAD_REQUEST, "请求体必须为 JSON 对象")
        r = svc.save_config(data)
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/exit_ip")
class ProxyExitIp(Resource):
    @ns.doc(security="token", description="需权限 proxy:read；?fresh=1 强制实探绕缓存（手动测试用）")
    def get(self):
        """出口 IP 对比检测（代理出口 vs 直连出口，确认流量是否真走代理）。
        默认命中 TTL 缓存（态势总览轮询提速）；带 ?fresh=1 强制实探。"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        fresh = request.args.get("fresh", "") in ("1", "true", "True")
        try:
            return ok(svc.detect_exit_ip(use_cache=not fresh))
        except TypeError:
            return ok(svc.detect_exit_ip())   # 兼容旧签名（未更新的实现）


@ns.route("/egress_options")
class ProxyEgressOptions(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def get(self):
        """出口模式可选性（新建任务页 AI 攻击出口用）：direct/global/smart 各档 {available, reason}。
        只校验源是否配置、不探可达（内网无公网出口不误伤）。未配置的模式 available=false，reason 供 tooltip。"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        try:
            return ok(svc.egress_options())
        except Exception:
            # 降级：服务异常时全部可用（不阻塞建任务），前端拿默认
            return ok({"direct": {"available": True, "reason": ""},
                       "global": {"available": True, "reason": ""},
                       "smart": {"available": True, "reason": ""}})


@ns.route("/health")
class ProxyHealth(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def get(self):
        """代理健康检查（经代理探出口 IP）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        return ok({"healthy": bool(svc.check_health())})


# ========== ② mihomo 内核生命周期 + profile/节点/流量/日志（2026-08-02 补齐，此前 phase-2 桩）==========

@ns.route("/core/<string:action>")
class ProxyCore(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（mihomo 启停 start/stop/restart）")
    def post(self, action):
        """启停 mihomo 内核"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.core_action(action)
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/profiles")
class ProxyProfiles(Resource):
    @ns.doc(security="token", description="需权限 proxy:read（订阅档列表）")
    def get(self):
        """机场订阅/上传配置档列表"""
        svc = _svc()
        return ok(svc.list_profiles()) if svc else err(CODE_ERROR, "代理服务未就绪")


@ns.route("/profile/import_url")
class ProxyProfileImportUrl(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（订阅 URL 导入，SSRF 校验）")
    def post(self):
        """从订阅链接导入机场配置档"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        b = request.get_json(silent=True) or {}
        if not b.get("url"):
            return err(CODE_BAD_REQUEST, "url 必填")
        r = svc.import_profile(name=b.get("name", ""), url=b["url"])
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/profile/upload")
class ProxyProfileUpload(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（上传 YAML 配置档）")
    def post(self):
        """上传机场配置档内容"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        b = request.get_json(silent=True) or {}
        if not b.get("content"):
            return err(CODE_BAD_REQUEST, "content 必填")
        r = svc.import_profile(name=b.get("name", ""), content=b["content"])
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/profile/<string:profile_id>/activate")
class ProxyProfileActivate(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（激活订阅档 + 重载内核）")
    def post(self, profile_id):
        """激活订阅档（内核在跑则重启重载）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.activate_profile(profile_id)
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/profile/<string:profile_id>")
class ProxyProfileDelete(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（删除订阅档）")
    def delete(self, profile_id):
        """删除机场配置档"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        return ok(svc.delete_profile(profile_id))


@ns.route("/proxies")
class ProxyProxies(Resource):
    @ns.doc(security="token", description="需权限 proxy:read（节点列表）")
    def get(self):
        """mihomo 节点列表（controller /proxies）"""
        svc = _svc()
        return ok(svc.list_proxies()) if svc else err(CODE_ERROR, "代理服务未就绪")


@ns.route("/proxies/select")
class ProxySelect(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（手动选节点）")
    def post(self):
        """手动选择节点"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        b = request.get_json(silent=True) or {}
        if not b.get("group") or not b.get("name"):
            return err(CODE_BAD_REQUEST, "group 与 name 必填")
        r = svc.select_node(b["group"], b["name"])
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/proxies/auto_select")
class ProxyAutoSelect(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（自动优选最快节点）")
    def post(self):
        """自动优选最快节点"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        b = request.get_json(silent=True) or {}
        r = svc.auto_select(b.get("group", "GLOBAL"))
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/logs")
class ProxyLogs(Resource):
    @ns.doc(security="token", description="需权限 proxy:read（内核日志）")
    def get(self):
        """mihomo 运行日志"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        try:
            lines = int(request.args.get("lines") or 200)
        except (TypeError, ValueError):
            lines = 200
        return ok({"logs": svc.read_logs(lines)})


@ns.route("/traffic")
class ProxyTraffic(Resource):
    @ns.doc(security="token", description="需权限 proxy:read（流量账本）")
    def get(self):
        """代理流量账本（实时连接数 + 跨重启累计总量/机场/节点）"""
        svc = _svc()
        return ok(svc.traffic()) if svc else err(CODE_ERROR, "代理服务未就绪")


@ns.route("/traffic/reset")
class ProxyTrafficReset(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（重置流量账本）")
    def post(self):
        """重置流量账本（scope+key 清一条 / scope 清一类 / 空清全部）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        b = request.get_json(silent=True) or {}
        return ok(svc.reset_traffic(b.get("scope", ""), b.get("key", "")))


@ns.route("/pool/list")
class ProxyPoolList(Resource):
    @ns.doc(security="token", description="需权限 proxy:read（公开代理池列表，size 无硬上限）")
    def get(self):
        """公开抓取代理池列表（分页 + status 过滤 alive/dead/unchecked）"""
        svc = _pool()
        if not svc:
            return err(CODE_ERROR, "代理池服务未就绪")
        from flask import request as _rq
        try:
            page = int(_rq.args.get("page") or 1); size = int(_rq.args.get("size") or 50)
        except (TypeError, ValueError):
            page, size = 1, 50
        return ok(svc.list(page=page, size=size, status=_rq.args.get("status") or ""))


@ns.route("/pool/stats")
class ProxyPoolStats(Resource):
    @ns.doc(security="token", description="需权限 proxy:read（代理池统计）")
    def get(self):
        """公开代理池统计（total/alive/dead/unchecked/enabled）"""
        svc = _pool()
        return ok(svc.stats()) if svc else err(CODE_ERROR, "代理池服务未就绪")


@ns.route("/pool/crawl")
class ProxyPoolCrawl(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（按配置从 FOFA/Hunter 抓取入池）")
    def post(self):
        """抓取公开代理入池（返回新增数 + 每查询明细 + 错误）"""
        svc = _pool()
        return ok(svc.crawl()) if svc else err(CODE_ERROR, "代理池服务未就绪")


@ns.route("/pool/verify")
class ProxyPoolVerify(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（验活，ids 空=全部；socks5 缺 PySocks 降级）")
    def post(self):
        """验活代理（经代理取出口 IP，失败累计剔除）"""
        svc = _pool()
        if not svc:
            return err(CODE_ERROR, "代理池服务未就绪")
        from flask import request as _rq
        ids = (_rq.get_json(silent=True) or {}).get("ids")
        return ok(svc.verify(ids))


@ns.route("/pool/enable")
class ProxyPoolEnable(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（批量启停）")
    def post(self):
        """批量启用/禁用代理"""
        svc = _pool()
        if not svc:
            return err(CODE_ERROR, "代理池服务未就绪")
        from flask import request as _rq
        body = _rq.get_json(silent=True) or {}
        ids = body.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "ids(非空数组) 必填")
        return ok(svc.enable(ids, bool(body.get("enabled", True))))


@ns.route("/pool/delete")
class ProxyPoolDelete(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（批量删除）")
    def post(self):
        """批量删除代理"""
        svc = _pool()
        if not svc:
            return err(CODE_ERROR, "代理池服务未就绪")
        from flask import request as _rq
        ids = (_rq.get_json(silent=True) or {}).get("ids") or []
        if not isinstance(ids, list) or not ids:
            return err(CODE_BAD_REQUEST, "ids(非空数组) 必填")
        return ok(svc.delete(ids))


@ns.route("/pool/add")
class ProxyPoolAdd(Resource):
    @ns.doc(security="token", description="需权限 proxy:write（手动添加单条 http/socks5）")
    def post(self):
        """手动添加一条代理"""
        svc = _pool()
        if not svc:
            return err(CODE_ERROR, "代理池服务未就绪")
        from flask import request as _rq
        b = _rq.get_json(silent=True) or {}
        if not b.get("host") or not b.get("port"):
            return err(CODE_BAD_REQUEST, "host 与 port 必填")
        r = svc.add(b.get("type", "http"), b.get("host"), b.get("port"))
        if not r.get("ok"):
            return err(CODE_BAD_REQUEST, r.get("error", "添加失败"))
        return ok(r)


@ns.route("/pool/config")
class ProxyPoolConfig(Resource):
    @ns.doc(security="token", description="读 proxy:read / 写 proxy:write（抓取配置 queries+limit）")
    def get(self):
        """公开代理池抓取配置"""
        svc = _pool()
        return ok(svc.get_config()) if svc else err(CODE_ERROR, "代理池服务未就绪")

    def post(self):
        """保存抓取配置（queries 校验 source/type，limit 无硬顶）"""
        svc = _pool()
        if not svc:
            return err(CODE_ERROR, "代理池服务未就绪")
        from flask import request as _rq
        return ok(svc.save_config(_rq.get_json(silent=True) or {}))


# ============================ 4模式重构：全局模式 / 自定义代理 / 规则代理 ============================
@ns.route("/custom")
class ProxyCustom(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def get(self):
        """列出自定义代理"""
        svc = _svc()
        return ok({"items": svc.list_custom()}) if svc else err(CODE_ERROR, "代理服务未就绪")

    @ns.doc(security="token", description="需权限 proxy:write")
    def post(self):
        """新增/更新自定义代理 {_id?, name, url, enabled?}"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.save_custom(request.get_json(silent=True) or {})
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "保存失败"))


@ns.route("/custom/<string:cid>")
class ProxyCustomItem(Resource):
    @ns.doc(security="token", description="需权限 proxy:write")
    def delete(self, cid):
        """删除自定义代理"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.delete_custom(cid)
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "删除失败"))


@ns.route("/custom/<string:cid>/test")
class ProxyCustomTest(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def post(self, cid):
        """探测自定义代理可达性"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.test_custom(cid)
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "探测失败"))


@ns.route("/rule")
class ProxyRule(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def get(self):
        """列出规则代理（供策略下拉选）"""
        svc = _svc()
        return ok({"items": svc.list_rule()}) if svc else err(CODE_ERROR, "代理服务未就绪")

    @ns.doc(security="token", description="需权限 proxy:write")
    def post(self):
        """新增/更新规则代理 {_id?, name, source:{type,ref_id}, enabled?}"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.save_rule(request.get_json(silent=True) or {})
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "保存失败"))


@ns.route("/rule/<string:rid>")
class ProxyRuleItem(Resource):
    @ns.doc(security="token", description="需权限 proxy:write")
    def delete(self, rid):
        """删除规则代理"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.delete_rule(rid)
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "删除失败"))


@ns.route("/rule/<string:rid>/test")
class ProxyRuleTest(Resource):
    @ns.doc(security="token", description="需权限 proxy:read")
    def post(self, rid):
        """探测规则代理绑定源可达性"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "代理服务未就绪")
        r = svc.test_rule(rid)
        return ok(r) if r.get("ok") else err(CODE_BAD_REQUEST, r.get("error", "探测失败"))
