"""network 端点 —— 网络检测 HTTP 接口（/api/network/*）。

纯 HTTP 编解层：参数解析 + 信封包装 + 经 registry 调 network_check_service 叶子能力。
业务逻辑（DNS 配置 CRUD、ICMP ping）在 modules/system/network_check.py。
"""
from __future__ import annotations

import re

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_BAD_REQUEST, CODE_ERROR

ns = Namespace("network", path="/network", description="网络检测：ping / DNS 配置")


def _svc():
    return get_registry().get("network_check_service")


@ns.route("/dns")
class _DnsConfig(Resource):
    def get(self):
        """获取 DNS 服务器配置"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        return ok(svc.get_dns_config())

    def post(self):
        """保存 DNS 服务器配置"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        body = request.get_json(silent=True) or {}
        servers = body.get("servers") or []
        if not isinstance(servers, list):
            return err(CODE_BAD_REQUEST, "servers 须为数组")
        result = svc.save_dns_config(servers)
        if not result.get("ok"):
            return err(CODE_BAD_REQUEST, result.get("error", "保存失败"))
        return ok(result)


@ns.route("/ping")
class _Ping(Resource):
    def post(self):
        """Ping 指定主机，返回终端风格输出"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        body = request.get_json(silent=True) or {}
        host = (body.get("host") or "").strip()
        count = int(body.get("count") or 4)
        if not host:
            return err(CODE_BAD_REQUEST, "host 必填")
        if not re.match(r'^[a-zA-Z0-9\.\-:]+$', host):
            return err(CODE_BAD_REQUEST, "主机名格式无效")
        if count < 1:
            count = 4
        if count > 20:
            count = 20
        output = svc.ping(host, count)
        return ok({"host": host, "output": output, "returncode": 0})


# ======================== 网络质量检测（v1.21.148-10）========================
_HOST_RE = re.compile(r'^[a-zA-Z0-9\.\-:]+$')


@ns.route("/quality/ping")
class _QualityPing(Resource):
    def post(self):
        """① 链路质量：多次 ping 算丢包率+RTT抖动。body:{host,count?}"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        body = request.get_json(silent=True) or {}
        host = (body.get("host") or "").strip()
        if not host or not _HOST_RE.match(host):
            return err(CODE_BAD_REQUEST, "host 必填且格式合法")
        count = int(body.get("count") or 10)
        count = min(max(count, 1), 30)
        return ok(svc.ping_quality(host, count))


@ns.route("/quality/stability")
class _QualityStability(Resource):
    def post(self):
        """② 出网稳定性：对国内+国外目标连续 HTTP 探 N 次统计成功率。body:{targets?,rounds?}"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        body = request.get_json(silent=True) or {}
        rounds = int(body.get("rounds") or 5)
        rounds = min(max(rounds, 1), 15)
        return ok(svc.egress_stability(body.get("targets"), rounds))


@ns.route("/quality/dns")
class _QualityDns(Resource):
    def post(self):
        """③ DNS 健康：多 DNS 解析同一域名对比成功率+耗时。body:{host?}"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        body = request.get_json(silent=True) or {}
        host = (body.get("host") or "www.baidu.com").strip()
        if not _HOST_RE.match(host):
            return err(CODE_BAD_REQUEST, "host 格式无效")
        return ok(svc.dns_health(host))


@ns.route("/quality/deps")
class _QualityDeps(Resource):
    def get(self):
        """④ 关键依赖一键体检：批量探 LLM/更新源/情报源/GitHub/订阅站可达性"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        return ok(svc.deps_healthcheck())


@ns.route("/quality/proxy")
class _QualityProxy(Resource):
    def get(self):
        """⑤ 代理出口质量：经代理测出口IP+延迟对比直连"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "网络检测服务未就绪")
        return ok(svc.proxy_egress_quality())


@ns.route("/quality/assess")
class _QualityAssess(Resource):
    def post(self):
        """综合评估：接收前端已跑完的5项结果，后端加权聚合成总分+总评级（单一事实源）。
        body:{ping,stability,dns,deps,proxy}（各为对应检测端点的 data，缺项按空处理）"""
        svc = _svc()
        if not svc or not hasattr(svc, "overall_assessment"):
            return err(CODE_ERROR, "网络检测服务未就绪")
        b = request.get_json(silent=True) or {}
        return ok(svc.overall_assessment(b.get("ping"), b.get("stability"),
                                         b.get("dns"), b.get("deps"), b.get("proxy")))


@ns.route("/quality/latest")
class _QualityLatest(Resource):
    def get(self):
        """读最新落库的体检结果（定时监测产出）。供态势总览显示总评 + 体检页进页展示缓存。"""
        svc = _svc()
        if not svc or not hasattr(svc, "get_latest_quality"):
            return err(CODE_ERROR, "网络检测服务未就绪")
        return ok(svc.get_latest_quality())

    def post(self):
        """保存前端已跑完的体检结果到库（前端并行跑5项后回传落库，供态势总览/下次进页读缓存）。
        body:{ping,stability,dns,deps,proxy}。后端算总评+落库，避免前端体检结果丢失、与定时监测统一存储。"""
        svc = _svc()
        if not svc or not hasattr(svc, "save_quality_result"):
            return err(CODE_ERROR, "网络检测服务未就绪")
        b = request.get_json(silent=True) or {}
        return ok(svc.save_quality_result(b.get("ping"), b.get("stability"),
                                          b.get("dns"), b.get("deps"), b.get("proxy")))
