"""about 端点 —— 更新检测 + 热更新执行（/api/about/*）。

对接 about/update_check 叶子（无 ROLE，核心路由暴露，endpoint 直调叶子函数）。
公开端点（探活/版本无需鉴权，同 meta）。
热更新流程：前端触发 /apply → 后台线程下载变更文件 → /progress 轮询进度 → 完成后刷新生效。
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
from urllib.request import Request, urlopen

from flask_restx import Namespace, Resource

from sentinel_platform.core import get_config
from sentinel_platform.contracts import get_registry
from ..envelope import ok, err, CODE_ERROR

ns = Namespace("about", path="/about", description="关于系统：版本 / 更新检测")


def _svc():
    """取 update_check 服务门面（字符串键 "update_check_service"，无 ROLE）。未注册降级。"""
    return get_registry().get("update_check_service")


_check_parser = ns.parser()
_check_parser.add_argument("client", type=str, location="args", help="前端构建版本(如 v1.21.21)")


@ns.route("/version")
class _Version(Resource):
    @ns.doc(security=None)
    def get(self):
        """服务端当前版本（公开）"""
        uc = _svc()
        if not uc:
            return err(CODE_ERROR, "更新检测服务未就绪")
        return ok({"version": uc.server_version()})


@ns.route("/check")
class _Check(Resource):
    @ns.doc(security=None)
    @ns.expect(_check_parser)
    def get(self):
        """更新检测：比对前端构建版本与服务端版本（公开）"""
        uc = _svc()
        if not uc:
            return err(CODE_ERROR, "更新检测服务未就绪")
        args = _check_parser.parse_args()
        return ok(uc.check_update(args.get("client") or ""))


# ============================ 热更新执行 ============================

# 进度状态持久化到文件（跨 gunicorn 多 worker 共享）；更新执行逻辑在独立模块 _updater（子进程运行）
from sentinel_platform.modules.about import _updater

_PROGRESS_FILE = _updater.PROGRESS_FILE


def _get_progress() -> dict:
    return _updater.get_progress()


def _set_progress(phase: str, total: int = 0, done: int = 0, msg: str = "", error: str = ""):
    _updater.set_progress(phase, total, done, msg, error)


def _project_root() -> str:
    """计算项目根目录（about.py 在 sentinel_platform/router/endpoints/ 下，上溯 3 层得到根）。"""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _read_update_key() -> str:
    """读取激活凭证 —— 统一走 system/activation.read_key()（始终 fresh 读盘，多 worker 一致）。"""
    from sentinel_platform.modules.system import activation
    return activation.read_key()


# 与分发系统 _update_common.TRACK_DIRS 对齐（不 import 分发系统——主平台零耦合，本地内联一份）。
# 回退时据此扫描本地跟踪目录，识别"目标版不存在但本地有"的多余文件。
def _launch_updater(source_url: str, key: str, current_root: str, target_version: str = ""):
    """以**独立子进程**启动更新执行器（_updater），免疫 gunicorn --reload 杀线程。
    根因：daemon 线程逐文件写后端 .py 触发 --reload 重启 worker→线程被杀→进度冻结（VM 实测卡 143/153）。
    子进程 detached（Linux setsid / Windows DETACHED），随本 worker 重启也不受影响；进度照旧写文件。"""
    import sys
    _set_progress("checking", msg="正在启动更新进程...")
    args = [sys.executable, "-m", "sentinel_platform.modules.about._updater",
            source_url, key, current_root]
    if target_version:
        args.append(target_version)
    kwargs = {"cwd": current_root, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "posix":
        kwargs["start_new_session"] = True          # setsid：脱离 worker 进程组，reload 杀不到
    else:
        kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen(args, **kwargs)


_DEFAULT_SOURCE = "https://watchtowers.info"


def _source_url() -> str:
    src = (get_config().section("UPDATE", "SOURCE_URL", default="") or "").strip().rstrip("/")
    return src or _DEFAULT_SOURCE


# 转发分发源的重试参数（对齐 update_check.remote_version：治间歇失败/超时闪烁，见记忆
# feedback-retry-not-cache-for-flaky-probe——间歇失败优先重试自愈，不引缓存/粘滞）。
_FWD_RETRY = 3       # 网络波动重试次数
_FWD_BACKOFF = 0.5   # 退避基数（0.5s / 1s / ... 指数退避）


def _forward_get(path: str, timeout: int = 15, retry: int = _FWD_RETRY):
    """带重试的分发源 GET 转发。返回 (data, err_reason)：
      data 非 None = 成功（已 json 解析）；
      err_reason ∈ {'', 'unauthorized', 'not_found', 'network'}。

    分发源 /versions 等需实时算全量 manifest，偶发慢/超时——单次超时不判定失败，
    重连 retry 次（指数退避）全失败才报 'network'。403（凭证）/404（端点不支持）是
    确定性错误，立即返回不重试（重试也没用）。"""
    key = _read_update_key()
    last = None
    for attempt in range(max(1, retry)):
        try:
            req = Request(_source_url() + path, headers={"X-Update-Key": key} if key else {})
            with urlopen(req, timeout=timeout) as r:
                return json.loads(r.read()), ""
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return None, "unauthorized"      # 凭证确定性错误
            if e.code == 404:
                return None, "not_found"          # 分发源尚不支持该端点，确定性
            last = e                              # 5xx 等偶发错误可重试
        except Exception as e:
            last = e
        if attempt < retry - 1:
            time.sleep(_FWD_BACKOFF * (2 ** attempt))
    return None, "network"


@ns.route("/apply")
class _Apply(Resource):
    @ns.doc(security=None)
    def post(self):
        """触发热更新（后台执行）"""
        p = _get_progress()
        if p.get("phase") in ("downloading", "validating", "applying"):
            return ok({"started": False, "msg": "更新正在进行中"})
        key = _read_update_key()
        if not key:
            return err(CODE_ERROR, "未激活，请先激活系统获取授权凭证")
        current_root = _project_root()
        # 一级一级更新：传哨兵 "__chain__" → _updater 走链式驱动，从当前版逐级升到最新，
        # 每级走完整下载/校验/提交流程，只在最终级重启（中间级只落盘+改版本号，不重启）。
        _launch_updater(_source_url(), key, current_root, "__chain__")   # 独立子进程，免疫 --reload
        return ok({"started": True})


@ns.route("/versions")
class _Versions(Resource):
    @ns.doc(security=None)
    def get(self):
        """历史版本列表（转发分发源版本仓，供 UI 回退选择）"""
        data, reason = _forward_get("/versions")
        if data is not None:
            return ok(data)
        if reason == "unauthorized":
            return err(CODE_ERROR, "授权凭证无效或已过期，无法获取版本列表")
        # 404 = 分发源版本落后、尚不支持版本仓端点：可选增强，优雅降级为空（不甩"失败:404"）。
        if reason == "not_found":
            return ok({"latest": "", "versions": [], "unsupported": True})
        # network = 重试 N 次仍失败（偶发超时）：区分于"真无历史"——标 fetch_failed 让前端
        # 提示"暂时获取失败，请重试"而非误报"暂无历史版本"（治闪烁：有历史但没拿到）。
        return ok({"latest": "", "versions": [], "fetch_failed": True})


@ns.route("/changes")
class _Changes(Resource):
    @ns.doc(security=None)
    @ns.expect(_check_parser)   # 复用 args 解析（此处取 version）
    def get(self):
        """某版相对上版的更新表（改了哪些文件）"""
        from flask import request as _rq
        version = (_rq.args.get("version") or "").strip()
        if not version:
            return err(CODE_ERROR, "version 必填")
        from urllib.parse import quote
        data, reason = _forward_get("/changes?version=" + quote(version, safe=""))
        if data is not None:
            return ok(data)
        if reason == "unauthorized":
            return err(CODE_ERROR, "授权凭证无效或已过期，无法获取更新表")
        if reason == "not_found":
            return err(CODE_ERROR, "分发源无该版本的更新表")
        return err(CODE_ERROR, "获取更新表失败，请稍后重试")


@ns.route("/rollback")
class _Rollback(Resource):
    def post(self):
        """回退到指定历史版本（高危：需 system:update 权限，绕过防降级守卫）"""
        from flask import request as _rq
        body = _rq.get_json(silent=True) or {}
        target = (body.get("version") or "").strip()
        if not target:
            return err(CODE_ERROR, "version 必填")
        p = _get_progress()
        if p.get("phase") in ("downloading", "validating", "applying"):
            return ok({"started": False, "msg": "更新正在进行中"})
        key = _read_update_key()
        if not key:
            return err(CODE_ERROR, "未激活，请先激活系统获取授权凭证")
        current_root = _project_root()
        _launch_updater(_source_url(), key, current_root, target)   # 独立子进程，免疫 --reload
        return ok({"started": True, "target_version": target})


@ns.route("/report_error")
class _ReportError(Resource):
    def post(self):
        """上传报错到云端分发系统（用户选中日志 + 描述 → 转发，带凭证）"""
        from flask import request as _rq
        body = _rq.get_json(silent=True) or {}
        desc = (body.get("description") or "").strip()
        log_content = body.get("log_content") or ""
        if not desc and not log_content:
            return err(CODE_ERROR, "描述和日志不能都为空")
        key = _read_update_key()
        if not key:
            return err(CODE_ERROR, "未激活，无法上传（需授权凭证）")
        payload = {"description": desc, "log_content": log_content,
                   "version": body.get("version") or "", "meta": body.get("meta") or ""}
        try:
            req = Request(_source_url() + "/report_error",
                          data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                          headers={"X-Update-Key": key, "Content-Type": "application/json"})
            with urlopen(req, timeout=15) as r:
                return ok(json.loads(r.read()))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return err(CODE_ERROR, "授权凭证无效或已过期，无法上传")
            return err(CODE_ERROR, "上传失败: {}".format(e.code))
        except Exception as e:
            return err(CODE_ERROR, "无法连接分发系统: {}".format(e))


@ns.route("/my_reports")
class _MyReports(Resource):
    @ns.doc(security="token", description="查本用户上传过的报错 + 开发者回复（凭激活 key 向分发系统查）")
    def get(self):
        """我的上报：凭本实例激活凭证向分发系统拉取归属本人的报错记录 + 开发者回复。"""
        key = _read_update_key()
        if not key:
            return err(CODE_ERROR, "未激活，无法查询（需授权凭证）")
        try:
            req = Request(_source_url() + "/my_reports", headers={"X-Update-Key": key})
            with urlopen(req, timeout=12) as r:
                return ok(json.loads(r.read()))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return err(CODE_ERROR, "授权凭证无效或已过期")
            return err(CODE_ERROR, "查询失败: {}".format(e.code))
        except Exception as e:
            return err(CODE_ERROR, "无法连接分发系统: {}".format(e))


@ns.route("/progress")
class _Progress(Resource):
    @ns.doc(security=None)
    def get(self):
        """热更新进度"""
        return ok(_get_progress())


@ns.route("/changelog")
class _Changelog(Resource):
    @ns.doc(security=None)
    def get(self):
        """更新日志：优先读本地 changelog.json（权威、离线可用、随版本部署即最新），
        读不到再转发分发源兜底。根治「前端硬编码列表卡在旧版本」——前端统一调本接口。"""
        import json
        try:
            p = os.path.join(_project_root(), "changelog.json")
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f:
                    local = json.load(f)
                if isinstance(local, list) and local:
                    return ok(local)
        except Exception:
            pass   # 本地读失败降级转发分发源
        data, _ = _forward_get("/changelog", timeout=10)
        return ok(data if data is not None else [])


@ns.route("/announcements")
class _Announcements(Resource):
    @ns.doc(security=None)
    def get(self):
        """通告拉取（转发分发源，仅返生效中的，供前端通告栏展示）。

        分发源 /announcements 返回 {announcements:[{id,ts,title,content,level,popup,...}]}。
        分发源落后未支持该端点(404)/不可达/未激活 → 优雅降级为空列表，
        不把失败甩给用户（通告是可选增强，分发源升级后自然恢复）。
        偶发超时经 _forward_get 重试自愈，不因单次抖动漏掉生效中的通告。"""
        data, _ = _forward_get("/announcements", timeout=10)
        return ok(data if data is not None else {"announcements": []})

