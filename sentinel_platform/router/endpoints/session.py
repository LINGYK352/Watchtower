"""session 端点 —— AI 渗透会话的对外 REST（挂 /api/pentest/session*）。

**独立成文件**：ai_pentest 类别的 endpoints/ai_pentest.py(ai_config)、ai_tools.py(工具目录) 已占用；
session 单独成文件。Namespace path `/pentest`、route `/session*`——与 ai_tools `/pentest/tools`、
vuln_center `/pentest/finding/*` 同 `/pentest` path 共存不冲突（Flask-RESTX 多 Namespace 同 path，路由不重叠）。

对齐前端 api/pentest.ts（路径/形状锁定）：
  GET  /api/pentest/session         列表(?status&page&size)   POST /api/pentest/session 新建
  GET  /api/pentest/session/<id>    详情   GET /api/pentest/session/<id>/messages 消息
  POST /api/pentest/session/<id>/{start,resume,stop,delete}   会话动作
  GET  /api/pentest/session/console/<resume_key>       AI 会话台载入(§十渗透窗口)
  POST /api/pentest/session/console/<resume_key>/chat  会话台交互回合
  POST /api/pentest/session/delete  批量删(body ids)   POST /api/pentest/session/progress 按任务查进度
  GET  /api/pentest/session/stat    全局统计

范式：经 get_registry().get(ROLE.PENTEST_DISPATCH) 调门面（不 import 叶子内部，缺失降级 500）+ env 信封。
权限：读 pentest:read / 写 pentest:write。**禁硬限制参数**：list size 透传不砍。**协作式停止**：stop 置 status。
"""
from __future__ import annotations

import json
import time

from flask import request, g, Response, stream_with_context
from flask_restx import Namespace, Resource

from sentinel_platform.core import get_logger
from sentinel_platform.contracts import get_registry, ROLE
from ..envelope import ok, err, page as env_page, CODE_BAD_REQUEST, CODE_ERROR, CODE_NOT_FOUND, CODE_FORBIDDEN

# 会话实时观察 SSE（只读）：终态集合 + 轮询间隔 + 总时长上限（防线程泄漏）。
_TERMINAL_STATUS = ("done", "fatal", "stopped", "paused_manual")
_STREAM_POLL_SEC = 2.0
_STREAM_MAX_SEC = 30 * 60

logger = get_logger()


def _current_username() -> str:
    """当前登录用户名（网关设 g.current_user；缺失/master key 降级空，会话归属为系统）。"""
    try:
        return (getattr(g, "current_user", None) or {}).get("username", "") or ""
    except Exception:
        return ""


def _current_role() -> str:
    try:
        return (getattr(g, "current_user", None) or {}).get("role", "") or ""
    except Exception:
        return ""


def _can_view_all() -> bool:
    """当前用户能否看/操作全部会话（否则仅限自己创建的）。多用户归属数据级过滤开关。
      • AUTH 关闭 → g.current_user 不存在 → 单用户模式，全看。
      • role==admin → 全看（admin 权限恒含所有点，含 pentest:view_all）。
      • 角色勾了 pentest:view_all → 全看（g.current_user.permissions 由 user_manage.verify_token
        经 rbac.resolve_perms 算好带入；master key 走 admin 分支不依赖它）。
      • 其余（operator/viewer/自定义角色未勾）→ 仅自己创建的。"""
    cu = getattr(g, "current_user", None)
    if not cu:                                   # 鉴权关闭/无上下文 → 单用户模式全看
        return True
    if cu.get("role") == "admin":
        return True
    return "pentest:view_all" in (cu.get("permissions") or [])

ns = Namespace("pentest_session", path="/pentest", description="AI 渗透会话")
try:
    from ..openapi import register_envelope_models
    register_envelope_models(ns)
except Exception:
    pass

_create_req = ns.model("SessionCreateReq", {})
_ids_req = ns.model("SessionIdsReq", {})


def _svc():
    return get_registry().get(ROLE.PENTEST_DISPATCH)


def _int(v, d):
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


@ns.route("/session")
class SessionList(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self):
        """渗透会话列表（分页 + status 过滤）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        a = request.args
        # 多用户归属：能看全部（admin/view_all/单用户）→ owner=None 不过滤；否则只返自己创建的。
        owner = None if _can_view_all() else _current_username()
        r = svc.list_sessions(status=a.get("status") or "", page=_int(a.get("page"), 1),
                              size=_int(a.get("size"), 20), owner=owner,
                              keyword=a.get("keyword") or "",
                              date_from=a.get("date_from") or "", date_to=a.get("date_to") or "")
        return env_page(r["items"], r["total"], r["page"], r["size"])

    @ns.doc(security="token", description="需权限 pentest:write")
    @ns.expect(_create_req)
    def post(self):
        """新建渗透会话"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        b = request.get_json(silent=True) or {}
        site = (b.get("site") or "").strip()
        if not site:
            return err(CODE_BAD_REQUEST, "site 必填")
        source = {k.split(".", 1)[1]: v for k, v in b.items() if k.startswith("source.")}
        r = svc.create_session(site, asset_key=b.get("asset_key", ""), scene=b.get("scene", "pentest_exec"),
                               prompt=b.get("prompt"), mode=b.get("mode", "src"), source=source or None,
                               auto_start=bool(b.get("auto_start", False)), owner=_current_username())
        return err(CODE_BAD_REQUEST, r["error"]) if r.get("error") else ok(r)


@ns.route("/session/stat")
class SessionStat(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self):
        """AI 渗透会话全局统计"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        return ok(svc.session_stat())


@ns.route("/session/progress")
class SessionProgress(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    @ns.expect(_ids_req)
    def post(self):
        """按扫描任务批量查 AI 渗透进度"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        b = request.get_json(silent=True) or {}
        return ok(svc.progress_by_tasks(b.get("task_ids") or []))


@ns.route("/session/delete")
class SessionBatchDelete(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    @ns.expect(_ids_req)
    def post(self):
        """批量删除会话"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        b = request.get_json(silent=True) or {}
        ids = b.get("ids") or []
        if isinstance(ids, str):
            ids = [ids]
        return ok(svc.delete_sessions(ids))


@ns.route("/session/<string:session_id>")
class SessionDetail(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self, session_id):
        """会话详情"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        d = svc.get_session(session_id, with_messages=False)
        return ok(d) if d else err(CODE_NOT_FOUND, "会话不存在")


@ns.route("/session/<string:session_id>/messages")
class SessionMessages(Resource):
    @ns.doc(security="token", description="需权限 pentest:read")
    def get(self, session_id):
        """会话消息历史"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        return ok(svc.get_session_messages(session_id))


def _sse(event: str, data) -> str:
    """拼一帧 SSE。data 为 dict → JSON。"""
    payload = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    return "event: {}\ndata: {}\n\n".format(event, payload)


def _stream_meta(sess: dict) -> dict:
    return {"status": sess.get("status", ""), "round": sess.get("round", 0),
            "total_tokens": sess.get("total_tokens", 0),
            "tool_count": len(sess.get("tool_log") or [])}


def _session_event_stream(session_id: str, svc):
    """只读实时观察生成器：轮询 get_session，增量推 tool_log + meta；终态推 end 后收尾。
    引擎每轮 checkpoint 落库(_engine._checkpoint)，故此处轮询能捕获每轮增量，新鲜度=每轮。
    gthread 下占线程不占 worker；终态/超时/断连即退出，try/finally 保证不泄漏。"""
    start = time.time()
    sent = 0                      # 已推送的 tool_log 条数（增量游标）
    think_sent = 0                # 已推送的 assistant 文本条数（增量游标）
    last_meta = None
    try:
        while True:
            # with_messages=True：需读 messages 增量推 AI 思考文本（否则实时台只见工具、无思考过程，
            # 用户实测"会话语句都为空只显示AI自动执行中"的根因=只推 tool 不推 assistant 文本）
            sess = svc.get_session(session_id, with_messages=True)
            if not sess:
                yield _sse("error", {"message": "会话不存在或已删除"})
                return
            # 增量推 AI 思考/研判文本（role=assistant 且有文本内容），按出现顺序推
            msgs = sess.get("messages") or []
            assist_texts = [m.get("content") for m in msgs
                            if m.get("role") == "assistant" and isinstance(m.get("content"), str)
                            and (m.get("content") or "").strip()]
            if len(assist_texts) > think_sent:
                for txt in assist_texts[think_sent:]:
                    yield _sse("think", {"text": txt})
                think_sent = len(assist_texts)
            tool_log = sess.get("tool_log") or []
            # 增量推新工具调用
            if len(tool_log) > sent:
                for tc in tool_log[sent:]:
                    yield _sse("tool", {"name": tc.get("name", ""),
                                        "arguments": tc.get("arguments", {}),
                                        "result": tc.get("result", "")})
                sent = len(tool_log)
            # meta 变化才推（省流）
            meta = _stream_meta(sess)
            if meta != last_meta:
                yield _sse("meta", meta)
                last_meta = meta
            # 终态：推 end 收尾，不再无限占线程
            if sess.get("status") in _TERMINAL_STATUS:
                yield _sse("end", {"status": sess.get("status")})
                return
            # 超时兜底（防会话卡 running 时线程永不退出）
            if time.time() - start > _STREAM_MAX_SEC:
                yield _sse("end", {"status": "timeout", "message": "观察超时，请刷新重连"})
                return
            yield ":keepalive\n\n"          # 心跳，防中间层断连
            time.sleep(_STREAM_POLL_SEC)
    except GeneratorExit:                   # 客户端断连 → 正常退出
        return
    except Exception as exc:
        logger.debug("session stream degraded: %s", exc)
        try:
            yield _sse("error", {"message": "流中断"})
        except Exception:
            pass


@ns.route("/session/<string:session_id>/stream")
class SessionStream(Resource):
    @ns.doc(security="token", description="需权限 pentest:read（只读实时观察运行中会话，SSE）")
    def get(self, session_id):
        """实时观察运行中会话（SSE：增量推 tool_log + meta，终态自动收尾）"""
        svc = _svc()
        if not svc:
            return err(CODE_ERROR, "渗透会话服务未就绪")
        # 归属校验（与 console_load 同口径：非本人且无 view_all → 403）
        sess = svc.get_session(session_id, with_messages=False)
        if not sess:
            return err(CODE_NOT_FOUND, "会话不存在")
        if not _can_view_all():
            owner = (sess.get("owner") or "").strip()
            if not (_current_username() and owner == _current_username()):
                return err(CODE_FORBIDDEN, "无权观察该会话（仅创建人或具备查看全部权限者可看）")
        resp = Response(stream_with_context(_session_event_stream(session_id, svc)),
                        mimetype="text/event-stream")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["X-Accel-Buffering"] = "no"    # 关 nginx 缓冲，SSE 才能实时下发
        return resp


def _action(session_id, fn_name):
    svc = _svc()
    if not svc:
        return err(CODE_ERROR, "渗透会话服务未就绪")
    r = getattr(svc, fn_name)(session_id)
    return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/session/<string:session_id>/start")
class SessionStart(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（启动引擎，phase-2 未建则入队）")
    def post(self, session_id):
        """启动会话（跑引擎）"""
        return _action(session_id, "run_session")


@ns.route("/session/<string:session_id>/resume")
class SessionResume(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def post(self, session_id):
        """续跑会话"""
        return _action(session_id, "resume_session")


@ns.route("/session/<string:session_id>/stop")
class SessionStop(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（协作式停止）")
    def post(self, session_id):
        """停止会话"""
        return _action(session_id, "stop_session")


@ns.route("/session/<string:session_id>/inject")
class SessionInject(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（运行中会话人工插话，指令排入队列 AI 下一轮读取）")
    def post(self, session_id):
        """运行中会话人工实时插话。body:{message}。指令入 pending_user_msgs 队列，
        引擎每轮边界原子取出并入对话（协作式，不打断当前 LLM 调用）。归属校验同观察流。"""
        svc = _svc()
        if not svc or not hasattr(svc, "inject_user_message"):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.inject_user_message(session_id, body.get("message", ""),
                                    caller=_current_username(), can_view_all=_can_view_all())
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/session/<string:session_id>/delete")
class SessionDelete(Resource):
    @ns.doc(security="token", description="需权限 pentest:write")
    def post(self, session_id):
        """删除会话"""
        return _action(session_id, "delete_session")


@ns.route("/session/<string:session_id>/set_provider")
class SessionSetProvider(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（改会话锁定 AI 模型；仅非运行态+同协议）")
    def post(self, session_id):
        """改会话锁定的 AI 模型（#14）。body:{provider_id}。运行态/跨协议→拒绝(forbidden)。"""
        svc = _svc()
        if not svc or not hasattr(svc, "update_session_provider"):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.update_session_provider(session_id, body.get("provider_id", ""))
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


# —— 渗透窗口 / AI 会话台（核心链路 §十，人工接管）——
@ns.route("/session/console_new")
class ConsoleNew(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（会话台新建作战会话，权限最高/全工具/无闸刀）")
    def post(self):
        """会话台新建作战会话（白板会话，site 可空，人工接管全开放）。body: {site?, name?, prompt?, mode?}
        返回 {_id, resume_key, site, status}。用返回的 resume_key 进会话台对话。"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_create_session")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        body = request.get_json(silent=True) or {}
        r = svc.console_create_session(
            site=(body.get("site") or "").strip(),
            name=(body.get("name") or "").strip(),
            prompt=(body.get("prompt") or "").strip(),
            mode=(body.get("mode") or "src").strip(),
            owner=_current_username())
        return err(CODE_BAD_REQUEST, r["error"]) if isinstance(r, dict) and r.get("error") else ok(r)


@ns.route("/session/console/<string:resume_key>")
class ConsoleLoad(Resource):
    @ns.doc(security="token", description="需权限 pentest:read（凭 resume_key 恢复会话台）")
    def get(self, resume_key):
        """按 resume_key 载入 AI 会话台（结构化恢复上下文 + console 对话历史）"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_load")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        r = svc.console_load(resume_key, caller=_current_username(), can_view_all=_can_view_all())
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_NOT_FOUND, r["error"])
        return ok(r)


@ns.route("/session/console/<string:resume_key>/topology")
class ConsoleTopology(Resource):
    @ns.doc(security="token", description="需权限 pentest:read（内网拓扑：从会话内网工具产出聚合）")
    def get(self, resume_key):
        """AI 控制台内网拓扑图数据（入口/已控落点/内网主机/网段/凭据线索）"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_topology")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        r = svc.console_topology(resume_key, caller=_current_username(), can_view_all=_can_view_all())
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_NOT_FOUND, r["error"])
        return ok(r)


@ns.route("/session/console/<string:resume_key>/chat")
class ConsoleChat(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（人工接管对话，无闸刀/scope/水位，trace 控留痕）")
    def post(self, resume_key):
        """会话台交互回合：发一句 → AI 调工具推进 → 出回复。body: {message, trace_enabled?}"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_chat")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        body = request.get_json(silent=True) or {}
        message = (body.get("message") or "").strip()
        if not message:
            return err(CODE_BAD_REQUEST, "message 必填")
        trace_enabled = bool(body.get("trace_enabled", False))
        r = svc.console_chat(resume_key, message, trace_enabled,
                             caller=_current_username(), can_view_all=_can_view_all())
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


def _console_stream_gen(svc, resume_key, message, trace_enabled, caller, can_view_all):
    """把 stream_turn 的事件 dict 逐个包成 SSE 帧下发；异常/断连安全收尾。"""
    try:
        for evt in svc.console_stream(resume_key, message, trace_enabled,
                                      caller=caller, can_view_all=can_view_all):
            etype = evt.get("type", "message") if isinstance(evt, dict) else "message"
            yield _sse(etype, evt)
    except GeneratorExit:                       # 客户端断连（前端 AbortController）→ 正常退出
        return
    except Exception as exc:
        logger.debug("console stream degraded: %s", exc)
        try:
            yield _sse("error", {"message": "流中断"})
        except Exception:
            pass


@ns.route("/session/console/<string:resume_key>/stream")
class ConsoleStream(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（流式交互回合，SSE 逐 step 推 AI 动作，类 Claude Code）")
    def post(self, resume_key):
        """会话台流式交互回合（SSE）：发一句 → 逐 step 推 assistant_text/tool_call/tool_result/done。
        body: {message, trace_enabled?}。前端用 fetch+ReadableStream 消费（POST+Token 头，EventSource 不支持）。"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_stream")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        body = request.get_json(silent=True) or {}
        message = (body.get("message") or "").strip()
        if not message:
            return err(CODE_BAD_REQUEST, "message 必填")
        trace_enabled = bool(body.get("trace_enabled", False))
        gen = _console_stream_gen(svc, resume_key, message, trace_enabled,
                                  _current_username(), _can_view_all())
        resp = Response(stream_with_context(gen), mimetype="text/event-stream")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["X-Accel-Buffering"] = "no"
        return resp


@ns.route("/session/console/<string:resume_key>/stop")
class ConsoleStop(Resource):
    @ns.doc(security="token", description="需权限 pentest:write（协作式停止正在跑的流式回合）")
    def post(self, resume_key):
        """请求停止会话台正在跑的流式回合（协作式：标记落库，循环下一步边界自停）。"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_stop")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        r = svc.console_stop(resume_key, caller=_current_username(), can_view_all=_can_view_all())
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_BAD_REQUEST, r["error"])
        return ok(r)


@ns.route("/session/console/<string:resume_key>/browser")
class ConsoleBrowser(Resource):
    @ns.doc(security="token", description="需权限 pentest:read（会话台浏览器面板：轮询取定格截图+url+元素）")
    def get(self, resume_key):
        """浏览器面板轮询：取该会话持久浏览器的定格截图/url/可交互元素（active:false=未开启）。"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_browser_state")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        r = svc.console_browser_state(resume_key, caller=_current_username(), can_view_all=_can_view_all())
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_BAD_REQUEST, r["error"])
        return ok(r)

    @ns.doc(security="token", description="需权限 pentest:write（会话台手动关闭持久浏览器释放资源）")
    def delete(self, resume_key):
        """手动关闭该会话的持久浏览器（人主动释放）。"""
        svc = _svc()
        if not (svc and hasattr(svc, "console_browser_close")):
            return err(CODE_ERROR, "渗透会话服务未就绪")
        r = svc.console_browser_close(resume_key, caller=_current_username(), can_view_all=_can_view_all())
        if isinstance(r, dict) and r.get("error"):
            return err(CODE_FORBIDDEN, r["error"]) if r.get("forbidden") else err(CODE_BAD_REQUEST, r["error"])
        return ok(r)
