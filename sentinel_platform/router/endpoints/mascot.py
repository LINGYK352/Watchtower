"""mascot 端点 —— 桌宠轻量 AI 对话（/api/mascot/*）。

复用平台已配置的 AI provider（ai_config_service）+ _llm.chat() 出回复，
不另建配置。默认走网关登录鉴权（不在 PUBLIC_PREFIXES），避免 LLM 额度裸奔。

前端：DeskPet.vue 双击（接入 AI 后）→ api/mascot.ts → POST /chat。
无服务端会话态，多轮上下文由前端携带 history（gunicorn 多 worker 无一致性问题）。
"""
from __future__ import annotations

from flask import request
from flask_restx import Namespace, Resource

from sentinel_platform.contracts import get_registry
from sentinel_platform.modules.ai_pentest import _llm
from ..envelope import ok, err, CODE_ERROR, CODE_BAD_REQUEST

ns = Namespace("mascot", path="/mascot", description="桌宠 AI 对话")

# 桌宠人设（system prompt）——限定为可爱、简短的安全平台吉祥物闲聊
MASCOT_SYSTEM = (
    "你是「DeepSeek 鲸鱼娘」，瞭望塔 Watchtower 安全平台右下角的桌面吉祥物。"
    "白发蓝眼、女仆装、头顶顶着一只小蓝鲸，性格活泼可爱、爱摸鱼但很靠谱。"
    "请用口语化、俏皮、简短的中文回答（一般 1-3 句，别长篇大论），可以适当带点鲸鱼/巡逻/找漏洞的小梗。"
    "你面向的是安全工程师用户，遇到安全/渗透/代码类问题可以简要帮忙，但保持轻松的桌宠语气。"
)

_HISTORY_TURNS = 8       # 前端最多携带的历史消息条数（截断防超长）
_CHAT_TIMEOUT = 60.0     # 桌宠对话超时，防拖死


@ns.route("/chat")
class _Chat(Resource):
    def post(self):
        """桌宠对话：{message, history?} -> {reply}"""
        body = request.get_json(silent=True) or {}
        msg = (body.get("message") or "").strip()
        if not msg:
            return err(CODE_BAD_REQUEST, "消息不能为空")

        # 取 provider：优先按 mascot_chat 场景解析，回退当前激活 provider
        provider = _llm.resolve_provider("mascot_chat")
        if not provider:
            svc = get_registry().get("ai_config_service")
            if svc:
                provider = svc.get_active_provider() or None
        if not provider:
            return err(CODE_ERROR, "AI 未配置，请先在「AI 配置」里设置并启用模型")

        history = body.get("history") or []
        turns = [h for h in history
                 if isinstance(h, dict) and h.get("role") in ("user", "assistant") and h.get("content")]
        messages = [{"role": "system", "content": MASCOT_SYSTEM}]
        messages += turns[-_HISTORY_TURNS:]
        messages.append({"role": "user", "content": msg})

        r = _llm.chat(provider, messages, timeout=_CHAT_TIMEOUT, scene="mascot_chat")
        if not r.get("ok"):
            return err(CODE_ERROR, r.get("error") or "AI 调用失败")
        return ok({"reply": r.get("content") or ""})
