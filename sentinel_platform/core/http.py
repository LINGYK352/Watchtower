"""平台出站 HTTP 工具（替代 app.utils.http_req 的平台侧用法，净室重写）。

平台模块(情报/漏洞源/泄露检索/ICP 等)需要发 HTTP 请求。这里给一个统一入口，
默认校验 TLS、带 UA、超时。代理策略由调用方传 proxies（平台不内建全局代理劫持）。
标题/头解析等小工具一并提供。

**默认真直连（trust_env=False，P0 止血）**：requests 模块级函数默认 trust_env=True 会读进程
环境里的 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY——而扫描出口会往 os.environ 注入 *_proxy 指向 mihomo，
一旦残留就劫持所有 http_req（含第三方情报 Hunter/FOFA 反查），代理不通即 DNS 失败/超时（表现为
"VM 能出网但反查失败/未发现资产"）。故本入口默认 trust_env=False（真直连、不读 env 代理）；
要走代理的调用方**显式传 proxies=**（可选 trust_env=True 显式允许读 env）。详见 代理出口规范.md。
"""
from __future__ import annotations

from typing import Any, Optional

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def http_req(url: str, method: str = "get", trust_env: bool = False, **kwargs: Any):
    """发 HTTP 请求。默认 verify=True、超时 (10,30)、带 UA、不自动跟随重定向。
    **默认 trust_env=False（真直连，不读环境 *_proxy 代理，防残留 env 劫持）**。
    代理由调用方**显式传 proxies=**；确需读 env 代理的场景显式传 trust_env=True。"""
    import requests
    kwargs.setdefault("verify", True)
    kwargs.setdefault("timeout", (10.1, 30.1))
    kwargs.setdefault("allow_redirects", False)
    # 防御：headers 必须是 dict。上游（尤其 AI 工具）可能误传 str/None，直接 .setdefault 会崩
    # 'str' object has no attribute 'setdefault'。非 dict 一律退化为空 dict，只保证请求能发出。
    headers = kwargs.get("headers")
    if not isinstance(headers, dict):
        headers = {}
    headers.setdefault("User-Agent", _UA)
    kwargs["headers"] = headers
    # 用显式 Session 控制 trust_env（模块级 requests.get 无法关 trust_env）。
    # 显式传了 proxies 的调用方走其指定代理；未传则 trust_env=False 下不会回落读 env → 真直连。
    sess = requests.Session()
    sess.trust_env = bool(trust_env)
    try:
        return sess.request(method, url, **kwargs)
    finally:
        try:
            sess.close()
        except Exception:
            pass


def get_title(content: bytes) -> str:
    """从 HTML 提取 <title>。"""
    try:
        text = content.decode("utf-8", "ignore") if isinstance(content, bytes) else str(content)
    except Exception:
        return ""
    low = text.lower()
    i = low.find("<title")
    if i == -1:
        return ""
    gt = low.find(">", i)
    end = low.find("</title>", gt)
    if gt == -1 or end == -1:
        return ""
    return text[gt + 1:end].strip()[:200]


def get_headers(resp: Any) -> str:
    """把响应头拼成多行 'Key: Value' 串。"""
    try:
        return "\n".join("{}: {}".format(k, v) for k, v in resp.headers.items())
    except Exception:
        return ""
