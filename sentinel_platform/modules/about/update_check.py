"""更新检测 update_check —— 服务端版本 + 上游更新源比对 + 前端构建比对（about 叶子，核心路由暴露）。

仅负责**版本比对与展示**，不触发实际更新操作。实际更新由外部守护进程 update_client.py（systemd 服务）
自动完成。前端 UpdateCheck.vue 携带其构建版本（brand.ts:APP_VERSION）调后端，后端查上游更新源比对。
上游不可达/未配置 → 优雅降级为纯本地比对（服务端 vs 前端），绝不因联网失败而报错。

纯 stdlib(re/json/urllib)，无第三方库。无 ROLE（核心路由暴露）。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Tuple
from urllib.request import Request, urlopen

from sentinel_platform.core import get_config, get_logger

logger = get_logger()

# 服务端版本默认值（ops 可经 config SYSTEM.VERSION 覆盖；非硬限制，是缺省）
# 与前端 brand.ts:APP_VERSION 对齐（前端标注版本为系统权威版本，2026-07-06 统一到 v1.21.21）
_DEFAULT_SERVER_VERSION = "v1.21.21"

_REMOTE_TIMEOUT = 6  # 单次查上游 /version 超时（秒）
_REMOTE_RETRY = 3    # 网络波动重试次数（治 bug2：上游偶发慢，单次超时不报错，重连 N 次全失败才判断线）
_REMOTE_BACKOFF = 0.5  # 重试间隔（秒），指数退避基数


def _version_txt() -> str:
    """读随代码部署的 version.txt（release 根，源自 brand.ts:APP_VERSION，§26.1 权威派生源）。

    本文件在 <release>/sentinel_platform/modules/about/update_check.py，上溯 3 层到 sentinel_platform、
    再上 1 层到 release 根（version.txt 所在）。读不到返回 ""。
    """
    import os
    try:
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        with open(os.path.join(root, "version.txt"), "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def server_version() -> str:
    """服务端当前版本。**优先 version.txt**（随代码部署、源自 brand.ts，§26.1 权威）——它是发布时
    自动同步的，不会漂移；其次 config `SYSTEM.VERSION`（手工旋钮，易忘同步而滞后，仅作兼容兜底）；
    再次默认值。历史坑：曾只读 config.SYSTEM.VERSION，版本递增后忘改 config → server_version 滞后
    （version.txt 已 v1.21.27 而 server_version 仍报 v1.21.24），更新检测因此失真。"""
    v = _version_txt()
    if v:
        return v
    try:
        v = get_config().section("SYSTEM", "VERSION", default="") or ""
    except Exception:
        v = ""
    return str(v).strip() or _DEFAULT_SERVER_VERSION


_DEFAULT_SOURCE_URL = "https://watchtowers.info"   # 官方分发源（直连 update-source 端口，config 未配时 fallback）


def _update_source() -> Tuple[str, str, bool]:
    """读 config UPDATE 段：(SOURCE_URL, KEY, CHECK_REMOTE)。
    SOURCE_URL 未配时 fallback 到官方分发源（保证开箱即能检测更新）。
    KEY 优先 config，fallback .activation_key 文件（Docker 只读 config 场景）。
    CHECK_REMOTE 默认 True（默认拉远程），显式配 false 才退回纯本地比对。"""
    try:
        cfg = get_config()
        url = str(cfg.section("UPDATE", "SOURCE_URL", default="") or "").strip().rstrip("/")
        if not url:
            url = _DEFAULT_SOURCE_URL
        cr = cfg.section("UPDATE", "CHECK_REMOTE", default=True)
        # key 统一走 system/activation.read_key()（始终 fresh 读盘，不经 config 缓存 → 多 worker 一致，
        # 治"一个 worker 激活其他没激活/间歇弹请重新激活"）。SOURCE_URL/CHECK_REMOTE 稳定,读缓存即可。
        from sentinel_platform.modules.system import activation
        key = activation.read_key()
        return url, key, bool(cr)
    except Exception:
        return "", "", True


def remote_version(source: str = "", key: str = "", timeout: int = _REMOTE_TIMEOUT,
                   retry: int = _REMOTE_RETRY) -> Tuple[str, str]:
    """查上游更新源 `<source>/version`。返回 (version, error_reason)。
    version 非空=成功；为空时 error_reason 区分原因：'unauthorized'/'network'/'unconfigured'。

    网络波动重试（治 bug2 连点报"无法连接"）：上游偶发慢/超时，单次失败不判断线，最多重连
    `retry` 次（指数退避），全失败才报 'network'——单次抖动自愈，避免"明明能连却报无法连接"。
    'unauthorized'（凭证 403）是确定性错误，立即返回不重试（重试也没用）。"""
    src = (source or "").strip().rstrip("/")
    if not src:
        return "", "unconfigured"
    last_err = None
    for attempt in range(max(1, retry)):
        try:
            _h = {"X-Client-Version": server_version()}   # 上报自身版本 → 分发源台阶闸据此区分新老客户端
            from sentinel_platform.core.update_platform import request_headers
            _h.update(request_headers())
            if key:
                _h["X-Update-Key"] = key
            req = Request(src + "/version", headers=_h)
            with urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            # 成功 → 通知云端重新认可（清除可能存在的吊销标记）
            try:
                from sentinel_platform.modules.system import activation
                activation.note_remote_result("")
            except Exception:
                pass
            return str((data or {}).get("version", "") or "").strip(), ""
        except Exception as e:
            err_str = str(e)
            if "403" in err_str or "unauthorized" in err_str.lower():
                # 云端一票否决：凭证失效 → 终结激活时钟
                try:
                    from sentinel_platform.modules.system import activation
                    activation.note_remote_result("unauthorized")
                except Exception:
                    pass
                return "", "unauthorized"   # 凭证问题确定性错误，重试无意义
            last_err = e
            if attempt < retry - 1:
                time.sleep(_REMOTE_BACKOFF * (2 ** attempt))   # 0.5s / 1s / ... 退避后重连
    logger.debug("update_check: 查上游 %s/version 重试 %d 次仍失败：%s", src, retry, last_err)
    return "", "network"


def _parse(version: str) -> Tuple[int, ...]:
    """版本号→可比较数值元组。用于正确比较 v1.21 > v1.9，且**预发布号 `-N` < 正式版**。

    语义化版本规则：`X.Y.Z-N`（测试/预发布号）排在 `X.Y.Z`（正式版）**之前**——
    `v1.21.147-12` 是正式版 `v1.21.147` 的第 12 次预发布，比正式版旧。
    实现：主版本段（`.` 分隔）转数值元组，末尾拼一个"预发布标记"二元组——
      正式版（无 `-N`）→ (1, 0)  （大，排后）
      预发布 `-N`      → (0, N)  （小，排前）
    故 147 正式 (1,21,147,1,0) > 147-12 预发布 (1,21,147,0,12)，修「正式版被判比测试版旧→报已最新不更新」。"""
    s = str(version or "").strip().lstrip("vV")
    # 分离主版本 与 预发布号（首个 - 或 _ 之后为预发布）
    m = re.match(r"^([0-9.]+)(?:[-_](.+))?$", s)
    main_part = m.group(1) if m else s
    pre_part = m.group(2) if (m and m.group(2)) else ""
    nums: List[int] = []
    for seg in main_part.split("."):
        mm = re.match(r"\d+", seg)
        nums.append(int(mm.group(0)) if mm else 0)
    if not nums:
        nums = [0]
    # 预发布标记：正式版(1,0)排在预发布(0,N)之后
    if pre_part:
        pm = re.search(r"\d+", pre_part)
        nums += [0, int(pm.group(0)) if pm else 0]
    else:
        nums += [1, 0]
    return tuple(nums)


def _cmp(a: str, b: str) -> int:
    """比较版本 a,b：a>b 返 1，a<b 返 -1，相等 0（补齐位数后逐段比）。"""
    ta, tb = _parse(a), _parse(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def check_update(client_version: str = "") -> Dict[str, Any]:
    """检测更新。**默认查上游更新源**（config UPDATE.SOURCE_URL），比对上游最新版 vs 本实例。

    返回 {server_version, client_version, latest_version, source, remote_ok, has_update, message}：
      - server_version：本实例服务端版本（SYSTEM.VERSION）。
      - latest_version：可获得的最新版（上游可达=上游版本，否则=服务端版本）。
      - remote_ok：是否成功查到上游。source：上游 URL（未配置为空）。
      - has_update：**是否有可用更新**——上游可达时=上游 > 本实例（本实例落后，真·远程有新版）；
        上游不可达/未配置时降级=服务端 > 前端构建（提示刷新拿新构建，旧行为）。
    """
    server = server_version()
    client = (client_version or "").strip()
    src, key, check_remote = _update_source()

    # —— 默认路径：查上游更新源 ——
    remote, err_reason = remote_version(src, key) if (check_remote and src) else ("", "unconfigured")
    if remote:
        latest = remote if _cmp(remote, server) >= 0 else server
        has_update = _cmp(remote, server) > 0
        if has_update:
            msg = "发现新版本 {}（本实例 {}）".format(remote, server)
        else:
            fe_behind = bool(client) and _cmp(server, client) > 0
            if fe_behind:
                has_update = True
                msg = "本实例已是最新 {}，但当前页面构建 {} 偏旧，刷新即可。".format(server, client)
            else:
                msg = "当前 {} 已是最新。".format(server)
        return {"server_version": server, "client_version": client, "latest_version": latest,
                "source": src, "remote_ok": True, "has_update": has_update, "message": msg}

    # —— 失败路径：区分原因 ——
    if err_reason == "unauthorized":
        msg = "授权凭证无效或已过期，无法检测更新。请重新激活系统。"
        return {"server_version": server, "client_version": client, "latest_version": server,
                "source": src, "remote_ok": False, "has_update": False, "message": msg,
                "error_type": "unauthorized"}
    if err_reason == "network":
        msg = "无法连接到更新服务器，请检查设备网络连接。"
        return {"server_version": server, "client_version": client, "latest_version": server,
                "source": src, "remote_ok": False, "has_update": False, "message": msg,
                "error_type": "network"}
    # 未配置或显式关闭远程检测：执行本实例服务端 vs 当前前端构建的本地比对。
    # 这与网络故障不同：网络故障不能把旧页面误报成可更新；本地模式则本来就只依赖这两个版本。
    has_update = bool(client) and _cmp(server, client) > 0
    if has_update:
        msg = "本实例版本 {} 高于当前页面构建 {}，刷新即可。".format(server, client)
    elif not src:
        msg = "更新源未配置，当前本地版本为 {}。".format(server)
    else:
        msg = "当前 {} 已是最新。".format(server)
    return {"server_version": server, "client_version": client, "latest_version": server,
            "source": src, "remote_ok": False, "has_update": has_update, "message": msg}
