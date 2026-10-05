"""about/_updater —— 一键热更新执行器（**独立子进程**运行，免疫 gunicorn --reload 杀线程）。

根因（2026-08-12 VM 实测）：原 /apply 用 daemon 线程跑更新，逐文件写入源目录；写到第一个后端
`sentinel_platform/**/*.py` 时 gunicorn `--reload` 检测到 .py 变化→重启 worker→daemon 更新线程
被杀→进度永久冻结（实测卡在 143/153 session.py）。

修复：更新逻辑抽到本模块，`/apply` 用 `subprocess.Popen` 以**独立进程**（detached/setsid）启动
`python -m sentinel_platform.modules.about._updater`，worker reload 杀不到它；进度照旧写文件，
前端 /progress 轮询不变。本模块 import 极简（不 import flask_restx/router），适合作 -m 入口。

用法：python -m sentinel_platform.modules.about._updater <source_url> <key> <current_root> [target_version]
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import py_compile
import re
import urllib.error
from contextlib import contextmanager
from urllib.request import Request, urlopen
from urllib.parse import quote

_ROOT = os.environ['SENTINEL_GUARDIAN_ROOT']
PROGRESS_FILE = os.path.join(_ROOT,'.update_stage','progress.json')


def _log(msg: str) -> None:
    """极简可观测性日志（stdlib logging，不 import 平台 logger——本模块作 -m 入口须保持 import 极简）。
    scheduler/web 进程内被调用时会汇入各自 root logger；独立子进程内 print 到 stderr 也无妨。"""
    try:
        import logging
        logging.getLogger("sentinel.updater").info(msg)
    except Exception:
        pass

_TRACK_DIRS = ["sentinel_platform", "docker/frontend", "docker/landing", "external", "dicts"]
_TRACK_FILES = ["version.txt", "docker/docker-compose.yml", "docker/nginx.conf"]
_SKIP_NAMES = {".git", "__pycache__", ".pytest_cache", "node_modules", "tests",
               ".update_backup", ".hotupdate_backup", "logs", "shared", ".venv"}


def get_progress() -> dict:
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            d = json.loads(f.read())
        d.setdefault("ts", 0)               # 存量/旧进度无 ts → 补 0（stale 检测视为很旧，兜底可触发）
        return d
    except Exception:
        return {"phase": "idle", "total": 0, "done": 0, "msg": "", "error": "", "ts": 0}


def _client_version(current_root: str) -> str:
    """读本地 version.txt 作为上报给分发源的客户端版本（X-Client-Version 头）。
    分发源台阶闸据此区分新老客户端：≥157 放行到最新（链式逐级爬），<157/无头拦到 157。
    链式更新中每跳会改写 version.txt，最终跳读到的是上一中间跳版本(≥157)，故不会被自己的闸拦回。"""
    try:
        with open(os.path.join(current_root, "version.txt"), "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def _auth_headers(key: str, current_root: str) -> dict:
    """构造带鉴权 key + 客户端版本头的请求头（所有向分发源的请求统一走它）。"""
    h = {"X-Client-Version": _client_version(current_root)}
    from sentinel_platform.core.update_platform import request_headers
    h.update(request_headers())
    h['X-Update-Guardian']='persistent-v1'
    if key:
        h["X-Update-Key"] = key
    return h


def set_progress(phase, total=0, done=0, msg='', error=''):
    from sentinel_platform.core.update_commit import write
    state=_read_chain_state(_ROOT)
    data={'phase':phase,'total':total,'done':done,'msg':msg,'error':error,'ts':time.time(),
          'current_version':_client_version(_ROOT),'target_version':state.get('target',''),
          'hop_version':state.get('current_target',''),'hop':min(state.get('cursor',0)+1,len(state.get('steps',[]))),
          'hops':len(state.get('steps',[])),'completed':state.get('completed',[]),
          'resumable':state.get('schema')==2 and state.get('cursor',0)<len(state.get('steps',[])),
          'chain_active':state.get('active',False),'run_id':state.get('id','')}
    write(PROGRESS_FILE,data)

# ============================ 一级一级（链式）更新：每级重启 + 启动自续跑状态机 ============================
# 规则（用户要求）：157→159 攀爬时，中间的 158 **必须被完整更新且其代码确实在运行**，才允许拉取 159。
# 即「每一级的代码确定完整运行起来后，才拉取下一级」。
#
# **实现（启动自续跑）**：一次链式更新 = 逐级循环，每级都是一个独立 _updater 进程完成
#   下载→校验→提交→改 version.txt→**重启本级代码**（worker + web/重建容器）。
# 重启会杀掉本 _updater 进程和 web，故不能靠一个长活进程串起整条链——改为**跨重启接力**：
#   新级的 web 启动时 `create_app()` 跑到底 = 该级代码"确定完整运行"的证据 → 触发启动钩子
#   `resume_chain_if_pending()` → 派发下一级的 _updater 进程。如此一级一级，每级都由"它自己的
#   启动"来确认在跑，再拉下一级，严格满足规则。
#
# 链路状态持久化到 current_root/.update_stage/.chain_state.json（bind-mount 代码目录，跨容器重启
# 保留；绝不放 /tmp——容器 recreate 会清空 /tmp 丢状态）。字段：
#   active     : 链路进行中（用户点了"立即更新"授权本次攀爬；到达最新才清除）
#   source_url : 分发源（启动续跑时复用；key 不持久化，续跑时 fresh 读盘 activation.read_key）
#   hops_done  : 已应用的级数（安全上限，防失控无限爬）
#   last_target: 上一级目标版本；retry: 同一目标反复未生效的重试计数（安全网）
_CHAIN_MAX_HOPS = 40      # 单次链式更新最多爬多少级（安全上限，正常 156→159 仅 2~3 级）
_CHAIN_MAX_RETRY = 3      # 同一级反复重启仍未生效（version 未推进）的最大重试，超过判失败停链
# 认领锁时效（秒）：锁持有超此值判为「持有进程已被杀/崩溃」的陈旧残留，可被清理自愈。
# 须覆盖「一跳下载+校验+提交+重启」最坏耗时（大文件慢传）——取 300s 留足余量。
_CLAIM_TTL = 300
# 链式卡住判定（秒）：progress 停在非终结相位（applying/checking/downloading）且 ts 超此值无推进，
# scheduler 看门狗判本跳断了 → 清陈旧锁 + 兜底重派下一跳。取 180s（> 单跳重启窗口，< 用户耐心极限）。
_CHAIN_STALL = 180


def _chain_state_path(current_root: str) -> str:
    return os.path.join(current_root, ".update_stage", ".chain_state.json")


def _read_chain_state(current_root: str) -> dict:
    try:
        with open(_chain_state_path(current_root), "r", encoding="utf-8") as f:
            return json.loads(f.read()) or {}
    except Exception:
        return {}


def _write_chain_state(current_root, st):
    from sentinel_platform.core.update_commit import write
    write(_chain_state_path(current_root),st)

def _clear_chain_state(current_root: str) -> None:
    try:
        os.remove(_chain_state_path(current_root))
    except OSError:
        pass


def _rollback_removed_files(current_root: str, target_rels: set) -> list:
    """扫描本地跟踪目录，返回"本地有但目标版 manifest 没有"的相对路径（回退需删除）。"""
    removed = []
    for f in _TRACK_FILES:
        rel = f.replace("\\", "/")
        if os.path.isfile(os.path.join(current_root, f)) and rel not in target_rels:
            removed.append(rel)
    for d in _TRACK_DIRS:
        base = os.path.join(current_root, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames if x not in _SKIP_NAMES]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, current_root).replace("\\", "/")
                if rel not in target_rels and not any(p in _SKIP_NAMES for p in rel.split("/")):
                    removed.append(rel)
    return removed


def _has_systemd() -> bool:
    """当前环境是否可用 systemctl 管理服务（裸机/systemd 部署为真；容器内通常为假）。
    用 shutil.which 判 systemctl 存在 + /run/systemd/system 目录存在（systemd 作 PID1 的标志）。"""
    try:
        return bool(shutil.which("systemctl")) and os.path.isdir("/run/systemd/system")
    except Exception:
        return False


def _safe_restart_worker():
    """重启 worker/scheduler 加载新代码。活跃 AI 会话中断，scheduler watchdog 心跳超时自动重投。
    无 docker.sock 且无 systemd（如 scheduler 兜底容器）时静默跳过（worker 重启非本级生效的必要条件）。"""
    if os.path.exists("/var/run/docker.sock"):
        subprocess.run(["docker", "restart", "docker-worker-1", "docker-scheduler-1"],
                       timeout=60, capture_output=True)
    elif _has_systemd():
        subprocess.run(["systemctl", "restart", "sentinel-worker"], timeout=30, capture_output=True)
        subprocess.run(["systemctl", "restart", "sentinel-scheduler"], timeout=30, capture_output=True)


def _restart_web():
    """Reload Gunicorn workers; source updates do not restart the container."""
    import psutil,signal
    for process in psutil.process_iter(['pid','ppid','cmdline']):
        command=' '.join(process.info['cmdline'] or [])
        if 'gunicorn' not in command or 'sentinel_platform.wsgi:application' not in command:continue
        try:
            parent=' '.join(process.parent().cmdline()) if process.parent() else ''
            if 'gunicorn' not in parent:
                os.kill(process.pid,signal.SIGHUP);return True
        except (psutil.Error,OSError):continue
    if _has_systemd():
        subprocess.run(['systemctl','reload','sentinel-web'],timeout=30,check=True,capture_output=True);return True
    # Scheduler/worker containers have their own PID namespace. The standard
    # Compose Web command uses --reload and watches this loaded WSGI module on
    # the shared source volume. Touch it even when only pinned guardian assets
    # or frontend/version files changed; those may not be watched imports.
    entry=os.path.join(os.environ.get('SENTINEL_GUARDIAN_ROOT',_ROOT),'sentinel_platform','wsgi.py')
    if os.name=='posix' and os.path.isfile('/.dockerenv') and os.path.isfile(entry):
        modified=os.stat(entry).st_mtime
        stamp=max(time.time(),modified+0.01)
        os.utime(entry,(stamp,stamp));return True
    return False

def _recreate_containers(compose_dir: str) -> tuple:
    """compose 变更（时区挂载/cap/端口/新服务等）后重建容器应用新配置。
    **根因（v1.21.150 事故）**：web 容器内只装了 docker CLI（docker.io），**没有 docker compose 插件**，
    故 `_updater` 直接跑 `docker compose up -d --force-recreate` 必然报 `'compose' is not a docker command`
    静默失败 → 容器从不重建 → compose 变更(时区)永不生效。此逻辑自 v1.21.60 加入起就是哑弹（60~149
    从没推过 compose 变更没被触发，150 首次推时区挂载才引爆）。
    **根治（经 docker.sock + nsenter 进宿主机用宿主机的 compose）**：起一个临时特权容器（--privileged
    --pid=host，载体用本地必有的 sentinel:base 不拉外网），nsenter -t 1 进宿主机 PID1 的命名空间，
    在宿主机上跑 `docker compose up -d --force-recreate`（宿主机有 compose）。临时容器 --rm 独立于 web，
    web 自身被重建也不影响它跑完（不像容器内跑会随 web 销毁而中断）。无常驻组件、无需预装 watcher、
    不怕误删——每次更新现起现用，天然自愈。VM 实测：5 容器全重建 + 时区挂载生效 + worker 显 CST。"""
    if not os.path.exists("/var/run/docker.sock"):
        # 裸机/systemd 部署：无 docker，compose 变更需人工，只重启服务（mount 类变更 restart 不生效，返False提示）
        return False, "非 docker 部署（无 docker.sock），compose 变更请在宿主机手动 docker compose up -d --force-recreate"
    # 宿主机侧 compose 目录（容器内 /opt/sentinel/current/docker 对应宿主机 /opt/sentinel/sentinel/docker，
    # 但 nsenter 进宿主机后用宿主机真实路径；从容器读挂载源反推宿主机路径）
    host_compose_dir = _host_compose_dir(compose_dir)
    # nsenter 进宿主机跑 compose recreate；日志写宿主机 /tmp 便于排查。末尾自删自身临时容器（--rm 与 -d
    # 偶有竞态，改容器内跑完 docker rm 自己更稳）。
    inner = ("cd {d} && (docker compose up -d --force-recreate || docker-compose up -d --force-recreate) "
             "> /tmp/sentinel_recreate.log 2>&1").format(d=host_compose_dir)
    # **detached(-d) 起特权容器**：由 docker daemon 托管，与发起它的 web 容器完全解耦——web 随 recreate 被
    # 重建杀掉也不影响这个容器把 recreate 跑完（关键：不能同步等，web 会先死）。跑完容器自己退出。
    cmd = ["docker", "run", "-d", "--rm", "--privileged", "--pid=host",
           "--name", "sentinel_recreate_helper", _self_image(),
           "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "sh", "-c", inner]
    try:
        # 先清理可能残留的同名 helper（上次异常遗留），再起新的
        subprocess.run(["docker", "rm", "-f", "sentinel_recreate_helper"], timeout=15, capture_output=True)
        r = subprocess.run(cmd, timeout=30, capture_output=True, text=True)
        if r.returncode == 0:
            return True, "已派发宿主机容器重建（detached，独立于本进程完成）"
        return False, "派发容器重建失败: {}".format((r.stderr or r.stdout or "")[-300:])
    except Exception as e:
        return False, "派发容器重建异常: {}".format(e)


def _self_image() -> str:
    """nsenter 载体镜像：优先本机主镜像 sentinel:base（装机必有，不拉外网）。取不到则退 busybox（需联网）。"""
    try:
        r = subprocess.run(["docker", "image", "inspect", "sentinel:base"],
                           timeout=15, capture_output=True)
        if r.returncode == 0:
            return "sentinel:base"
    except Exception:
        pass
    return "busybox:latest"


def _host_compose_dir(container_compose_dir: str) -> str:
    """把容器内 compose 目录路径映射成宿主机真实路径（nsenter 进宿主机后按宿主机路径找 compose）。
    默认部署：容器 /opt/sentinel/current/docker → 宿主机 /opt/sentinel/sentinel/docker（compose 卷挂载）。
    经 docker inspect 自身容器的 Mounts 反查 /opt/sentinel/current 的宿主机 Source，最稳。取不到用默认。"""
    default = "/opt/sentinel/sentinel/docker"
    try:
        import json as _json, socket
        cid = socket.gethostname()   # 容器内 hostname = 容器 ID 短码
        r = subprocess.run(["docker", "inspect", cid], timeout=15, capture_output=True, text=True)
        if r.returncode == 0:
            d = _json.loads(r.stdout)[0]
            for m in d.get("Mounts", []):
                if m.get("Destination") == "/opt/sentinel/current":
                    src = m.get("Source", "")
                    if src:
                        return src.rstrip("/") + "/docker"
    except Exception:
        pass
    return default


def _prune_frontend_assets(current_root: str, remote_manifest: dict, backup_dir: str) -> int:
    """清理前端旧 hash 产物：删除 docker/frontend/assets/ 里不在 remote_manifest 的文件。
    前端 assets 是内容哈希命名（index-<hash>.js），更新只加不删会无限堆积（实测 273 vs 89 应有）。
    manifest 含全部当前版本文件，不在其中的 assets 即旧构建残留。只清 assets 目录（哈希命名安全），
    删前备份到 backup_dir，可回滚。返回删除数。"""
    assets_dir = os.path.join(current_root, "docker", "frontend", "assets")
    if not os.path.isdir(assets_dir):
        return 0
    keep = {rel.replace("\\", "/") for rel in remote_manifest
            if rel.replace("\\", "/").startswith("docker/frontend/assets/")}
    pruned = 0
    for fn in os.listdir(assets_dir):
        rel = "docker/frontend/assets/" + fn
        full = os.path.join(assets_dir, fn)
        if not os.path.isfile(full) or rel in keep:
            continue
        try:
            bpath = os.path.join(backup_dir, rel)
            os.makedirs(os.path.dirname(bpath), exist_ok=True)
            shutil.copy2(full, bpath)     # 备份可回滚
            os.remove(full)
            pruned += 1
        except OSError:
            continue
    return pruned


_DL_RETRIES = 3                 # 单文件下载重试次数（退避）
_DL_BACKOFF = [2, 5, 10]        # 各次重试前等待秒数
_DL_TIMEOUT = 60                # 单文件下载超时（秒）——比原 30 长，容大二进制经激活鉴权慢传


def _download_to(file_url: str, headers: dict, dst_tmp: str) -> str:
    """下载一个文件到临时路径（**流式写盘 + Range 断点续传**）+ 重试退避。返回 sha256(供校验)。

    **v1.21.159-x 根治大文件哈希不符 + 断点续传失效**：
    - 旧实现每次全量下载、失败即删残缺重下（`open(wb)`），32MB 大 .so（numpy libopenblas）单连接
      中途被截断（网络抖动/nginx 缓冲/keep-alive）→ 落地部分内容 → sha 与 manifest 不符 → 拒绝安装；
      且每次重试从头下，白耗流量。服务端 `/file` 本就支持 Range(206)，客户端却没用。
    - 新实现：**保留已下字节，带 `Range: bytes=<已有>-` 续传追加**（`open(ab)`）；每次重试不删残缺、
      从断点续；**下完校验 Content-Length**（服务端给的总长）——实际字节数不足则判截断、重试续传，
      不返回残缺内容。sha 对整份文件算（续传后重算全量）。跨「多次点击更新」也续传（dst_tmp 稳定复用，
      见 run_update stage_dir 不再每次新建/失败不删）。"""
    last_exc = None
    for attempt in range(_DL_RETRIES):
        try:
            have = os.path.getsize(dst_tmp) if os.path.isfile(dst_tmp) else 0
            req_headers = dict(headers)
            if have > 0:
                req_headers["Range"] = "bytes={}-".format(have)   # 断点续传：从已下字节续
            req = Request(file_url, headers=req_headers)
            resp = urlopen(req, timeout=_DL_TIMEOUT)
            status = getattr(resp, "status", None) or resp.getcode()
            # 服务端支持续传返 206（从 have 追加）；否则 200=全量（须从头写，重置 have）
            mode = "ab" if (status == 206 and have > 0) else "wb"
            if mode == "wb":
                have = 0
            # 总长 = 已有 + 本次响应体长（206 时 Content-Length 是剩余段长）
            clen = resp.headers.get("Content-Length")
            expect_total = (have + int(clen)) if clen is not None else None
            with open(dst_tmp, mode) as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
            resp.close()
            got = os.path.getsize(dst_tmp)
            # 截断检测：拿到字节数 < 声明总长 → 判残缺，退避后带 Range 续传（不删，保留已下）
            if expect_total is not None and got < expect_total:
                raise IOError("下载不完整：得 {} 字节 / 期望 {} 字节（截断，续传重试）".format(got, expect_total))
            # 对整份文件算 sha（续传拼接后重算全量，与 manifest 比对）
            h = hashlib.sha256()
            with open(dst_tmp, "rb") as f:
                for blk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(blk)
            return h.hexdigest()
        except Exception as exc:                      # 超时/连接中断/截断 → 退避后带 Range 续传（保留残缺）
            last_exc = exc
            if attempt < _DL_RETRIES - 1:
                time.sleep(_DL_BACKOFF[min(attempt, len(_DL_BACKOFF) - 1)])
    raise last_exc if last_exc else RuntimeError("下载失败")


def _apply_restart(current_root: str, backend_changed: bool, compose_changed: bool,
                   remote_version: str, going_back: bool = False, terminal: bool = True):
    """提交后应用重启：按 compose / backend 变更选择「重建容器 / 重启 worker+web / systemctl reload」。
    **fire-and-forget**：web 重启/重建会杀掉本 _updater 进程，故先落进度再触发（等不到返回——web 先死）。

    terminal=True（单版更新/回退）：落终结相位 "done"，前端见 done 后 reload 显示成功。
    terminal=False（一级一级更新的每一级）：落**非终结** "applying"——前端持续轮询、每次 web 重启后
      onMounted 重新挂轮询，绝不 reload/停；到达最新时由新级 web 启动钩子 resume_chain_if_pending 落
      "done"。链式每级 backend_changed 恒传 True 强制重启 web：既让本级代码真正跑起来（规则要求），
      又触发新级启动钩子续拉下一级（不重启 web 则钩子不触发、链会停住）。"""
    phase = "done" if terminal else "applying"

    def _msg(extra: str) -> str:
        if terminal:
            base = ("已回退到 {}" if going_back else "更新完成！已升级到 {}").format(remote_version)
        else:
            base = "已更新到 {}，正在重启应用该级代码，随后自动拉取下一级…".format(remote_version)
        return base + extra

    time.sleep(2)
    try:
        from sentinel_platform.core import get_config
        reload_cmd = (get_config().section("UPDATE", "RELOAD_CMD", default="") or "").strip()
    except Exception:
        reload_cmd = ""
    if reload_cmd:
        subprocess.run(reload_cmd, shell=True, timeout=30, capture_output=True)
    if os.path.exists("/var/run/docker.sock"):
        if compose_changed:
            compose_dir = os.path.join(current_root, "docker")
            if os.path.isfile(os.path.join(compose_dir, "docker-compose.yml")):
                set_progress(phase, msg=_msg("，正在重建容器应用配置变更（约 10~30 秒，期间页面可能短暂断连，稍后刷新）"))
                try:
                    _recreate_containers(compose_dir)   # --rm 特权容器 nsenter 宿主机 compose recreate
                except Exception:
                    pass
                return
        if backend_changed:
            set_progress(phase, msg=_msg("，正在重启服务应用新代码（约 5~15 秒，期间页面可能短暂断连，稍后刷新）"))
            try:
                _restart_web()   # create_app 全量重跑（挂全部 Namespace + ensure_indexes 补播种 + 触发链式续跑钩子）
            except Exception:
                pass
            return
    else:
        if backend_changed:
            set_progress(phase, msg=_msg("，正在重启服务应用新代码（约 5~15 秒，期间页面可能短暂断连，稍后刷新）"))
            restarted = False
            try:
                restarted = _restart_web()
            except Exception:
                pass
            # 无重启能力（scheduler 兜底容器：无 docker.sock 也无 systemd）：代码已落地，无法自重启 web。
            # 落非 error 的可感知进度——由有 sock 的 web 容器续跑钩子/ compose restart 拉起后本级才生效；
            # 绝不静默（静默会让 applying 永久停滞 = 卡死复现）。terminal 场景同理提示需刷新。
            if not restarted:
                set_progress(phase, msg=_msg("。本级代码已就位，等待应用服务重启后生效（若长时间未刷新，请手动刷新页面）"))
            return
        if _has_systemd():
            subprocess.run(["systemctl", "reload", "sentinel-web"], timeout=15, capture_output=True)


def _validate_release_path(path, sha):
    if (not isinstance(path, str) or "\\" in path or ":" in path
            or any(p in ("", ".", "..") for p in path.split("/"))
            or not (path in _TRACK_FILES or any(path.startswith(d + "/") for d in _TRACK_DIRS + ["runtime_libs"]))
            or any(p in {".git", ".update_backup", ".hotupdate_backup", "shared", "logs", ".venv", "__pycache__"} for p in path.split("/"))
            or (not path.startswith("runtime_libs/") and (
                re.search(r"(?:^|/)(?:config\.ya?ml|\.activation[^/]*|\.app_platform_key|\.disclaimer_accepted)$", path, re.I)
                or path.lower().endswith((".key", ".pem", ".db", ".sqlite", ".sqlite3"))))
            or path.lower().endswith((".pyc", ".pyo"))
            or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)):
        raise ValueError("invalid release file entry")


def _release_file(current_root, path):
    root = os.path.realpath(current_root)
    full = os.path.join(root, *path.split("/"))
    if os.path.commonpath([root, os.path.realpath(full)]) != root:
        raise ValueError("release path escapes installation root")
    return full


def _download_candidates(data, local_version):
    full = data.get("manifest", {})
    if not isinstance(full, dict) or not full:
        raise ValueError("invalid release manifest")
    for path, sha in full.items():
        _validate_release_path(path, sha)
    if data.get("download_mode") != "delta" or data.get("base_version") != local_version:
        return full
    selected = data.get("download_manifest")
    if not isinstance(selected, dict) or any(p not in full or full[p] != h for p, h in selected.items()):
        raise ValueError("invalid release download plan")
    return selected


def _removed_candidates(data, local_version):
    """仅接受版本仓声明的旧发布文件，不按目录扫描删除用户自加文件。"""
    if data.get("base_version") != local_version or "remove_manifest" not in data:
        return []
    removed = data["remove_manifest"]
    if not isinstance(removed, dict):
        raise ValueError("invalid release removal plan")
    for path, sha in removed.items():
        _validate_release_path(path, sha)
        if path in data.get("manifest", {}):
            raise ValueError("removal overlaps release inventory")
    return sorted(removed)


def _frontend_removed(current_root, manifest):
    """构建 assets 是专用生成目录；它的旧产物仍可独立清理。"""
    folder = os.path.join(current_root, "docker/frontend/assets")
    if not os.path.isdir(folder):
        return []
    return ["docker/frontend/assets/" + name for name in os.listdir(folder)
            if "docker/frontend/assets/" + name not in manifest
            and os.path.isfile(os.path.join(folder, name))]


@contextmanager
def _apply_lock(current_root):
    """OS 文件锁跨 worker/进程共享，进程退出自动释放，无 TTL 抢锁窗口。"""
    folder = os.path.join(current_root, ".update_stage")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, ".apply.lock"), "a+b") as lock:
        if os.fstat(lock.fileno()).st_size == 0:
            lock.write(b"0"); lock.flush()
        lock.seek(0)
        acquired = False
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError:
            pass
        try:
            yield acquired
        finally:
            if acquired:
                if os.name == "nt":
                    lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def run_update(source_url: str, key: str, current_root: str, target_version: str = "",
               chain_hop: bool = False, chain_final: bool = False, full: bool = False):
    if not target_version or target_version!=_client_version(current_root):
        from . import _update_chain
        return _update_chain.begin(__import__(__name__,fromlist=['']),source_url,key,current_root,target_version)
    with _apply_lock(current_root) as acquired:
        if not acquired:
            _log("另一个更新进程正在应用；保留其进度，不启动第二个提交")
            return
        from sentinel_platform.core.update_commit import recover
        recover(current_root)
        import uuid
        _write_chain_state(current_root,{'schema':2,'id':uuid.uuid4().hex,'active':True,'kind':'rollback','source_url':source_url,
                          'origin':_client_version(current_root),'target':target_version,'steps':[target_version],'cursor':0,'completed':[],
                          'phase':'checking','current_target':target_version})
        _run_update_impl(source_url,key,current_root,target_version,chain_hop=True,full=full)
        if get_progress().get('phase')=='error':
            state=_read_chain_state(current_root);state.update(active=False,phase='error');_write_chain_state(current_root,state);return
    _spawn_chain_step(source_url,key,current_root)


def _run_update_impl(source_url: str, key: str, current_root: str, target_version: str = "",
               chain_hop: bool = False, chain_final: bool = False, full: bool = False):
    """独立进程执行热更新：fetch manifest → diff → 逐文件(下载+校验+写入)。
    进度持久化到 PROGRESS_FILE，前端轮询。因是独立进程，gunicorn worker reload 杀不到它。

    target_version 非空 = 回退/前滚到指定历史版本（绕过防降级守卫）；为空 = 正常更新（守卫生效）。
    chain_hop=True = 一级一级更新的一跳（旧多跳模式遗留）：强制重启 + 落非终结 "applying"，由续跑接力。
    chain_final=True = 链式单跳到最新的收尾跳：落终结 "done"，且**在触发重启前清链状态**（重启会杀本
      进程，不能靠返回后清；清链使重启后 resume 钩子见非 active 立即返回，不重复派发）。
    两者皆 False（默认）= 单版更新/回退：按 diff 决定重启，落终结 "done"。"""
    is_rollback = bool(target_version)
    try:
        if not key:
            set_progress("error", error="未激活，请先激活系统获取授权凭证")
            return
        set_progress("checking", msg="正在获取更新清单..." if not is_rollback
                     else "正在获取版本 {} 清单...".format(target_version))
        headers = _auth_headers(key, current_root)
        headers["X-Update-Protocol"] = "3"
        if full:
            headers["X-Update-Mode"] = "full"

        from sentinel_platform.core import update_policy,update_bundle
        from . import _update_chain
        backward=target_version and update_policy.key(target_version)<update_policy.key(headers['X-Client-Version'])
        policy=_update_chain.fetch(__import__(__name__,fromlist=['']),source_url,key,current_root,target_version if backward else '')
        requested=target_version or policy['next']
        update_policy.allow(headers['X-Client-Version'],requested,policy)
        remote_version=requested
        bundle=None
        if update_policy.uses_packages(headers['X-Client-Version'],requested):
            bundle=update_bundle.fetch_plan(source_url,headers,'web-linux-amd64',requested,headers['X-Client-Version'],_validate_release_path,full)
            if not bundle:raise ValueError('公共包与Web专属包尚未准备，禁止降级为逐文件更新')
            remote_manifest=bundle['inventory']
            selected={name:item['sha256'] for package in bundle['packages'] for name,item in package['members'].items()}
            data={'manifest':remote_manifest,'download_manifest':selected,'download_mode':bundle['mode'],
                  'base_version':bundle['base_version'],'version':requested,'remove_manifest':bundle['removed']}
        else:
            with urlopen(Request(source_url+'/manifest?version='+quote(requested,safe=''),headers=headers),timeout=30) as response:data=json.load(response)
            remote_manifest=data.get('manifest',{})
            if data.get('version')!=requested:raise ValueError('守门员清单版本不匹配')

        # 方向判定：is_rollback 仅表示「带 target_version、绕过防降级守卫」，不代表方向——
        # 一级一级更新的每一跳都带 target_version（升级方向），故不能用 is_rollback 判措辞。
        # going_back = 真·回退（目标严格低于本地），仅用于「已回退到 / 已升级到」的措辞，不影响逻辑。
        going_back = False
        try:
            from sentinel_platform.modules.about.update_check import server_version, _cmp
            _local_now = server_version()
            if is_rollback and remote_version and _local_now and _cmp(remote_version, _local_now) < 0:
                going_back = True
        except Exception:
            pass

        # 防降级守卫（回退/前滚绕过）
        if not is_rollback and not full:
            try:
                from sentinel_platform.modules.about.update_check import server_version, _cmp
                local_version = server_version()
                if remote_version and local_version and _cmp(remote_version, local_version) <= 0:
                    set_progress("done", msg="本地已是最新（{}），分发源为 {}，无需更新（不降级）".format(
                        local_version, remote_version))
                    return
            except Exception:
                pass

        # 保留完整目标目录供回滚/前端清理；正常升级只核验服务端指定的变更候选。
        candidates = _download_candidates(data, headers["X-Client-Version"])
        # 仅 stat 未变更文件，不读几千个依赖内容；缺文件也必须恢复，不能由增量计划掩盖。
        candidates = dict(candidates)
        for rel, sha in remote_manifest.items():
            fp = _release_file(current_root, rel)
            if not os.path.isfile(fp):
                candidates[rel] = sha
        removed = _removed_candidates(data, headers["X-Client-Version"])
        receipt_path=os.path.join(current_root,'.update_stage','.release_receipt.json')
        if os.path.isfile(receipt_path):
            with open(receipt_path,encoding='utf-8') as receipt_file:owned=json.load(receipt_file)
            if owned.get('version')==headers['X-Client-Version']:
                for rel,sha in owned.get('files',{}).items():
                    if rel not in remote_manifest:
                        _validate_release_path(rel,sha);data.setdefault('remove_manifest',{})[rel]=sha;removed.append(rel)
        removed = sorted(set(removed + _frontend_removed(current_root, remote_manifest)))
        for rel in removed:
            _release_file(current_root, rel)
        set_progress("checking", total=len(candidates),
                     msg="{}核验 {} 个文件（库存 {}，清理 {}）".format(
                         "增量" if data.get("download_mode") == "delta" else "完整",
                         len(candidates), len(remote_manifest), len(removed)))
        local_manifest = {}
        for rel in ([] if bundle and not full else candidates):
            fp = _release_file(current_root, rel)
            if os.path.isfile(fp):
                h = hashlib.sha256()
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                local_manifest[rel] = h.hexdigest()

        if bundle:
            packaged={n for p in bundle['packages'] for n in p['members']}
            if not set(candidates).issubset(packaged):raise ValueError('未变动程序文件丢失或损坏，请修复基板安装；禁止临时逐文件拉取')
            if full:
                for rel,sha in remote_manifest.items():
                    if rel not in packaged:
                        fp=_release_file(current_root,rel)
                        if not os.path.isfile(fp) or update_bundle.sha256(fp)!=sha:raise ValueError('完整核验发现未变动基板文件损坏，请修复安装：'+rel)
            changed=list(candidates)
        else:changed = [r for r, h in candidates.items() if local_manifest.get(r) != h]
        if not changed and not removed:
            set_progress("done", msg="已是最新，无需更新" if not is_rollback
                         else "本地已与版本 {} 一致".format(target_version))
            return
        # 排序：代码/前端小文件优先，external/bin 大文件最后
        changed.sort(key=lambda rel: (1, rel) if rel.startswith("external/bin/") else (0, rel))
        total = len(changed)
        set_progress("downloading", total=total, done=0, msg="更新 0/{}".format(total))
        import uuid
        backup_dir = os.path.join(current_root, ".update_backup", time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])

        # ===== 事务化更新（AUD-04 + AUD-12）：先全部下载到独立 staging 区并逐个校验哈希/编译，
        #        全部通过后才一次性提交替换（备份+os.replace）；任一步失败则不动/回滚已替换的运行文件。=====
        # 修复前：单循环内逐文件 下载→编译→替换，第 N 个失败留下前 N-1 个已替换=半新半旧运行代码；
        #        且下载哈希算了不与 manifest 比对，内容被篡改/错版照样落地并标记成功。
        # **v1.21.159-x 断点续传根治**：stage_dir 用**目标版本命名（稳定复用，非时间戳+pid）**——
        #   下载中断/失败后再次点击更新，命中同一 stage_dir、复用已下部分文件（配合 _download_to 的
        #   Range 续传）；失败时**不删 stage**（保留残缺供续传），仅成功提交后才清。已下且 sha 已对的
        #   文件跳过重下（秒过），只续未完成的。跨会话/切菜单返回再点也续传。
        stage_version = remote_version or target_version or "latest"
        if not re.fullmatch(r"[A-Za-z0-9._-]+", stage_version) or stage_version in (".", ".."):
            raise ValueError("invalid release version")
        stage_dir = os.path.join(current_root, ".update_stage", stage_version)
        os.makedirs(stage_dir, exist_ok=True)

        def _cleanup_stage():
            try:
                shutil.rmtree(stage_dir, ignore_errors=True)
            except OSError:
                pass

        # ---- Phase 1：下载到 staging + 逐文件校验（哈希对 manifest + .py 编译）。----
        # **v1.21.159-x 断点续传**：失败**不删 stage**（保留已下文件供下次续传/复用）；已下且 sha 已对的
        # 文件跳过重下（秒过）。仅"哈希不符"这一个坏文件删掉重下（可能是残缺/错版），其余保留。
        def _sha256_file(p):
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for blk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(blk)
            return h.hexdigest()

        staged = []   # [(rel, staged_abs)]
        if bundle:
            available = {n for p in bundle['packages'] for n in p['members']}
            if not set(changed).issubset(available):
                bundle = update_bundle.fetch_plan(source_url, headers, 'web-linux-amd64', remote_version,
                                                   headers['X-Client-Version'], _validate_release_path, True)
                if not bundle:raise ValueError('Full repair bundle unavailable')
            expanded = sum(bundle['inventory_bytes'][n] for n in changed)
            if shutil.disk_usage(stage_dir).free < expanded * 2 + sum(p['bytes'] for p in bundle['packages']) + 128*1024**2:
                raise ValueError('Insufficient update staging and rollback space')
            def package_progress(done, size):
                set_progress('downloading', total=size, done=done, msg='下载公共包与Web专属包')
            extracted = update_bundle.stage(bundle, source_url, headers, os.path.join(current_root,'.update_stage','package-cache'),
                                            stage_dir, changed, package_progress)
            for rel, spath in extracted.items():
                if rel.endswith('.py'):py_compile.compile(spath, doraise=True)
                staged.append((rel, spath))
        for i, rel in enumerate([] if bundle else changed):
            fname = os.path.basename(rel)
            set_progress("downloading", total=total, done=i,
                         msg="下载校验 {}/{} {}".format(i + 1, total, fname))
            # URL 编码 path/version：rel 可能含 + 空格 中文等特殊字符（如 tzdata 的 GMT+0）。
            # 不编码则 query 里的 + 被服务端 parse_qs 解成空格 → 找不到文件 404（runtime_libs tzdata 引入后暴露）。
            file_url = source_url + "/file?path=" + quote(rel, safe="")
            if is_rollback or data.get("immutable"):
                file_url += "&version=" + quote(remote_version, safe="")
            spath = os.path.join(stage_dir, rel)
            os.makedirs(os.path.dirname(spath), exist_ok=True)
            want_sha = remote_manifest.get(rel, "")
            # 断点续传：若已下且 sha 已对（上次成功下的），跳过重下（秒过大文件）
            if want_sha and os.path.isfile(spath):
                try:
                    if _sha256_file(spath) == want_sha:
                        staged.append((rel, spath))
                        continue
                except OSError:
                    pass
            try:
                dl_sha = _download_to(file_url, headers, spath)
            except Exception as exc:
                # 不删 stage（保留已下文件供续传）；本文件残缺已由 _download_to 保留供 Range 续传
                set_progress("error", total=total, done=i,
                             error="下载文件失败({}/{} {}): {}。已重试 {} 次，运行代码未改动，"
                                   "已下部分保留，再次点击更新将从断点续传。".format(
                                 i + 1, total, fname, str(exc)[:120], _DL_RETRIES))
                return
            # AUD-04：下载内容 sha256 必须与远端清单一致，否则拒绝（防错版/篡改/切版竞态落地）
            if want_sha and dl_sha != want_sha:
                try:
                    os.unlink(spath)      # 仅删这个坏文件（残缺/错版），下次重下；其余已下的保留
                except OSError:
                    pass
                set_progress("error", total=total, done=i,
                             error="文件 {} 校验失败：下载内容哈希与清单不符（期望 {}… 实得 {}…），"
                                   "运行代码未改动，拒绝安装。再次点击更新将重下此文件。".format(fname, want_sha[:12], dl_sha[:12]))
                return
            # .py 编译校验（坏文件不进运行目录，防更新后 import 崩）
            if rel.endswith(".py"):
                try:
                    py_compile.compile(spath, doraise=True)
                except Exception as exc:
                    try:
                        os.unlink(spath)
                    except OSError:
                        pass
                    set_progress("error", total=total, done=i,
                                 error="文件 {} 编译校验失败: {}。运行代码未改动。".format(fname, str(exc)[:120]))
                    return
            staged.append((rel, spath))

        # ---- Phase 2：全部通过 → 一次性提交（备份旧文件 + 原子替换）；提交中任一失败则回滚已替换的。----
        set_progress("downloading", total=total, done=total, msg="校验通过，正在提交 {} 个文件…".format(total))
        from sentinel_platform.core.update_commit import commit
        removal_plan = {rel: data.get('remove_manifest', {}).get(rel, '') for rel in removed}
        deleted, protected = commit(current_root, dict(staged), removal_plan, backup_dir, remote_version,remote_manifest)
        _cleanup_stage()
        pruned = len(deleted)
        if protected:_log('保留用户修改的旧文件: ' + ', '.join(protected))

        backend_changed = any(rel.endswith(".py") and not rel.startswith("docker/") for rel in changed + removed)
        compose_changed = any(rel.endswith(("docker-compose.yml", "nginx.conf")) for rel in changed + removed)

        # —— 一级一级更新·每一级：本级已完整提交 + version.txt 已写成本级 → 强制重启让本级代码真正跑起来 ——
        # 规则（用户要求）：每一级的代码必须确实运行起来，才允许拉取下一级。故：
        #   1) chain_hop 时 backend_changed 恒为 True（强制重启 web），即使本级 diff 恰好没动 .py——
        #      重启是"让本级代码作为运行态生效"+"触发新级启动钩子续拉下一级"的必要手段，不可省。
        #   2) 落**非终结** "applying" 进度（terminal=False）：前端持续轮询不 reload，每次 web 重启后
        #      onMounted 重新挂轮询；到达最新版本时由新级 web 启动钩子 resume_chain_if_pending 落 "done"。
        # 单版更新/回退（chain_hop=False）：落终结 "done"，正常按 diff 决定重启。
        if chain_hop:
            # 本跳文件已全部落地 + version.txt 已写成本级：先把「本跳完成」记进链状态（供 watchdog/续跑判推进），
            # 再清本跳 hop-<remote_version> 锁——此刻即便重启杀掉本进程，下一跳判定也不受残留锁阻塞（A.3）。
            try:
                st = _read_chain_state(current_root)
                if st.get("active"):
                    st.update({"last_committed": remote_version, "committed_ts": time.time()})
                    _write_chain_state(current_root, st)
            except Exception:
                pass
            st=_read_chain_state(current_root)
            st.update(phase='await_running',current_target=remote_version,frontend_sha=remote_manifest.get('docker/frontend/index.html',''))
            _write_chain_state(current_root,st)
            set_progress("applying", total=total, done=total,
                         msg="第 {} 级已就绪，正在重启应用该级代码…".format(remote_version)
                             + ("，清理旧产物 {}个".format(pruned) if pruned else ""))
            _apply_restart(current_root, backend_changed=True, compose_changed=compose_changed,
                           remote_version=remote_version, going_back=False, terminal=False)
            return

        # 链式单跳收尾：**重启前**清链状态（重启杀本进程，返回后代码不可靠执行）。清链后重启，
        # 新 web 起来 resume 钩子见非 active 立即返回，不重复派发；version 已=最新，看门狗见 done 也不兜底。
        if chain_final:
            raise ValueError('旧单跳收尾参数已经停用，必须通过运行确认收尾')
        set_progress("done", total=total, done=total,
                     msg=("已回退到 {}".format(remote_version) if going_back
                          else "更新完成！已升级到 {}".format(remote_version))
                          + ("，清理旧产物 {}个".format(pruned) if pruned else ""))
        _apply_restart(current_root, backend_changed=backend_changed, compose_changed=compose_changed,
                       remote_version=remote_version, going_back=going_back, terminal=True)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            set_progress("error", error="授权凭证无效或已过期，请重新激活后再更新")
        else:
            set_progress("error", error="服务器错误: {}".format(e.code))
    except urllib.error.URLError:
        set_progress("error", error="无法连接更新服务器，请检查网络连接")
    except Exception as e:
        set_progress("error", error=str(e))


# ============================ 一级一级（链式）更新驱动 ============================

def _spawn_chain_step(source_url, key, current_root):
    import sys
    args=[sys.executable,'-m','sentinel_platform.modules.about._updater',source_url,'__activation__',current_root,'__chain_step__']
    kwargs={'cwd':current_root,'stdout':subprocess.DEVNULL,'stderr':subprocess.DEVNULL}
    if os.name=='posix':kwargs['start_new_session']=True
    else:kwargs['creationflags']=getattr(subprocess,'DETACHED_PROCESS',0)
    subprocess.Popen(args,**kwargs)

def run_chain_update(source_url,key,current_root):
    from . import _update_chain
    return _update_chain.begin(__import__(__name__,fromlist=['']),source_url,key,current_root)

def _chain_apply_next_step(source_url,key,current_root):
    from . import _update_chain
    return _update_chain.step(__import__(__name__,fromlist=['']),source_url,key,current_root)

def resume_chain_if_pending(current_root=''):
    from . import _update_chain
    return _update_chain.pending(__import__(__name__,fromlist=['']),current_root)

def tick_chain_watchdog(current_root=''):
    return resume_chain_if_pending(current_root)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        set_progress("error", error="updater 参数不足（需 source_url key current_root [target_version]）")
        sys.exit(2)
    _source_url = sys.argv[1]
    _key = sys.argv[2]
    if _key=='__activation__':
        from sentinel_platform.modules.system import activation
        _key=activation.read_key()
    _current_root = sys.argv[3]
    _target = sys.argv[4] if len(sys.argv) > 4 else ""
    # 哨兵：__chain__=一级一级更新入口（从当前版逐级升到最新）；__chain_step__=启动续跑派发的「下一级」；
    # 否则=单跳更新/回退（target 为空=正常更新，非空=指定版本回退/前滚）。
    if _target == "__chain__":
        run_chain_update(_source_url, _key, _current_root)
    elif _target == "__chain_step__":
        _chain_apply_next_step(_source_url, _key, _current_root)
    else:
        run_update(_source_url, _key, _current_root, _target, full="--full" in sys.argv[5:])
