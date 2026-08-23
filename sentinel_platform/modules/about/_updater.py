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
import tempfile
import time
import py_compile
import urllib.error
from urllib.request import Request, urlopen

PROGRESS_FILE = "/tmp/.sentinel_update_progress.json"

_TRACK_DIRS = ["sentinel_platform", "docker/frontend", "docker/landing", "external", "dicts"]
_TRACK_FILES = ["version.txt", "docker/docker-compose.yml", "docker/nginx.conf"]
_SKIP_NAMES = {".git", "__pycache__", ".pytest_cache", "node_modules", "tests",
               ".update_backup", ".hotupdate_backup", "logs", "shared", ".venv"}


def get_progress() -> dict:
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            return json.loads(f.read())
    except Exception:
        return {"phase": "idle", "total": 0, "done": 0, "msg": "", "error": ""}


def set_progress(phase: str, total: int = 0, done: int = 0, msg: str = "", error: str = ""):
    data = {"phase": phase, "total": total, "done": done, "msg": msg, "error": error}
    try:
        tmp = PROGRESS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, PROGRESS_FILE)
    except Exception:
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


def _safe_restart_worker():
    """重启 worker/scheduler 加载新代码。活跃 AI 会话中断，scheduler watchdog 心跳超时自动重投。"""
    if os.path.exists("/var/run/docker.sock"):
        subprocess.run(["docker", "restart", "docker-worker-1", "docker-scheduler-1"],
                       timeout=60, capture_output=True)
    else:
        subprocess.run(["systemctl", "restart", "sentinel-worker"], timeout=30, capture_output=True)
        subprocess.run(["systemctl", "restart", "sentinel-scheduler"], timeout=30, capture_output=True)


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


def run_update(source_url: str, key: str, current_root: str, target_version: str = ""):
    """独立进程执行热更新：fetch manifest → diff → 逐文件(下载+校验+写入)。
    进度持久化到 PROGRESS_FILE，前端轮询。因是独立进程，gunicorn worker reload 杀不到它。

    target_version 非空 = 回退/前滚到指定历史版本（绕过防降级守卫）；为空 = 正常更新（守卫生效）。"""
    is_rollback = bool(target_version)
    try:
        if not key:
            set_progress("error", error="未激活，请先激活系统获取授权凭证")
            return
        set_progress("checking", msg="正在获取更新清单..." if not is_rollback
                     else "正在获取版本 {} 清单...".format(target_version))
        headers = {"X-Update-Key": key}

        manifest_url = source_url + "/manifest"
        if is_rollback:
            manifest_url += "?version=" + target_version
        req = Request(manifest_url, headers=headers)
        with urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        remote_manifest = data.get("manifest", {})
        remote_version = data.get("version", "") or target_version

        # 防降级守卫（回退绕过）
        if not is_rollback:
            try:
                from sentinel_platform.modules.about.update_check import server_version, _cmp
                local_version = server_version()
                if remote_version and local_version and _cmp(remote_version, local_version) <= 0:
                    set_progress("done", msg="本地已是最新（{}），分发源为 {}，无需更新（不降级）".format(
                        local_version, remote_version))
                    return
            except Exception:
                pass

        # 计算本地 sha256
        local_manifest = {}
        for rel in remote_manifest:
            fp = os.path.join(current_root, rel)
            if os.path.isfile(fp):
                h = hashlib.sha256()
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                local_manifest[rel] = h.hexdigest()

        changed = [r for r, h in remote_manifest.items() if local_manifest.get(r) != h]
        removed = _rollback_removed_files(current_root, set(remote_manifest.keys())) if is_rollback else []
        if not changed and not removed:
            set_progress("done", msg="已是最新，无需更新" if not is_rollback
                         else "本地已与版本 {} 一致".format(target_version))
            return
        # 排序：代码/前端小文件优先，external/bin 大文件最后
        changed.sort(key=lambda rel: (1, rel) if rel.startswith("external/bin/") else (0, rel))
        total = len(changed)
        set_progress("downloading", total=total, done=0, msg="更新 0/{}".format(total))
        backup_dir = os.path.join(current_root, ".update_backup", time.strftime("%Y%m%d-%H%M%S"))

        for i, rel in enumerate(changed):
            fname = os.path.basename(rel)
            set_progress("downloading", total=total, done=i,
                         msg="下载 {}/{} {}".format(i + 1, total, fname))
            file_url = source_url + "/file?path=" + rel
            if is_rollback:
                file_url += "&version=" + target_version
            req = Request(file_url, headers=headers)
            resp = urlopen(req, timeout=30)
            content = b"".join(iter(lambda: resp.read(65536), b""))
            resp.close()
            if rel.endswith(".py"):
                tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
                tmp.write(content)
                tmp.close()
                try:
                    py_compile.compile(tmp.name, doraise=True)
                finally:
                    os.unlink(tmp.name)
            dst = os.path.join(current_root, rel)
            if os.path.isfile(dst):
                bpath = os.path.join(backup_dir, rel)
                os.makedirs(os.path.dirname(bpath), exist_ok=True)
                shutil.copy2(dst, bpath)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(content)
            if "/bin/" in rel and not rel.endswith((".py", ".txt", ".json", ".yaml", ".yml")):
                os.chmod(dst, 0o755)
            set_progress("downloading", total=total, done=i + 1,
                         msg="完成 {}/{} {}".format(i + 1, total, fname))

        for rel in removed:
            dst = os.path.join(current_root, rel)
            if os.path.isfile(dst):
                bpath = os.path.join(backup_dir, rel)
                os.makedirs(os.path.dirname(bpath), exist_ok=True)
                shutil.copy2(dst, bpath)
                try:
                    os.remove(dst)
                except OSError:
                    pass

        # 清理前端旧 hash 产物（更新/回退都清，保持目录精确=当前版本，无残留堆积）
        pruned = _prune_frontend_assets(current_root, remote_manifest, backup_dir)

        if remote_version:
            with open(os.path.join(current_root, "version.txt"), "w", encoding="utf-8") as f:
                f.write(remote_version)

        set_progress("done", total=total, done=total,
                     msg=("已回退到 {}".format(remote_version) if is_rollback
                          else "更新完成！已升级到 {}".format(remote_version))
                          + ("，清理旧产物 {}个".format(pruned) if pruned else ""))

        # 重启 worker/scheduler 加载新后端代码（本进程独立，重启它们不影响本进程收尾）
        backend_changed = any(rel.endswith(".py") and not rel.startswith("docker/") for rel in changed)
        compose_changed = any(rel.endswith(("docker-compose.yml", "nginx.conf")) for rel in changed)
        time.sleep(2)
        try:
            from sentinel_platform.core import get_config
            reload_cmd = (get_config().section("UPDATE", "RELOAD_CMD", default="") or "").strip()
        except Exception:
            reload_cmd = ""
        if reload_cmd:
            subprocess.run(reload_cmd, shell=True, timeout=30, capture_output=True)
        if os.path.exists("/var/run/docker.sock"):
            if backend_changed:
                _safe_restart_worker()
            if compose_changed:
                compose_dir = os.path.join(current_root, "docker")
                if os.path.isfile(os.path.join(compose_dir, "docker-compose.yml")):
                    subprocess.run(["docker", "compose", "up", "-d", "--force-recreate"],
                                   cwd=compose_dir, timeout=120, capture_output=True)
        else:
            subprocess.run(["systemctl", "reload", "sentinel-web"], timeout=15, capture_output=True)
            if backend_changed:
                _safe_restart_worker()
    except urllib.error.HTTPError as e:
        if e.code == 403:
            set_progress("error", error="授权凭证无效或已过期，请重新激活后再更新")
        else:
            set_progress("error", error="服务器错误: {}".format(e.code))
    except urllib.error.URLError:
        set_progress("error", error="无法连接更新服务器，请检查网络连接")
    except Exception as e:
        set_progress("error", error=str(e))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        set_progress("error", error="updater 参数不足（需 source_url key current_root [target_version]）")
        sys.exit(2)
    _source_url = sys.argv[1]
    _key = sys.argv[2]
    _current_root = sys.argv[3]
    _target = sys.argv[4] if len(sys.argv) > 4 else ""
    run_update(_source_url, _key, _current_root, _target)
