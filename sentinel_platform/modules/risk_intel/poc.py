"""PoC 信息 poc —— PoC 插件元数据查询/清空/同步（risk_intel 叶子，核心路由暴露）。

poc 集合存 PoC 插件"有哪些"（plugin_name/app_name/scheme/vul_name/plugin_type/category），
供前端策略编辑页 Transfer 穿梭框选择。净室重写，不 import app。

无 ROLE（对核心路由暴露能力，endpoints/risk_intel.py 挂 /api/poc/*）。只依赖 core.db，
无第三方库（无需 vendor）。分页返回对齐数据 API 规范 {page,size,total,items}。

sync 通过 AST 静态扫描 external/npoc/xing/plugins/ 目录，提取每个 Plugin 类的
plugin_type/vul_name/app_name/scheme 属性，写入 poc 集合。不 import npoc 包（防腐）。
"""
from __future__ import annotations

import ast
import os
import re
from datetime import datetime
from typing import Any, Dict, List

from sentinel_platform.core import get_logger, get_repo

logger = get_logger()

POC_COLL = "poc"

# 文本字段（正则模糊匹配）vs 精确匹配字段
_TEXT_FIELDS = {"plugin_name", "app_name", "vul_name", "category"}
_EQUAL_FIELDS = {"plugin_type", "scheme"}
_QUERY_KEYS = {"page", "size", "order"}


def _build_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """据查询参数构造 Mongo 查询：文本字段正则、枚举字段等值。"""
    q: Dict[str, Any] = {}
    for key, val in (args or {}).items():
        if key in _QUERY_KEYS or val in (None, ""):
            continue
        if key == "_id":
            continue
        if key in _TEXT_FIELDS:
            q[key] = {"$regex": re.escape(str(val)), "$options": "i"}
        elif key in _EQUAL_FIELDS:
            q[key] = val
    return q


def _clean(doc: Dict[str, Any]) -> Dict[str, Any]:
    """序列化：_id/日期转 str（对齐前端 RowRecord，避免 ObjectId 不可 JSON）。"""
    out = dict(doc)
    for k in ("_id", "save_date", "update_date"):
        if k in out and out[k] is not None:
            out[k] = str(out[k])
    return out


def list_poc(args: Dict[str, Any] = None) -> Dict[str, Any]:
    """分页查询 PoC 信息。返回 {page,size,total,items}（数据 API 规范载荷）。"""
    args = args or {}
    try:
        page = max(1, int(args.get("page", 1) or 1))
        size = max(1, int(args.get("size", 10) or 10))   # 不设硬上限：size 由调用方决定（禁硬限制参数）
    except (TypeError, ValueError):
        page, size = 1, 10
    query = _build_query(args)
    try:
        coll = get_repo().collection(POC_COLL)
        total = coll.count_documents(query)
        cur = coll.find(query).skip((page - 1) * size).limit(size)
        items = [_clean(d) for d in cur]
    except Exception as e:
        logger.warning("list_poc error: %s", e)
        total, items = 0, []
    return {"page": page, "size": size, "total": total, "items": items}


def clear_poc() -> Dict[str, Any]:
    """清空 PoC 信息。返回 {delete_cnt}。"""
    try:
        result = get_repo().collection(POC_COLL).delete_many({})
        return {"delete_cnt": getattr(result, "deleted_count", 0)}
    except Exception as e:
        logger.warning("clear_poc error: %s", e)
        return {"error": "清空失败: {}".format(e)}


def sync_poc() -> Dict[str, Any]:
    """从 external/npoc/xing/plugins/ 目录静态扫描插件元数据，写入 poc 集合。

    用 AST 解析每个 Plugin 类的 __init__ 赋值（plugin_type/vul_name/app_name/scheme），
    不 import npoc 包（防腐层 + 不依赖其运行时环境）。
    """
    plugins_dir = _locate_plugins_dir()
    if not plugins_dir:
        return {"error": "未找到 external/npoc/xing/plugins 目录", "plugin_cnt": 0}

    records = _scan_plugins(plugins_dir)
    if not records:
        return {"error": "插件目录扫描结果为空", "plugin_cnt": 0}

    try:
        coll = get_repo().collection(POC_COLL)
        coll.delete_many({})
        coll.insert_many(records)
        logger.info("sync_poc: synced %d plugins from %s", len(records), plugins_dir)
    except Exception as e:
        logger.warning("sync_poc db error: %s", e)
        return {"error": "写入数据库失败: {}".format(e), "plugin_cnt": 0}
    return {"plugin_cnt": len(records)}


# ——— 插件目录扫描（AST 静态提取）——————————————————————————

# 目录名 → plugin_type 映射（和 PluginType 常量一致）
_DIR_TYPE_MAP = {
    "poc": "poc",
    "noauth": "poc",       # 未授权类归 poc
    "brute": "brute",
    "sniffer": "sniffer",
    "identify": "poc",     # 指纹识别类归 poc
    "listener": "poc",
}

# HTTP 类 scheme（用于判定 category：应用弱口令 vs 服务弱口令）
_HTTP_SCHEMES = {"http", "https"}

# SchemeType 名称 → 值映射（从 const.py 硬编码，避免 import）
_SCHEME_MAP = {
    "AJP": "ajp", "DUBBO": "dubbo", "IIOP": "iiop", "JDWP": "jdwp",
    "LDAP": "ldap", "MEMCACHED": "memcached", "MONGODB": "mongodb",
    "MYSQL": "mysql", "SQLSERVER": "mssql", "POSTGRESQL": "psql",
    "ZOOKEEPER": "zookeeper", "RSYNC": "rsync", "ORACLE": "oracle",
    "REDIS": "redis", "RMI": "rmi", "SSH": "ssh", "FTP": "ftp",
    "IMAP": "imap", "T3": "t3", "SMTP": "smtp", "RDP": "rdp",
    "POP3": "pop3", "ZMTP": "zmtp", "HTTP": "http", "HTTPS": "https",
    "SOCKS4": "socks4", "SOCKS5": "socks5", "NFS": "nfs",
    "PROXY_HTTPS": "proxy_https", "COBALT_STRIKE": "csts", "HRPC": "hrpc",
}


def _locate_plugins_dir() -> str:
    """定位 external/npoc/xing/plugins 目录（相对于项目根）。"""
    # 向上找项目根（有 sentinel_platform/ 和 external/ 的目录）
    base = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        candidate = os.path.join(base, "external", "npoc", "xing", "plugins")
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(base)
        if parent == base:
            break
        base = parent
    return ""


def _scan_plugins(plugins_dir: str) -> List[Dict[str, Any]]:
    """扫描插件目录所有 .py → AST 提取属性 → 返回 poc 集合记录列表。"""
    records: List[Dict[str, Any]] = []
    now = datetime.utcnow()

    for subdir in sorted(os.listdir(plugins_dir)):
        subpath = os.path.join(plugins_dir, subdir)
        if not os.path.isdir(subpath) or subdir.startswith(("_", ".")):
            continue
        dir_type = _DIR_TYPE_MAP.get(subdir, "poc")
        for fname in sorted(os.listdir(subpath)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            fpath = os.path.join(subpath, fname)
            info = _extract_plugin_info(fpath)
            if info is None:
                continue
            # 确定 plugin_type：优先 AST 解析值，否则按目录
            ptype = info.get("plugin_type") or dir_type
            schemes = info.get("scheme") or ""
            # category 逻辑（对齐旧代码 gen_poc_info）
            if ptype == "brute":
                if any(s in _HTTP_SCHEMES for s in schemes.split(",")):
                    category = "应用弱口令"
                else:
                    category = "服务弱口令"
            elif ptype == "sniffer":
                category = "协议识别"
            else:
                category = "漏洞PoC"

            plugin_name = fname[:-3]  # 去 .py
            records.append({
                "plugin_name": plugin_name,
                "app_name": info.get("app_name") or "",
                "scheme": schemes,
                "vul_name": info.get("vul_name") or "",
                "plugin_type": ptype,
                "category": category,
                "update_date": now,
            })
    return records


def _extract_plugin_info(filepath: str) -> "Dict[str, str] | None":
    """AST 解析单个插件文件，提取 Plugin.__init__ 中的 self.xxx = ... 赋值。"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, OSError, ValueError):
        return None

    # 找 class Plugin 的 __init__ 方法
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != "Plugin":
            continue
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                return _extract_init_attrs(item)
    return None


def _extract_init_attrs(func: ast.FunctionDef) -> Dict[str, str]:
    """从 __init__ 函数体中提取 self.plugin_type / self.vul_name / self.app_name / self.scheme。"""
    info: Dict[str, str] = {}
    for stmt in ast.walk(func):
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            if not (isinstance(target, ast.Attribute) and
                    isinstance(target.value, ast.Name) and
                    target.value.id == "self"):
                continue
            attr = target.attr
            if attr == "plugin_type":
                info["plugin_type"] = _resolve_constant(stmt.value)
            elif attr == "vul_name":
                info["vul_name"] = _resolve_constant(stmt.value)
            elif attr == "app_name":
                info["app_name"] = _resolve_constant(stmt.value)
            elif attr == "scheme":
                info["scheme"] = _resolve_scheme(stmt.value)
    return info


def _resolve_constant(node: ast.AST) -> str:
    """解析 AST 节点为字符串值（支持字面量和 PluginType.XXX 属性引用）。"""
    # 字面量字符串
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    # PluginType.POC / PluginType.BRUTE 等属性引用
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id == "PluginType":
            return node.attr.lower()  # POC→poc, BRUTE→brute
    return ""


def _resolve_scheme(node: ast.AST) -> str:
    """解析 scheme 赋值：支持列表 [SchemeType.HTTP, ...] 和单值。返回逗号分隔字符串。"""
    if isinstance(node, ast.List):
        parts = []
        for elt in node.elts:
            val = _resolve_scheme_item(elt)
            if val:
                parts.append(val)
        return ",".join(parts)
    return _resolve_scheme_item(node)


def _resolve_scheme_item(node: ast.AST) -> str:
    """解析单个 scheme 值：SchemeType.HTTP → "http"，字面量直出。"""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id == "SchemeType":
            return _SCHEME_MAP.get(node.attr, node.attr.lower())
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


# ========== POC 导入（统一 .py 形态；npoc 结构→内核自动扫，其他→AI 读/调资料库）==========

MAX_POC_SIZE = 512 * 1024        # 单文件上限 512KB（脚本足够；防超大文件）
MAX_BATCH_FILES = 2000           # 批量单包文件数软上限（防 zip 炸弹，非业务硬限）


def _project_root() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        if os.path.isdir(os.path.join(base, "sentinel_platform")) and os.path.isdir(os.path.join(base, "external")):
            return base
        parent = os.path.dirname(base)
        if parent == base:
            break
        base = parent
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _imported_npoc_dir() -> str:
    """npoc 结构插件落点：external/npoc/xing/plugins/imported/（xing 两层扫描会扫到，自动执行）。"""
    d = os.path.join(_project_root(), "external", "npoc", "xing", "plugins", "imported")
    os.makedirs(d, exist_ok=True)
    return d


def _poc_scripts_dir() -> str:
    """非 npoc 脚本落点：dicts/poc_scripts/（AI 读源码参考/指定执行的资料库，同 vuln_playbook 级）。"""
    root = _project_root()
    d = os.path.join(root, "dicts", "poc_scripts")
    if not os.path.isdir(os.path.join(root, "dicts")):
        d = os.path.join(root, "sentinel_platform", "dicts", "poc_scripts")
    os.makedirs(d, exist_ok=True)
    return d


def _sanitize_filename(name: str) -> "str | None":
    """清洗文件名防目录穿越：取 basename、拒隐藏/非法字符、限 .py 扩展。非法返 None。"""
    if not name:
        return None
    base = os.path.basename(str(name).strip().replace("\\", "/"))
    if not base or base.startswith(".") or "/" in base or "\0" in base:
        return None
    if not base.endswith(".py"):
        return None
    if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*\.py$", base):
        return None
    return base


def _is_npoc_plugin(source: str) -> bool:
    """AST 探测是否 npoc 结构（含 class Plugin(BasePlugin) + __init__）。语法错→False。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Plugin":
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            bases += [b.attr for b in node.bases if isinstance(b, ast.Attribute)]
            if "BasePlugin" in bases:
                return True
    return False


def _poc_meta(filename: str, source: str, poc_format: str, file_path: str) -> Dict[str, Any]:
    """构造 poc 集合元数据记录。npoc 结构复用 AST 提取 vul_name/app_name/scheme；其他脚本留空由 name 兜底。"""
    plugin_name = os.path.splitext(filename)[0]
    rec: Dict[str, Any] = {
        "plugin_name": plugin_name, "app_name": "", "scheme": "", "vul_name": "",
        "plugin_type": "poc", "category": "导入脚本",
        "poc_format": poc_format,          # "npoc" | "script"
        "source": "imported",              # 区分内置(synced)/导入(imported)
        "file_path": file_path, "source_code": source,
        "update_date": datetime.utcnow(),
    }
    if poc_format == "npoc":
        try:
            info = _extract_plugin_info_from_source(source)
            if info:
                rec["vul_name"] = info.get("vul_name", "") or ""
                rec["app_name"] = info.get("app_name", "") or ""
                rec["scheme"] = info.get("scheme", "") or ""
                rec["plugin_type"] = info.get("plugin_type", "poc") or "poc"
                rec["category"] = "漏洞PoC"
        except Exception:
            pass
    return rec


def _extract_plugin_info_from_source(source: str) -> "Dict[str, str] | None":
    """从源码文本 AST 提取 Plugin.__init__ 属性（复用 _extract_init_attrs，不落盘再读）。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Plugin":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                    return _extract_init_attrs(item)
    return None


def import_poc(filename: str, content: str, overwrite: bool = False) -> Dict[str, Any]:
    """导入单个 .py POC：清洗文件名→大小校验→AST 探测 npoc 结构分落点→落盘→元数据入库。
    npoc 结构落 plugins/imported/（内核 xing 自动扫执行），其他落 dicts/poc_scripts/（AI 读/调）。
    返回 {ok, plugin_name, poc_format, file_path} 或 {ok:False, error}。"""
    fname = _sanitize_filename(filename)
    if not fname:
        return {"ok": False, "error": "非法文件名（须 .py，无路径穿越/隐藏文件）"}
    src = content or ""
    if not src.strip():
        return {"ok": False, "error": "文件内容为空"}
    if len(src.encode("utf-8", "ignore")) > MAX_POC_SIZE:
        return {"ok": False, "error": "文件过大（>{}KB）".format(MAX_POC_SIZE // 1024)}
    # 语法校验（连合法 Python 都不是直接拒，避免脏文件入库）
    try:
        ast.parse(src)
    except SyntaxError as e:
        return {"ok": False, "error": "Python 语法错误: {}".format(e.msg)}
    is_npoc = _is_npoc_plugin(src)
    poc_format = "npoc" if is_npoc else "script"
    target_dir = _imported_npoc_dir() if is_npoc else _poc_scripts_dir()
    fpath = os.path.join(target_dir, fname)
    if os.path.exists(fpath) and not overwrite:
        return {"ok": False, "error": "同名 POC 已存在（overwrite=true 覆盖）", "exists": True}
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(src)
    except Exception as e:
        return {"ok": False, "error": "写入失败: {}".format(e)}
    # 元数据入库（按 file_path 幂等 upsert）
    try:
        rec = _poc_meta(fname, src, poc_format, fpath)
        coll = get_repo().collection(POC_COLL)
        coll.update_one({"file_path": fpath}, {"$set": rec}, upsert=True)
    except Exception as e:
        logger.warning("import_poc meta upsert error: %s", e)
    return {"ok": True, "plugin_name": rec["plugin_name"], "poc_format": poc_format, "file_path": fpath}


def batch_import_poc(zip_bytes: bytes, overwrite: bool = False) -> Dict[str, Any]:
    """批量导入 zip 内所有 .py POC。逐个 import_poc（防 zip 炸弹/路径穿越：文件数上限 + 只取 .py basename）。
    返回 {ok, success, skipped, failed, details}。非 zip/解压失败返 {ok:False, error}。"""
    import io, zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception as e:
        return {"ok": False, "error": "非法 zip: {}".format(e)}
    names = [n for n in zf.namelist() if n.endswith(".py") and not n.endswith("/")]
    if not names:
        return {"ok": False, "error": "zip 内无 .py 文件"}
    if len(names) > MAX_BATCH_FILES:
        return {"ok": False, "error": "zip 内 .py 超 {} 个（防炸弹）".format(MAX_BATCH_FILES)}
    success = skipped = failed = 0
    details: List[Dict[str, Any]] = []
    for n in names:
        # 只取 basename（zip 内可能带路径，_sanitize_filename 再兜底防穿越）
        try:
            raw = zf.read(n)
            if len(raw) > MAX_POC_SIZE:
                failed += 1; details.append({"file": n, "error": "过大"}); continue
            r = import_poc(os.path.basename(n), raw.decode("utf-8", "ignore"), overwrite=overwrite)
            if r.get("ok"):
                success += 1
            elif r.get("exists"):
                skipped += 1; details.append({"file": n, "skip": "已存在"})
            else:
                failed += 1; details.append({"file": n, "error": r.get("error", "")})
        except Exception as e:
            failed += 1; details.append({"file": n, "error": str(e)[:80]})
    return {"ok": True, "success": success, "skipped": skipped, "failed": failed, "details": details[:50]}


def import_template() -> str:
    """返回批量导入的 .py POC 模板骨架（含 npoc 结构示例 + 非结构脚本说明）。供前端下载。"""
    return '''# 哨兵 POC 模板 —— 统一 .py 形态。两类都支持，导入时自动识别：
#
# 【类型一】npoc 结构插件（含 class Plugin(BasePlugin)）→ 落 external/npoc/xing/plugins/imported/，
#           内核 xing 引擎自动扫描并可在扫描任务/AI 渗透中执行。示例：
#
# from xing.core.BasePlugin import BasePlugin
# from xing.utils import http_req
# from xing.core import PluginType, SchemeType
#
# class Plugin(BasePlugin):
#     def __init__(self):
#         super(Plugin, self).__init__()
#         self.plugin_type = PluginType.POC          # POC / BRUTE / SNIFFER
#         self.vul_name = "示例组件 未授权访问"
#         self.app_name = "示例组件"
#         self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]
#
#     def check_app(self, target):                   # 指纹判定：是否该组件
#         conn = http_req(target + "/", "get")
#         return "示例特征" in conn.text
#
#     def verify(self, target):                      # 漏洞验证：命中返回证据/True
#         conn = http_req(target + "/admin/api", "get")
#         if conn.status_code == 200 and "secret" in conn.text:
#             return {"vul": True, "detail": conn.text[:200]}
#         return False
#
# 【类型二】普通 exploit 脚本（非 npoc 结构）→ 落 dicts/poc_scripts/，
#           不进内核自动扫描，但 AI 渗透可 query_poc 检索 / read_poc 读源码参考复现 / run_poc 指定执行。
#           约定（利于 AI 指定调用）：从 argv 读目标 `python <poc>.py <target_url>`，命中打印证据到 stdout。
#
# import sys, requests
# def run(target):
#     r = requests.get(target + "/vuln/path", timeout=10, verify=False)
#     if "flag" in r.text:
#         print("[VULN]", target, r.text[:200])
#         return True
#     return False
# if __name__ == "__main__":
#     run(sys.argv[1] if len(sys.argv) > 1 else "")
'''


def delete_poc(ids: List[str]) -> Dict[str, Any]:
    """删除导入的 POC：删 poc 集合记录 + 删对应 .py 文件（仅限 imported 来源，内置 synced 不删文件）。
    返回 {ok, deleted, files_removed}。"""
    if not ids or not isinstance(ids, list):
        return {"ok": False, "error": "_id 列表必填"}
    from bson import ObjectId
    coll = get_repo().collection(POC_COLL)
    deleted = files_removed = 0
    for _id in ids:
        try:
            oid = ObjectId(_id)
        except Exception:
            oid = _id
        doc = coll.find_one({"_id": oid})
        if not doc:
            continue
        # 仅删导入来源的物理文件（内置 synced 的不动 external 原始插件）
        fp = doc.get("file_path", "")
        if doc.get("source") == "imported" and fp and os.path.isfile(fp):
            try:
                os.remove(fp); files_removed += 1
            except OSError:
                pass
        deleted += getattr(coll.delete_one({"_id": oid}), "deleted_count", 0)
    return {"ok": True, "deleted": deleted, "files_removed": files_removed}


def read_poc(plugin_name: str) -> Dict[str, Any]:
    """读某 POC 源码（AI 渗透用：读利用逻辑参考复现）。按 plugin_name 精确匹配。
    返回 {ok, plugin_name, poc_format, source_code, file_path} 或 {ok:False, error}。"""
    name = (plugin_name or "").strip()
    if not name:
        return {"ok": False, "error": "plugin_name 必填"}
    try:
        doc = get_repo().collection(POC_COLL).find_one({"plugin_name": name})
    except Exception as e:
        return {"ok": False, "error": str(e)}
    if not doc:
        return {"ok": False, "error": "未找到 POC: {}".format(name)}
    src = doc.get("source_code", "")
    # 内置 synced 的无 source_code 字段（只存元数据）→ 从 file_path 现读
    if not src and doc.get("file_path") and os.path.isfile(doc["file_path"]):
        try:
            with open(doc["file_path"], "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
        except Exception:
            pass
    return {"ok": True, "plugin_name": name, "poc_format": doc.get("poc_format", ""),
            "source_code": src, "file_path": doc.get("file_path", ""),
            "vul_name": doc.get("vul_name", ""), "app_name": doc.get("app_name", "")}
