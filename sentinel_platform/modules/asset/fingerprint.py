"""指纹管理 fingerprint —— 指纹规则 CRUD + human_rule 规则校验（asset 叶子，核心路由暴露）。

指纹规则形如 `body="Powered by X" && title="登录"`，字段限 body/title/header/server/cert/icon_hash，
运算符 && || 与 = / !=。存 fingerprint 集合 {name, human_rule, update_date}。

净室重写 routes/fingerprint.py + services/fingerprint.py：**安全改进——不用 eval 校验**。
旧代码 `eval(express,{"__builtins__":{}},...)` 对用户输入 eval（受限但仍是代码注入面）；
本实现用 `ast.parse` + 节点白名单校验语法（只允许比较/布尔运算/字段名/字符串），零 eval。

无 ROLE（核心路由暴露）。只依赖 core.db + stdlib(ast/re)，无第三方库（无需 vendor）。
分页不设硬上限（禁硬限制参数）。
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Tuple

from sentinel_platform.core import get_logger, get_repo

logger = get_logger()

FP_COLL = "fingerprint"
# 指纹规则允许的字段（其余标识符视为非法）
FP_FIELDS = {"body", "title", "header", "server", "cert", "icon_hash"}
_QUERY_KEYS = {"page", "size", "order"}


def validate_rule(human_rule: str) -> Tuple[bool, str]:
    """校验指纹规则语法（不 eval，用 ast + 节点白名单）。返回 (ok, error_msg)。

    规则语义：字段 == / != 字符串，用 && || 组合，可加括号。转成 Python 布尔表达式后
    ast.parse 成 AST，遍历只放行：布尔运算(and/or)、比较(==/!=)、字段名(FP_FIELDS)、字符串常量、括号。
    出现函数调用/属性访问/其他名字/其他运算 → 非法（杜绝注入与非法字段）。
    """
    if not human_rule or not str(human_rule).strip():
        return False, "规则为空"
    expr = str(human_rule).replace("&&", " and ").replace("||", " or ")
    expr = re.sub(r'(?<![=!<>])=(?!=)', "==", expr)     # 单 = → ==（不动 == != >= <=）
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        return False, "语法错误: {}".format(e.msg)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Expression, ast.BoolOp, ast.Compare,
                             ast.And, ast.Or, ast.Eq, ast.NotEq, ast.Load)):
            continue
        if isinstance(node, ast.Name):
            if node.id not in FP_FIELDS:
                return False, "非法字段: {}（仅支持 {}）".format(node.id, "/".join(sorted(FP_FIELDS)))
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            continue
        # 兼容旧 Python 的 ast.Str
        if node.__class__.__name__ == "Str":
            continue
        return False, "规则含不允许的语法: {}".format(node.__class__.__name__)
    return True, ""


def _clean(doc: Dict[str, Any]) -> Dict[str, Any]:
    """序列化：ObjectId/datetime 等非 JSON 原生类型统一转 str（按类型兜底，
    不只依赖字段名——flask_restx 的 JSON 编码器不支持 datetime，任何 datetime 泄漏都会 500）。"""
    import datetime as _dt
    out = {}
    for k, v in doc.items():
        if isinstance(v, (_dt.datetime, _dt.date)):
            out[k] = v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, _dt.datetime) else str(v)
        elif k == "_id" or type(v).__name__ == "ObjectId":
            out[k] = str(v)
        else:
            out[k] = v
    return out


def _build_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """name 模糊匹配（其余查询键忽略）。"""
    q: Dict[str, Any] = {}
    name = (args or {}).get("name")
    if name:
        q["name"] = {"$regex": re.escape(str(name)), "$options": "i"}
    return q


def list_fingerprint(args: Dict[str, Any] = None) -> Dict[str, Any]:
    """分页查询指纹。返回 {page,size,total,items}（禁硬限制 size）。"""
    args = args or {}
    try:
        page = max(1, int(args.get("page", 1) or 1))
        size = max(1, int(args.get("size", 10) or 10))      # 不设硬上限（禁硬限制参数）
    except (TypeError, ValueError):
        page, size = 1, 10
    query = _build_query(args)
    try:
        coll = get_repo().collection(FP_COLL)
        total = coll.count_documents(query)
        cur = coll.find(query).sort("update_date", -1).skip((page - 1) * size).limit(size)
        items = [_clean(d) for d in cur]
    except Exception as e:
        logger.warning("list_fingerprint error: %s", e)
        total, items = 0, []
    return {"page": page, "size": size, "total": total, "items": items}


def add_fingerprint(name: str, human_rule: str) -> Dict[str, Any]:
    """新增指纹。校验规则语法 + 去重（同 human_rule 已存在则拒）。返回 {_id,name} 或 {error}。"""
    name = (name or "").strip()
    human_rule = (human_rule or "").strip()
    if not name or not human_rule:
        return {"error": "名称与规则必填"}
    ok_rule, msg = validate_rule(human_rule)
    if not ok_rule:
        return {"error": "规则非法: {}".format(msg)}
    try:
        coll = get_repo().collection(FP_COLL)
        if coll.find_one({"human_rule": human_rule}):
            return {"error": "规则已存在"}
        import datetime
        doc = {"name": name, "human_rule": human_rule, "update_date": datetime.datetime.now()}
        coll.insert_one(doc)
        return {"_id": str(doc.get("_id", "")), "name": name}
    except Exception as e:
        logger.warning("add_fingerprint error: %s", e)
        return {"error": "新增失败: {}".format(e)}


def _oid(v: Any) -> Any:
    """字符串 → bson.ObjectId（惰性 import，对齐 core/db.py + vuln_center/search 范式）。
    无 bson（Windows/离线单测无 pymongo）或非法 → 回退原值；真实 Linux 部署 ObjectId 生效，
    测试用 fake repo 存字符串 _id，回退原值即可匹配。"""
    if not v:
        return v
    try:
        from bson import ObjectId
        return ObjectId(v)
    except ImportError:
        return v                       # 无 bson：回退原值（测试/无 pymongo 环境）
    except Exception:
        return v                       # 非法 ObjectId 字符串：原值（查不中即跳过）


def delete_fingerprint(ids: List[str]) -> Dict[str, Any]:
    """按 _id 列表删除指纹。返回 {deleted, ids}。"""
    if not ids or not isinstance(ids, list):
        return {"error": "_id 列表必填"}
    deleted = 0
    try:
        coll = get_repo().collection(FP_COLL)
        for _id in ids:
            try:
                r = coll.delete_one({"_id": _oid(_id)})
                deleted += getattr(r, "deleted_count", 0)
            except Exception:
                continue
        return {"deleted": deleted, "ids": ids}
    except Exception as e:
        logger.warning("delete_fingerprint error: %s", e)
        return {"error": "删除失败: {}".format(e)}


def export_yaml() -> str:
    """导出全部指纹为 YAML 文本（[{name, rule}]，对齐旧格式，供前端下载）。
    **禁止硬限制参数**：全量导出不 limit。PyYAML 惰性 import（已 vendor）；无库/异常返空串。"""
    try:
        import yaml
        coll = get_repo().collection(FP_COLL)
        items = [{"name": d.get("name", ""), "rule": d.get("human_rule", "")}
                 for d in coll.find() if d.get("human_rule")]
        return yaml.dump(items, default_flow_style=False, sort_keys=False, allow_unicode=True)
    except Exception as e:
        logger.warning("export_yaml error: %s", e)
        return ""


def import_yaml(text: str) -> Dict[str, Any]:
    """导入 YAML 指纹（[{name, rule}]）。逐条校验规则语法 + 去重（同 human_rule 跳过）。
    返回 {success_cnt, repeat_cnt, error_cnt}；顶层非 list 或解析失败返 {error}。
    **禁止硬限制参数**：条数不砍，全量导入。"""
    try:
        import yaml
        obj = yaml.safe_load(text or "")
    except Exception as e:
        return {"error": "YAML 解析失败: {}".format(e)}
    if not isinstance(obj, list):
        return {"error": "YAML 顶层须为列表 [{name, rule}]"}
    success = repeat = error = 0
    try:
        coll = get_repo().collection(FP_COLL)
        import datetime
        for rule in obj:
            if not isinstance(rule, dict):
                error += 1
                continue
            human_rule = (rule.get("rule") or rule.get("human_rule") or "").strip()
            name = (rule.get("name") or "").strip()
            if not human_rule or not name:
                error += 1
                continue
            ok_rule, _ = validate_rule(human_rule)      # 复用现有 ast 白名单校验（防注入）
            if not ok_rule:
                error += 1
                continue
            if coll.find_one({"human_rule": human_rule}):
                repeat += 1
                continue
            coll.insert_one({"name": name, "human_rule": human_rule,
                             "update_date": datetime.datetime.now()})
            success += 1
        return {"success_cnt": success, "repeat_cnt": repeat, "error_cnt": error}
    except Exception as e:
        logger.warning("import_yaml error: %s", e)
        return {"error": "导入失败: {}".format(e)}
