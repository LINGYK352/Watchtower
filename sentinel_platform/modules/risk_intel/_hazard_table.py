"""risk_intel/_hazard_table —— 漏洞危害等级表加载 + 类型名规范化（单一事实源）。

数据源：`dicts/vuln_hazard_table.json`（桌面《漏洞危害等级表》两表转出，UTF-8）。
**整表绝不进 AI 上下文**——AI 提示词里只留极简标准类型名清单，AI 照抄类型名；
本模块供两个消费方，都只按「单个类型名」查/归一，永不把整表塞给模型：
  ① vuln_center._record_one 落库时 canonicalize（别名/去标点映射标准名 + 垃圾名识别 + CVE 保留），零 AI token；
  ② _tools.query_finding_template 按类型名返回**单条**危害模板（几百字），不返整表。

进程内惰性加载 + 缓存；文件缺失/损坏降级空表（不崩，归一退化为原值）。
路径解析双候选（对齐 _tools._list_playbook_types）：根 dicts/ 与 sentinel_platform/dicts/。
"""
from __future__ import annotations

import json
import os
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

_LOCK = threading.Lock()
_CACHE: Optional[Dict[str, Any]] = None


def _norm_key(s: str) -> str:
    """归一比对键：小写 + 去空白/标点/下划线/连字符/竖线（别名匹配用，吸收措辞微差）。
    竖线也去——治 AI 把表头「类型|目标|等级|证据」当漏洞名，归一后能命中垃圾名。"""
    s = (s or "").strip().lower()
    return re.sub(r"[\s\-_:：、,，.。/|()（）\[\]【】]+", "", s)


# 常见后缀（比对前剥除，吸收 "ssrf漏洞"/"XSS攻击" 这类带尾缀的措辞）。
_SUFFIX_RE = re.compile(r"(漏洞|风险|缺陷|攻击|问题)$")


def _strip_suffix(k: str) -> str:
    prev = None
    while prev != k:
        prev = k
        k = _SUFFIX_RE.sub("", k)
    return k


def _dicts_path() -> Optional[str]:
    """定位 vuln_hazard_table.json：根 dicts/ 优先，退 sentinel_platform/dicts/。"""
    here = os.path.abspath(__file__)
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(here))))
    for d in (os.path.join(root, "dicts"),
              os.path.join(root, "sentinel_platform", "dicts")):
        fp = os.path.join(d, "vuln_hazard_table.json")
        if os.path.isfile(fp):
            return fp
    return None


def _load() -> Dict[str, Any]:
    """加载并构建索引（缓存）。失败降级空索引。返回
    {types, garbage_set, alias_index(归一key→标准名), name_index(标准名归一key→标准名)}。"""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    with _LOCK:
        if _CACHE is not None:
            return _CACHE
        types: List[Dict[str, Any]] = []
        garbage: List[str] = []
        fp = _dicts_path()
        if fp:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    data = json.load(f)
                types = data.get("types", []) or []
                garbage = data.get("garbage_names", []) or []
            except Exception:
                types, garbage = [], []
        alias_index: Dict[str, str] = {}
        name_index: Dict[str, str] = {}
        by_name: Dict[str, Dict[str, Any]] = {}
        for t in types:
            name = (t.get("name") or "").strip()
            if not name:
                continue
            by_name[name] = t
            nk = _norm_key(name)
            name_index[nk] = name
            alias_index.setdefault(nk, name)          # 标准名自身也可反查
            for a in t.get("aliases", []) or []:
                ak = _norm_key(a)
                if ak:
                    alias_index.setdefault(ak, name)
        _CACHE = {
            "types": types, "by_name": by_name,
            "garbage_set": {_norm_key(g) for g in garbage if g},
            "alias_index": alias_index, "name_index": name_index,
        }
        return _CACHE


def reload_table() -> None:
    """清缓存（热更新替换 json 后可调；平时不需要）。"""
    global _CACHE
    with _LOCK:
        _CACHE = None


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def canonicalize(raw: str) -> Tuple[str, bool, bool]:
    """漏洞类型名规范化（落库用，零 AI token）。

    返回 (canon_name, matched, is_garbage)：
      - 命中标准表(别名/标准名/去标点) → (标准名, True, False)；
      - 含 CVE 编号 → 保留原名(CVE 优先)，(原名去空白, False, False)；
      - 命中垃圾名(表头/纯符号/占位) 且无 CVE → (原名, False, True)；
      - 都不中 → 保留原名，(原名, False, False)。
    绝不因匹配不到就丢/清空——保留 AI 原名兜底。"""
    name = (raw or "").strip()
    if not name:
        return "", False, True
    idx = _load()
    k = _norm_key(name)
    ks = _strip_suffix(k)
    # 1) 标准表命中（别名或标准名；剥常见后缀再试一次：ssrf漏洞→ssrf）
    hit = idx["alias_index"].get(k) or idx["alias_index"].get(ks)
    if hit:
        return hit, True, False
    # 2) CVE 编号优先保留原名（不视作垃圾）
    if _CVE_RE.search(name):
        return name, False, False
    # 3) 垃圾名识别（表头/纯符号/占位/表头行残留）
    #    含竖线的多为表头行(如 "类型|目标|等级|证据")：任一段命中垃圾名即判垃圾。
    if k in idx["garbage_set"] or ks in idx["garbage_set"] or not re.search(r"[0-9a-z一-鿿]", k):
        return name, False, True
    if "|" in name or "｜" in name:
        segs = [_norm_key(x) for x in re.split(r"[|｜]", name) if x.strip()]
        if segs and any(s in idx["garbage_set"] for s in segs):
            return name, False, True
    # 4) 未知类型：保留原名（可能是新型/客户自定义），不算垃圾
    return name, False, False


def query_template(vuln_type: str) -> Dict[str, Any]:
    """按类型名返回**单条**危害模板（供 query_finding_template 工具）。不返整表。
    命中 → 该类型的 level_range/desc/hazard_template/fix_advice/requirement；
    不中 → {matched:False} + 可选标准类型名清单（仅名字，几十字）。"""
    canon, matched, _garbage = canonicalize(vuln_type)
    idx = _load()
    if matched:
        t = idx["by_name"].get(canon, {})
        return {
            "matched": True, "canonical_type": canon,
            "level_range": t.get("level_range", ""),
            "criteria": t.get("desc", ""),
            "hazard_template": t.get("hazard_template", ""),
            "fix_advice": t.get("fix_advice", ""),
            "requirement": t.get("requirement", ""),
        }
    return {
        "matched": False, "queried": (vuln_type or "").strip(),
        "note": "未匹配标准类型（可能是 CVE/新型，据实填写）；类型名请从下列标准名选一照抄",
        "standard_types": standard_type_names(),
    }


def standard_type_names() -> List[str]:
    """标准类型名清单（仅名字，供不命中时提示；不含模板正文）。"""
    return [t.get("name", "") for t in _load()["types"] if t.get("name")]
