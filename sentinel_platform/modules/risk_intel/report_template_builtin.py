# -*- coding: utf-8 -*-
"""risk_intel/report_template_builtin —— 内置默认报告模板（会话级 / 任务级）。

设计（不走 LLM 学习路径，直接产「已学好」的模板）：
  - 直接用 python-docx 构造带 docxtpl 标签的 template.docx（{{}} 标量 / {%tr%} 表格行循环 /
    {%p%} 段落块循环），这就是 report_template 学习流程最终产出的等价物，省掉一次性 LLM 学习。
  - 同时产一份 origin.docx（填了示例数据的样本）供复核抽屉左右对比（左=样本排版，右=打标记模板）。
  - schema 只声明 scalars（report.* 单值）+ images（严重度饼图位）；stat.* 与 findings/systems
    循环变量由 generate_from_template 直接注入 ctx（{{ stat.high }} / {%p for sys in systems%}），
    不需在 schema 里逐个声明。

会话级 vs 任务级：唯一区别是任务级多一级「分系统」目录——漏洞部分按系统分组
（{%p for sys in systems%} 外层循环，组内各自漏洞清单表 + 详情）；会话级直接一个清单。

POC 携带（对齐真实数据模型）：每条漏洞详情渲染 {{ item.poc }}（AI 写入的 payload/请求/关键响应）
  + {{ item.evidence }}（工具原始响应），等宽字体承载请求/响应包。不臆造 request/response 字段
  （数据模型里 poc 是单一自由文本，见 _tools.py report_finding）。

播种：seed_builtin_templates() 由 bootstrap.ensure_indexes 幂等调用（同 seed_prompts）。
纯后端代码 → 走分发热更即到达存量实例，不需 rebuild 镜像（python-docx/docxtpl 已在依赖）。
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

import shutil

from sentinel_platform.core import get_repo, get_logger, template_dir, project_root
from sentinel_platform.contracts import Collections

logger = get_logger()


def _prebuilt_dir() -> str:
    """预生成内置模板 docx 的分发目录：<项目根>/dicts/report_templates/（在 TRACK_DIRS 内随热更分发，
    v1.21.159）。播种时优先拷贝这里的 template.docx/origin.docx，**不依赖本地 python-docx 现场生成**
    ——治「存量镜像缺 docx 依赖 → 内置模板生不出」。缺失才回退现场 _build_*_docx（兜底）。"""
    return os.path.join(project_root(), "dicts", "report_templates")

# 固定内置模板 ID（字符串 _id；_oid() 遇非法 ObjectId 原样返回，find_one/_tpl_root 均兼容）
BUILTIN_SESSION_ID = "builtin_session_v1"
BUILTIN_TASK_ID = "builtin_task_v1"
BUILTIN_FINDING_ID = "builtin_finding_v1"   # 单漏洞级（在会话级基础上精简：单条漏洞、无清单表/统计图）
BUILTIN_IDS = (BUILTIN_SESSION_ID, BUILTIN_TASK_ID, BUILTIN_FINDING_ID, "ncc_event_finding_v1")

_BUILTIN_VERSION = 3   # 结构版本；调整内置模板结构时 +1，force 重播覆盖（v2：新增漏洞级 builtin_finding_v1；v3：证据截图位改 {%p for shot in item.shots%} 循环，生成时嵌入人工上传截图）


def _now() -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ========== docx 构造小工具（模板侧直接写 docxtpl 标签）==========

def _kv(doc, key: str, value: str) -> None:
    """键值段落：粗体键 + 值（值可含 {{ 占位符 }}）。"""
    p = doc.add_paragraph()
    r = p.add_run(key + "："); r.bold = True
    p.add_run(value)


def _code_block(doc, text: str) -> None:
    """等宽代码块（承载请求/响应包、payload）。text 可为 {{ 占位符 }}。"""
    from docx.shared import Pt
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.font.name = "Consolas"
    r.font.size = Pt(9)


def _finding_table(doc):
    """漏洞清单表：序号|漏洞名称|目标|危害等级，数据行用 {%tr%} 行循环包裹。
    返回后由调用方决定循环变量（会话级 findings / 任务级 sys.findings）。"""
    t = doc.add_table(rows=2, cols=4)
    t.style = "Table Grid"
    hdr = t.rows[0].cells
    hdr[0].text, hdr[1].text, hdr[2].text, hdr[3].text = "序号", "漏洞名称", "目标", "危害等级"
    return t


def _fill_loop_row(table, loop_var: str) -> None:
    """把 table 第 1 行（data_row=1）填成 {{ item.* }} 占位并用 {%tr%} 行循环包裹。
    loop_var = 'findings' 或 'sys.findings'。docxtpl 的 {%tr%} for/endfor 各占独立一行。"""
    cells = table.rows[1].cells
    cells[0].text = "{{ item.seq }}"
    cells[1].text = "{{ item.vuln_type }}"
    cells[2].text = "{{ item.target }}"
    cells[3].text = "{{ item.severity_cn }}"
    _insert_tag_row(table, 1, "{%%tr for item in %s %%}" % loop_var, before=True)
    _insert_tag_row(table, 2, "{%tr endfor %}", before=False)


def _insert_tag_row(tbl, ref_row_idx: int, tag: str, before: bool) -> None:
    """在 tbl ref_row_idx 行前/后插整行，首单元格放 docxtpl 行循环标签（复刻 report_template._insert_tag_row）。"""
    new_row = tbl.add_row()
    new_row.cells[0].text = tag
    tr = new_row._tr
    tr.getparent().remove(tr)
    ref_tr = tbl.rows[ref_row_idx]._tr
    if before:
        ref_tr.addprevious(tr)
    else:
        ref_tr.addnext(tr)


def _finding_details_block(doc, loop_var: str) -> None:
    """逐条漏洞详情块（段落级 {%p%} 循环）：目标/等级/危害/验证/POC(请求响应)/证据/加固。
    loop_var = 'findings' 或 'sys.findings'。用 {%p for%}/{%p endfor%} 段落循环
    （docxtpl 段落块循环，标签独占段落，循环体内 {{ item.* }} 每条漏洞重复渲染）。"""
    doc.add_paragraph("{%%p for item in %s %%}" % loop_var)
    # 小标题（漏洞名，Heading 3）
    h = doc.add_paragraph("{{ item.seq }}. {{ item.vuln_type }}")
    try:
        h.style = doc.styles["Heading 3"]
    except Exception:
        pass
    _kv(doc, "目标", "{{ item.target }}")
    _kv(doc, "危害等级", "{{ item.severity_cn }}（CVSS {{ item.cvss_score }}）")
    _kv(doc, "危害描述", "{{ item.impact }}")
    _kv(doc, "验证方式", "{{ item.verify_method }}")
    # —— POC（复现验证材料）——
    pp = doc.add_paragraph(); pr = pp.add_run("POC / 复现："); pr.bold = True
    _code_block(doc, "{{ item.poc }}")            # AI 写入的 payload / 请求包 / 关键响应（自由文本）
    doc.add_paragraph("证据（工具原始响应）：")
    _code_block(doc, "{{ item.evidence }}")       # match_evidence 归集的真实响应体
    doc.add_paragraph("证据截图：")
    # 人工上传、按 finding_id 绑定的证据截图 → generate_from_template 注入 item.shots(InlineImage)。
    # 段落级 {%p%} 循环嵌在外层 {%p for item in findings%} 内（无截图则整段不渲染）。
    doc.add_paragraph("{%p for shot in item.shots %}")
    doc.add_paragraph("{{ shot }}")
    doc.add_paragraph("{%p endfor %}")
    doc.add_paragraph("{%p endfor %}")


# ========== schema（等价于「学习产出」的结构判定，手工冻结）==========

def _builtin_schema() -> Dict[str, Any]:
    """内置模板 schema：只声明 scalars（report.* 单值）+ images（严重度饼图位）。
    stat.*/findings/systems 循环由 generate_from_template 直接注入 ctx，无需 schema 声明。
    placeholder 名与模板里写死的 {{ }} 变量名严格一致（生成时 ctx[ph]=scalar_vals[semantic]）。"""
    return {
        "version": 1,
        "scalars": [
            {"idx": "builtin", "placeholder": "report_title", "semantic": "report.title", "sample_text": ""},
            {"idx": "builtin", "placeholder": "report_unit", "semantic": "report.unit", "sample_text": ""},
            {"idx": "builtin", "placeholder": "report_period", "semantic": "report.period", "sample_text": ""},
            {"idx": "builtin", "placeholder": "report_system", "semantic": "report.system_name", "sample_text": ""},
            {"idx": "builtin", "placeholder": "report_summary", "semantic": "report.summary", "sample_text": ""},
        ],
        "loops": [],   # 循环由模板内 {%tr%}/{%p%} 标签承载，不经 schema 注入
        "images": [
            {"idx": "builtin", "placeholder": "chart_severity", "semantic": "chart.severity_dist", "sample_text": ""},
        ],
        "fixed_kept": [],
    }


# ========== 会话级模板（单系统）==========

def _build_session_docx(path: str) -> None:
    """会话级模板：单业务系统，直接一个漏洞清单 + 逐条详情（含 POC）。写 template.docx。"""
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    doc = Document()
    t = doc.add_heading("{{ report_title }}", level=0)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_heading("一、概述", 1)
    _kv(doc, "受测单位", "{{ report_unit }}")
    _kv(doc, "系统名称", "{{ report_system }}")
    _kv(doc, "测试时间", "{{ report_period }}")
    doc.add_paragraph("{{ report_summary }}")
    doc.add_paragraph("本报告针对单个业务系统（会话级）开展渗透测试，记录发现的安全问题、验证证据与加固建议。")
    doc.add_heading("二、漏洞统计", 1)
    doc.add_paragraph("本次共发现漏洞 {{ stat.total }} 个：严重 {{ stat.critical }} 个、高危 {{ stat.high }} 个、"
                      "中危 {{ stat.medium }} 个、低危 {{ stat.low }} 个、信息 {{ stat.info }} 个。")
    doc.add_paragraph("{{ chart_severity }}")   # 严重度分布饼图位
    doc.add_heading("三、漏洞清单", 1)
    tbl = _finding_table(doc)
    _fill_loop_row(tbl, "findings")
    doc.add_heading("四、漏洞详情", 1)
    _finding_details_block(doc, "findings")
    doc.add_heading("五、总体加固建议", 1)
    doc.add_paragraph("1. 全站输入统一做校验与输出编码；2. 所有接口强制身份与权限校验；"
                      "3. 前端不得硬编码密钥；4. 补齐安全响应头（CSP/X-Frame-Options 等）。")
    doc.save(path)


# ========== 单漏洞级模板（会话级精简：单条漏洞，无清单表/统计图）==========

def _build_finding_docx(path: str) -> None:
    """单漏洞级模板：只针对一个漏洞出报告。在会话级基础上精简——去掉漏洞统计、
    严重度饼图、漏洞清单表，只保留概述 + 单条漏洞详情（含 POC）+ 加固建议。
    仍复用 findings 段落循环（{%p for item in findings%}）——生成时 findings 只含 1 条，
    故与会话级模板同一套 ctx 注入，schema 也复用 _builtin_schema。写 template.docx。"""
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    doc = Document()
    t = doc.add_heading("{{ report_title }}", level=0)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_heading("一、概述", 1)
    _kv(doc, "受测单位", "{{ report_unit }}")
    _kv(doc, "系统名称", "{{ report_system }}")
    _kv(doc, "测试时间", "{{ report_period }}")
    doc.add_paragraph("{{ report_summary }}")
    doc.add_paragraph("本报告针对单个漏洞出具，记录该漏洞的验证证据、危害与加固建议。")
    doc.add_heading("二、漏洞详情", 1)
    _finding_details_block(doc, "findings")   # findings 只含 1 条 → 单漏洞详情
    doc.add_heading("三、加固建议", 1)
    doc.add_paragraph("针对本漏洞按验证方式定位根因并修复；修复后复测验证；"
                      "举一反三排查同类接口/参数是否存在相同问题。")
    doc.save(path)


# ========== 任务级模板（多系统，多一级「分系统」目录）==========

def _build_task_docx(path: str) -> None:
    """任务级模板：会话级 + 多一级「分系统」目录——漏洞部分按系统分组（{%p for sys in systems%}
    外层段落循环，组内各自漏洞清单表 + 详情）。写 template.docx。"""
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    doc = Document()
    t = doc.add_heading("{{ report_title }}", level=0)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_heading("一、概述", 1)
    _kv(doc, "受测单位", "{{ report_unit }}")
    _kv(doc, "测试时间", "{{ report_period }}")
    doc.add_paragraph("{{ report_summary }}")
    doc.add_paragraph("本报告针对该单位整体资产（任务级）开展安全评估，覆盖多个业务系统，"
                      "按系统分别列出漏洞与加固建议。")
    doc.add_heading("二、总体漏洞统计", 1)
    doc.add_paragraph("本次共发现漏洞 {{ stat.total }} 个：严重 {{ stat.critical }} 个、高危 {{ stat.high }} 个、"
                      "中危 {{ stat.medium }} 个、低危 {{ stat.low }} 个、信息 {{ stat.info }} 个。")
    doc.add_paragraph("{{ chart_severity }}")
    doc.add_paragraph("本次评估共覆盖 {{ systems | length }} 个业务系统。")
    doc.add_heading("三、分系统漏洞情况", 1)   # ← 多一级目录：任务级比会话级多的这一层
    # 外层按系统循环（段落块循环）
    doc.add_paragraph("{%p for sys in systems %}")
    sh = doc.add_paragraph("{{ loop.index }}. {{ sys.name }}")
    try:
        sh.style = doc.styles["Heading 2"]
    except Exception:
        pass
    doc.add_paragraph("本系统发现漏洞 {{ sys.stat.total }} 个（严重 {{ sys.stat.critical }} / 高危 {{ sys.stat.high }} / "
                      "中危 {{ sys.stat.medium }} / 低危 {{ sys.stat.low }} / 信息 {{ sys.stat.info }}）。")
    doc.add_paragraph("漏洞清单：")
    tbl = _finding_table(doc)
    _fill_loop_row(tbl, "sys.findings")
    doc.add_paragraph("漏洞详情：")
    _finding_details_block(doc, "sys.findings")
    doc.add_paragraph("{%p endfor %}")
    doc.add_heading("四、总体加固建议", 1)
    doc.add_paragraph("按系统优先级修复高危项；统一鉴权与输入校验规范；建立密钥集中管理；定期复测验证修复效果。")
    doc.save(path)


# ========== 样本数据（供 origin.docx 复核对比渲染）==========

def _sample_findings() -> List[Dict[str, Any]]:
    """示例漏洞（字段对齐 generate_from_template 注入的 finding dict）。poc 内含请求/关键响应
    （复刻真实数据模型：AI 把 payload/请求/响应写进单一 poc 自由文本）。"""
    return [
        {"seq": 1, "vuln_type": "SQL 注入", "target": "https://oa.example.gov.cn/login?id=1",
         "severity_cn": "高危", "cvss_score": "8.6",
         "impact": "登录接口 id 参数存在报错型 SQL 注入，可读取数据库任意表，泄露用户口令散列。",
         "verify_method": "sqlmap 手工验证 + 延时盲注确认",
         "poc": ("payload：id=1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -\n"
                 "请求：GET /login?id=1'%20AND%20(SELECT%20SLEEP(5))-- - HTTP/1.1  Host: oa.example.gov.cn\n"
                 "关键响应：HTTP/1.1 200，X-Response-Time: 5023ms，返回 SQL 语法错误堆栈"),
         "evidence": "响应体返回 You have an error in your SQL syntax；延时 payload 稳定延迟 5.02s，无 payload 时 12ms。"},
        {"seq": 2, "vuln_type": "未授权访问", "target": "https://oa.example.gov.cn/api/admin/userList",
         "severity_cn": "高危", "cvss_score": "7.5",
         "impact": "后台用户列表接口未校验身份，匿名可拉取全量用户姓名/手机号/部门。",
         "verify_method": "匿名请求直接返回敏感数据",
         "poc": ("请求：GET /api/admin/userList?page=1&size=1000 HTTP/1.1  Host: oa.example.gov.cn\n"
                 "关键响应：HTTP/1.1 200，{\"total\":328,\"data\":[{\"name\":\"张三\",\"phone\":\"138****0001\"}...]}"),
         "evidence": "响应含 328 条用户记录，字段包括 phone/idcard 明文。"},
        {"seq": 3, "vuln_type": "敏感信息泄露", "target": "https://oa.example.gov.cn/js/app.config.js",
         "severity_cn": "中危", "cvss_score": "5.3",
         "impact": "前端配置文件硬编码后端 AK/SK 与内网接口地址。",
         "verify_method": "静态分析前端 JS",
         "poc": ("请求：GET /js/app.config.js HTTP/1.1  Host: oa.example.gov.cn\n"
                 "关键响应：window.APP_CONFIG={apiBase:'http://10.10.20.15:8080', secretKey:'AKID****'}"),
         "evidence": "app.config.js 第 12 行含 secretKey 明文与内网 API 地址 10.10.20.15:8080。"},
    ]


def _sample_ctx(scope: str) -> Dict[str, Any]:
    """渲染 origin.docx 用的样本 context（模拟 generate_from_template 的注入）。
    scope: 'task'=多系统分组 / 'finding'=单条漏洞 / 其余(session)=单系统多漏洞。"""
    from collections import Counter
    is_task = (scope == "task")

    def _stat(fs):
        c = Counter(f["severity_cn"] for f in fs)
        return {"total": len(fs), "critical": c.get("严重", 0), "high": c.get("高危", 0),
                "medium": c.get("中危", 0), "low": c.get("低危", 0), "info": c.get("信息", 0)}

    fs = _sample_findings()
    if scope == "finding":
        fs = fs[:1]   # 单漏洞样本：只取一条
    ctx: Dict[str, Any] = {
        "report_title": "示例单位 渗透测试报告",
        "report_unit": "示例单位（样本占位，生成时自动替换为真实单位）",
        "report_period": _now()[:10],
        "report_system": "OA 办公系统",
        "report_summary": "本次测试共发现漏洞 {} 个。".format(len(fs)),
        "chart_severity": "【严重度分布饼图】",
        "findings": fs, "stat": _stat(fs),
    }
    if is_task:
        # 任务级样本：拆两个系统体现「多一级目录」
        g1 = [dict(f) for f in fs]
        g2 = [{"seq": 1, "vuln_type": "反射型 XSS", "target": "https://www.example.gov.cn/search?kw=x",
               "severity_cn": "中危", "cvss_score": "6.1",
               "impact": "搜索关键词未过滤，反射到页面执行任意 JS。",
               "verify_method": "浏览器手工验证",
               "poc": "payload：kw=<script>alert(document.cookie)</script>\n关键响应：响应原样回显 script 标签并执行",
               "evidence": "响应原样回显 script 标签并弹出会话 cookie。"}]
        ctx["systems"] = [
            {"name": "OA 办公系统", "findings": g1, "stat": _stat(g1)},
            {"name": "门户网站", "findings": g2, "stat": _stat(g2)},
        ]
        allf = g1 + g2
        ctx["findings"] = allf
        ctx["stat"] = _stat(allf)
        ctx["report_title"] = "示例单位 安全评估报告"
        ctx["report_summary"] = "本次评估共发现漏洞 {} 个。".format(len(allf))
    elif scope == "finding":
        ctx["report_title"] = "{} 漏洞报告".format(fs[0]["vuln_type"])
        ctx["report_summary"] = "本报告针对「{}」单个漏洞出具。".format(fs[0]["vuln_type"])
    # 证据截图样本位（内置模板 v3 起有 {%p for shot in item.shots%} 循环，样本/自检渲染需该键存在，空列表即不渲染图）
    for _f in ctx.get("findings", []):
        _f.setdefault("shots", [])
    for _sys in ctx.get("systems", []):
        for _f in _sys.get("findings", []):
            _f.setdefault("shots", [])
    return ctx


def _build_origin_docx(template_path: str, origin_path: str, scope: str) -> None:
    """用样本 context 渲染 template.docx → origin.docx（真实数据填充后的排版，供复核左右对比）。
    scope: 'task'/'finding'/其余(session)——透传给 _sample_ctx 选样本形态。"""
    from docxtpl import DocxTemplate
    tpl = DocxTemplate(template_path)
    tpl.render(_sample_ctx(scope), autoescape=True)   # 与生成一致，POC 里的 < > & 不丢
    tpl.save(origin_path)


# ========== 播种入口（bootstrap 幂等调用）==========

def _tpl_root(tid: str) -> str:
    return os.path.join(template_dir(), str(tid))


_DEFS = [
    {"id": BUILTIN_SESSION_ID, "name": "内置默认模板·会话级（单系统，携带 POC）",
     "scope": "session", "is_task": False,
     "source_filename": "builtin_session.docx",
     # 预生成分发文件名（dicts/report_templates/ 下）；缺失回退现场生成
     "prebuilt_template": "builtin_session.docx", "prebuilt_origin": "builtin_session_origin.docx"},
    {"id": BUILTIN_TASK_ID, "name": "内置默认模板·任务级（多系统分组，携带 POC）",
     "scope": "task", "is_task": True,
     "source_filename": "builtin_task.docx",
     "prebuilt_template": "builtin_task.docx", "prebuilt_origin": "builtin_task_origin.docx"},
    {"id": BUILTIN_FINDING_ID, "name": "内置默认模板·漏洞级（单个漏洞，携带 POC）",
     "scope": "finding", "is_task": False,
     "source_filename": "builtin_finding.docx",
     "prebuilt_template": "builtin_finding.docx", "prebuilt_origin": "builtin_finding_origin.docx"},
]


def _build_one(d: Dict[str, Any]) -> Dict[str, Any]:
    """构造单个内置模板的磁盘产物（template.docx + origin.docx）并返回落库 doc。
    失败抛异常由调用方捕获（单个失败不阻断另一个）。"""
    tid = d["id"]
    root = _tpl_root(tid)
    os.makedirs(root, exist_ok=True)
    template_dst = os.path.join(root, "template.docx")
    origin_dst = os.path.join(root, "origin.docx")
    # v1.21.159：优先拷贝分发的预生成 docx（dicts/report_templates/），不依赖本地 python-docx。
    # 治「存量镜像缺 docx 依赖 → 现场 _build_*_docx import docx 失败 → 内置模板生不出」。
    pre = _prebuilt_dir()
    pre_tpl = os.path.join(pre, d.get("prebuilt_template", ""))
    pre_ori = os.path.join(pre, d.get("prebuilt_origin", ""))
    if os.path.isfile(pre_tpl):
        shutil.copyfile(pre_tpl, template_dst)
        if os.path.isfile(pre_ori):
            shutil.copyfile(pre_ori, origin_dst)
        else:
            _build_origin_docx(template_dst, origin_dst, d.get("scope", ""))   # 预生成缺 origin → 现场补
    else:
        # 兜底：预生成文件缺失（未分发到位）→ 现场用 python-docx 构造（需本地装 docx）
        scope = d.get("scope", "")
        if scope == "task":
            _build_task_docx(template_dst)
        elif scope == "finding":
            _build_finding_docx(template_dst)
        else:
            _build_session_docx(template_dst)
        _build_origin_docx(template_dst, origin_dst, scope)
    now = _now()
    rel = lambda p: os.path.relpath(p, template_dir()).replace("\\", "/")
    return {
        "_id": tid, "name": d["name"], "status": "ready",
        "scope": d["scope"], "builtin": True, "builtin_version": _BUILTIN_VERSION,
        "source_filename": d["source_filename"], "schema": _builtin_schema(),
        "learn_tokens": 0, "learn_error": "", "refine_count": 0,
        "learn_phase": "内置", "learn_progress": 100,
        "learn_provider_id": "", "learn_provider_name": "内置（无需学习）",
        "need_review": False, "created_by": "system",
        "template_path": rel(template_dst), "origin_path": rel(origin_dst),
        "save_date": now, "update_date": now,
    }


def seed_builtin_templates(force: bool = False) -> int:
    """播种内置默认模板（会话级 / 任务级）。幂等：
      - 库里已存在且 builtin_version 不低于当前 → 跳过（保留用户可能的改名等）；
      - force=True 或 版本更旧 → 用代码最新版覆盖（重建 docx + 覆盖 doc）。
    返回本次实际播种/更新的条数。纯磁盘+mongo 写，不触发 gunicorn --reload（安全）。"""
    from sentinel_platform.modules.risk_intel.report_template import repo_coll
    coll = repo_coll()
    seeded = 0
    for d in _DEFS:
        tid = d["id"]
        try:
            existing = coll.find_one({"_id": tid})
            need = force or (existing is None) or \
                int((existing or {}).get("builtin_version", 0) or 0) < _BUILTIN_VERSION
            # 磁盘产物缺失也需重建（存量库有 doc 但目录被清）
            if existing and not need:
                tpath = os.path.join(template_dir(), (existing.get("template_path") or ""))
                if not os.path.isfile(tpath):
                    need = True
            if not need:
                continue
            doc = _build_one(d)
            coll.update_one({"_id": tid}, {"$set": doc}, upsert=True)
            seeded += 1
        except Exception as exc:
            logger.warning("seed_builtin_templates %s failed: %s", tid, exc)
    try:
        from .report_template_ncc import seed
        seeded += seed(force=force)
    except Exception as exc:
        logger.warning("seed NCC template failed: %s", exc)
    return seeded
