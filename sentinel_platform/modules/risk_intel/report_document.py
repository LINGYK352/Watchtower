"""Editable report snapshots and evidence image layout (no network or database IO)."""
from __future__ import annotations

import copy
import io
import math
import os
import re
from typing import Any, Dict

REPORT_FIELDS = ("title", "unit", "system_name", "period", "summary")
FINDING_FIELDS = (
    "vuln_type", "target", "severity", "severity_cn", "cvss_score", "impact",
    "poc", "evidence", "verify_method", "verification_status", "poc_notes",
    "discovered_at", "affected_ip", "version", "test_environment",
    "discovery_context", "affected_users", "affected_data", "quantification",
    "trigger_path", "root_cause", "remediation", "hardening", "fix_validation", "notes",
)
SHOT_SECTIONS = ("icp", "steps", "evidence")


def safe_component(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("无效的漏洞或截图标识")
    return value


def normalize_image(raw: bytes) -> bytes:
    """Decode at upload time; Word accepts the resulting PNG, including WebP input."""
    from PIL import Image, ImageOps
    if not raw or len(raw) > 20 * 1024 * 1024:
        raise ValueError("截图不能为空且不得超过 20 MB")
    try:
        with Image.open(io.BytesIO(raw)) as image:
            if image.width * image.height > 40_000_000:
                raise ValueError("截图像素过大，请分段上传")
            image.seek(0)
            image = ImageOps.exif_transpose(image)
            image.load()
            normalized = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            buf = io.BytesIO()
            normalized.save(buf, format="PNG")
            return buf.getvalue()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("无法读取截图，请上传有效图片") from exc


def validate_edit(current: Dict[str, Any], submitted: Any) -> Dict[str, Any]:
    """Only editable text/layout changes; retain finding identity and source binding."""
    if not isinstance(submitted, dict) or not isinstance(submitted.get("report"), dict):
        raise ValueError("报告编辑数据格式错误")
    result = copy.deepcopy(current)
    def text(value):
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            raise ValueError("报告字段必须是文本")
        value = str(value)
        if len(value) > 200000:
            raise ValueError("单个报告字段过长")
        return value
    for key in REPORT_FIELDS:
        if key in submitted["report"]:
            result["report"][key] = text(submitted["report"][key])
    edits = submitted.get("findings")
    originals = result.get("findings", [])
    if not isinstance(edits, list) or len(edits) != len(originals):
        raise ValueError("不能通过报告编辑增删或替换来源漏洞")
    for original, edit in zip(originals, edits):
        if not isinstance(edit, dict) or edit.get("finding_id") != original.get("finding_id"):
            raise ValueError("报告来源漏洞不匹配")
        for key in FINDING_FIELDS:
            if key in edit:
                original[key] = text(edit[key])
        steps = edit.get("reproduction_steps", original.get("reproduction_steps", []))
        if not isinstance(steps, list) or len(steps) > 100:
            raise ValueError("复现步骤格式错误或超过 100 步")
        if any(not isinstance(step, dict) for step in steps):
            raise ValueError("复现步骤格式错误")
        original["reproduction_steps"] = [{"text": text(step.get("text", ""))} for step in steps]
        shots = edit.get("screenshots", original.get("screenshots", []))
        if not isinstance(shots, list) or len(shots) > 100:
            raise ValueError("截图格式错误或超过 100 张")
        normalized = []
        seen = set()
        for shot in shots:
            if not isinstance(shot, dict):
                raise ValueError("截图格式错误")
            name = shot.get("name", "")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+\.(?:png|jpg|jpeg|gif|webp)", name, re.I):
                raise ValueError("无效的截图文件名")
            if name in seen:
                raise ValueError("报告中同一截图不能重复添加")
            seen.add(name)
            section = shot.get("section", "evidence")
            if section not in SHOT_SECTIONS:
                raise ValueError("截图位置无效")
            step = shot.get("step", 1)
            if isinstance(step, bool) or not isinstance(step, int) or step < 1:
                raise ValueError("截图对应步骤必须是正整数")
            if section == "steps" and step > len(steps):
                raise ValueError("截图对应的复现步骤不存在")
            width = shot.get("width_percent", 100)
            if isinstance(width, bool) or not isinstance(width, (int, float)) or not 10 <= width <= 100:
                raise ValueError("截图宽度须为正文宽度的 10% 到 100%")
            normalized.append({"name": name, "caption": text(shot.get("caption", "")),
                               "section": section, "step": step, "width_percent": width})
        original["screenshots"] = normalized
    return result


def _inline_parts(tpl, path, width_mm, height_mm, caption):
    """Keep aspect ratio and all pixels; split tall captures instead of tiny scaling."""
    from PIL import Image
    from docxtpl import InlineImage
    from docx.shared import Mm
    with open(path, "rb") as stream:
        data = normalize_image(stream.read())
    with Image.open(io.BytesIO(data)) as image:
        width = min(width_mm, image.width * 25.4 / 96)
        rows = max(1, int(height_mm * image.width / width))
        count = int(math.ceil(image.height / rows))
        output = []
        for index in range(count):
            piece = image.crop((0, index * rows, image.width, min((index + 1) * rows, image.height)))
            buf = io.BytesIO()
            piece.save(buf, format="PNG")
            buf.seek(0)
            label = caption or ""
            if count > 1:
                label += "（第 {}/{} 段）".format(index + 1, count)
            output.append({"image": InlineImage(tpl, buf, width=Mm(width)), "caption": label})
        return output


def render(template_path: str, data: Dict[str, Any], schema: Dict[str, Any],
           output_path: str, image_root: str, charts=None) -> None:
    from docxtpl import DocxTemplate
    tpl = DocxTemplate(template_path)
    doc = tpl.get_docx()
    width = min((s.page_width - s.left_margin - s.right_margin) / 36000 for s in doc.sections)
    height = min((s.page_height - s.top_margin - s.bottom_margin) / 36000 for s in doc.sections) - 18
    findings = copy.deepcopy(data.get("findings", []))
    for finding in findings:
        finding.update(shots=[], icp_shots=[], evidence_shots=[])
        steps = finding.setdefault("reproduction_steps", [])
        for step in steps:
            step["shots"] = []
        fid = safe_component(finding["finding_id"])
        base = os.path.realpath(os.path.join(image_root, "finding_" + fid))
        for shot in finding.get("screenshots", []):
            path = os.path.realpath(os.path.join(base, shot["name"]))
            if os.path.commonpath([base, path]) != base or not os.path.isfile(path):
                raise ValueError("证据截图缺失或路径无效：{}".format(shot["name"]))
            try:
                parts = _inline_parts(tpl, path, width * shot.get("width_percent", 100) / 100,
                                      height, shot.get("caption", ""))
            except Exception as exc:
                raise ValueError("证据截图无法嵌入：{}；{}".format(shot["name"], exc)) from exc
            finding["shots"].extend(part["image"] for part in parts)
            section = shot.get("section", "evidence")
            if section == "icp":
                finding["icp_shots"].extend(parts)
            elif section == "steps" and 0 < shot.get("step", 1) <= len(steps):
                steps[shot.get("step", 1) - 1]["shots"].extend(parts)
            else:
                finding["evidence_shots"].extend(parts)
    from .report_template import _severity_stat, _group_findings_by_system
    report = data["report"]
    stat = _severity_stat(findings)
    ctx = {"findings": findings, "stat": stat,
           "systems": _group_findings_by_system(data.get("source", "finding"), findings,
                                               report.get("system_name", ""))}
    values = {"report." + k: v for k, v in report.items()}
    values.update({"stat." + k: v for k, v in stat.items()})
    for scalar in schema.get("scalars", []):
        ctx[scalar["placeholder"]] = values.get(scalar.get("semantic", ""),
                                               data.get("variables", {}).get(scalar["placeholder"], ""))
    # NCC has a stable named contract independent of learned schema aliases.
    ctx.update({"report_" + k: v for k, v in report.items()})
    ctx["report_system"] = report.get("system_name", "")
    for placeholder, path in (charts or {}).items():
        from docxtpl import InlineImage
        from docx.shared import Mm
        ctx[placeholder] = InlineImage(tpl, path, width=Mm(min(120, width))) if path else ""
    tpl.render(ctx, autoescape=True)
    tpl.save(output_path)
