"""Automatic report evidence: immutable browser captures and recorded HTTP diagrams.

No request replay. Packet diagrams are explicitly labelled reconstructions of saved
tool records, not screenshots of Burp or proof of a newly performed test.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
from urllib.parse import urlsplit, urlunsplit


def _object(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            result = json.loads(value)
            return result if isinstance(result, dict) else {}
        except ValueError:
            return {}
    return {}


def _font(size):
    from PIL import ImageFont
    for path in ("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/simsun.ttc",
                 "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                 "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"):
        if os.path.isfile(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap(draw, text, font, width):
    lines = []
    for raw in str(text).expandtabs(4).splitlines() or [""]:
        line = ""
        for ch in raw:
            if line and draw.textlength(line + ch, font=font) > width:
                lines.append(line); line = ""
            line += ch
        lines.append(line)
    return lines


def _headers(headers):
    if not isinstance(headers, dict):
        return "[请求头/响应头未记录]"
    return "\n".join("{}: {}".format(k, "[已遮盖]" if str(k).lower() in
        ("authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization") else v)
        for k, v in headers.items())


def packet_images(record):
    """Render exact saved request inputs and response excerpts, with a visible origin label."""
    from PIL import Image, ImageDraw
    args = _object(record.get("arguments"))
    response = _object(record.get("result"))
    prepared = _object(response.get("request_meta"))
    url = prepared.get("url") or args.get("url") or args.get("target") or ""
    status = response.get("status_code")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")) or not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        return []
    method = str(prepared.get("method") or args.get("method") or "GET").upper()
    request_body = prepared.get("body", "") if prepared else args.get("body", "")
    if not isinstance(request_body, str):
        request_body = json.dumps(request_body, ensure_ascii=False, indent=2)
    request = method + " " + str(prepared.get("path") or url) + " " + str(response.get("http_version") or "")
    request += "\n\n" + _headers(prepared.get("headers") if prepared else args.get("headers")) + "\n\n" + request_body
    body = response.get("body", "")
    if not isinstance(body, str):
        body = json.dumps(body, ensure_ascii=False, indent=2)
    response_text = "记录的状态码: {}\n{}\n\n{}".format(status, _headers(response.get("headers")), body)
    font, title_font = _font(25), _font(30)
    measure = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    request_lines = _wrap(measure, request, font, 730)
    response_lines = _wrap(measure, response_text, font, 730)
    # Pictures show readable excerpts; original evidence remains intact in the document snapshot.
    limit = 32
    pages = min(4, max(1, (max(len(request_lines), len(response_lines)) + limit - 1) // limit))
    digest = hashlib.sha256(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
    output = []
    for part in range(pages):
        left = request_lines[part * limit:(part + 1) * limit]
        right = response_lines[part * limit:(part + 1) * limit]
        height = 205 + max(len(left), len(right), 4) * 35
        image = Image.new("RGB", (1600, height), "white")
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, 1600, 54), fill="#28323c")
        draw.text((20, 8), "HTTP 交互记录可视化 · 保存数据重建 · 非 Burp 现场截图", font=title_font, fill="white")
        for x, label in ((18, "已留存请求 / Request" if prepared else "请求输入参数（非实际报文记录）"), (814, "响应记录 / Response")):
            draw.rectangle((x, 65, x + 766, 107), fill="#f0f2f5")
            draw.text((x + 12, 70), label, font=font, fill="#222222")
        draw.line((799, 65, 799, height - 40), fill="#d0d0d0", width=2)
        for x, lines in ((28, left), (824, right)):
            for index, line in enumerate(lines):
                draw.text((x, 116 + index * 35), line, font=font, fill="#202830")
        limited = response.get("partial") or response.get("truncated") or record.get("partial") or record.get("truncated") or prepared.get("truncated")
        more = max(len(request_lines), len(response_lines)) > pages * limit
        footer = "{}  |  证据 {}  |  图 {}/{}  |  认证头已遮盖".format(
            "留存片段/节选" if limited or more or pages > 1 else "基于已保存记录", digest[:12], part + 1, pages)
        url_lines = _wrap(draw, "URL: " + url, _font(20), 1540)
        draw.text((20, height - 65), url_lines[0] + ("…" if len(url_lines) > 1 else ""), font=_font(20), fill="#666666")
        draw.text((20, height - 36), footer, font=_font(20), fill="#666666")
        buf = io.BytesIO(); image.save(buf, format="PNG")
        output.append((buf.getvalue(), digest, part + 1))
    return output


def _store(fid, data, provenance):
    import time
    from .report_template import _finding_shots_dir
    from .report_document import normalize_image
    normalized = normalize_image(data)
    digest = hashlib.sha256(normalized).hexdigest()
    identity = hashlib.sha256((digest + str(provenance.get("source_url", "")) + str(provenance.get("kind", ""))).encode()).hexdigest()
    name = "auto_{}.png".format(identity[:24])
    root = _finding_shots_dir(fid)
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, name)
    if not os.path.isfile(path):
        with open(path, "wb") as stream: stream.write(normalized)
    meta = dict(provenance, name=name, image_sha256=digest,
                stored_at=time.strftime("%Y-%m-%d %H:%M:%S"))
    with open(path + ".json", "w", encoding="utf-8") as stream:
        json.dump(meta, stream, ensure_ascii=False, indent=2)
    return meta


def archive_session_shot(session_id, state, kind="browser_capture"):
    """Preserve action-time pixels before latest.png is overwritten or the browser closes."""
    import time
    from sentinel_platform.core import image_dir
    from .report_document import safe_component, normalize_image
    safe_component(session_id)
    shot = urlsplit(str(state.get("shot") or state.get("screenshot_url") or "")).path
    prefix = "/image/{}_{}/".format("app" if kind == "app_capture" else "console", session_id)
    if not shot.startswith(prefix):
        return ""
    root = os.path.realpath(image_dir())
    source = os.path.realpath(os.path.join(root, shot[len("/image/"):]))
    if os.path.commonpath([root, source]) != root or not os.path.isfile(source):
        return ""
    with open(source, "rb") as stream: data = normalize_image(stream.read())
    url = str(state.get("url") or "")
    digest = hashlib.sha256(data + url.encode()).hexdigest()
    folder = os.path.join(root, "evidence_" + session_id)
    os.makedirs(folder, exist_ok=True)
    name = digest[:24] + ".png"
    path = os.path.join(folder, name)
    if not os.path.isfile(path):
        with open(path, "wb") as stream: stream.write(data)
        with open(path + ".json", "w", encoding="utf-8") as stream:
            json.dump({"kind": kind, "session_id": session_id, "source_url": url,
                       "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"), "image_sha256": hashlib.sha256(data).hexdigest()},
                      stream, ensure_ascii=False)
    return "/image/evidence_{}/{}".format(session_id, name)


def _collect_archived(finding):
    from sentinel_platform.core import get_repo, image_dir
    from sentinel_platform.contracts import Collections
    from .report_template import _oid
    sid = finding.get("session_id")
    if not sid:
        return
    session = get_repo().collection(Collections.PENTEST_SESSION).find_one({"_id": _oid(sid)}) or {}
    origin = urlsplit(finding.get("target", ""))
    candidates = []
    for entry in session.get("tool_log", []):
        name = str(entry.get("name") or "")
        if not name.startswith(("browser_", "app_")):
            continue
        result = _object(entry.get("result"))
        shot = urlsplit(str(result.get("report_shot") or "")).path
        if not shot.startswith("/image/evidence_{}/".format(sid)):
            continue
        root = os.path.realpath(image_dir())
        path = os.path.realpath(os.path.join(root, shot[len("/image/"):]))
        if os.path.commonpath([root, path]) != root or not os.path.isfile(path + ".json"):
            continue
        with open(path + ".json", encoding="utf-8") as stream: meta = json.load(stream)
        if meta.get("session_id") != sid:
            continue
        page = urlsplit(meta.get("source_url") or "")
        if (page.scheme, page.netloc) != (origin.scheme, origin.netloc):
            continue
        exact = page.path == origin.path and page.query == origin.query
        candidates.append((path, meta, exact))
    # Exact endpoint captures are evidence candidates; keep only the most recent
    # same-origin context image otherwise, explicitly labelled as system context.
    selected = [c for c in candidates if c[2]] or candidates[-1:]
    for path, meta, exact in selected:
        with open(path, "rb") as stream: data = stream.read()
        if hashlib.sha256(data).hexdigest() != meta.get("image_sha256"):
            continue
        _store(finding["finding_id"], data, dict(meta, section="steps", step=1,
            caption="{}截图 · {}{}".format("应用" if meta["kind"] == "app_capture" else "页面",
                meta.get("captured_at", "时间未记录"), "" if exact else "（系统上下文，不单独作为漏洞结果证明）")))


def capture_browser(finding_id, session_id, target):
    """Capture only an already-open, same-origin session page; never navigate or replay."""
    from sentinel_platform.modules.ai_pentest import _browser_session
    from sentinel_platform.core import image_dir
    from .report_document import safe_component
    if not session_id:
        return None
    safe_component(session_id)
    # This is invoked where the finding is recorded, while the owning worker is live.
    worker = _browser_session._worker_for(session_id)
    if worker is None:
        return None
    state = worker.call("screenshot", {})
    page_url = str(state.get("url") or "")
    source, expected = urlsplit(page_url), urlsplit(target)
    if (source.scheme, source.netloc) != (expected.scheme, expected.netloc):
        return None
    shot = urlsplit(str(state.get("shot") or "")).path
    expected_prefix = "/image/console_{}/".format(session_id)
    if not shot.startswith(expected_prefix):
        return None
    root = os.path.realpath(image_dir())
    path = os.path.realpath(os.path.join(root, shot[len("/image/"):]))
    if os.path.commonpath([root, path]) != root or not os.path.isfile(path):
        return None
    with open(path, "rb") as stream: raw = stream.read()
    exact = urlunsplit(source._replace(fragment="")) == urlunsplit(expected._replace(fragment=""))
    return _store(finding_id, raw, {"kind": "browser_capture", "source_url": page_url,
        "session_id": session_id, "section": "steps", "step": 1,
        "caption": "现有浏览器会话的页面截图：{}{}".format(page_url, "" if exact else "（系统页面，不单独作为漏洞结果证明）")})


def _icp_record(finding):
    """Use existing asset provenance only; do not invent an ICP record from a unit name."""
    from sentinel_platform.core import get_repo
    from sentinel_platform.core.domains import extract_fld
    from sentinel_platform.contracts import Collections
    from PIL import Image, ImageDraw
    host = urlsplit(finding.get("target", "")).hostname or ""
    domain = extract_fld(host)
    if not domain:
        return None
    record = get_repo().collection(Collections.ICP_CACHE).find_one({"domain": domain}) or {}
    if not record.get("source") or not (record.get("unit") or record.get("icp_no")):
        return None
    finding["owner_unit"] = str(record.get("unit") or "")
    lines = ["域名：" + domain, "单位：" + str(record.get("unit") or "未记录"),
             "备案号：" + str(record.get("icp_no") or "未记录"), "数据来源：" + str(record["source"]),
             "原始查询时间：" + str(record.get("update_date") or record.get("save_date") or "未记录")]
    font = _font(28)
    measure = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    lines = _wrap(measure, "\n".join(lines), font, 1400)
    image = Image.new("RGB", (1500, 140 + len(lines) * 48), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 1500, 64), fill="#edf2f7")
    draw.text((28, 12), "主体归属资料 · 已保存查询结果可视化（非官网截图）", font=_font(30), fill="#172b4d")
    for index, line in enumerate(lines):
        draw.text((30, 90 + index * 48), line, font=font, fill="#172b4d")
    buf = io.BytesIO(); image.save(buf, format="PNG")
    return _store(finding["finding_id"], buf.getvalue(), {"kind": "icp_record", "section": "icp", "step": 1,
        "caption": "主体归属查询记录（来源：{}；原始查询时间：{}）".format(record["source"], record.get("update_date") or record.get("save_date") or "未记录"),
        "source_domain": domain, "source_sha256": hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()})


def _site_metadata(finding):
    """Enrich from the same asset's saved recon data, never a fresh DNS guess."""
    import ipaddress
    from sentinel_platform.core import get_repo, image_dir
    from sentinel_platform.contracts import Collections
    target = urlsplit(finding.get("target") or "")
    if target.scheme not in ("http", "https") or not target.hostname:
        return
    if not finding.get("affected_ip"):
        try: finding["affected_ip"] = str(ipaddress.ip_address(target.hostname))
        except ValueError: pass
    base = urlunsplit((target.scheme, target.netloc, "", "", ""))
    candidates = [finding.get("asset_key"), base, base + "/"]
    for candidate in dict.fromkeys(c for c in candidates if c):
        parsed = urlsplit(candidate)
        if parsed.hostname != target.hostname:
            continue
        site = get_repo().collection(Collections.SITE).find_one({"site": candidate}) or {}
        if not site:
            continue
        if not finding.get("affected_ip") and site.get("ip"):
            try: finding["affected_ip"] = str(ipaddress.ip_address(site["ip"]))
            except ValueError: pass
        if not finding.get("system_name") and isinstance(site.get("title"), str):
            finding["system_name"] = site["title"]
        image = site.get("screenshot")
        if not isinstance(image, str) or not image.startswith(("/image/", "/api/image/")):
            break
        image = urlsplit(image).path.split("/image/", 1)[-1]
        root = os.path.realpath(image_dir())
        path = os.path.realpath(os.path.join(root, image))
        if os.path.commonpath([root, path]) == root and os.path.isfile(path):
            with open(path, "rb") as stream: data = stream.read()
            _store(finding["finding_id"], data, {"kind": "site_capture", "source_url": candidate,
                "section": "steps", "step": 1, "caption": "站点发现阶段的页面截图（系统上下文，不单独作为漏洞验证结果）"})
        break


def prepare(finding):
    """Automatically match recorded screenshots and HTTP figures to reproducible steps."""
    from .report_template import list_finding_shots, _finding_shots_dir
    fid = finding["finding_id"]
    root = _finding_shots_dir(fid)
    shots, warnings = [], []
    for collect, label in ((_site_metadata, "资产元数据"), (_collect_archived, "会话截图"), (_icp_record, "主体归属资料")):
        try:
            collect(finding)
        except Exception:
            warnings.append("{}读取失败，未使用不完整资料生成证据图".format(label))
    records = finding.get("evidence_records") or []
    steps = finding.get("reproduction_steps") or []
    if not any(str(s.get("text") or "").strip() for s in steps):
        steps = []
    generated_steps = not steps
    active_records = set()
    for record_index, record in enumerate(records):
        if not isinstance(record, dict) or record.get("tool") != "http_request":
            continue
        args, response = _object(record.get("arguments")), _object(record.get("result"))
        images = packet_images(record)
        if not images:
            warnings.append("一条 HTTP 证据缺少可解析的原始响应，未生成交互图")
            continue
        try:
            from datetime import datetime, timezone, timedelta
            observed = datetime.fromisoformat(str(response.get("observed_at") or "").replace("Z", "+00:00"))
            if observed.tzinfo is None:
                raise ValueError("timezone missing")
            age = datetime.now(timezone.utc) - observed
            if age > timedelta(days=3) or age < -timedelta(minutes=5):
                warnings.append("HTTP 证据的观测时间不在近期有效范围，提交前需要重新核实")
        except ValueError:
            warnings.append("HTTP 证据没有可核实的观测时间，不能自动认定为近期取证")
        prepared = _object(response.get("request_meta"))
        method = str(prepared.get("method") or args.get("method") or "GET").upper()
        url = str(prepared.get("url") or args.get("url") or args.get("target"))
        if generated_steps:
            steps.append({"text": "根据已保存记录，{} {}；响应状态码为 {}，请求与响应见下图。".format(method, url, response["status_code"])})
        step = len(steps) if generated_steps else 1
        for raw, digest, part in images:
            active_records.add(digest)
            _store(fid, raw, {"kind": "http_record", "source_sha256": digest, "source_url": url,
                "section": "steps", "step": step, "source_order": record_index, "part": part,
                "observed_at": response.get("observed_at", ""),
                "caption": "请求/响应交互记录图 {}（原始数据重建，非现场工具截图；观测时间：{}）".format(part, response.get("observed_at") or "原记录未提供")})
    if not steps:
        steps = [{"text": finding.get("verify_method") or "现有记录未提供可复核的复现步骤。"}]
    for shot in list_finding_shots(fid):
        meta = {}
        meta_path = os.path.join(root, shot["name"] + ".json")
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as stream: meta = json.load(stream)
            except (OSError, ValueError):
                warnings.append("一张自动证据图的来源说明不可读")
        if meta.get("kind") == "http_record" and meta.get("source_sha256") not in active_records:
            continue
        if shot["name"].startswith("auto_") and not meta:
            warnings.append("一张自动证据图缺少来源记录，未插入报告")
            continue
        shots.append({"name": shot["name"], "caption": meta.get("caption", ""),
                      "section": meta.get("section", "evidence"),
                      "step": min(len(steps), max(1, int(meta.get("step", 1)))),
                      "provenance": meta})
    shots.sort(key=lambda shot: ({"icp": 0, "steps": 1, "evidence": 2}.get(shot["section"], 2), shot["step"],
        1 if shot["provenance"].get("kind") == "http_record" else 0,
        shot["provenance"].get("source_order", 0), shot["provenance"].get("part", 0), shot["name"]))
    finding["reproduction_steps"] = steps
    finding["screenshots"] = shots
    if not shots:
        warnings.append("未找到该漏洞的可用截图或可重建 HTTP 记录")
    return warnings
