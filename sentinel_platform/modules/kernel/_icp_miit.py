"""kernel/_icp_miit —— 工信部政务平台 ICP 备案官方查询（ext_source 私有辅助）。

直连工信部 hlwicpfwc.miit.gov.cn 官方查询链路，作为 icp_query 多源链的**兜底/校准源**
（第三方测绘 Hunter/FOFA 查不到或需权威校准时补上）。全链路实测跑通（2026-08）：

  ① auth：md5("testtest"+毫秒时间戳) 换 token（有效 5 分钟）
  ② getCheckImagePoint：拿滑块拼图验证码（大图 500x190 + 滑块 70x70 + y 坐标）
  ③ 滑块缺口识别：纯 stdlib（zlib 解 PNG + 颜色量化游程找缺口方块），零新依赖，
     实测 numpy 版算法 15/15、纯 stdlib 解码逐像素与 PIL 一致。识别失败自动重试换新图。
  ④ checkImage {key:uuid, value:缺口x} → 拿 sign（JWT）
  ⑤ queryByCondition/（**末尾斜杠绕创宇盾 WAF**，无斜杠恒 403）带 token+sign → 备案数据

**零新依赖铁律**：只用标准库（hashlib/zlib/struct/base64/json/urllib）——线上容器无 numpy/Pillow，
纯 stdlib 才能走热更触达存量用户（见 [[feedback-fix-must-reach-users-via-hotupdate]]）。
**防腐层**：本文件是官方源对接模块，结构化成 {unit, icp_no, source}，不裸调、不把原始响应入库。
出口固定直连（国内源，走机场节点会被创宇盾拦，对齐 ext_source._intel_proxies 逻辑）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import struct
import time
import uuid
import zlib
import urllib.request
import urllib.parse
import urllib.error
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from sentinel_platform.core import get_logger

logger = get_logger()

_BASE = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36 Edg/101.0.1210.32")
_TIMEOUT = 25
_CAPTCHA_RETRY = 6        # 单次查询内验证码识别重试上限（换新图重试）
_SLIDE_TRY_DX = (0, -2, 2, -4, 4)   # 缺口 x 微调偏移（识别有 ±像素误差，逐个试）

# serviceType：1=网站 web（本平台按域名查主体，固定用 web）
_SERVICE_WEB = 1

# 忽略证书校验（该站证书链在部分环境不完整，且我们只取公开备案数据，非敏感传输）
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

def _post(path: str, form: Optional[Dict[str, Any]] = None, raw: Optional[str] = None,
          headers: Optional[Dict[str, str]] = None) -> str:
    """POST 到官方接口，返回响应文本（失败返回空串，不抛异常）。form=表单编码；raw=原始 body。"""
    body: Optional[bytes] = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
    elif raw is not None:
        body = raw.encode("utf-8")
    h = {"User-Agent": _UA, "Origin": "https://beian.miit.gov.cn",
         "Referer": "https://beian.miit.gov.cn/", "Accept": "application/json, text/plain, */*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(_BASE + path, data=body, headers=h, method="POST")
    try:
        return urllib.request.urlopen(req, timeout=_TIMEOUT, context=_SSL_CTX).read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "ignore")
    except Exception as exc:
        logger.debug("icp_miit POST %s error: %s", path, exc)
        return ""


def _jpost(path: str, want_params: bool = True, **kw) -> Dict[str, Any]:
    """POST 并解析 JSON；want_params 时要求含非空 params（滤瞬时限流空响应）。失败返回 {}。"""
    txt = _post(path, **kw)
    if not txt:
        return {}
    try:
        j = json.loads(txt)
    except Exception:
        return {}
    if want_params and not (j.get("params")):
        return {}
    return j


# ———————— 纯 stdlib PNG 解码（8-bit，支持 RGB/RGBA/灰度/调色板）————————

def _png_decode(b64: str) -> Tuple[int, int, int, int, Optional[bytes], bytearray, int]:
    """解 base64 PNG → (W, H, 通道数, 色彩类型, 调色板, 去滤波后像素字节, 每行字节数 stride)。
    实测逐像素与 PIL 一致。只处理 8-bit（工信部验证码即 8-bit），其他位深不支持。"""
    raw = base64.b64decode(b64)
    i = 8
    idat = b""
    palette = None
    W = H = coltype = None
    while i < len(raw):
        ln = struct.unpack(">I", raw[i:i + 4])[0]
        typ = raw[i + 4:i + 8]
        chunk = raw[i + 8:i + 8 + ln]
        i += 12 + ln
        if typ == b"IHDR":
            W, H, _bitd, coltype = struct.unpack(">IIBB", chunk[:10])
        elif typ == b"PLTE":
            palette = chunk
        elif typ == b"IDAT":
            idat += chunk
        elif typ == b"IEND":
            break
    data = zlib.decompress(idat)
    nch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[coltype]
    stride = W * nch
    out = bytearray()
    prev = bytearray(stride)
    pos = 0
    for _y in range(H):
        ft = data[pos]
        pos += 1
        line = bytearray(data[pos:pos + stride])
        pos += stride
        for x in range(stride):
            a = line[x - nch] if x >= nch else 0
            b = prev[x]
            c = prev[x - nch] if x >= nch else 0
            if ft == 1:
                line[x] = (line[x] + a) & 255
            elif ft == 2:
                line[x] = (line[x] + b) & 255
            elif ft == 3:
                line[x] = (line[x] + ((a + b) >> 1)) & 255
            elif ft == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 255
        out += line
        prev = line
    return W, H, nch, coltype, palette, out, stride


def _png_size(b64: str) -> Tuple[int, int]:
    """只取 PNG 宽高（IHDR），不解码像素。"""
    raw = base64.b64decode(b64)
    return struct.unpack(">II", raw[16:24])


def _slider_offset(small_b64: str, big_b64: str) -> Optional[int]:
    """滑块缺口 x 位移识别（纯 stdlib 复刻 HG-ha 颜色量化算法，实测 numpy 版 15/15）。
    原理：缺口是一块颜色均匀的正方形凹陷。下采样 ::2 + 颜色量化(&~3) → 找 Top-3 高频色中
    宽高比 0.7~1.4 的最大方块，其左边缘 x（×2 还原）即滑块要移动的距离。识别不到返回 None。"""
    try:
        sw, sh = _png_size(small_b64)
        W, H, nch, coltype, palette, out, stride = _png_decode(big_b64)
    except Exception as exc:
        logger.debug("icp_miit slider decode fail: %s", exc)
        return None

    def rgb(x: int, y: int) -> Tuple[int, int, int]:
        o = y * stride + x * nch
        if coltype == 3:                       # 调色板
            idx = out[o]
            return palette[idx * 3], palette[idx * 3 + 1], palette[idx * 3 + 2]
        if coltype in (0, 4):                  # 灰度
            v = out[o]
            return v, v, v
        return out[o], out[o + 1], out[o + 2]  # RGB/RGBA

    rw2, rh2 = (W + 1) // 2, (H + 1) // 2       # 下采样后尺寸
    cid = [[0] * rw2 for _ in range(rh2)]
    cnt: Counter = Counter()
    for yy in range(rh2):
        for xx in range(rw2):
            r, g, b = rgb(xx * 2, yy * 2)
            c = (r & ~3) + ((g & ~3) << 8) + ((b & ~3) << 16)   # 颜色量化
            cid[yy][xx] = c
            cnt[c] += 1

    min_side = max(1, int(min(sw, sh) * 0.25))
    skip_left = sw // 4                         # 跳过滑块初始区（左侧）
    good_enough = (min_side * min_side * 3) // 2
    best_area, best_x = 0, 0
    for c, _n in cnt.most_common(3):            # 只查 Top-3 高频色（背景/缺口色）
        col_run = [[0] * rw2 for _ in range(rh2)]
        for xx in range(rw2):
            col_run[0][xx] = 1 if cid[0][xx] == c else 0
        for yy in range(1, rh2):               # 每列同色连续游程高度
            crow, prow, cr = col_run[yy], col_run[yy - 1], cid[yy]
            for xx in range(rw2):
                crow[xx] = (prow[xx] + 1) if cr[xx] == c else 0
        for yy in range(min_side, rh2):
            row = col_run[yy]
            x = skip_left
            while x < rw2:
                if row[x] < min_side:
                    x += 1
                    continue
                s = x
                while x < rw2 and row[x] >= min_side:
                    x += 1
                run_w, run_h = x - s, row[s]
                if run_h > 0:
                    ratio, area = run_w / run_h, run_w * run_h
                    if 0.7 < ratio < 1.4 and area > best_area:  # 近正方形的最大块=缺口
                        best_area, best_x = area, s
                        if best_area >= good_enough:
                            return best_x * 2
    return best_x * 2 if best_area > 0 else None


def _auth() -> Tuple[str, str]:
    """换 token。返回 (token, cookie)；失败返回 ("", "")。"""
    ts = round(time.time() * 1000)
    auth_key = hashlib.md5(("testtest" + str(ts)).encode()).hexdigest()
    cookie = "__jsluid_s=" + uuid.uuid4().hex
    j = _jpost("/auth", form={"authKey": auth_key, "timeStamp": ts}, headers={"Cookie": cookie})
    tok = (j.get("params") or {}).get("bussiness", "")
    return tok, (cookie if tok else "")


def _solve_captcha(tok: str, cookie: str) -> Tuple[str, str]:
    """取验证码→识别→校验，拿到 (sign, 图片uuid)。多次换图重试；全失败返回 ("", "")。
    注意：查询请求头必须带该图片 uuid（与 sign 配对，缺则 code:500 服务器异常——实测踩坑）。"""
    for _ in range(_CAPTCHA_RETRY):
        img = _jpost("/image/getCheckImagePoint",
                     form={"clientUid": "point-" + str(uuid.uuid4())},
                     headers={"token": tok, "Cookie": cookie}).get("params")
        if not img:
            time.sleep(1.0)
            continue
        x = _slider_offset(img.get("smallImage", ""), img.get("bigImage", ""))
        if x is None:
            continue
        uid = img.get("uuid", "")
        for dx in _SLIDE_TRY_DX:               # 识别有 ±像素误差，微调逐个试
            r = _jpost("/image/checkImage", want_params=False,
                       raw=json.dumps({"key": uid, "value": str(x + dx)}),
                       headers={"token": tok, "Cookie": cookie, "Content-Type": "application/json"})
            if r.get("success"):
                sign = r.get("params")
                return (sign if isinstance(sign, str) else ""), uid
    return "", ""


def _query_condition(tok: str, cookie: str, sign: str, img_uuid: str, unit_name: str) -> List[Dict[str, Any]]:
    """带 token+sign+图片uuid 查备案。**末尾斜杠绕创宇盾 WAF**（无斜杠恒 403）。
    uuid 必须是验证码图片 uuid（与 sign 配对，缺/错则 code:500）。返回 list（原始条目）。"""
    info = {"pageNum": "", "pageSize": "", "unitName": unit_name, "serviceType": _SERVICE_WEB}
    # 末尾斜杠是绕 WAF 的关键（实测无斜杠 → 创宇盾 403 拦截页）
    txt = _post("/icpAbbreviateInfo/queryByCondition/",
                raw=json.dumps(info, ensure_ascii=False),
                headers={"token": tok, "sign": sign, "uuid": img_uuid, "Content-Type": "application/json"})
    if not txt or txt.lstrip().startswith("<"):   # HTML=WAF 拦截页
        if "疑似黑客" in txt or "cresc" in txt.lower() or "365cyd" in txt:
            logger.warning("icp_miit 查询被创宇盾 WAF 拦截（出口 IP 可能被风控）")
        return []
    try:
        j = json.loads(txt)
    except Exception:
        return []
    return (j.get("params") or {}).get("list") or []


def query_icp(domain_or_unit: str) -> Dict[str, str]:
    """官方 ICP 查询入口。输入域名主体（或单位名），返回 {unit, icp_no, source}；
    查不到/任一步失败返回空 unit（不抛异常，交多源链降级）。source 恒为 'miit'。"""
    if not domain_or_unit:
        return {"unit": "", "icp_no": "", "source": ""}
    tok, cookie = _auth()
    if not tok:
        logger.debug("icp_miit auth 失败（出口 IP 可能被限流）")
        return {"unit": "", "icp_no": "", "source": ""}
    sign, img_uuid = _solve_captcha(tok, cookie)
    if not sign:
        logger.debug("icp_miit 验证码未通过（%d 次重试用尽）", _CAPTCHA_RETRY)
        return {"unit": "", "icp_no": "", "source": ""}
    rows = _query_condition(tok, cookie, sign, img_uuid, domain_or_unit)
    for it in rows:
        unit = (it.get("unitName") or "").strip()
        icp_no = (it.get("serviceLicence") or it.get("mainLicence") or "").strip()
        if unit or icp_no:
            return {"unit": unit, "icp_no": icp_no, "source": "miit"}
    return {"unit": "", "icp_no": "", "source": ""}

