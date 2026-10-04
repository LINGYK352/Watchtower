"""漏洞报送质量的确定性辅助：类别身份、请求复现和脚本旁证，不执行任何 PoC。"""
import hashlib
import json
import re
import shlex
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from . import _hazard_table

QUALITY_VERSION = 3
_METHOD = r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)"
_SECRET = re.compile(r"password|passwd|secret|token|authorization|cookie|api[-_]?key|private[-_]?key", re.I)


def category(raw):
    canonical, matched, garbage = _hazard_table.canonicalize(raw)
    if matched or garbage or re.search(r"CVE-\d{4}-\d+", raw, re.I):
        return canonical, matched, garbage
    # 只识别标准类别 + 明确分隔符，不用任意子串吞并其他独立漏洞类型。
    prefix = re.split(r"\s*[-—:：]\s*", raw, maxsplit=1)[0]
    base, hit, _ = _hazard_table.canonicalize(prefix)
    return (base, True, False) if hit else (canonical, matched, garbage)


def endpoint(url):
    try:
        u = urlsplit(url if '://' in url else 'https://' + url)
        host = (u.hostname or '').lower()
        port = u.port
        return (host, port if port not in (80, 443) else None, u.path or '/')
    except (ValueError, TypeError):
        return ('', None, '')


def identity(session_id, target, vuln_type, parameter="", method=""):
    # The same endpoint/type is one finding. Sessions, methods and parameters
    # remain provenance, never create another row for the same vulnerability.
    return hashlib.sha256(json.dumps([endpoint(target),category(vuln_type)[0]],ensure_ascii=False).encode()).hexdigest()[:24]


def request_method(finding):
    explicit = str(finding.get('method') or finding.get('request_method') or '').upper()
    if re.fullmatch(_METHOD, explicit):
        return explicit
    poc = str(finding.get('poc') or '')
    match = re.match(r'^\s*(' + _METHOD + r')\s+', poc)
    if match:
        return match.group(1)
    if poc.strip().startswith('curl '):
        try:
            tokens = shlex.split(poc)
            for flag in ('-X', '--request'):
                if flag in tokens:
                    value = tokens[tokens.index(flag) + 1].upper()
                    return value if re.fullmatch(_METHOD, value) else ''
            return 'HEAD' if '-I' in tokens or '--head' in tokens else 'POST' if any(
                flag in tokens for flag in ('-d', '--data', '--data-raw', '--data-binary', '-F', '--form')) else 'GET'
        except (ValueError, IndexError):
            return ''
    return ''


def _redact(value):
    if isinstance(value, dict):
        return {k: '<REDACTED>' if _SECRET.search(str(k)) else _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _body(value):
    if isinstance(value, (dict, list)):
        return json.dumps(_redact(value), ensure_ascii=False, indent=2)
    text = str(value or '')
    try:
        return json.dumps(_redact(json.loads(text)), ensure_ascii=False, indent=2)
    except (ValueError, TypeError):
        # 表单值与常见头格式也脱敏；不去猜业务响应中的个人数据。
        text = re.sub(r'(?im)^(\s*(?:authorization|cookie|api[-_]?key)\s*:\s*)[^\r\n]+', r'\1<REDACTED>', text)
        return re.sub(r'(?i)((?:password|passwd|token|secret|api[-_]?key)=)([^\s&\x22\x27]+)', r'\1<REDACTED>', text)


def _command(text):
    """简单 curl/wget 命令按参数脱敏，保留引号结构；不执行也不补造参数。"""
    if not text.lstrip().startswith(('curl ', 'wget ')):
        return _body(text)
    try:
        tokens = shlex.split(text)
    except ValueError:
        return ''
    for i in range(1, len(tokens)):
        previous = tokens[i - 1]
        if previous in ('-H', '--header') and ':' in tokens[i]:
            key, value = tokens[i].split(':', 1)
            if _SECRET.search(key):
                tokens[i] = key + ': <REDACTED>'
        elif previous in ('-b', '--cookie', '-u', '--user'):
            tokens[i] = '<REDACTED>'
        elif previous in ('-d', '--data', '--data-raw', '--data-binary'):
            tokens[i] = _body(tokens[i])
        else:
            tokens[i] = _body(tokens[i])
    return ' '.join(shlex.quote(token) for token in tokens)


def http_request_text(args):
    url = str(args.get('url') or args.get('target') or '')
    u = urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname:
        return ''
    method = str(args.get('method') or 'GET').upper()
    if not re.fullmatch(_METHOD, method):
        return ''
    query = parse_qsl(u.query, keep_blank_values=True)
    if isinstance(args.get('params'), dict):
        query += list(args['params'].items())
    query = [(k, '<REDACTED>' if _SECRET.search(str(k)) else v) for k, v in query]
    path = urlunsplit(('', '', u.path or '/', urlencode(query, doseq=True), ''))
    host = u.hostname + (':' + str(u.port) if u.port else '')
    headers = args.get('headers') or {}
    if isinstance(headers, dict):
        host = next((str(value).replace('\r', '').replace('\n', '') for key, value in headers.items()
                     if str(key).lower() == 'host'), host)
    lines = [method + ' ' + path + ' HTTP/1.1', 'Host: ' + host]
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() in ('host', 'content-length'):
                continue
            clean = '<REDACTED>' if _SECRET.search(str(key)) else str(value).replace('\r', '').replace('\n', '')
            lines.append(str(key).replace('\r', '').replace('\n', '') + ': ' + clean)
    if args.get('body') is not None:
        body = _body(args['body'])
        lines += ['Content-Length: ' + str(len(body.encode('utf-8'))), '', body]
    return '\n'.join(lines)


def _reported_http(text, target):
    """接受明确请求行和真实给出的 headers/body；不从说明文字猜 POST 参数。"""
    lines = text.replace('\r\n', '\n').split('\n')
    match = re.fullmatch(r'\s*(' + _METHOD + r')\s+(\S+?)(?:\s+HTTP/\d(?:\.\d)?)?\s*', lines[0])
    if not match:
        return ''
    method, location = match.groups()
    base = urlsplit(target)
    url = location if '://' in location else urlunsplit((base.scheme, base.netloc, location, '', ''))
    if endpoint(url) != endpoint(target):
        return ''
    headers, body_lines = {}, []
    for index, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_lines = lines[index + 1:]
            break
        header = re.fullmatch(r'([A-Za-z0-9!#$%&\x27*+.^_`|~-]+):\s*(.*)', line)
        if header:
            headers[header.group(1)] = header.group(2)
        elif line.lstrip().startswith(('{', '[')):
            body_lines = lines[index:]
            break
        else:
            return ''
    args = {'url': url, 'method': method, 'headers': headers}
    if body_lines:
        args['body'] = '\n'.join(body_lines)
    return http_request_text(args)


def looks_like_poc(text):
    text = str(text or '').strip()
    return bool(re.match(r'^(?:curl\s|wget\s|python(?:3)?\s|' + _METHOD + r'\s+\S+\s+HTTP/\d)', text))


def _poc_matches_target(text, target):
    try:
        if re.match(_METHOD + r'\s', text):
            location = text.split()[1]
            base = urlsplit(target)
            url = location if '://' in location else urlunsplit((base.scheme, base.netloc, location, '', ''))
            return endpoint(url) == endpoint(target)
        if text.startswith(('curl ', 'wget ')):
            return any(endpoint(token) == endpoint(target) for token in shlex.split(text) if token.startswith(('http://', 'https://')))
    except (ValueError, IndexError):
        return False
    return True  # 非 HTTP 的脚本命令仅作待复核材料，不提升验证状态。


def reproduction(finding, tool_log):
    """优先实抓请求，其次明确的上报请求；描述性清单放 notes，不假称可直接执行。"""
    target = finding.get('target', '')
    original = str(finding.get('poc') or '').strip()
    for log in reversed(tool_log or []):
        args = log.get('arguments') or log.get('input') or {}
        if (log.get('name') or log.get('tool')) != 'http_request' or not isinstance(args, dict):
            continue
        if endpoint(args.get('url') or '') != endpoint(target):
            continue
        if request_method(finding) and request_method(finding) != str(args.get('method') or 'GET').upper():
            continue
        request = http_request_text(args)
        if request:
            return {'poc': request, 'poc_format': 'http', 'poc_source': 'tool_log',
                    'poc_notes': _body(original) if original != request else '',
                    'poc_quality': 'captured_request'}
    reported = _reported_http(original, target) if original else ''
    if reported:
        return {'poc': reported, 'poc_format': 'http', 'poc_source': 'reported',
                'poc_notes': '', 'poc_quality': 'needs_review'}
    if looks_like_poc(original) and _poc_matches_target(original, target):
        return {'poc': _command(original), 'poc_format': 'http' if re.match(_METHOD, original) else 'command',
                'poc_source': 'reported', 'poc_notes': '', 'poc_quality': 'needs_review'}
    # 从接口清单仅提取与当前 finding 精确对应的请求行，不补造其他端点或请求体。
    parsed = urlsplit(target)
    for method, location in re.findall(r'\b(' + _METHOD + r')\s+(https?://[^\s<>]+|/[^\s<>]+)', original):
        location = location.rstrip('。，,;；)）')
        url = location if '://' in location else urlunsplit((parsed.scheme, parsed.netloc, location, '', ''))
        if endpoint(url) == endpoint(target) and method in ('GET', 'HEAD', 'OPTIONS'):
            return {'poc': http_request_text({'url': url, 'method': method}), 'poc_format': 'http',
                    'poc_source': 'reported', 'poc_notes': _body(original), 'poc_quality': 'needs_review'}
    return {'poc': '', 'poc_format': 'missing', 'poc_source': 'reported',
            'poc_notes': _body(original), 'poc_quality': 'missing_request'}


def script_support(target, tool_log):
    """脚本旁证保留日志定位，不把 stdout 宣称当成真实 HTTP 证据。"""
    path = urlsplit(target).path
    support = []
    if not path or path == '/':
        return support
    pattern = re.compile(re.escape(path) + r'(?=$|[\s\x22\x27?\x29,;])')
    for index, log in enumerate(tool_log or []):
        if (log.get('name') or log.get('tool')) != 'run_script':
            continue
        args, result = log.get('arguments') or {}, log.get('result') or {}
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except ValueError:
                continue
        if not isinstance(result, dict) or not isinstance(args, dict):
            continue
        # stdout 或脚本源码包含精确路径仅用于定位旁证，永远不提升 verified。
        if pattern.search(str(result.get('stdout') or '') + '\n' + str(args.get('code') or '')):
            support.append({'tool': 'run_script', 'tool_log_index': index, 'exit_code': result.get('exit_code'),
                            'stdout_chars': len(str(result.get('stdout') or '')),
                            'note': '脚本执行旁证；需结构化请求/响应核验，不能独立确认漏洞'})
    return support
