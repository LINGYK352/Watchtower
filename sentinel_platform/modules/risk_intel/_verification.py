"""Deterministic review of captured evidence; no model verdict and no PoC execution."""
import json,re
from urllib.parse import urlsplit
from . import _finding_quality as quality

SENSITIVE=re.compile(r'(?i)(?:password(?:hash)?|passwd|private[_-]?key|access[_-]?token|身份证(?:号)?)\s*[\"\x27:=\s]+(?!<redacted>|null|none|\*{3,})[^\s\",}]{6,}')
SQL_ERROR=re.compile(r'(?i)SQL syntax.*?(?:MySQL|MariaDB)|ORA-\d{4,}|PostgreSQL.*ERROR|SQLSTATE\[[0-9A-Z]+\]')

def assess(finding,logs):
    kind=quality.category(finding.get('vuln_type',''))[0];target=quality.endpoint(finding.get('target',''))
    matching=[]
    wanted=quality.request_method(finding)
    for entry in logs or []:
        args=entry.get('arguments') or {};result=entry.get('result') or {}
        try:
            if isinstance(args,str):args=json.loads(args)
            if isinstance(result,str):result=json.loads(result)
        except (TypeError,ValueError):continue
        if not isinstance(args,dict) or not isinstance(result,dict) or any(result.get(key) for key in ('error','blocked','partial','truncated')):continue
        if quality.endpoint(str(args.get('url') or args.get('target') or ''))!=target:continue
        if wanted and str(args.get('method') or 'GET').upper()!=wanted:continue
        name=entry.get('name') or entry.get('tool')
        try:count=int(result.get('count',0) or 0)
        except (TypeError,ValueError):count=0
        if name in ('run_nuclei','run_npoc') and count>0:
            return {'confirmed':True,'status':'confirmed','reason':'已捕获匹配端点的验证工具命中'}
        if name=='http_request' and isinstance(result.get('status_code'),int):matching.append((args,result))
    for args,result in matching:
        body=str(result.get('body') or '')
        if not 200<=result['status_code']<300 or result.get('body_skipped'):continue
        if any(name in kind for name in ('源码泄露','源代码')) and re.search(r'<\?php|<%@\s*(?:Page|WebHandler)|from\s+\w+\s+import\s+',body):
            return {'confirmed':True,'status':'confirmed','reason':'完整响应含可识别源码，不是仅凭200确认'}
        if any(name in kind for name in ('泄露','未授权','认证绕过')) and SENSITIVE.search(body):
            actual=result.get('request_meta') or args
            headers=actual.get('headers') or {}
            credentialed=bool(urlsplit(str(actual.get('url') or '')).username) or (any(str(k).lower() in ('authorization','cookie') and v for k,v in headers.items()) if isinstance(headers,dict) else True)
            if '未授权' not in kind and '认证绕过' not in kind or not credentialed:
                return {'confirmed':True,'status':'confirmed','reason':'完整实抓响应含敏感字段；访问控制类请求未携带认证头'}
        if 'SQL' in kind.upper() and SQL_ERROR.search(body):
            control=[str(r.get('body') or '') for a,r in matching if a!=args and 200<=r['status_code']<300]
            if any(not SQL_ERROR.search(text) for text in control):
                return {'confirmed':True,'status':'confirmed','reason':'同端点测试与对照响应存在数据库错误差异'}
    if '枚举' in kind:
        bodies=[str(result.get('body') or '') for args,result in matching]
        if any(re.search('密码错误|incorrect password',b,re.I) for b in bodies) and any(re.search('账号不存在|用户不存在|user.*not exist',b,re.I) for b in bodies):
            return {'confirmed':True,'status':'confirmed','reason':'同端点真实对照响应区分存在账号和不存在账号'}
    if any(result.get('status_code',0)>=500 for args,result in matching):
        status=next(result['status_code'] for args,result in matching if result.get('status_code',0)>=500)
        return {'confirmed':False,'status':'failed','reason':'验证请求返回HTTP '+str(status)+'，未作为漏洞成功证据'}
    return {'confirmed':False,'status':'needs_evidence','reason':'已即时复核；现有实抓结果不足以证明该类型漏洞，需补充类型相符的复现证据'}
