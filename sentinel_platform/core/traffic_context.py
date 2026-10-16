"""Scoped traffic audit with a bounded combined request/response packet budget."""
from contextlib import contextmanager
from contextvars import ContextVar
from . import get_logger

_current = ContextVar('watchtower_traffic', default=None)
PREVIEW_BYTES = 1024 * 1024  # Combined request + response packet budget.


@contextmanager
def scope(ctx, source='tool'):
    token = _current.set({'session_id':str(ctx.get('session_id') or ''), 'mode':ctx.get('mode',''),
                          'site':ctx.get('site',''), 'source':source})
    try: yield
    finally: _current.reset(token)


def current(): return _current.get()


def preview(request=b'', response=b'', *, total=None, reason=''):
    import base64
    first,second=bytes(request or b''),bytes(response or b'')
    remaining=max(0,PREVIEW_BYTES-min(len(first),PREVIEW_BYTES))
    clipped=len(first)+len(second)>PREVIEW_BYTES or (total is not None and total>len(second))
    return {'request_preview_b64':base64.b64encode(first[:PREVIEW_BYTES]).decode(),
            'response_preview_b64':base64.b64encode(second[:remaining]).decode(),
            'preview_truncated':clipped or bool(reason),
            'truncation_reason':reason or ('请求与响应合计超过1 MiB，仅保存上限内字节 / Combined packets over 1 MiB; bounded capture' if clipped else '')}


def record(method, url, *, context=None, status=None, error='', source='', level='sent', **meta):
    info = context if context is not None else current()
    if not info or not info.get('session_id'): return
    from sentinel_platform.contracts import get_registry
    service = get_registry().get('guard_log_service')
    if not service: return
    try:
        return service.record(method,url,info.get('mode',''),True,level,error,
                       session_id=info['session_id'],site=info.get('site',''),
                       source=source or info.get('source','tool'),status_code=status,event='traffic',**meta)
    except Exception as exc:
        get_logger().debug('Traffic audit unavailable (%s)',type(exc).__name__)


def observe_response(response):
    """Tee only bytes the caller consumes. Never read extra or change Burps data."""
    info=current()
    if not info:return
    prepared=getattr(response,'request',None)
    if prepared is None:return
    body=getattr(prepared,'body',None)
    original=body.encode('utf-8') if isinstance(body,str) else body if isinstance(body,bytes) else b''
    request=('\r\n'.join([prepared.method+' '+prepared.path_url+' HTTP/1.1']+[k+': '+v for k,v in prepared.headers.items()])+'\r\n\r\n').encode('latin-1',errors='replace')+original[:PREVIEW_BYTES]
    reason='请求体为流，日志未额外读取 / Stream request body not consumed for logging' if body is not None and not isinstance(body,(str,bytes)) else ''
    buffered=getattr(response,'_content',False)
    data=buffered if isinstance(buffered,bytes) else b''
    reply_header=('HTTP/1.1 '+str(response.status_code)+' '+str(response.reason or '')+'\r\n'+'\r\n'.join(k+': '+v for k,v in response.headers.items())+'\r\n\r\n').encode('latin-1',errors='replace')
    identity=record(prepared.method,prepared.url,context=info,status=response.status_code,capture_note='响应体由HTTP库解码 / Body decoded by HTTP library' if response.headers.get('Content-Encoding') else '',**preview(request,reply_header+data,reason=reason))
    if isinstance(buffered,bytes):return
    iterator=response.iter_content;close=response.close;captured=bytearray();read=0;finished=False
    def save():
        nonlocal finished
        if finished or not identity:return
        finished=True
        try:
            declared=int(response.headers.get('Content-Length') or 0)
            note=reason
            if not getattr(response,'_content_consumed',False):note=(note+'；' if note else '')+'调用方只读取响应窗口，未为日志继续下载 / Caller read window only'
            meta=preview(request,reply_header+captured,total=len(reply_header)+max(declared,read),reason=note)
            from sentinel_platform.contracts import get_registry
            get_registry().get('guard_log_service').update_preview(identity,**meta)
        except Exception as exc:get_logger().debug('Traffic prefix save unavailable (%s)',type(exc).__name__)
    def iterate(*args,**kwargs):
        nonlocal read
        try:
            for chunk in iterator(*args,**kwargs):
                raw=chunk.encode(response.encoding or 'utf-8') if isinstance(chunk,str) else chunk
                read+=len(raw);captured.extend(raw[:max(0,PREVIEW_BYTES-len(captured))]);yield chunk
        finally:save()
    def closing():
        try:save()
        finally:close()
    response.iter_content=iterate;response.close=closing
