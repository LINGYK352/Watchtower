"""Session-scoped packet history, lossless codec and explicitly initiated replay."""
import base64,re
from flask import request,g,Response,stream_with_context
from flask_restx import Namespace,Resource
from ..envelope import ok,err,CODE_BAD_REQUEST,CODE_NOT_FOUND,CODE_ERROR
from .session import _svc,_session_access_error
from sentinel_platform.modules.ai_pentest import _burps as history,_burps_codec as codec,_burps_jobs as replay,_burps_tls as tls
from sentinel_platform.core import get_config
from sentinel_platform.contracts import get_registry,ROLE

ns=Namespace('pentest_burps',path='/pentest',description='Burps traffic history and replay')


def _body():
    body=request.get_json(silent=True)
    if not isinstance(body,dict):raise ValueError('Request body must be a JSON object')
    return body

def authorized(identity):
    if not re.fullmatch(r'[0-9a-fA-F]{24}',identity):return None,err(CODE_BAD_REQUEST,'Invalid session id')
    service=_svc()
    if not service:return None,err(CODE_ERROR,'Session service is unavailable')
    denied=_session_access_error(service,identity)
    if denied:return None,denied
    session=service.get_session(identity,with_messages=False)
    if not session:return None,err(CODE_NOT_FOUND,'Session not found')
    return session,None

def execute(identity,operation):
    session,denied=authorized(identity)
    if denied:return denied
    try:return ok(operation(session))
    except (ValueError,TypeError,OverflowError) as exc:return err(CODE_BAD_REQUEST,str(exc))

@ns.route('/session/<string:identity>/burps/history')
class History(Resource):
    def get(self,identity):return execute(identity,lambda _:history.query(identity,request.args))

@ns.route('/session/<string:identity>/burps/history/clear')
class ClearHistory(Resource):
    def post(self,identity):
        def remove(_):
            body=request.get_json(silent=True)
            if not isinstance(body,dict) or body.get('confirmed') is not True:raise ValueError('Explicit confirmation required')
            return history.clear(identity)
        return execute(identity,remove)

@ns.route('/session/<string:identity>/burps/stream')
class Stream(Resource):
    def get(self,identity):
        session,denied=authorized(identity)
        if denied:return denied
        args=request.args.to_dict()
        try:history._filters(identity,args)
        except (ValueError,TypeError,OverflowError) as exc:return err(CODE_BAD_REQUEST,str(exc))
        token=request.headers.get('Token','')
        def allowed():
            import hmac
            config=get_config()
            if config.auth:
                if config.api_key and hmac.compare_digest(token,config.api_key):g.current_user={'role':'admin'}
                else:
                    user=get_registry().get(ROLE.USER);current=user.verify_token(token) if user else None
                    if not current:return False
                    if hasattr(user,'check_permission'):
                        permitted,_=user.check_permission(current,request.path,'GET')
                        if not permitted:return False
                    g.current_user=current
            return authorized(identity)[1] is None
        return Response(stream_with_context(history.events(identity,args,allowed)),content_type='text/event-stream; charset=utf-8',
            headers={'Cache-Control':'no-cache, no-transform','X-Accel-Buffering':'no'})

@ns.route('/session/<string:identity>/burps/history/<string:packet_id>')
class Detail(Resource):
    def get(self,identity,packet_id):return execute(identity,lambda _:history.detail(identity,packet_id))

@ns.route('/session/<string:identity>/burps/codec')
class Codec(Resource):
    def post(self,identity):
        def convert(_):
            args=_body();encoding=args.get('encoding','utf-8')
            if 'bytes_b64' in args:
                value=args['bytes_b64']
                if not isinstance(value,str) or len(value)>codec.MAX_MESSAGE*2:raise ValueError('Packet exceeds its byte budget')
                try:data=base64.b64decode(value,validate=True)
                except ValueError:raise ValueError('Invalid packet Base64') from None
                if len(data)>codec.MAX_MESSAGE:raise ValueError('Packet exceeds its byte budget')
            else:data=codec.encode_editor(args.get('packet',''),args.get('from_encoding',encoding))
            if args.get('editor_view') is True:return codec.editor_view(data)
            if args.get('decode_http') is True:
                parts=codec.message_parts(data)
                if parts['view_error']:raise ValueError(parts['view_error'])
                return {'packet':parts['line']+'\r\n'+parts['headers']+'\r\n\r\n'+parts['body'],
                        'encoding':parts['charset'],'size':len(data),'display_only':True}
            return {'packet':codec.decode_editor(data,encoding),'encoding':encoding,'bytes_b64':base64.b64encode(data).decode(),'size':len(data)}
        return execute(identity,convert)

@ns.route('/session/<string:identity>/burps/certificates')
class Certificates(Resource):
    def get(self,identity):return execute(identity,lambda _:tls.profiles(identity))
    def post(self,identity):return execute(identity,lambda _:tls.create(identity,_body()))

@ns.route('/session/<string:identity>/burps/certificates/<string:certificate_id>/delete')
class DeleteCertificate(Resource):
    def post(self,identity,certificate_id):return execute(identity,lambda _:replay.revoke_certificate(identity,certificate_id))

@ns.route('/session/<string:identity>/burps/replay')
class Replay(Resource):
    def post(self,identity):return execute(identity,lambda session:replay.start(identity,session,_body()))

@ns.route('/session/<string:identity>/burps/replay/<string:job_id>')
class ReplayStatus(Resource):
    def get(self,identity,job_id):return execute(identity,lambda _:replay.status(identity,job_id))

@ns.route('/session/<string:identity>/burps/replay/<string:job_id>/cancel')
class Cancel(Resource):
    def post(self,identity,job_id):return execute(identity,lambda _:replay.cancel(identity,job_id))

@ns.route('/session/<string:identity>/burps/replay/<string:job_id>/frame')
class Frame(Resource):
    def post(self,identity,job_id):return execute(identity,lambda _:replay.send_frame(identity,job_id,_body()))
