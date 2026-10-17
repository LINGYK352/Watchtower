"""User-authenticated workgroup management and separately authenticated peer traffic."""
from flask import Blueprint,g,request,jsonify,send_file
from flask_restx import Namespace,Resource
from sentinel_platform.contracts import get_registry
from sentinel_platform.router.gateway import verify_token
from sentinel_platform.router.envelope import envelope
from sentinel_platform.modules.workspace.control_sync.security import ControlSyncError
ns=Namespace('collaboration',path='/collaboration',description='跨端协同工作组 / Cross-platform workgroups')
peer_routes=Blueprint('collaboration_peer',__name__)

def service():
    value=get_registry().get('collaboration_service')
    if value is None:
        # Bootstrap failure may be transient (database or disk). Retry the
        # same locked initializer instead of making this worker dead forever.
        from sentinel_platform.modules.workspace.collaboration import get_service
        value=get_service()
        get_registry().register('collaboration_service',value)
    return value
def user():
    value=getattr(g,'current_user',None) or verify_token(request.headers.get('Token',''))
    if not value or value.get('via')=='control_key':raise ControlSyncError('工作组操作需要用户登录 / Human user login required',401)
    return value
def body():
    if request.content_length is None or request.content_length>16384:raise ControlSyncError('请求大小无效 / Invalid request size')
    value=request.get_json(silent=True)
    if not isinstance(value,dict):raise ControlSyncError('JSON对象必填 / JSON object required')
    return value
def call(fn):
    try:
        actor=user()  # Only this local login check may issue HTTP401.
        try:result=fn(service(),actor)
        except (ControlSyncError,ValueError) as exc:
            status=getattr(exc,'status',400)
            if status==401:
                return envelope(code=403,message='工作组通信认证失效，请刷新连接 / Workgroup transport authentication failed; refresh the connection'),403
            if status==402:
                return envelope(code=424,message='工作组对端服务受限，请检查对端状态 / Workgroup peer service is restricted; check the peer'),424
            raise
        return envelope(data=result),200
    except (ControlSyncError,ValueError) as exc:
        status=getattr(exc,'status',400);return envelope(code=status,message=str(exc)),status
    except Exception:
        from sentinel_platform.core import get_logger
        get_logger().exception('collaboration management failed')
        return envelope(code=503,message='协同服务暂不可用 / Collaboration temporarily unavailable'),503
@ns.route('/state')
class State(Resource):
    def get(self):return call(lambda s,u:s.state(u))
@ns.route('/pending')
class Pending(Resource):
    def get(self):return call(lambda s,u:s.pending(u))
@ns.route('/groups/<string:gid>/invitations')
class InvitationKeys(Resource):
    def get(self,gid):return call(lambda s,u:s.invite_keys(gid,u))
@ns.route('/groups/<string:gid>/invitations/<string:iid>/reveal')
class RevealInvitation(Resource):
    def post(self,gid,iid):return call(lambda s,u:s.reveal_invite(gid,iid,u))
@ns.route('/groups/<string:gid>/invitations/<string:iid>/revoke')
class RevokeInvitation(Resource):
    def post(self,gid,iid):return call(lambda s,u:s.revoke_invite(gid,iid,u))
@ns.route('/groups')
class Groups(Resource):
    def post(self):return call(lambda s,u:s.create(u,body()))
@ns.route('/nodes')
class Nodes(Resource):
    def get(self):return call(lambda s,u:s.cache.node_list(u,request.args.get('group_id'),refresh=request.args.get('health')=='1'))
    def post(self):return call(lambda s,u:s.cache.add_node(u,body()))
@ns.route('/node-tool/download')
class DownloadNode(Resource):
    def get(self):
        try:
            user()
            from pathlib import Path
            from sentinel_platform.modules.workspace.collaboration_cache import node
            path=Path(node.__file__).parent/'assets'/'Watchtower-public-node-linux-amd64.tar.gz'
            if not path.is_file():raise ControlSyncError('节点工具候选未就绪 / Node tool candidate unavailable',503)
            return send_file(str(path),as_attachment=True,download_name='Watchtower-maintenance-node-linux-amd64.tar.gz',mimetype='application/gzip',max_age=0)
        except ControlSyncError as exc:return envelope(code=exc.status,message=str(exc)),exc.status
@ns.route('/nodes/<string:nid>/delete')
class DeleteNode(Resource):
    def post(self,nid):
        def remove(s,u):
            if body().get('confirmed') is not True:raise ControlSyncError('请确认删除 / Confirm deletion')
            return s.cache.delete_node(nid,u)
        return call(remove)
@ns.route('/groups/<string:gid>/cache')
class CacheSettings(Resource):
    def get(self,gid):return call(lambda s,u:{'policy':s.cache.workspace(gid,u)['cache_policy'],'delivery':s.cache.delivery_status(gid,u)})
    def post(self,gid):return call(lambda s,u:s.cache.configure(gid,u,body()))
@ns.route('/groups/<string:gid>/deliveries')
class Deliveries(Resource):
    def get(self,gid):return call(lambda s,u:s.cache.delivery_status(gid,u))
@ns.route('/groups/<string:gid>/identity/<string:mid>')
class PeerIdentity(Resource):
    def get(self,gid,mid):return call(lambda s,u:s.cache.peer_identity(gid,mid,u))
    def post(self,gid,mid):return call(lambda s,u:s.cache.verify_peer(gid,mid,u,body()))
@ns.route('/groups/<string:gid>/deliveries/<string:iid>/<string:action>')
class DeliveryAction(Resource):
    def post(self,gid,iid,action):return call(lambda s,u:s.cache.change_task(gid,iid,u,action))
@ns.route('/join')
class Join(Resource):
    def post(self):return call(lambda s,u:s.join(u,body()))
@ns.route('/links/<string:mid>/refresh')
class Refresh(Resource):
    def post(self,mid):return call(lambda s,u:s.refresh(mid,u,background=body().get('background') is True))
@ns.route('/links/<string:mid>/delete')
class DeleteLink(Resource):
    def post(self,mid):
        def remove(s,u):
            if body().get('confirmed') is not True:raise ControlSyncError('请确认删除 / Confirm deletion')
            return s.delete_link(mid,u)
        return call(remove)
@ns.route('/groups/<string:gid>/delete')
class DeleteGroup(Resource):
    def post(self,gid):
        def remove(s,u):
            if body().get('confirmed') is not True:raise ControlSyncError('请确认删除 / Confirm deletion')
            return s.delete_group(gid,u)
        return call(remove)
@ns.route('/groups/<string:gid>/workspace')
class Workspace(Resource):
    def get(self,gid):return call(lambda s,u:s.workspace(gid,u))
@ns.route('/groups/<string:gid>/read')
class ReadRoom(Resource):
    def post(self,gid):return call(lambda s,u:s.cache.notifications.read(gid,u,body()))
@ns.route('/groups/<string:gid>/service-offer')
class ServiceOffer(Resource):
    def post(self,gid):return call(lambda s,u:s.cache.replicas.offer(gid,u,body()))
@ns.route('/groups/<string:gid>/members/<string:mid>/service-role')
class ServiceRole(Resource):
    def post(self,gid,mid):return call(lambda s,u:s.cache.replicas.grant(gid,mid,u,body()))
@ns.route('/groups/<string:gid>/messages')
class Messages(Resource):
    def get(self,gid):
        def read(s,u):
            values={'audience':request.args.get('audience','group'),'peer_id':request.args.get('peer_id','')}
            for field in ('cursor','before'):
                if request.args.get(field) is not None:
                    raw=request.args[field];values[field]=raw if field=='before' and raw.startswith('c.') else int(raw)
            return s.conversation(gid,u,values)
        return call(read)
    def post(self,gid):return call(lambda s,u:s.send_message(gid,u,body()))
@ns.route('/groups/<string:gid>/invite')
class Invite(Resource):
    def post(self,gid):return call(lambda s,u:s.invite(gid,u,body()))
@ns.route('/groups/<string:gid>/members/<string:mid>/decide')
class Decide(Resource):
    def post(self,gid,mid):return call(lambda s,u:s.decide(gid,mid,u,body().get('accepted') is True))
@ns.route('/groups/<string:gid>/members/<string:mid>/remove')
class Remove(Resource):
    def post(self,gid,mid):return call(lambda s,u:s.remove(gid,mid,u))
@ns.route('/groups/<string:gid>/rename-request')
class RenameRequest(Resource):
    def post(self,gid):return call(lambda s,u:s.request_name(gid,u,body()))
@ns.route('/groups/<string:gid>/members/<string:mid>/rename')
class RenameMember(Resource):
    def post(self,gid,mid):return call(lambda s,u:s.rename_member(gid,mid,u,body()))
@ns.route('/groups/<string:gid>/members/<string:mid>/rename-decision')
class RenameDecision(Resource):
    def post(self,gid,mid):return call(lambda s,u:s.rename_member(gid,mid,u,body(),True))
@ns.route('/candidates')
class Candidates(Resource):
    def get(self):return call(lambda s,u:s.candidate_page(u,request.args['kind'],request.args.get('page',1),request.args.get('keyword','')) if request.args.get('kind') else s.candidates(u))
@ns.route('/groups/<string:gid>/share')
class Share(Resource):
    def post(self,gid):return call(lambda s,u:s.share(gid,u,body()))
@ns.route('/groups/<string:gid>/attachments')
class Attachments(Resource):
    def post(self,gid):
        def upload(s,u):
            s.attachment_permission(gid,u)
            if request.content_length is None or request.content_length>20*1024*1024:raise ControlSyncError('附件请求需小于20MiB / Attachment request must be under20MiB',413)
            file=request.files.get('file')
            if not file:raise ControlSyncError('请选择附件 / Select an attachment')
            values={key:request.form.get(key,'') for key in ('audience','peer_id','nonce')}
            return s.share_attachment(gid,u,values,file.filename or '',file.stream.read(20*1024*1024))
        return call(upload)
@ns.route('/groups/<string:gid>/attachments/<string:iid>/download')
class AttachmentDownload(Resource):
    def get(self,gid,iid):
        try:
            import io
            meta,raw=service().attachment_data(gid,iid,user())
            response=send_file(io.BytesIO(raw),as_attachment=True,download_name=meta['name'],mimetype='application/octet-stream',max_age=0)
            response.headers['Cache-Control']='no-store';response.headers['X-Content-Type-Options']='nosniff';response.headers['Content-Security-Policy']='sandbox'
            return response
        except (ControlSyncError,ValueError) as exc:
            status=getattr(exc,'status',400);return envelope(code=status,message=str(exc)),status
@ns.route('/groups/<string:gid>/items/<string:iid>/receive')
class Receive(Resource):
    def post(self,gid,iid):return call(lambda s,u:s.receive(gid,iid,u))
@ns.route('/groups/<string:gid>/items/<string:iid>/import')
class ImportItem(Resource):
    def post(self,gid,iid):return call(lambda s,u:s.save_item(gid,iid,u))
@ns.route('/groups/<string:gid>/items/<string:iid>/restore')
class Restore(Resource):
    def post(self,gid,iid):return call(lambda s,u:s.receive(gid,iid,u,body().get('provider_id',''),resume=True))
@peer_routes.route('/api/collaboration/peer/<string:action>',methods=['POST'])
def peer(action):
    try:
        if request.headers.get('Origin'):raise ControlSyncError('Peer requests do not accept browser Origin',403)
        if request.content_length is None or request.content_length>8*1024*1024:raise ControlSyncError('Peer request size invalid',413)
        packet=request.get_json(silent=True)
        if not isinstance(packet,dict):raise ControlSyncError('Peer JSON object required')
        return jsonify(service().peer(action,packet))
    except ControlSyncError as exc:return jsonify(error=str(exc)),exc.status
    except Exception:return jsonify(error='Collaboration peer unavailable'),503
