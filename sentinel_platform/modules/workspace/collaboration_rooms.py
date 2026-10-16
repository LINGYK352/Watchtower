"""Persistent group rooms and participant-only conversations, shared across workers."""
from __future__ import annotations
import hashlib,json,re
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from .control_sync.security import ControlSyncError,text

ID=re.compile(r'^[0-9a-f]{32}$')
EVENT_WINDOW=512

class CollaborationRooms:
    @staticmethod
    def room_id(value):
        value=text(value,32)
        if not ID.fullmatch(value):raise ControlSyncError('成员标识无效 / Invalid member id')
        return value

    def room_member(self,gid,mid,active=True):
        member=self.members.find_one({'_id':self.room_id(mid),'group_id':gid})
        if not member or member.get('state') not in ('approved','revoked'):
            raise ControlSyncError('成员不可用 / Member unavailable',403)
        if active and (member.get('state')!='approved' or member.get('expires_at') is not None and member['expires_at']<=self.clock()):
            raise ControlSyncError('成员凭证已撤销或到期 / Membership revoked or expired',403)
        return member

    def room_scope(self,gid,mid,audience,peer_id='',sending=False):
        self._group(gid);self.room_member(gid,mid)
        if audience not in ('group','direct'):raise ControlSyncError('工作区类型无效 / Invalid workspace type')
        participants=[];peer=None
        if audience=='direct':
            peer_id=self.room_id(peer_id)
            if peer_id==mid:raise ControlSyncError('请选择另一位成员 / Choose another member')
            peer=self.room_member(gid,peer_id,active=sending);participants=sorted((mid,peer_id))
        elif peer_id:raise ControlSyncError('总工作区不指定单点成员 / Group room has no direct recipient')
        key=hashlib.sha256((gid+':'+audience+':'+':'.join(participants)).encode()).hexdigest()
        query={'group_id':gid,'audience':audience,'state':'complete'}
        if participants:query['participants']=participants
        available=peer is None or peer['state']=='approved' and (peer.get('expires_at') is None or peer['expires_at']>self.clock())
        return {'key':key,'query':query,'audience':audience,'participants':participants,'peer':peer,'can_send':available}

    def share_scope(self,gid,mid,body):
        audience=body.get('audience') or 'legacy'
        if audience=='legacy':return {'audience':'legacy','recipients':body.get('recipients'),'participants':[]}
        scope=self.room_scope(gid,mid,audience,body.get('peer_id',''),sending=True)
        supplied=body.get('recipients') or []
        if audience=='group':
            if supplied:raise ControlSyncError('总工作区由系统确定接收成员 / Group recipients are server-controlled')
            recipients=[]  # Visibility follows current membership, including later-approved members.
        else:
            recipients=[body['peer_id']]
            if supplied and supplied!=recipients:raise ControlSyncError('单点成员与接收范围不一致 / Direct recipient mismatch')
        return {'audience':audience,'recipients':recipients,'participants':scope['participants']}

    def item_allowed(self,item,mid,host=False):
        audience=item.get('audience','legacy')
        if audience=='direct':return mid in item.get('participants',[])
        if audience=='group':return True  # Caller membership was freshly checked at the API/peer boundary.
        return host or mid==item.get('sender') or mid in item.get('recipients',[])

    def visible_items_query(self,gid,mid,host=False):
        legacy={'$and':[{'$or':[{'audience':{'$exists':False}},{'audience':'legacy'}]}]}
        if not host:legacy['$and'].append({'$or':[{'sender':mid},{'recipients':mid}]})
        return {'group_id':gid,'state':'complete','kind':{'$in':['finding','report','session']},'$or':[
            {'audience':'group'},{'audience':'direct','participants':mid},legacy]}

    def publish_room_item(self,item):
        if item.get('audience') not in ('group','direct'):return item
        if item.get('published') is True and item.get('published_revision') is not None:return item
        rooms=self.repo.collection('collaboration_rooms')
        participants=item.get('participants',[]) if item['audience']=='direct' else []
        rid=hashlib.sha256((item['group_id']+':'+item['audience']+':'+':'.join(participants)).encode()).hexdigest()
        rooms.update_one({'_id':rid},{'$setOnInsert':{'revision':0,'events':[]}},upsert=True)
        # Publication order and its event are one atomic Mongo update. A slow file upload
        # receives its revision only when complete, so it cannot fall behind a time cursor.
        document=rooms.find_one_and_update({'_id':rid,'events.id':{'$ne':item['_id']}},[
            {'$set':{'revision':{'$add':['$revision',1]},'events':{'$slice':[{'$concatArrays':['$events',[
                {'id':item['_id'],'seq':{'$add':['$revision',1]}}
            ]]},-EVENT_WINDOW]}}}
        ],return_document=ReturnDocument.AFTER)
        if document is None:document=rooms.find_one({'_id':rid})
        event=next((e for e in document['events'] if e['id']==item['_id']),None)
        if not event:raise ControlSyncError('消息发布需重试 / Publication needs retry',503)
        self.items.update_one({'_id':item['_id'],'published':{'$ne':True}},{'$set':{'published':True,'published_revision':event['seq'],'room_id':rid}})
        return {**item,'published_revision':event['seq'],'room_id':rid}

    def send_message(self,gid,user,body):
        access=self._access(gid,user)
        group=access.get('group') or access['link'].get('workspace_snapshot',{}).get('group',{})
        if group.get('crypto_format')==1:return self.cache.queue(gid,user,body)
        if not access['host']:return self._request(access['link'],'message',body)
        return self.store_message(gid,access['member_id'],body,self.identity(user))

    def store_message(self,gid,mid,body,source):
        scope=self.room_scope(gid,mid,body.get('audience','group'),body.get('peer_id',''),sending=True)
        content=body.get('text');nonce=body.get('nonce')
        if not isinstance(content,str) or not content.strip() or len(content)>2000 or len(content.encode('utf-8'))>8192:
            raise ControlSyncError('消息不能为空且最多2000字 / Message required, maximum 2000 characters')
        if not isinstance(nonce,str) or not re.fullmatch(r'[0-9a-f]{32}',nonce):raise ControlSyncError('发送凭据无效 / Invalid send nonce')
        iid=hashlib.sha256((gid+':'+mid+':'+nonce).encode()).hexdigest()[:32]
        fingerprint=hashlib.sha256(json.dumps([scope['audience'],scope['participants'],content],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        item={'_id':iid,'group_id':gid,'sender':mid,'source':source,'created_at':self.clock(),'kind':'message','text':content,
              'state':'complete','audience':scope['audience'],'participants':scope['participants'],'fingerprint':fingerprint,'published':False}
        try:self.items.insert_one(item)
        except DuplicateKeyError:
            item=self.items.find_one({'_id':iid,'group_id':gid,'sender':mid})
            if not item or item.get('fingerprint')!=fingerprint:raise ControlSyncError('发送凭据已用于不同消息 / Send nonce conflict',409) from None
        item=self.publish_room_item(item)
        return {'entry':self.public_entry(item)}

    def public_entry(self,item):
        if item['kind']=='message':return {k:item.get(k) for k in ('_id','group_id','sender','source','created_at','kind','text','audience','participants','published_revision')}
        return {**self.public_item(item),'published_revision':item.get('published_revision')}

    def conversation(self,gid,user,body):
        access=self._access(gid,user)
        group=access.get('group') or access['link'].get('workspace_snapshot',{}).get('group',{})
        if group.get('crypto_format')==1:return self.cache.read_room(gid,user,body)
        if not access['host']:return self._request(access['link'],'conversation',body)
        return self.read_conversation(gid,access['member_id'],body)

    def read_conversation(self,gid,mid,body):
        scope=self.room_scope(gid,mid,body.get('audience','group'),body.get('peer_id',''))
        cursor=body.get('cursor');before=body.get('before')
        for value in (cursor,before):
            if value is not None and (isinstance(value,bool) or not isinstance(value,int) or value<0):raise ControlSyncError('消息游标无效 / Invalid message cursor')
        # Recover an interrupted publisher using shared persistent state, rather than a worker cache.
        for item in self.items.find({**scope['query'],'published':{'$ne':True}}).limit(100):self.publish_room_item(item)
        room=self.repo.collection('collaboration_rooms').find_one({'_id':scope['key']}) or {'revision':0,'events':[]}
        reset=False
        if before is not None:
            query={**scope['query'],'published_revision':{'$lt':before}}
            records=list(self.items.find(query).sort('published_revision',-1).limit(100));records.reverse()
        elif cursor is not None and cursor<=room['revision'] and (not room['events'] or cursor>=room['events'][0]['seq']-1):
            selected=[e for e in room['events'] if e['seq']>cursor]
            documents={d['_id']:d for d in self.items.find({**scope['query'],'_id':{'$in':[e['id'] for e in selected]}})}
            records=[{**documents[e['id']],'published_revision':e['seq']} for e in selected if e['id'] in documents]
        else:
            reset=cursor is not None
            records=list(self.items.find({**scope['query'],'published':True}).sort('published_revision',-1).limit(100));records.reverse()
        entries=[self.public_entry(item) for item in records]
        oldest=min((item['published_revision'] for item in records),default=before or room['revision']+1)
        older=bool(self.items.find_one({**scope['query'],'published_revision':{'$lt':oldest}}))
        return {'entries':entries,'cursor':room['revision'],'oldest':oldest,'has_older':older,'reset':reset,
                'can_send':scope['can_send'],'self_member_id':mid,'audience':scope['audience'],'participants':scope['participants']}

    def room_contacts(self,gid,mid):
        ids={m['_id'] for m in self.members.find({'group_id':gid,'state':'approved'}) if m['_id']!=mid}
        for item in self.items.find({'group_id':gid,'audience':'direct','participants':mid,'state':'complete'},{'participants':1}):
            ids.update(p for p in item.get('participants',[]) if p!=mid)
        return [self._public_member(m) for m in self.members.find({'group_id':gid,'_id':{'$in':list(ids)}}) if m.get('state')!='pending']
