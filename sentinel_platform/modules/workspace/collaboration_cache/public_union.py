"""Read the union of authenticated stores; only the approved public overlay is added."""
from .client import NodeClient
from .policy import CacheError

_UNAVAILABLE=(404,410,502,503,504)

class PublicUnionClient(NodeClient):
    def __init__(self,primary,public,public_writes=False):
        self.primary,self.overlay,self.public_writes=primary,public,public_writes
        self.config,self.private,self.public,self.peer,self.clock=primary.config,primary.private,primary.public,primary.peer,primary.clock
        self._routes={}

    def upload_target(self,manifest):
        return self.overlay if self.public_writes and manifest.get('audience')=='group' else self.primary

    def _route(self,oid):
        if oid in self._routes:return self._routes[oid]
        try:
            self.primary.call('metadata',{'id':oid})
            result=self.primary
        except CacheError as exc:
            if exc.status not in _UNAVAILABLE:raise
            meta=self.overlay.call('metadata',{'id':oid})
            if meta['manifest'].get('audience')!='group':
                raise CacheError('公共副本不包含单点资料 / Public replica does not contain private data',403)
            result=self.overlay
        self._routes[oid]=result
        return result

    def call(self,action,body=None,joining=False):
        body=body or {}
        if action=='list':
            limit=body.get('limit',100);items={};successes=0;last_error=None
            for client in (self.primary,self.overlay):
                cursor=body.get('before');public_rows=[]
                try:
                    while True:
                        response=client.call('list',{'limit':limit,**({'before':cursor} if cursor else {})})
                        rows=response['items']
                        if client is self.overlay:rows=[row for row in rows if row.get('audience')=='group']
                        public_rows.extend(rows);cursor=response.get('next')
                        if len(public_rows)>=limit or not cursor:break
                    successes+=1
                except CacheError as exc:
                    if exc.status not in _UNAVAILABLE:raise
                    last_error=exc;continue
                for row in public_rows:
                    items.setdefault(row['id'],row)
            if not successes:raise last_error
            rows=sorted(items.values(),key=lambda r:(r['created_at'],r['id']),reverse=True)[:limit]
            return {'items':rows,'next':[rows[-1]['created_at'],rows[-1]['id']] if len(rows)==limit else None}
        oid=body.get('id') or (body.get('manifest') or {}).get('id')
        if action=='reserve':
            client=self.upload_target(body.get('manifest') or {})
            self._routes[oid]=client
        elif oid:
            client=self._routes.get(oid) if action in ('progress','put','commit') else None
            client=client or self._route(oid)
        else:client=self.primary
        self.config=client.config
        result=client.call(action,body,joining)
        if action=='metadata' and result.get('manifest',{}).get('audience')=='group':
            other=self.overlay if client is self.primary else self.primary
            try:duplicate=other.call(action,body,joining)
            except CacheError as exc:
                if exc.status not in _UNAVAILABLE:raise
            else:
                first,second=result['manifest'],duplicate['manifest']
                if any(first.get(key)!=second.get(key) for key in ('id','bytes','sha256','audience')) or first['envelope']['header']!=second['envelope']['header'] or first['envelope']['signature']!=second['envelope']['signature']:
                    raise CacheError('公共副本与原对象不符 / Public replica differs from original object',409)
                proofs={(row.get('recipient'),row.get('kind')):row for row in result.get('receipts',[])}
                for row in duplicate.get('receipts',[]):proofs.setdefault((row.get('recipient'),row.get('kind')),row)
                result=dict(result,receipts=list(proofs.values()))
        return result

