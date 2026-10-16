"""Existing signed object client over a host-approved sealed service entrance."""
import secrets
from . import crypto
from .client import NodeClient


class ServiceClient(NodeClient):
    def __init__(self,cache,gid,user,config):
        super().__init__(config,cache.key(user),cache.clock)
        self.cache,self.gid,self.user=cache,gid,user

    def call(self,action,body=None,joining=False):
        frame={'realm':self.gid,'peer':self.peer,'public':self.public,'ts':int(self.clock()),'nonce':secrets.token_hex(16),
               'action':action,'body':body or {},'token':self.config['member_token'],'grant':self.config['grant']}
        request={'frame':frame,'signature':crypto.sign(self.private,frame)}
        return self.cache.replicas.call(self.gid,self.user,self.config['rpc_service'],'node',{'request':request})
