"""Small Docker Engine adapter for update control; independent of image CLI age.

Only the local Unix socket is used. Advertised API bounds are checked before a
mutation. Existing images are reused; this adapter never pulls images or changes
daemon security settings. Python3.8 and newer, standard library only.
"""
from __future__ import annotations
import http.client
import json
import socket
import re
from urllib.parse import quote

class EngineError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__('Docker Engine HTTP %s: %s' % (status, message[:300]))

def api_key(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+', value):
        raise ValueError('Invalid Docker API version')
    return tuple(int(x) for x in value.split('.'))

class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try: self.sock.connect(self.path)
        except Exception: self.sock.close(); raise

class Engine:
    def __init__(self, path='/var/run/docker.sock', timeout=15):
        self.path, self.timeout = path, timeout
        info = self._request('GET', '/version')
        maximum = api_key(info.get('ApiVersion'))
        minimum = api_key(info.get('MinAPIVersion', '1.12'))
        chosen = min(maximum, (1, 52))
        if minimum > maximum or chosen < minimum or chosen < (1, 25):
            raise ValueError('Docker API range is unsupported: %s..%s' % (info.get('MinAPIVersion'),info.get('ApiVersion')))
        self.api = 'v%d.%d' % chosen
        self.version = info.get('Version', '')

    def _request(self, method, path, body=None):
        conn = UnixConnection(self.path, self.timeout)
        raw = json.dumps(body).encode('utf-8') if body is not None else None
        try:
            conn.request(method, path, body=raw, headers={'Content-Type':'application/json'} if raw is not None else {})
            response = conn.getresponse()
            data = response.read(8*1024*1024+1)
            if len(data)>8*1024*1024: raise ValueError('Docker control response too large')
            result = json.loads(data) if data else {}
            if not 200<=response.status<300:
                raise EngineError(response.status, str(result.get('message',response.reason)))
            return result
        finally: conn.close()

    def request(self, method, path, body=None):
        return self._request(method, '/'+self.api+path, body)
    def inspect(self, name):
        return self.request('GET','/containers/'+quote(name,safe='')+'/json')
    def image(self, name):
        return self.request('GET','/images/'+quote(name,safe='')+'/json')
    def remove(self, name):
        return self.request('DELETE','/containers/'+quote(name,safe='')+'?force=false&v=false')
    def restart(self, name):
        return self.request('POST','/containers/'+quote(name,safe='')+'/restart?t=30')
    def launch(self, name, image, command, labels):
        body={'Image':image,'Cmd':command,'Labels':labels,'AttachStdin':False,'AttachStdout':False,'AttachStderr':False,
              'HostConfig':{'AutoRemove':True,'Privileged':True,'PidMode':'host'}}
        created=self.request('POST','/containers/create?name='+quote(name,safe=''),body)
        identity=created.get('Id')
        if not isinstance(identity,str) or not identity: raise ValueError('Docker helper identity missing')
        try:self.request('POST','/containers/'+quote(identity,safe='')+'/start')
        except Exception:
            try:self.remove(identity)
            except Exception:pass
            raise
        return identity
