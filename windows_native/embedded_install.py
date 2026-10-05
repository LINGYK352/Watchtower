"""Single complete setup EXE: a signed payload range, with no ZIP temp copy."""
from pathlib import Path
import base64,hashlib,io,json,struct
from windows_preview._trust import PUBLIC_KEY
from windows_preview.signed_download import canonical
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
MAGIC=b'WATCHTOWER-INST1'
FOOTER=struct.Struct('<16sQQQQ')

class Range(io.RawIOBase):
    def __init__(self,path,start,size):self.handle=Path(path).open('rb');self.start=start;self.size=size;self.position=0
    def readable(self):return True
    def seekable(self):return True
    def tell(self):return self.position
    def seek(self,offset,whence=0):
        position=offset if whence==0 else self.position+offset if whence==1 else self.size+offset
        if not 0<=position<=self.size:raise ValueError('Embedded payload seek exceeds signed range')
        self.position=position;return position
    def read(self,size=-1):
        remaining=self.size-self.position;size=remaining if size is None or size<0 else min(size,remaining)
        self.handle.seek(self.start+self.position);data=self.handle.read(size);self.position+=len(data);return data
    def close(self):
        if not self.closed:self.handle.close()
        super().close()

class Source:
    def __init__(self,path):
        self.path=Path(path);total=self.path.stat().st_size
        with self.path.open('rb') as stream:
            stream.seek(-FOOTER.size,2);magic,self.start,self.size,metadata,metadata_size=FOOTER.unpack(stream.read(FOOTER.size))
            if magic!=MAGIC or self.start+self.size!=metadata or metadata+metadata_size+FOOTER.size!=total or not 0<metadata_size<=4*1024**2 or not 0<self.size<=4*1024**3:raise ValueError('Invalid complete installer footer')
            stream.seek(metadata);envelope=json.loads(stream.read(metadata_size))
        self.manifest=envelope['descriptor']
        Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY)).verify(base64.b64decode(envelope['signature'],validate=True),canonical(self.manifest))
        if self.manifest.get('schema')!=1 or self.manifest.get('product')!='watchtower-native-install' or self.manifest.get('bytes')!=self.size:raise ValueError('Invalid embedded installation product')
    def payload(self):return Range(self.path,self.start,self.size)
    def verify_payload(self):
        digest=hashlib.sha256()
        with self.payload() as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
        if digest.hexdigest()!=self.manifest['sha256']:raise ValueError('Complete installation payload checksum mismatch')

def detect(path):
    path=Path(path)
    with path.open('rb') as stream:
        if path.stat().st_size<FOOTER.size:return None
        stream.seek(-FOOTER.size,2)
        if stream.read(16)!=MAGIC:return None
    return Source(path)
