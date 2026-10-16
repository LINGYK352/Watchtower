from pathlib import Path
import base64,hashlib,json,tempfile,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from windows_preview.signed_download import download,validate_url,signed_manifest,canonical
from windows_preview.setup import install_name,extract_component
import zipfile

class TransportTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.data=b'transport-fixture-'*4096;self.sha=hashlib.sha256(self.data).hexdigest();self.mode='normal';self.requests=[]
  owner=self
  class Handler(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    value=self.headers.get('Range','');owner.requests.append(value);start=int(value[6:-1]) if value else 0
    if owner.mode=='wrong-range':
     self.send_response(206);self.send_header('Content-Range','bytes 0-99/'+str(len(owner.data)));body=owner.data[:100]
    elif owner.mode=='ignore':self.send_response(200);body=owner.data
    elif owner.mode=='partial':
     self.send_response(206);body=owner.data[start:start+1024];self.send_header('Content-Range',f'bytes {start}-{start+len(body)-1}/{len(owner.data)}');owner.mode='normal'
    else:
     self.send_response(206 if value else 200);body=owner.data[start:]
     if value:self.send_header('Content-Range',f'bytes {start}-{len(owner.data)-1}/{len(owner.data)}')
    self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=self.server.serve_forever,daemon=True).start();self.url='http://127.0.0.1:'+str(self.server.server_port)+'/asset'
 def tearDown(self):self.server.shutdown();self.server.server_close();self.tmp.cleanup()
 def test_complete_verified(self):self.assertEqual(download(self.url,self.root,self.sha,len(self.data)).read_bytes(),self.data)
 def test_short_response_resumes(self):
  self.mode='partial'
  with self.assertRaises(ConnectionError):download(self.url,self.root,self.sha,len(self.data))
  self.assertEqual((self.root/(self.sha+'.part')).stat().st_size,1024)
  self.assertEqual(download(self.url,self.root,self.sha,len(self.data)).read_bytes(),self.data);self.assertEqual(self.requests[-1],'bytes=1024-')
 def test_ignored_range_restarts_without_append(self):
  (self.root/(self.sha+'.part')).write_bytes(self.data[:17]);self.mode='ignore';self.assertEqual(download(self.url,self.root,self.sha,len(self.data)).read_bytes(),self.data)
 def test_wrong_range_keeps_partial_untouched(self):
  part=self.root/(self.sha+'.part');part.write_bytes(self.data[:17]);self.mode='wrong-range'
  with self.assertRaises(ValueError):download(self.url,self.root,self.sha,len(self.data))
  self.assertEqual(part.read_bytes(),self.data[:17])
 def test_equal_size_complete_avoids_network(self):
  (self.root/(self.sha+'.part')).write_bytes(self.data);download(self.url,self.root,self.sha,len(self.data));self.assertEqual(self.requests,[])
 def test_equal_size_bad_hash_restarts(self):
  (self.root/(self.sha+'.part')).write_bytes(b'x'*len(self.data));self.assertEqual(download(self.url,self.root,self.sha,len(self.data)).read_bytes(),self.data)
 def test_corrupted_hash_not_activated(self):
  wrong='0'*64
  with self.assertRaises(ValueError):download(self.url,self.root,wrong,len(self.data))
  self.assertFalse((self.root/(wrong+'.asset')).exists())
 def test_cancel_preserves_partial(self):
  cancel=threading.Event();cancel.set()
  with self.assertRaises(InterruptedError):download(self.url,self.root,self.sha,len(self.data),cancel=cancel)
  self.assertFalse((self.root/(self.sha+'.asset')).exists())
 def test_external_http_and_credential_urls_rejected(self):
  for value in ['http://example.com/','https://user:pass@example.com/','file:///C:/data','https://example.com:bad/','\nhttps://example.com']:
   with self.assertRaises(ValueError):validate_url(value)
 def test_signed_manifest_wrong_signature(self):
  private=Ed25519PrivateKey.generate();public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw);data={'schema':1,'product':'test'}
  (self.root/'manifest.json').write_bytes(canonical(data));(self.root/'manifest.json.sig').write_bytes(base64.b64encode(private.sign(canonical(data))))
  self.assertEqual(signed_manifest(self.root,public,'test'),data)
  (self.root/'manifest.json').write_bytes(canonical({**data,'extra':True}))
  with self.assertRaises(Exception):signed_manifest(self.root,public,'test')
 def test_install_private_paths_rejected(self):
  for name in ['state/guest.key','开发源码/file','runtime/../state/file','engine/a:stream','versions/x/CON.txt']:
   with self.assertRaises(ValueError):install_name(name)
 def test_archive_traversal_does_not_escape(self):
  zip_path=self.root/'bad.zip';stage=self.root/'stage';stage.mkdir()
  with zipfile.ZipFile(zip_path,'w') as z:z.writestr('../outside',b'bad')
  with self.assertRaises(ValueError):extract_component(zip_path,stage,set())
  self.assertFalse((self.root/'outside').exists())

if __name__=='__main__':unittest.main()
