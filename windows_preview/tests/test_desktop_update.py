from pathlib import Path
import base64, hashlib, json, tempfile, unittest, zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from windows_preview import desktop_update as updater


class DesktopUpdateTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.base='v1.21.167-6-build1';self.target='v1.21.167-6-build2'
        self.current=self.root/'versions'/self.base;self.current.mkdir(parents=True)
        (self.current/'app.exe').write_bytes(b'old app');(self.current/'obsolete.txt').write_bytes(b'old asset')
        (self.root/'state').mkdir();(self.root/'state/user-secret.txt').write_bytes(b'data stays private')
        (self.root/'active.json').write_text(json.dumps({'version':self.base}))
        self.key=Ed25519PrivateKey.generate()
        self.public=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    def tearDown(self):self.temp.cleanup()
    def bundle(self, changes=None, complete=None, **overrides):
        changes=changes if changes is not None else {'app.exe':b'new app'}
        complete=complete if complete is not None else {n:hashlib.sha256(b).hexdigest() for n,b in changes.items()}
        manifest={'schema':1,'product':updater.PRODUCT,'base':self.base,'target':self.target,
                  'files':complete,'changes':{n:hashlib.sha256(b).hexdigest() for n,b in changes.items()}}
        manifest.update(overrides)
        path=self.root/'update.zip'
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('manifest.json',updater.canonical(manifest))
            archive.writestr('manifest.sig',base64.b64encode(self.key.sign(updater.canonical(manifest))))
            for name,data in changes.items():archive.writestr('files/'+name,data)
        return path
    def apply(self,path,health=True):return updater.apply(self.root,path,self.public,lambda folder,meta:health)
    def assert_base_retained(self):
        self.assertEqual(updater.active(self.root)['version'],self.base)
        self.assertEqual((self.current/'app.exe').read_bytes(),b'old app')
        self.assertEqual((self.root/'state/user-secret.txt').read_bytes(),b'data stays private')
    def test_success_switches_only_after_health_and_keeps_user_data(self):
        self.apply(self.bundle())
        self.assertEqual(updater.active(self.root)['version'],self.target)
        self.assertFalse((self.root/'versions'/self.target/'obsolete.txt').exists())
        self.assertEqual((self.current/'obsolete.txt').read_bytes(),b'old asset')
        self.assertEqual((self.root/'state/user-secret.txt').read_bytes(),b'data stays private')
    def test_unchanged_file_must_match_full_target_manifest(self):
        files={'app.exe':hashlib.sha256(b'old app').hexdigest(),'new.txt':hashlib.sha256(b'new').hexdigest()}
        self.apply(self.bundle({'new.txt':b'new'},files))
        self.assertEqual((self.root/'versions'/self.target/'app.exe').read_bytes(),b'old app')
    def test_wrong_base_rejected(self):
        with self.assertRaises(updater.UpdateError):self.apply(self.bundle(base='v1.21.167-5-build1'))
        self.assert_base_retained()
    def test_signature_from_other_publisher_rejected(self):
        path=self.bundle();other=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        with self.assertRaises(updater.UpdateError):updater.apply(self.root,path,other,lambda *args:True)
        self.assert_base_retained()
    def test_payload_tampering_rejected(self):
        path=self.bundle()
        with zipfile.ZipFile(path,'a') as archive:archive.writestr('files/app.exe',b'tampered')
        with self.assertRaises(updater.UpdateError):self.apply(path)
        self.assert_base_retained()
    def test_hash_mismatch_rejected(self):
        with self.assertRaises(updater.UpdateError):self.apply(self.bundle(complete={'app.exe':'0'*64}))
        self.assert_base_retained()
    def test_user_data_and_absolute_traversal_rejected(self):
        for name in ['../state/user-secret.txt','state/user-secret.txt','/app.exe','C:/app.exe','app.exe:stream','sub\\app.exe']:
            with self.subTest(name=name),self.assertRaises(updater.UpdateError):self.apply(self.bundle({name:b'bad'}))
            self.assert_base_retained()
    def test_health_failure_keeps_pointer_and_allows_retry(self):
        path=self.bundle()
        with self.assertRaises(updater.UpdateError):self.apply(path,False)
        self.assert_base_retained()
        self.assertFalse((self.root/'versions'/self.target).exists())
        self.apply(path,True)
        self.assertEqual(updater.active(self.root)['version'],self.target)
    def test_parallel_update_lock_is_exclusive(self):
        with updater.update_lock(self.root):
            with self.assertRaises(updater.UpdateError):self.apply(self.bundle())
        self.assert_base_retained()
    def test_wrong_product_rejected(self):
        with self.assertRaises(updater.UpdateError):self.apply(self.bundle(product='other-product'))
        self.assert_base_retained()
    def test_interrupted_activation_recovers_without_touching_data(self):
        path=self.bundle()
        target=self.root/'versions'/self.target;target.mkdir();(target/'partial.exe').write_bytes(b'interrupted')
        (self.root/'state/desktop-update.json').write_text(json.dumps({'phase':'prepared','base':self.base,'target':self.target}))
        self.apply(path)
        self.assertEqual(updater.active(self.root)['version'],self.target)
        self.assertTrue(list((self.root/'versions').glob('.recovery-*')))
        self.assertEqual((self.root/'state/user-secret.txt').read_bytes(),b'data stays private')

if __name__=='__main__':unittest.main()
