from windows_preview.frontend_update import APPLY_SCRIPT as SCRIPT, validate_bundle

from pathlib import Path
import unittest,tempfile,tarfile,hashlib,io,json,contextlib
@unittest.skipIf(__import__('os').name == 'nt', 'Guest filesystem and flock cases run inside the local Linux test guest')
class FrontendUpdateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.stage=Path(self.tmp.name);self.root=self.stage/'core';self.state=self.stage/'state';self.root.mkdir()
  (self.root/'docker/frontend').mkdir(parents=True);(self.root/'version.txt').write_text('v1.21.167-8');(self.root/'docker/frontend/index.html').write_text('old index');(self.root/'docker/frontend/unchanged.png').write_bytes(b'unchanged')
  (self.root/'config').mkdir();(self.root/'config/config.yaml').write_text('private configuration must remain')
  self.payload={'version.txt':b'v1.21.167-10','changelog.json':b'[]','docker/frontend/index.html':b'new index'}
  self.files={name:hashlib.sha256(data).hexdigest() for name,data in self.payload.items()};self.files['docker/frontend/unchanged.png']=hashlib.sha256(b'unchanged').hexdigest()
 def tearDown(self):self.tmp.cleanup()
 def bundle(self,extra=None,duplicate=False,symlink=False):
  archive=self.stage/'frontend-update.tar.gz'
  changes={n:self.files[n] for n in self.payload}
  manifest={'version':'v1.21.167-10','files':self.files,'changes':changes}
  with tarfile.open(archive,'w:gz') as tar:
   def add(name,data):
    info=tarfile.TarInfo(name);info.size=len(data);tar.addfile(info,io.BytesIO(data))
   add('frontend-manifest.json',json.dumps(manifest).encode())
   for name,data in self.payload.items():
    if symlink and name=='docker/frontend/index.html':
     info=tarfile.TarInfo(name);info.type=tarfile.SYMTYPE;info.linkname='../config/config.yaml';tar.addfile(info)
    else:add(name,data)
   if duplicate:add('version.txt',self.payload['version.txt'])
  self.expected={'version':'v1.21.167-10','sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
 def apply(self):
  code=SCRIPT.replace("root=Path('/opt/sentinel/sentinel').resolve()",'root=Path('+repr(str(self.root))+').resolve()').replace("state=Path('/opt/watchtower-preview')",'state=Path('+repr(str(self.state))+')').replace('expected=EXPECTED','expected='+repr(self.expected))
  out=io.StringIO()
  try:
   with contextlib.redirect_stdout(out):exec(compile(code,'<fixture>','exec'),{'__file__':str(self.stage/'apply.py'),'__name__':'__main__'})
  except SystemExit as e:
   if e.code!=0:raise
  return json.loads(out.getvalue().strip())
 def assert_old(self):
  self.assertEqual((self.root/'version.txt').read_text(),'v1.21.167-8');self.assertEqual((self.root/'docker/frontend/index.html').read_text(),'old index');self.assertEqual((self.root/'config/config.yaml').read_text(),'private configuration must remain')
 def test_apply_keeps_configuration_and_unchanged_assets(self):
  self.bundle();self.assertEqual(self.apply()['status'],'applied');self.assertEqual((self.root/'docker/frontend/index.html').read_text(),'new index');self.assertEqual((self.root/'config/config.yaml').read_text(),'private configuration must remain');self.assertEqual((self.root/'docker/frontend/unchanged.png').read_bytes(),b'unchanged')
 def test_repeat_does_not_create_duplicate_backup(self):
  self.bundle();self.apply();before=list((self.root/'.update_backup').iterdir());self.assertEqual(self.apply()['status'],'current');self.assertEqual(list((self.root/'.update_backup').iterdir()),before)
 def test_corrupted_transfer_rejected_before_writes(self):
  self.bundle();(self.stage/'frontend-update.tar.gz').write_bytes(b'bad')
  with self.assertRaisesRegex(RuntimeError,'hash mismatch'):self.apply()
  self.assert_old()
 def test_member_hash_rejected_before_writes(self):
  self.files['docker/frontend/index.html']='0'*64;self.bundle()
  with self.assertRaisesRegex(RuntimeError,'member hash'):self.apply()
  self.assert_old()
 def test_non_frontend_config_changes_rejected(self):
  name='config/config.yaml';self.payload[name]=b'bad';self.files[name]=hashlib.sha256(b'bad').hexdigest();self.bundle()
  with self.assertRaisesRegex(RuntimeError,'Non-frontend'):self.apply()
  self.assert_old()
 def test_duplicate_members_rejected(self):
  self.bundle(duplicate=True)
  with self.assertRaisesRegex(RuntimeError,'Duplicate'):self.apply()
  self.assert_old()
 def test_symlink_rejected(self):
  self.bundle(symlink=True)
  with self.assertRaisesRegex(RuntimeError,'Non-regular'):self.apply()
  self.assert_old()
 def test_wrong_unchanged_baseline_rejected(self):
  self.bundle();(self.root/'docker/frontend/unchanged.png').write_bytes(b'altered')
  with self.assertRaisesRegex(RuntimeError,'baseline'):self.apply()
  self.assert_old()
 def test_newer_core_is_not_downgraded(self):
  self.bundle();(self.root/'version.txt').write_text('v1.21.167-11');self.assertEqual(self.apply()['status'],'newer-core-preserved');self.assertEqual((self.root/'version.txt').read_text(),'v1.21.167-11');self.assertEqual((self.root/'docker/frontend/index.html').read_text(),'old index')
 def test_partial_update_resumes(self):
  self.bundle();(self.root/'version.txt').write_text('v1.21.167-10');self.assertEqual(self.apply()['status'],'applied');self.assertEqual((self.root/'docker/frontend/index.html').read_text(),'new index')
 def test_traversal_rejected(self):
  name='docker/frontend/../config.yaml';self.payload[name]=b'bad';self.files[name]=hashlib.sha256(b'bad').hexdigest();self.bundle()
  with self.assertRaisesRegex(RuntimeError,'Invalid'):self.apply()
  self.assert_old()
if __name__ == '__main__': unittest.main()
