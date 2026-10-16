from pathlib import Path
import base64,json,tempfile,unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from windows_preview import online_update as updater
from windows_preview.signed_download import canonical

class OnlineUpdateTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.feed=self.root/'feed';self.feed.mkdir();self.base='v1.21.167-11-build1'
  (self.root/'active.json').write_text(json.dumps({'version':self.base}));(self.root/'update-channel.json').write_text(json.dumps({'channel':'testing','source':str(self.feed)}))
  self.private=Ed25519PrivateKey.generate();self.public=self.private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
  self.keypatch=patch.object(updater,'PUBLIC_KEY',base64.b64encode(self.public).decode());self.keypatch.start()
 def tearDown(self):self.keypatch.stop();self.tmp.cleanup()
 def publish(self,releases,channel='testing'):
  data={'schema':1,'product':updater.CHANNEL_PRODUCT,'channel':channel,'releases':releases};raw=canonical(data)
  (self.feed/'channel.json').write_bytes(raw);(self.feed/'channel.json.sig').write_bytes(base64.b64encode(self.private.sign(raw)))
 def offer(self,**kw):return {'base':self.base,'target':'v1.21.167-11-build2','file':'update.zip','runtime_abi':'linux-amd64-py311-v1',**kw}
 def test_matching_upgrade_selected(self):
  self.publish([self.offer()]);self.assertEqual(updater.check(self.root)['release']['target'],'v1.21.167-11-build2')
 def test_wrong_base_not_selected(self):
  self.publish([self.offer(base='v1.21.167-10-build2')]);self.assertFalse(updater.check(self.root)['available'])
 def test_downgrade_not_selected(self):
  self.publish([self.offer(target='v1.21.167-10-build3')]);self.assertFalse(updater.check(self.root)['available'])
 def test_final_release_orders_after_test(self):self.assertGreater(updater.version_key('v1.21.167-build1'),updater.version_key('v1.21.167-99-build99'))
 def test_wrong_channel_rejected(self):
  self.publish([self.offer()],channel='stable')
  with self.assertRaises(ValueError):updater.check(self.root)
 def test_wrong_runtime_rejected(self):
  self.publish([self.offer(runtime_abi='different')])
  with self.assertRaises(ValueError):updater.check(self.root)
 def test_tampered_metadata_rejected(self):
  self.publish([self.offer()]);data=json.loads((self.feed/'channel.json').read_text());data['releases'][0]['target']='v9.9.9-build1';(self.feed/'channel.json').write_bytes(canonical(data))
  with self.assertRaises(Exception):updater.check(self.root)
 def test_missing_source_is_not_network_failure(self):
  (self.root/'update-channel.json').write_text(json.dumps({'source':''}));self.assertIsNone(updater.check(self.root))

if __name__=='__main__':unittest.main()
