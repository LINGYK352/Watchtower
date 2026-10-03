from pathlib import Path
import ast,json,os,tempfile,unittest
from unittest.mock import patch
import yaml
from sentinel_platform.core import deployment_profile as profile

class DeploymentProfileTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);(self.root/'docker').mkdir()
  self.original={'services':{'web':{'image':'sentinel:runtime-v1','volumes':['../:/opt/sentinel/current']},'rabbitmq':{'environment':{'RABBITMQ_DEFAULT_PASS':'${WT_BROKER_PASSWORD}'}}}}
  self.path=self.root/'docker/docker-compose.yml';self.path.write_text(yaml.safe_dump(self.original,sort_keys=False),encoding='utf-8')
 def tearDown(self):self.tmp.cleanup()
 def managed(self):
  (self.root/profile.PROFILE).write_text(json.dumps({'schema':1,'contract':1,'runtime_abi':'linux-amd64-py311-v1','preserve_compose_paths':[['services','web','image'],['services','web','volumes'],['services','rabbitmq','environment','RABBITMQ_DEFAULT_PASS']]}))
 def staged(self,value):
  file=self.root/'incoming.yml';file.write_text(yaml.safe_dump(value,sort_keys=False),encoding='utf-8');return file
 def test_default_web_is_passthrough(self):
  stage=self.staged({'services':{'web':{'image':'sentinel:base'}}});before=stage.read_bytes();out=profile.prepare(self.root,[('docker/docker-compose.yml',stage)],{})
  self.assertEqual(out,[('docker/docker-compose.yml',stage)]);self.assertEqual(stage.read_bytes(),before);profile.validate(self.root,{})
 def test_managed_preserves_images_volumes_and_password_reference(self):
  self.managed();incoming={'services':{'web':{'image':'sentinel:base','volumes':['bad:/data'],'command':'new'},'rabbitmq':{'environment':{'RABBITMQ_DEFAULT_PASS':'default','NEW':'new'}}}};stage=self.staged(incoming);upstream=profile.digest(stage)
  out=profile.prepare(self.root,[('docker/docker-compose.yml',stage)],{'docker/docker-compose.yml':upstream});result=yaml.safe_load(stage.read_text(encoding='utf-8'))
  self.assertEqual(result['services']['web']['image'],'sentinel:runtime-v1');self.assertEqual(result['services']['web']['volumes'],self.original['services']['web']['volumes']);self.assertEqual(result['services']['web']['command'],'new');self.assertEqual(result['services']['rabbitmq']['environment']['RABBITMQ_DEFAULT_PASS'],'${WT_BROKER_PASSWORD}')
  os.replace(stage,self.path);self.assertEqual(profile.source_hash(self.root,'docker/docker-compose.yml',profile.digest(self.path)),upstream)
 def test_effectively_identical_compose_is_not_recreated(self):
  self.managed();incoming=json.loads(json.dumps(self.original));incoming['services']['web']['image']='sentinel:base';stage=self.staged(incoming);upstream=profile.digest(stage)
  self.assertEqual(profile.prepare(self.root,[('docker/docker-compose.yml',stage)],{'docker/docker-compose.yml':upstream}),[]);self.assertEqual(profile.source_hash(self.root,'docker/docker-compose.yml',profile.digest(self.path)),upstream)
 def test_receipt_does_not_hide_manual_file_change(self):
  self.managed();state=self.root/profile.STATE;state.mkdir();(state/'overlays.json').write_text(json.dumps({'docker/docker-compose.yml':{'effective':'old','upstream':'claimed'}}))
  self.assertEqual(profile.source_hash(self.root,'docker/docker-compose.yml','new'),'new')
 def test_missing_contract_and_wrong_abi_rejected(self):
  self.managed()
  for data in [{},{'deployment_contract':1,'runtime_abi':'different'},{'deployment_contract':1,'runtime_abi':'linux-amd64-py311-v1','manifest':{}}]:
   with self.assertRaises(ValueError):profile.validate(self.root,data)
 def test_supported_contract_accepted(self):
  self.managed();profile.validate(self.root,{'deployment_contract':1,'runtime_abi':'linux-amd64-py311-v1','manifest':{profile.SELF:'a',profile.UPDATER:'b'}})
 def test_updater_without_shared_contract_rejected(self):
  self.managed();stage=self.root/'bad.py';stage.write_text('x=1')
  with self.assertRaises(ValueError):profile.prepare(self.root,[(profile.UPDATER,stage)],{})
 def test_removed_managed_service_rejected(self):
  self.managed();stage=self.staged({'services':{'rabbitmq':{}}})
  with self.assertRaises(ValueError):profile.prepare(self.root,[('docker/docker-compose.yml',stage)],{'docker/docker-compose.yml':'hash'})
 def test_shared_update_lock_rejects_concurrency(self):
  with profile.transaction(self.root):
   with self.assertRaises(RuntimeError):
    with profile.transaction(self.root):pass
 def test_missing_managed_profile_is_not_default_web(self):
  state=self.root/profile.STATE;state.mkdir();(state/'managed.json').write_text('{}')
  with self.assertRaises(ValueError):profile.load(self.root)

if __name__=='__main__':unittest.main()
