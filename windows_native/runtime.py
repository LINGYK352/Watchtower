from pathlib import Path
import json,os,socket,time,secrets,subprocess,hashlib
from urllib.parse import quote
import yaml,pymongo

HIDDEN=getattr(subprocess,'CREATE_NO_WINDOW',0)
def atomic(path,data):
 from windows_native.update_state import write
 write(path,data)
def private(path):
 path.mkdir(parents=True,exist_ok=True)
 import csv,io
 out=subprocess.check_output(['whoami','/user','/fo','csv','/nh'],creationflags=HIDDEN);sid=next(csv.reader(io.StringIO(out.decode('utf-8','replace'))))[1]
 subprocess.run(['icacls',str(path),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F'],check=True,capture_output=True,creationflags=HIDDEN)
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
class Runtime:
 def __init__(self,root,backend=None):
  self.root=Path(root).resolve();self.state=self.root/'state';private(self.state);self.mongo=None;self.service=None;self.backend=backend
  setting=self.state/'runtime.json'
  if setting.exists():
   from windows_native.update_state import read
   self.config=read(setting)
  else:
   self.config={'mongo_port':port(),'web_port':port(),'admin_user':'native_supervisor','admin_password':secrets.token_hex(32),'app_user':'native_app','app_password':secrets.token_hex(32),'db':'watchtower_native_test','control_token':secrets.token_hex(32)};atomic(setting,self.config)
  self.url='http://127.0.0.1:'+str(self.config['web_port'])
  if 'browser_port' not in self.config:
   self.config['browser_port']=port();atomic(setting,self.config)
 def client(self,admin=False):
  c=self.config;return pymongo.MongoClient(host='127.0.0.1',port=c['mongo_port'],username=c['admin_user' if admin else 'app_user'],password=c['admin_password' if admin else 'app_password'],authSource='admin',serverSelectionTimeoutMS=2000)
 def start(self,progress=None):
  if progress:progress('database',25)
  from sentinel_platform.core import process_control as process
  data=self.state/'mongo';data.mkdir(exist_ok=True);stop=self.state/'shutdown';stop.unlink(missing_ok=True)
  with (self.state/'mongo-console.log').open('ab') as log:
   self.mongo=process.popen([str(self.root/'runtime/mongodb/mongod.exe'),'--dbpath',str(data),'--port',str(self.config['mongo_port']),'--bind_ip','127.0.0.1','--auth','--wiredTigerCacheSizeGB','0.25','--setParameter','diagnosticDataCollectionEnabled=false','--logpath',str(self.state/'mongodb.log'),'--logappend'],stdout=log,stderr=log)
  deadline=time.monotonic()+40
  while time.monotonic()<deadline:
   if self.mongo.poll() is not None:raise RuntimeError('Native database exited; inspect state/mongodb.log')
   try:
    with pymongo.MongoClient('mongodb://127.0.0.1:'+str(self.config['mongo_port'])+'/',serverSelectionTimeoutMS=200) as c:c.admin.command('ping')
    break
   except pymongo.errors.PyMongoError:time.sleep(.1)
  else:raise RuntimeError('Native database startup timed out')
  marker=self.state/'db-initialized.json'
  if not marker.exists():
   with pymongo.MongoClient('mongodb://127.0.0.1:'+str(self.config['mongo_port'])+'/',serverSelectionTimeoutMS=2000) as c:
    c.admin.command('createUser',self.config['admin_user'],pwd=self.config['admin_password'],roles=['root'])
   with self.client(True) as c:c.admin.command('createUser',self.config['app_user'],pwd=self.config['app_password'],roles=[{'role':'readWrite','db':self.config['db']},{'role':'dbAdmin','db':self.config['db']}])
   atomic(marker,{'initialized':True})
  configuration=self.state/'config.yaml'
  if not configuration.exists():
   sample=yaml.safe_load((self.root/'app/config/config.yaml.example').read_text(encoding='utf-8'));c=self.config
   sample['MONGO']={'URI':'mongodb://'+c['app_user']+':'+quote(c['app_password'],safe='')+'@127.0.0.1:'+str(c['mongo_port'])+'/?authSource=admin','DB':c['db']}
   account_path=self.state/'install-account.json'
   if not account_path.is_file():raise ValueError('Initial installation requires an administrator account')
   account=json.loads(account_path.read_text(encoding='utf-8'))
   sample['SENTINEL'].update(AUTH=True,API_KEY=secrets.token_hex(32),SALT=secrets.token_hex(32),DEFAULT_ADMIN_USER=account['username'],DEFAULT_ADMIN_PASS=account['password'])
   sample['UPDATE'].update(CHECK_REMOTE=False,KEY='');sample['ACTIVATION']={'ENFORCE':True};sample['CELERY']={};sample['NATIVE']={'TEST':False}
   for section,key,folder in [('AI_EXTENSION','ROOT','extensions'),('SCREENSHOT','DIR','screenshots'),('TEMPLATE','DIR','templates')]:
    sample.setdefault(section,{})[key]=str(self.state/folder)
   configuration.write_text(yaml.safe_dump(sample,allow_unicode=True),encoding='utf-8')
   account_path.unlink()
  if progress:progress('service',60)
  result=self.start_service()
  if progress:progress('workspace',90)
  return result
 def start_service(self):
  from sentinel_platform.core import process_control as process
  (self.state/'shutdown').unlink(missing_ok=True)
  self.boot=secrets.token_hex(16)
  command=[str(self.backend),'--root',str(self.root),'--boot',self.boot] if self.backend else [__import__('sys').executable,'-m','windows_native.backend','--root',str(self.root),'--boot',self.boot]
  with (self.state/'service.log').open('ab') as log:self.service=process.popen(command,stdout=log,stderr=log)
  atomic(self.state/'processes.json',{'mongo_pid':self.mongo.pid,'service_pid':self.service.pid,'boot':self.boot})
  import urllib.request
  deadline=time.monotonic()+45
  while time.monotonic()<deadline:
   if self.service.poll() is not None:raise RuntimeError('Native API exited; inspect state/service.log')
   try:
    request=urllib.request.Request(self.url+'/__native_ready',headers={'X-Native-Control':self.config['control_token']})
    with urllib.request.urlopen(request,timeout=1) as r:
     if json.load(r).get('ready'):return self.url
   except (OSError,ValueError):time.sleep(.1)
  raise RuntimeError('Native API startup timed out')
 def stop_service(self):
  from sentinel_platform.core import process_control as process
  (self.state/'shutdown').touch()
  if self.service is not None:
   try:self.service.wait(timeout=8)
   except subprocess.TimeoutExpired:process.terminate_tree(self.service)
   process.close(self.service)
 def stop(self):
  from sentinel_platform.core import process_control as process
  self.stop_service()
  if self.mongo is not None:
   try:
    with self.client(True) as c:c.admin.command('shutdown',force=False)
   except pymongo.errors.AutoReconnect:pass
   except pymongo.errors.PyMongoError:pass
   try:self.mongo.wait(timeout=8)
   except subprocess.TimeoutExpired:process.terminate_tree(self.mongo)
   process.close(self.mongo)
