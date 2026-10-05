"""Controlled local test handlers, never a production tool or API."""
from pathlib import Path
import json,sys

def register(root):
 import yaml
 settings=yaml.safe_load((Path(root)/'state/config.yaml').read_text(encoding='utf-8')) or {}
 if not settings.get('NATIVE',{}).get('TEST',False):return
 from sentinel_platform.modules.kernel import orchestration as tasks
 from sentinel_platform.modules.kernel.recon.tools.httpx import Httpx
 from sentinel_platform.modules.kernel.recon.base import ExternalTool,ToolCancelled
 def http(task_id,ctx):
  url=ctx.options['url']
  if not url.startswith('http://127.0.0.1:'):raise ValueError('QA fixture must remain loopback')
  tool=Httpx(binary_path=str(root/'runtime/tools/httpx.exe'),timeout=20);tool.cancel_check=lambda:tasks._read_status(task_id) in tasks._STOP_STATES
  rows=tool.probe([url],concurrency=1)
  tasks.get_repo().collection('native_qa_results').insert_one({'task_id':task_id,'hits':len(rows),'urls':[getattr(v,'url','') for v in rows]})
  return {'recon':'done','hits':len(rows)}
 class Tree(ExternalTool):
  binary=sys.executable;adapter='native_qa_tree'
  def build_argv(self,**kwargs):
   if getattr(sys,'frozen',False):return ['--root',str(root),'--boot','controlled-native-qa','--qa-tree']
   script=str(root/'state/qa-child.py');Path(script).write_text("import subprocess,sys,time; c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);open(sys.argv[1],'w').write(str(c.pid));time.sleep(60)")
   return ['-c',Path(script).read_text(),str(root/'state/qa-child.pid')]
 def tree(task_id,ctx):
  tool=Tree(timeout=30);tool.cancel_check=lambda:tasks._read_status(task_id) in tasks._STOP_STATES
  try:tool.run()
  except ToolCancelled:return {'recon':'stopped'}
  return {'recon':'done'}
 tasks.register_handler('_native_qa_http',http);tasks.register_handler('_native_qa_tree',tree)
