from pathlib import Path

import io,json,os,uuid
from unittest.mock import patch
from types import SimpleNamespace
from hepta import hia_agent_worker as w
from hepta.hia_worker_report_native import installed_worker_report
from hashlib import sha256
ident={'worker_sha256':'a'*64,'backend_sha256':'b'*64,'catalog_sha256':'c'*64}
request={'schema':'hia-agent-worker-request-v1','tool':'hia_status','arguments':{},'profile_sha256':'d'*64,'catalog_sha256':'c'*64}
request['request_sha256']=sha256(w.wire(request)).hexdigest()
raw=w.wire(request)
owner=installed_worker_report('/workspace/scratch/e26ed3e2edcf/worker-report-development-r1/manifest.json')
args=SimpleNamespace(installation_manifest=False,request_json_stdin=True,state_root='/unused',artifact_root=[],expected_worker_sha256=None,expected_backend_sha256=None,expected_catalog_sha256=None)
class P:
 def error(self,message): raise ValueError(message)
def one(native,kind):
 events=[];out=io.BytesIO();err=io.StringIO()
 class S:
  def __init__(self,*a,**kw): events.append('construct')
  def call(self,*a):
   events.append('call')
   if kind=='value': raise ValueError('bad')
   if kind=='runtime': raise RuntimeError('bad')
   return {'status':'completed','a':1.5}
  def close(self): events.append('close')
 def after():
  events.append('after')
  return {**ident,**({'extra':1} if kind=='extra' else {})}
 with patch.dict(os.environ,{},clear=True),patch('hepta.hia_agent_service.HIAAgentService',S),patch.object(w,'installation_manifest',after),patch.object(w.uuid,'uuid4',return_value=uuid.UUID(int=1)),patch.object(w.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))),patch.object(w.sys,'stdout',SimpleNamespace(buffer=out)),patch.object(w.sys,'stderr',err):
  try:
   code=owner.run(args,P(),dict(ident),w) if native else w._reference_run(args,P(),dict(ident))
   result=['return',code]
  except BaseException as e: result=['raise',type(e).__name__,str(e)]
 return {'result':result,'events':events,'out':out.getvalue().decode(),'err':err.getvalue()}
results=[]
for kind in ['success','extra','value','runtime']:
 old=one(False,kind);new=one(True,kind)
 results.append({'case':kind,'same':old==new,'old':old,'new':new})
Path('/workspace/scratch/e26ed3e2edcf/worker-report-basic-r1-results.json').write_text(json.dumps(results,indent=2))
print(json.dumps([{k:v for k,v in r.items() if k in ('case','same')} for r in results]))
assert all(r['same'] for r in results)
