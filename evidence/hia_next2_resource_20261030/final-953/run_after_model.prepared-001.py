#!/usr/bin/env python3
"""Prepared only: invoke after root releases the model window. No native/model run."""
from pathlib import Path
from hashlib import sha256
import json,subprocess,time,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
RAW=HERE.parent/'p1-p2-scoped-cleanup-final-launches-20261030'
PYTHON=str(HERE.parent/'hepta-native-venv/bin/python')
def identity(p):
 b=p.read_bytes();return {'bytes':len(b),'sha256':sha256(b).hexdigest()}
def save(p,value):p.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def command(label,argv,timeout):
 directory=HERE/label;directory.mkdir(exist_ok=False)
 row={'label':label,'argv':argv,'timeout_seconds':timeout,'status':'starting','native_model_or_archived_code_executed':False}
 started=time.monotonic_ns();save(directory/'EXECUTION.json',row)
 try:
  result=subprocess.run(argv,capture_output=True,timeout=timeout)
  row.update(returncode=result.returncode,status='completed' if result.returncode==0 else 'failed')
  (directory/'stdout').write_bytes(result.stdout);(directory/'stderr').write_bytes(result.stderr)
  row.update(stdout=identity(directory/'stdout'),stderr=identity(directory/'stderr'))
 except BaseException as error:
  row.update(status='failed',error=type(error).__name__+': '+str(error))
  for field in ('stdout','stderr'):
   value=getattr(error,field,None)
   if value is not None:
    if isinstance(value,str):value=value.encode()
    (directory/field).write_bytes(value);row[field]=identity(directory/field)
 finally:
  row['outer_wall_ns']=time.monotonic_ns()-started
  row['wall_scope']='through child wait and raw persistence; terminal execution receipt outside interval'
  save(directory/'EXECUTION.json',row)
 if row['status']!='completed':raise RuntimeError(label+' failed; retained attempt is not overwritten')
 return row
assert len(sys.argv)==1
assert not (HERE/'evidence.tar.xz').exists() and not (HERE/'directory-readback').exists()
source=json.loads((RAW/'PLAN.json').read_bytes())
assert source['source_head']=='953fa62dee5aa563551d57b1374ab95b6d548b45'
rows=[]
rows.append(command('directory-readback',[PYTHON,'-B',str(RAW/'verify.py'),str(RAW)],30))
rows.append(command('bundle-execution',[PYTHON,'-B',str(HERE/'build_bundle.py')],60))
manifest_sha=identity(HERE/'MANIFEST.json')['sha256']
rows.append(command('archive-readback',[PYTHON,'-B',str(HERE/'verify_archive.py'),str(HERE/'evidence.tar.xz'),str(HERE/'MANIFEST.json'),manifest_sha],30))
save(HERE/'POST_MODEL_EXECUTIONS.json',{'schema':'hepta.scoped-cleanup.953-post-model-executions.v1','source_head':source['source_head'],'stages':rows,'status':'completed','nested_costs_not_added':True,'full_human_agent_development_cost':None})
print(json.dumps({'status':'completed','archive':identity(HERE/'evidence.tar.xz'),'manifest_sha256':manifest_sha},sort_keys=True))
