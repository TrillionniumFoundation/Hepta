from pathlib import Path
from hashlib import sha256
from contextlib import ExitStack
import json, os, subprocess, sys, time, gzip, base64
from unittest.mock import patch

os.nice(10)
old=Path('/var/tmp/he26journal/development-r4-rog')
oldfiles={name:base64.b64encode((old/name).read_bytes()).decode() for name in ('selected-callers.json','selected-callers.log','dedicated.log','run-observations.json','development-build.json','selector-cache-controls.json')}
oldraw=json.dumps(oldfiles,sort_keys=True).encode()
oldpack={'gzip_base64':base64.b64encode(gzip.compress(oldraw,mtime=0)).decode(),'sha256':sha256(oldraw).hexdigest(),'bytes':len(oldraw)}
(old/'compact-original-evidence.json').write_text(json.dumps(oldpack)+'\n')

root=Path('/var/tmp/he26journal')
checkout=root/'s'
commit='3335436fddece200bb466374211ef4ea0fe59a2d'
original=Path('/var/tmp/he26v63/s')
before=subprocess.check_output(['git','-C',str(original),'rev-parse','HEAD'],text=True).strip()
assert before=='93d66bcc3acb88212c9b153d7852ba22eeab24c8'
assert not subprocess.check_output(['git','-C',str(checkout),'status','--porcelain'],text=True).strip()
subprocess.run(['git','-C',str(checkout),'fetch','--no-tags','https://github.com/TrillionniumFoundation/Hepta.git',commit],check=True)
subprocess.run(['git','-C',str(checkout),'checkout','--detach',commit],check=True)
assert subprocess.check_output(['git','-C',str(original),'rev-parse','HEAD'],text=True).strip()==before
os.chdir(checkout);sys.path.insert(0,str(checkout))
out=root/'development-r9-rog';out.mkdir(mode=0o700)
from tools.qualify_hia_selfhost import compile_stage
compiler=Path('/var/tmp/he26v63/q/cold.cold/qualification.evidence/B3.image.bin')
compiler_sha=sha256(compiler.read_bytes()).hexdigest()
assert compiler_sha=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
specs=[('agent_journal','agent-journal','hepta.hia.agent-journal-native.v2','journal'),
       ('core_patch','core-patch','hepta.hia.core-patch-native.v1','candidate'),
       ('core_admission','core-admission','hepta.hia.core-admission-native.v1','candidate'),
       ('agent_data_json','agent-data-json','hepta.hia.agent-data-json-native.v1','data'),
       ('json_preflight','json-preflight','hepta.hia.json-preflight-native.v1','preflight'),
       ('worker_request','worker-request','hepta.hia.worker-request-native.v1','worker')]
manifests={};builds={}
for stem,label,schema,foldername in specs:
 folder=out/foldername;folder.mkdir(mode=0o700,exist_ok=True)
 source=(checkout/'examples/hia_bootstrap'/f'{stem}.hiaasm').read_bytes()
 image,receipt=compile_stage(folder,label,compiler,source)
 manifest={'schema':schema,'source_sha256':sha256(source).hexdigest(),'image_path':image.name,
           'image_sha256':sha256(image.read_bytes()).hexdigest(),'compiler_sha256':compiler_sha}
 name='admission-manifest.json' if label=='core-admission' else 'manifest.json'
 path=folder/name;path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
 manifests[label]=str(path);builds[label]={'manifest':manifest,'receipt':receipt}
assert builds['agent-journal']['manifest']['image_sha256']=='7846c445c22236e2c9c694af5bb5928588c67ade966cbf8b0f96e389c09bcac8'
(out/'development-build.json').write_text(json.dumps({'commit':commit,'scope':'DEVELOPMENT_ONLY_NOT_CURRENT_SOURCE_COLD','python':sys.version,'executable':sys.executable,'builds':builds},indent=2,sort_keys=True)+'\n')
env=os.environ.copy()
for key in tuple(env):
 if key.startswith('HEPTA_HIA_') and key.endswith(('_MANIFEST','_COLD_REPORT')):
  env.pop(key)
env['HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST']=manifests['agent-journal']
env['HEPTA_HIA_AGENT_CANDIDATE_DEVELOPMENT_MANIFEST']=manifests['core-patch']
env['HEPTA_HIA_WORKER_REQUEST_DEVELOPMENT_MANIFEST']=manifests['worker-request']
from tools.qualify_hia_agent_journal_callers import DEFAULT_MODULES
command=[sys.executable,'-B','-m','tools.qualify_hia_agent_journal_callers','--manifest',manifests['agent-journal'],
         '--development','--output',str(out/'selected-callers.json'),
         '--exclude','tests.test_hia_agent_native_tools.ArtifactContractTests.test_discovery_is_readable_and_source_bound=Unmerged-development-source-requires-root-global-contract-integration']
for module in DEFAULT_MODULES:
 command+=['--module',module]
runs={}
for name,command in [('selected-callers',command),
                     ('dedicated',[sys.executable,'-B','-m','unittest','-v','tests.test_hia_agent_journal_native'])]:
 with (out/(name+'.log')).open('wb') as log:
  started=time.monotonic()
  result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=420)
  runs[name]={'returncode':result.returncode,'wall_seconds':time.monotonic()-started,'command':command}
 (out/'run-observations.json').write_text(json.dumps(runs,indent=2,sort_keys=True)+'\n')
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import wire
from hepta.hia_agent_journal_native import SELECTOR
payloads=[b'"\xff"',b'"\xe2("',b'"\xe2\x82',b'"\xed\xa0\x80"',
          b'\xff'+b' '*(8<<20),'{"bad":','"\\uQQQQ"','1e','[1.2e,0]',
          '{"a":1,"\\u0061":2}','['*129+'0'+']'*129,'{"z":1,"status":"rejected","a":2}',
          '{"status":"rejected","number":1.25}','{"number":1e400}','"\\u𐐷']
controls=[]
for mode in ('data','preflight','both'):
 selection={}
 if mode in ('data','both'):selection['HEPTA_HIA_AGENT_DATA_JSON_MANIFEST']=manifests['agent-data-json']
 if mode in ('preflight','both'):selection['HEPTA_HIA_JSON_PREFLIGHT_MANIFEST']=manifests['json-preflight']
 for index,payload in enumerate(payloads):
  observations=[]
  for native in (False,True):
   service=HIAAgentService(out/f'cache-{mode}-{index}-{native}')
   args={'request_key':'selected-cache'}
   digest=sha256(wire({'tool':'hia_artifact','arguments':args})).hexdigest()
   key=sha256(wire({'tool':'hia_artifact','key':args['request_key']})).hexdigest()
   service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',(key,digest,'hia_artifact','completed',payload,'1'))
   with ExitStack() as stack:
    stack.enter_context(patch.dict(os.environ,selection))
    stack.enter_context(patch('hepta.hia_agent_service.time.monotonic_ns',side_effect=[1,9]))
    stack.enter_context(patch.object(service,'_hia_artifact',side_effect=AssertionError('cached JSON reran effect')))
    if native:
     stack.enter_context(patch.dict(os.environ,{SELECTOR:manifests['agent-journal']}))
     stack.enter_context(patch.object(HIAAgentService,'_reference_call',side_effect=AssertionError('retained journal owner')))
    response=service.call('hia_artifact',args) if native else service._reference_call('hia_artifact',args)
   row=service.store.db.execute('SELECT response FROM requests WHERE key=?',(key,)).fetchone()[0]
   assert type(row) is type(payload) and row==payload
   costs=[dict(r) for r in service.store.db.execute('SELECT * FROM costs')]
   observations.append({'response':response,'costs':costs,'cache_unchanged':True})
   service.close()
  controls.append({'mode':mode,'case':index,'raw_size':len(payload),'equal':observations[0]==observations[1],'observations':observations})
(out/'selector-cache-controls.json').write_text(json.dumps({'scope':'DEVELOPMENT_ONLY_EXACT333','commit':commit,'manifests':manifests,'controls':controls},indent=2,sort_keys=True)+'\n')
assert not subprocess.check_output(['git','status','--porcelain'],text=True).strip()
assert subprocess.check_output(['git','-C',str(original),'rev-parse','HEAD'],text=True).strip()==before
ok=all(r['returncode']==0 for r in runs.values()) and all(r['equal'] for r in controls)
print(json.dumps({'status':'PASS' if ok else 'FAIL_OR_INCOMPLETE','output':str(out),'runs':runs,'selector_controls':len(controls),'mismatches':[(r['mode'],r['case']) for r in controls if not r['equal']]}),flush=True)
sys.exit(0 if ok else 1)

