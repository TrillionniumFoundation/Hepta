"""Compare actual native MCP resource reads with same-job frozen-runtime replay.

Use a dedicated complete Worker installation and the same explicit prefix
when resuming an uncertain run. A pending resource is observed with the same
URI; this driver never invents a new request key to turn pending into success.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import os
import sys
import json
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.hia_agent_native_qualification import Session, ToolClient
from tools.hia_agent_native_transport import MCPStdio


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('service','runtime','config','manifest','catalog','output'):
  parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--prefix',required=True)
 args=parser.parse_args()
 for name in ('service','runtime','config','manifest','catalog','output'):
  setattr(args,name,getattr(args,name).resolve())
 D=args.output;D.mkdir(mode=0o700,exist_ok=False)
 cfg=args.config;config=json.loads(cfg.read_bytes());manifest=args.manifest
 catalog=args.catalog;service=args.service
 inputs={str(p):sha256(p.read_bytes()).hexdigest() for p in
         (args.service,args.runtime,args.config,args.manifest,args.catalog)}
 env={k:v for k,v in os.environ.items() if not k.startswith(('HEPTA_HIA_','HIA_LOCAL_MCP_','HIA_TRANSPORT_','HEPTA_EFFECT_OWNER_'))};env['PATH']=''
 report={'scope':'new resource Worker components in private complete fixture, native parent plus same-job frozen Rust oracle','status':'running','calls':[],'resources':[],'full_ordinary_release_qualified':False,'outer_request_audit_qualified':False,'prefix':args.prefix,'inputs':inputs}
 transport=None
 def note(row):
  if 'response' in row:report['calls'].append(row)
  with (D/'application.jsonl').open('a') as f:f.write(json.dumps(row,sort_keys=True)+'\n')
  print('TOOL',row['tool'],row.get('phase'),row.get('response',{}).get('status'),flush=True)
 def resource(t,uri):
  end=time.monotonic()+180
  while True:
   try:result=t.rpc('resources/read',{'uri':uri});return {'result':result}
   except Exception:
    if not t.protocol_records:raise
    record=t.protocol_records[-1]
    if record['request'].get('method')!='resources/read':raise
    error=record['response'].get('error')
    if not isinstance(error,dict):raise
    data=error.get('data')
    if isinstance(data,dict) and data.get('status')=='accepted' and time.monotonic()<end:time.sleep(.05);continue
    return {'error':error}
 def snapshot():
  return {p.name:sha256(p.read_bytes()).hexdigest() for p in (Path(config['state_dir'])/'jobs').glob('*.json')}
 try:
  command=[str(service),str(cfg),sha256(cfg.read_bytes()).hexdigest(),str(manifest),sha256(manifest.read_bytes()).hexdigest()]
  transport=MCPStdio(command,cwd=D,env=env,timeout=180)
  client=ToolClient(transport.call,catalog_path=catalog,validate=True,journal=note)
  session=Session(client,prefix=args.prefix)
  for label,text in [('short','HIA resource native read.\n'),('utf8',('0123456789abcdef\n'*3800)+'雪🙂'),('paged','🙂'*20000)]:
   ref=session.artifact(text)
   ordinary=client.result('hia_read',{'catalog_sha256':session.catalog_sha256,'artifact':ref,'max_bytes':65536})
   answer=resource(transport,ref['uri'])
   assert 'result' in answer,(label,answer)
   content=answer['result']['contents'];assert len(content)==1 and content[0]['uri']==ref['uri']
   assert content[0]['mimeType']=='text/plain'
   decoded=json.loads(content[0]['text']);assert decoded['encoding']=='utf8'
   expected=text if label!='paged' else '🙂'*16384
   assert decoded['content']==expected and ordinary['content']==expected,(label,len(decoded['content']))
   assert (decoded['next_cursor'] is None)==(label!='paged')
   report['resources'].append({'label':label,'uri':ref['uri'],'answer':answer})
   print('RESOURCE',label,'PASS',flush=True)
  missing=resource(transport,'hia://artifacts/not-issued-resource-v1')
  assert 'error' in missing and missing['error']['data']['status']=='rejected',missing
  assert missing['error']['data']['error']['code']=='E_HIA_ARTIFACT_IDENTITY',missing
  assert missing['error']['data']['error']['message']=='resource URI was not issued in this runtime namespace',missing
  report['resources'].append({'label':'missing','uri':'hia://artifacts/not-issued-resource-v1','answer':missing})
  before=snapshot()
  for row in report['resources']:assert resource(transport,row['uri'])==row['answer']
  assert snapshot()==before
  (D/'native-protocol.json').write_text(json.dumps(transport.protocol_records,indent=2))
  (D/'native-stderr').write_text(transport.stderr());transport.close();transport=None
  runtime=args.runtime
  command=[str(runtime),'mcp','--path',str(D),'--runtime-config',str(cfg),'--hia-controller-manifest',str(manifest),'--hia-controller-sha256',sha256(manifest.read_bytes()).hexdigest()]
  transport=MCPStdio(command,cwd=D,env={**env,'PATH':'/usr/bin','RUST_LOG':'warn'},timeout=180)
  for i,row in enumerate(report['calls']):
   actual=transport.call(row['tool'],row['arguments']);assert actual==row['response'],(i,row['tool'],actual,row['response'])
  for row in report['resources']:
   actual=resource(transport,row['uri']);assert actual==row['answer'],(row['label'],actual,row['answer'])
  assert snapshot()==before
  assert all(sha256(Path(path).read_bytes()).hexdigest()==pin for path,pin in inputs.items())
  report.update(status='passed',no_effect_relaunch=True,no_job_record_replacement=True,public_calls=len(report['calls']),resource_cases=len(report['resources']),service_sha256=sha256(service.read_bytes()).hexdigest(),oracle_sha256=sha256(runtime.read_bytes()).hexdigest())
 except BaseException:
  report['status']='failed';report['failure']=traceback.format_exc();raise
 finally:
  if transport is not None:
   (D/'last-protocol.json').write_text(json.dumps(transport.protocol_records,indent=2))
   (D/'last-stderr').write_text(transport.stderr());transport.close()
  (D/'qualification.json').write_text(json.dumps(report,indent=2))
  print(json.dumps({k:v for k,v in report.items() if k not in ('calls','resources')},sort_keys=True),flush=True)


if __name__=='__main__':
 main()
