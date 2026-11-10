"""Paired actual native phase development; existing B3/reference reused, not cold."""
from pathlib import Path
from hashlib import sha256
import json,subprocess,sys,time
B=Path(__file__).resolve().parents[1];R=B/'agent-core-native-state-cost-development';E=B/'evidence';D=E/'core-native-state-cost-development-02'
sys.path.insert(0,str(R));assert sys.flags.isolated and sys.flags.no_site
assert not D.exists();D.mkdir(mode=0o700)
from tools.qualify_hia_selfhost import SOURCE,compile_stage,source_manifest,_phase_manifest_digest
request=json.loads((E/'core-signed-native-phase-cpu-profile-01/request.json').read_bytes())
old=Path(request['inputs']['compiler']['path']);before=source_manifest()
c1,r1=compile_stage(D,'C1',old,SOURCE.read_bytes())
c2,r2=compile_stage(D,'C2',c1,SOURCE.read_bytes())
c3,r3=compile_stage(D,'C3',c2,SOURCE.read_bytes())
assert c2.read_bytes()==c3.read_bytes()
observations=[]
for i in range(4):
 for variant in (('original','candidate') if i%2==0 else ('candidate','original')):
  root=D/(str(i)+'-'+variant);root.mkdir();out=root/'actual';out.mkdir()
  req=json.loads(json.dumps(request));req['directory']=str(out)
  compiler=old if variant=='original' else c3
  req['inputs']['compiler']=dict(path=str(compiler),sha256=sha256(compiler.read_bytes()).hexdigest())
  req['source_manifest_sha256']=_phase_manifest_digest(before)
  rp=root/'request.json';rp.write_text(json.dumps(req,sort_keys=True,indent=2));report=root/'report.json'
  started=time.monotonic()
  with (root/'driver.log').open('x') as f:
   p=subprocess.run([sys.executable,'-I','-S','-B',str(R/'tools/qualify_hia_selfhost.py'),'--phase-request',str(rp),'--output',str(report)],cwd=R,stdout=f,stderr=subprocess.STDOUT,timeout=90)
  assert p.returncode==0,(variant,(root/'driver.log').read_text())
  d=json.loads(report.read_bytes());assert d['status']=='PASS' and all(d['checks'].values())
  native=0;count=0
  for receipt in out.glob('*.receipt.json'):
   v=json.loads(receipt.read_bytes())
   if 'native_elapsed_ns' in v:native+=v['native_elapsed_ns'];count+=1
  row=dict(pair=i,variant=variant,checks=len(d['checks']),wall_seconds=time.monotonic()-started,
    native_seconds=native/1e9,observations=count,compiler_sha256=sha256(compiler.read_bytes()).hexdigest())
  observations.append(row);print(json.dumps(row),flush=True)
assert source_manifest()==before
record=dict(status='DEVELOPMENT_DIAGNOSTIC_ONLY',source_manifest_sha256=_phase_manifest_digest(before),
 old_B3_and_reference_reused=True,actual_C2_C3_fixed_point=True,source_unchanged=True,
 new_cold_or_whole_qualification_claimed=False,observations=observations)
with (E/'core-native-state-cost-development-02.json').open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
