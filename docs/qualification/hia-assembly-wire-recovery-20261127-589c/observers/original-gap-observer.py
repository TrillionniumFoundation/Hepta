from pathlib import Path
from hashlib import sha256
import json,sys,time
from unittest.mock import patch
from hepta import hia_agent_assembly as assembly, hia_default_native as defaults, hia_program as core
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_json_canonical_native import NativeJsonCanonicalizer
from hepta.hia_core_admission_native import NativeCoreAdmission
D=Path('/workspace/scratch/589c0a6dd85b/runtime-c13-native-int-probe-589c')
metadata=json.loads((D/'compile-report.json').read_bytes())
def image(role,cls):
 p=Path(metadata['components'][role]['image']);raw=p.read_bytes();assert sha256(raw).hexdigest()==metadata['components'][role]['sha256'];return cls(raw,sha256(raw).hexdigest())
syntax=image('syntax',NativeHiaJsonImage);presenter=image('presenter',NativeHiaJsonImage)
canonicalizer=image('canonical',NativeJsonCanonicalizer);admission=image('core',NativeCoreAdmission)
T='''hia-asm.v1 hepta.hia.program.v8 digit_probe
exports(main)
fn main() -> (u64) effects() entry(entry)
block entry()
  value:u64 = const() {"value":REPLACE}
  ret(value)
end
'''
cases=[]
for n in (19,20,21,639,640,641,4299,4300,4301,5000,16000):
 for sign in ('','-'):
  cases.append((f'integer-{n}-'+('negative' if sign else 'positive'),T.replace('REPLACE',sign+'9'*n)))
for label,token in [('long-string',json.dumps('9'*5000)),('escaped-string',json.dumps('\\"'+'9'*5000)),('string-followed-integer','"'+('9'*5000)+'","extra":'+('9'*641)),('two-integers','9'*641+',"extra":'+'9'*4301),('duplicate-key','9'*4301+',"value":1'),('nonfinite','NaN'),('trailing-invalid','9'*4301+',"other":]')]:cases.append((label,T.replace('REPLACE',token)))
cases.extend([('earlier-core-error-and-integer',T.replace('effects()','effects(weird)').replace('REPLACE','9'*4301)),('earlier-syntax-error-and-integer',T.replace('block entry()','block ???').replace('REPLACE','9'*4301)),('later-syntax-error-and-integer',T.replace('ret(value)','not syntax').replace('REPLACE','9'*4301))])
def observe(fn):
 try:
  result=fn()
  return {'kind':'accepted','canonical_sha256':sha256(result.canonical_bytes).hexdigest()}
 except Exception as exc:
  return {'kind':'error','type':type(exc).__name__,'message':str(exc),'code':getattr(exc,'code',None),'phase':getattr(exc,'phase',None),'line':getattr(exc,'line',None),'cause_type':type(exc.__cause__).__name__ if exc.__cause__ is not None else None,'cause_message':str(exc.__cause__) if exc.__cause__ is not None else None}
def route(source,fast):
 def owner(text,verify=False):
  wire=assembly._native_assembly_document(syntax,presenter,text)
  if not fast:return json.loads(wire)
  canonical=canonicalizer.canonicalize(wire,max_nodes=core.MAX_NODES,max_depth=core.MAX_DEPTH)
  admission.admit(canonical)
  return core.VerifiedProgram(canonical)
 with patch.object(defaults,'default_assembly_document',owner):return assembly.assemble_program(source)
original=sys.get_int_max_str_digits();rows=[]
try:
 for limit in (0,640,4300):
  sys.set_int_max_str_digits(limit)
  for label,source in cases:
   row={'limit':limit,'case':label,'source_bytes':len(source.encode()),'source_sha256':sha256(source.encode()).hexdigest(),'old_packaged_json_route':observe(lambda:route(source,False)),'unguarded_native_wire_route':observe(lambda:route(source,True))}
   row['equal']=row['old_packaged_json_route']==row['unguarded_native_wire_route'];rows.append(row)
finally:sys.set_int_max_str_digits(original)
report={'schema':'hepta.hia.assembly-integer-route-gap.v1','scope':metadata['scope'],'compile_report_sha256':sha256((D/'compile-report.json').read_bytes()).hexdigest(),'actual_native_images':{name:{key:value for key,value in item.items() if key!='receipt'} for name,item in metadata['components'].items()},'cases':rows,'case_count':len(rows),'mismatch_count':sum(not row['equal'] for row in rows),'installed_native_release_qualified':False,'whole_native_qualified':False}
(D/'original-digit-gap.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print({'cases':len(rows),'mismatches':report['mismatch_count']})
for row in rows:
 if not row['equal']:
  print(row['limit'],row['case'],row['old_packaged_json_route']['type'],row['old_packaged_json_route'].get('message','')[:130],'=>',row['unguarded_native_wire_route']['type'],row['unguarded_native_wire_route'].get('message','')[:130])
