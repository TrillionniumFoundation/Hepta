from pathlib import Path
from hashlib import sha256
import json,sys,os,time,tempfile
from unittest.mock import patch
from hepta import hia_agent_assembly as assembly, hia_default_native as defaults, hia_program as core, hia_native_helpers as helpers
from hepta.hia_core_admission_native import NativeCoreAdmission
from hepta.hia_core_json_bytes_native import NativeCoreJSONBytes
from hepta.hia_json_canonical_native import NativeJsonCanonicalizer
from tests.test_hia_agent_assembly import integer_attribute_cases
D=Path('/workspace/scratch/589c0a6dd85b/runtime-c13-native-int-probe-589c')
metadata=json.loads((D/'compile-report-with-front.json').read_bytes())
resources={defaults.ASSEMBLY_SYNTAX_RESOURCE:'syntax',defaults.ASSEMBLY_DIAGNOSTIC_RESOURCE:'presenter',defaults.ASSEMBLY_CANONICAL_RESOURCE:'canonical',defaults.ASSEMBLY_CORE_JSON_RESOURCE:'core-json'}
P=D/'component-resource-capture';P.mkdir(exist_ok=False)
for name,role in resources.items():
 item=metadata['components'][role];raw=Path(item['image']).read_bytes();assert sha256(raw).hexdigest()==item['sha256'];target=P/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
pin=P/'component-pins.json';pin.write_text(json.dumps({'scope':'TEST_COMPONENT_CAPTURE_WITH_SELECTION_MOCKED','resources':{name:metadata['components'][role]['sha256'] for name,role in resources.items()}},sort_keys=True)+'\n')
pins=((helpers._read(pin,1<<20),1<<20),)
class ComponentReadback:
 def __init__(self):self.snapshots=pins;self.calls=0
 def check_files(self):
  self.calls+=1
  if any(helpers._read(item.path,limit)!=item for item,limit in self.snapshots):raise ValueError('component pin changed')
binding=ComponentReadback();item=metadata['components']['core'];admission=NativeCoreAdmission(Path(item['image']).read_bytes(),item['sha256']);admission._default_package_binding=binding
value=tuple(['component-only']*16+[metadata['components'][role]['sha256'] for role in ('syntax','presenter','canonical','core-json')])
original_default=defaults.default_assembly_document
calls=[];native_front=NativeCoreJSONBytes.canonicalize
def front(self,wire,**controls):
 row={'image_sha256':self.image_sha256,'input_sha256':sha256(wire).hexdigest(),'limit':sys.get_int_max_str_digits()};calls.append(row)
 try:result=native_front(self,wire,**controls)
 except core.HIAProgramRejected as exc:row.update(status='native-refusal-host-compatibility-route',code=exc.code,message=str(exc));raise
 else:row.update(status='accepted',canonical_sha256=result.canonical_sha256);return result
def old_package(source,*,verify=False):return original_default(source,verify=False)
def observe(source):
 try:result=assembly.assemble_program(source);return {'kind':'accepted','canonical_sha256':sha256(result.canonical_bytes).hexdigest()}
 except Exception as exc:return {'kind':'error','type':type(exc).__name__,'message':str(exc),'code':getattr(exc,'code',None),'phase':getattr(exc,'phase',None),'line':getattr(exc,'line',None),'cause_type':None if exc.__cause__ is None else type(exc.__cause__).__name__,'cause_message':None if exc.__cause__ is None else str(exc.__cause__)}
def forbidden(*args,**kwargs):raise AssertionError('host payload parser or Core snapshot entered for accepted native route')
rows=[];safe_controls=[];original=sys.get_int_max_str_digits();cases=integer_attribute_cases();started=time.monotonic()
try:
 with patch.object(defaults,'_capture_package',return_value=(P,value,pins)),patch.object(defaults,'default_core_admission',return_value=admission),patch.object(NativeCoreJSONBytes,'canonicalize',front):
  for limit in (0,640,4300):
   sys.set_int_max_str_digits(limit)
   for label,source in cases:
    with patch.object(defaults,'default_assembly_document',old_package):old=observe(source)
    begin=len(calls)
    new=observe(source)
    rows.append({'case':label,'limit':limit,'source_bytes':len(source.encode()),'source_sha256':sha256(source.encode()).hexdigest(),'old_packaged_json_route':old,'guarded_native_wire_route':new,'front_calls':calls[begin:],'equal':old==new})
   safe=next(source for label,source in cases if label=='one');before=len(calls)
   with patch.object(core,'_decode',forbidden),patch.object(core,'_bounded_detached_snapshot',forbidden),patch.object(assembly,'_parse_assembly_document',forbidden):answer=observe(safe)
   assert answer['kind']=='accepted' and len(calls)==before+1
   safe_controls.append({'limit':limit,'result':answer,'native_front':calls[-1],'host_payload_routes_forbidden':True})
  sys.set_int_max_str_digits(640)
  long=next(source for label,source in cases if label=='integer-641-positive')
  with patch.object(defaults,'_capture_package',return_value=(P,value[:-1],pins)),patch.object(NativeCoreJSONBytes,'canonicalize',forbidden),patch.object(defaults,'default_core_admission',side_effect=AssertionError('unguarded 19-pin admission')):
   legacy=observe(long)
  assert legacy['type']=='ValueError' and '641 digits' in legacy['message']
  front_path=P/defaults.ASSEMBLY_CORE_JSON_RESOURCE;original_front=front_path.read_bytes()
  try:
   front_path.write_bytes(original_front[:-1]+bytes([original_front[-1]^1]))
   changed=observe(next(source for label,source in cases if label=='one'))
   assert changed['kind']=='error' and 'identity' in changed['message'],changed
  finally:front_path.write_bytes(original_front)
  def retarget(self,wire,**options):
   result=native_front(self,wire,**options)
   front_path.write_bytes(original_front[:-1]+bytes([original_front[-1]^1]))
   return result
  try:
   with patch.object(NativeCoreJSONBytes,'canonicalize',retarget):retargeted=observe(next(source for label,source in cases if label=='one'))
   assert retargeted['kind']=='error' and 'changed during the operation' in retargeted['message'],retargeted
  finally:front_path.write_bytes(original_front)
finally:sys.set_int_max_str_digits(original)
report={'schema':'hepta.hia.assembly-integer-native-guard-component.v1','scope':metadata['scope'],'selection_boundary':'package capture and Core owner selection mocked for component test; all five HIA images and file readback execute for real; this is not an installed-wheel qualification','compiler':metadata['compiler'],'components':{name:{key:value for key,value in item.items() if key!='receipt'} for name,item in metadata['components'].items()},'case_count':len(rows),'mismatch_count':sum(not row['equal'] for row in rows),'cases':rows,'accepted_native_controls':safe_controls,'legacy_19_pin_refusal':legacy,'wrong_front_pin_refusal':changed,'front_retarget_during_call_refusal':retargeted,'binding_readback_calls':binding.calls,'elapsed_seconds':time.monotonic()-started,'refused_front_inputs_use_hosted_compatibility_route':True,'installed_native_release_qualified':False,'whole_native_qualified':False}
(D/'guarded-digit-results.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print({'cases':len(rows),'mismatches':report['mismatch_count'],'accepted_native_controls':len(safe_controls),'binding_readback_calls':binding.calls,'elapsed_seconds':report['elapsed_seconds']})
for row in rows:
 if not row['equal']:print(row)
assert report['mismatch_count']==0
