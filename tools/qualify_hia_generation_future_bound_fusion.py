"""Source-bound Runtime/provider/Future fusion with one current Value image."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,os,struct,subprocess,time,traceback
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools import generate_hia_generation_future_bound_fusion_packer as spec
from tools.qualify_hia_publication_cancellation import Image,address
ROOT=Path(__file__).resolve().parents[1]
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def write(path,data):path.write_text(json.dumps(data,indent=2)+'\n')
def pack_controls(packer,frame,obj):
 image=Image(packer);rows=[]
 changes=[('short-header',frame[:15]),('truncated-role',frame[:-1]),('trailing-byte',frame+b'x')]
 for label,offset,value in [('magic',0,0),('role-count-low',8,len(spec.ROLES)-1),('role-count-high',8,len(spec.ROLES)+1)]:
  raw=bytearray(frame);struct.pack_into('<Q',raw,offset,value);changes.append((label,bytes(raw)))
 for i,role in enumerate(spec.ROLES):
  for label,value in [('empty',0),('oversize',4194305)]:
   raw=bytearray(frame);struct.pack_into('<Q',raw,16+i*8,value);changes.append((label+'-'+role,bytes(raw)))
 capsule_index=spec.ROLES.index('provider_capsule')
 capsule_at=16+8*len(spec.ROLES)+sum(struct.unpack_from('<Q',frame,16+i*8)[0]for i in range(capsule_index))
 for i,(off,_)in enumerate(spec.owner.provider.RELOCATIONS):
  raw=bytearray(frame);struct.pack_into('<I',raw,capsule_at+off,1);changes.append(('unresolved-provider-hole-'+str(i),bytes(raw)))
 with mmap.mmap(-1,32<<20)as output,mmap.mmap(-1,1<<20)as workspace:
  for name,raw in changes:
   source=C.create_string_buffer(raw);output[:128]=b'\xa5'*128
   rc=image.entry(source,len(raw),address(output),len(output),address(workspace),len(workspace))
   assert rc==0xffffffff and output[:128]==b'\xa5'*128,(name,rc)
   rows.append(name)
  source=C.create_string_buffer(frame)
  for name,outn,workn in [('short-output',len(obj)-1,len(workspace)),('short-workspace',len(output),2047)]:
   output[:128]=b'\xa5'*128
   rc=image.entry(source,len(frame),address(output),outn,address(workspace),workn)
   assert rc==0xfffffffe and output[:128]==b'\xa5'*128,(name,rc)
   rows.append(name)
 return rows
def build(compiler,owner_build,owner_snapshot,out):
 out.mkdir(mode=0o700);captured=json.loads((owner_build/'build.json').read_text())
 assert pin(compiler.read_bytes())==dict(bytes=813129,sha256=q.old.COMPILER_SHA)
 assert captured['source_capture_verified_after_build'] and captured['build']['roles']==55 and captured['build']['value_roles']==13
 record=dict(schema='hepta.hia.generation-future-bound-fusion-build.v1',passed=False,whole_public_runtime_qualified=False,whole_public_future_qualified=False,compile=[],products={},source_files={},owner_captured_sources=captured['compile'],owner_source_snapshot=str(owner_snapshot),owner_build=dict(path=str(owner_build/'build.json'),**pin((owner_build/'build.json').read_bytes())))
 try:
  flats={}
  for row in captured['compile']:
   source=(owner_snapshot/row['path']).read_bytes();name=Path(row['path']).stem;flat=(owner_build/(name+'.flat')).read_bytes()
   assert pin(source)==dict(bytes=row['source_bytes'],sha256=row['source_sha256']),name
   assert pin(flat)==dict(bytes=row['flat_bytes'],sha256=row['flat_sha256']),name
   flats[name]=flat;(out/(name+'.flat')).write_bytes(flat)
  for i in range(2):
   r=subprocess.run([os.sys.executable,'-m','tools.generate_hia_generation_future_bound_fusion_packer'],cwd=ROOT,capture_output=True,timeout=30);assert r.returncode==0,r.stderr
   generated=(ROOT/'examples/hia_bootstrap/generation_future_bound_fusion_packer.hepta').read_bytes()
   if i==0:first=generated
   else:assert first==generated
  names=resources.PUBLIC+('background_optimizer_future_public_cleanup','background_optimizer_future_public_observers_notify','background_optimizer_future_public_observers_notify_packer','generation_future_bound_fusion_packer')
  for name in names:
   if name not in flats:
    rel='examples/hia_bootstrap/'+name+'.hepta';source=(ROOT/rel).read_bytes()
    flat=q.old.compiler_run(compiler,source,name);flats[name]=flat;(out/(name+'.flat')).write_bytes(flat)
    record['compile'].append(dict(path=rel,source_bytes=len(source),source_sha256=q.sha(source),flat_bytes=len(flat),flat_sha256=q.sha(flat),two_builds_identical=True));record['source_files'][rel]=q.sha(source)
    print('BOUND_FUSION_COMPILE',name,len(flat),flush=True)
  value=(owner_build/'hia-generation-lease-values.core.bin').read_bytes()
  assert pin(value)==captured['build']['products']['hia-generation-lease-values.core.bin']
  candidates=[p for p in owner_build.iterdir()if p.is_file()and p.stat().st_size==captured['build']['provider_capsule']['bytes']]
  capsules=[p.read_bytes()for p in candidates if pin(p.read_bytes())==captured['build']['provider_capsule']]
  assert capsules;capsule=capsules[0]
  notify_body=flats['background_optimizer_future_public_observers_notify'];wire=b'HIABFNPK'+struct.pack('<3Q',len(notify_body),0,0)+notify_body
  ni=Image(flats['background_optimizer_future_public_observers_notify_packer']);src=C.create_string_buffer(wire)
  with mmap.mmap(-1,16<<20)as output,mmap.mmap(-1,16<<20)as work:
   rc=ni.entry(src,len(wire),address(output),len(output),address(work),len(work));n=q.get(work,0);assert rc==0 and 0<n<len(output);notify=bytes(output[:n])
  body=[flats['generation_lease_owner_bound'],flats['generation_lease_public_lifecycle'],value,flats['generation_lease_typed_policy'],flats['generation_lease_owner_finalizer']]
  body.extend(flats[Path(row['path']).stem]for row in spec.owner.CARRIER_SOURCES);body.append(capsule)
  body.extend(flats[name]for name in resources.PUBLIC);body.extend([notify,flats['background_optimizer_future_public_cleanup']])
  assert len(body)==len(spec.ROLES)==63
  frame=struct.pack('<'+str(2+len(body))+'Q',spec.MAGIC,len(body),*map(len,body))+b''.join(body)
  obj=q.old.run_packer(flats['generation_future_bound_fusion_packer'],frame);assert obj==spec.reference_object(body)
  linked=q.old.run_packer(flats['multiversion_runtime_linker'],obj)
  assert obj.count(value)==linked.count(value)==1
  offsets={};unique={}
  for role,flat in zip(spec.ROLES,body):
   targets={64+h+4+struct.unpack_from('<i',obj,64+h)[0]for h in spec.HOLES[role]};assert len(targets)==1
   at=targets.pop();offsets[role]=at-64
   if flat in unique:assert at==unique[flat]
   else:unique[flat]=at
  for role,flat in zip(spec.ROLES,body):
   at=64+offsets[role];expected=bytearray(flat)
   if role=='provider_capsule':
    destinations=dict(carrier=64+spec.owner.CARRIER_OFFSET,effects=64+spec.owner.EFFECTS_OFFSET,values=64+offsets['values'])
    for name,target in spec.owner.CAPSULE_IMPORTS:
     hole=spec.owner.provider.OUTER_HOLES[name];struct.pack_into('<i',expected,hole,destinations[target]-at-hole-4)
   assert obj[at:at+len(flat)]==expected,role
  path=out/'hia-generation-future-bound-fusion.so'
  for name,raw in [('generation-future-bound-fusion.o',obj),(path.name,linked),('hia-generation-lease-values.core.bin',value),('hia-future-notify.core.bin',notify),('hia-provider-capsule.core.bin',capsule)]:
   (out/name).write_bytes(raw);record['products'][name]=pin(raw)
  record['packer_controls']=pack_controls(flats['generation_future_bound_fusion_packer'],frame,obj)
  record['role_layout']=[dict(role=r,offset=offsets[r],**pin(f))for r,f in zip(spec.ROLES,body)]
  record['logical_roles']=len(body);record['unique_bodies']=len(unique);record['identical_code_bytes_removed']=sum(map(len,body))-sum(map(len,unique))
  for rel in ('tools/generate_hia_generation_future_bound_fusion_packer.py','tools/qualify_hia_generation_future_bound_fusion.py','tools/generate_hia_generation_lease_owner_bound_packer.py','tools/generate_hia_generation_lease_owner_provider_packer.py','tools/generate_hia_background_optimizer_future_public_cleanup_packer.py'):
   record['source_files'][rel]=q.sha((ROOT/rel).read_bytes())
  record.update(passed=True,native_construction_qualified=True,native_pack_reference_equal=True,single_value_body=True,provider_imports_fixed_to_same_owner=True,provider_dynamic_relocations_rebased=True,legacy_protocols_unchanged=True,text_limit_bytes=16777216,role_limit_bytes=4194304)
  print('BOUND_FUSION_NATIVE_BUILD_PASS',json.dumps(record['products']),len(record['packer_controls']),flush=True)
  return path,record
 except BaseException as e:record['error']=repr(e);record['traceback']=traceback.format_exc();raise
 finally:write(out/'build.json',record)
def qualify(path,out,tools):
 build=json.loads((path.parent/'build.json').read_bytes())
 assert build['passed'] and pin(path.read_bytes())==build['products'][path.name]
 for row in build['owner_captured_sources']:
  assert q.sha((Path(build['owner_source_snapshot'])/row['path']).read_bytes())==row['source_sha256']
 for rel,expected in build['source_files'].items():assert q.sha((ROOT/rel).read_bytes())==expected,rel
 out.mkdir(mode=0o700);files=[];rows=[];entries=[]
 class FusionImage:
  def __init__(self,unused):
   self.lib=C.CDLL(str(path));self.entry=self.lib.hia_background_optimizer_future_public
   self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
 OriginalPublic=resources.Public
 class BoundPublic(OriginalPublic):
  def __init__(self,value,image):
   super().__init__(value,image);owner=value.engine.owner
   assert q.get(self.ctx,72)==q.get(owner.context,40)
   assert q.get(self.ctx,112)==C.addressof(owner.context)+512
   assert q.get(self.ctx,120)==256
   entries.append(dict(runtime_value_entry=q.get(owner.context,40),future_value_entry=q.get(self.ctx,72),same_code_entry=True,same_native_arena=True))
 resources.Image=FusionImage;resources.Public=BoundPublic
 report=dict(schema='hepta.hia.generation-future-fusion-qualification.v1',passed=False,
  product=pin(path.read_bytes()),cases=rows,actual_entry_bindings=entries,
  whole_public_runtime_qualified=False,whole_public_future_qualified=False,production_activated=False,
  bound_provider_source=build['owner_build'],value_source=build['products']['hia-generation-lease-values.core.bin'])
 try:
  for tool in tools:
   raw=tool.read_bytes();files.append((q.old.sealed(raw),raw))
  cases=[('resource-lease-first',lambda p:resources.resource_case(path,files,p,False)),
   ('resource-runtime-first',lambda p:resources.resource_case(path,files,p,True)),
   ('resource-binding',lambda p:resources.binding_cases(path,files,p)),
   ('resource-concurrent',lambda p:resources.concurrent_last_refs(path,files,p)),
   ('pending-runtime',lambda p:resources.pending_case(path,files,p,False)),
   ('pending-lease',lambda p:resources.pending_case(path,files,p,True)),
   ('future-runtime-first',lambda p:resources.future_case(path,path,files,p,False)),
   ('future-lease-first',lambda p:resources.future_case(path,path,files,p,True)),
   ('lifecycle-lease-first',lambda p:q.lifecycle_case(path,files,p,False)),
   ('lifecycle-runtime-first',lambda p:q.lifecycle_case(path,files,p,True)),
   ('active-destroy',lambda p:q.active_destroy(path,files,p)),
   ('typed-calls',lambda p:q.typed_calls(path,files,p))]
  for name,fn in cases:
   parent=out/name;parent.mkdir(mode=0o700);start=time.monotonic()
   result=fn(parent);row=dict(name=name,seconds=time.monotonic()-start,result=result)
   rows.append(row);write(out/(name+'.json'),row);write(out/'report.json',report)
   print('FUSION_ORIGINAL_CASE_PASS',name,flush=True)
  for name,fn in [('os-failure-retention',lambda:q.os_failure_retention(path,out)),('tool-bank-custody',lambda:q.tool_bank_custody(path,files))]:
   start=time.monotonic();result=fn();row=dict(name=name,seconds=time.monotonic()-start,result=result)
   rows.append(row);write(out/(name+'.json'),row);write(out/'report.json',report)
   print('FUSION_ORIGINAL_CASE_PASS',name,flush=True)
  assert len(entries)==2 and len(rows)==14
  report.update(passed=True,single_actual_value_entry_qualified=True,shared_native_value_arena_qualified=True,original_resource_and_owner_assertions_preserved=True)
  print('FUSION_NATIVE_QUALIFICATION_PASS',len(rows),flush=True)
 except BaseException as exc:
  report['failure']=repr(exc);report['traceback']=traceback.format_exc();raise
 finally:
  write(out/'report.json',report)
  for fd,_ in files:os.close(fd)
def main():
 p=argparse.ArgumentParser();p.add_argument('--compiler',type=Path);p.add_argument('--owner-build',type=Path);p.add_argument('--owner-snapshot',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--built-dir',type=Path);p.add_argument('--build-only',action='store_true')
 for name in ('normalizer','proof','builder'):p.add_argument('--'+name,type=Path)
 a=p.parse_args()
 if a.built_dir:path=a.built_dir/'hia-generation-future-bound-fusion.so'
 else:
  assert a.compiler and a.owner_build and a.owner_snapshot
  path,_=build(a.compiler,a.owner_build,a.owner_snapshot,a.output)
 if not a.build_only:
  assert a.normalizer and a.proof and a.builder
  qualify(path,a.output if a.built_dir else a.output/'qualification',[a.normalizer,a.proof,a.builder])
if __name__=='__main__':main()
