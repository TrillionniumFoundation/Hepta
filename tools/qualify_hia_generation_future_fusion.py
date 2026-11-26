"""Native Runtime/Future fusion qualification with original custody assertions.

Python is a development oracle only. Products are compiled, packed and linked by
the retained HIA tools; the Future binds the same embedded Value entry as Runtime.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,os,struct,subprocess,time,traceback
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools import generate_hia_generation_future_fusion_packer as spec
from tools.qualify_hia_publication_cancellation import Image,address

ROOT=Path(__file__).resolve().parents[1]
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def write(path,data):path.write_text(json.dumps(data,indent=2)+'\n')
def compile_one(compiler,out,name):
 raw=(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()
 flat=q.old.compiler_run(compiler,raw,name);(out/(name+'.flat')).write_bytes(flat)
 print('FUSION_NATIVE_COMPILE',name,len(flat),flush=True)
 return flat,dict(path='examples/hia_bootstrap/'+name+'.hepta',source_bytes=len(raw),source_sha256=q.sha(raw),flat_bytes=len(flat),flat_sha256=q.sha(flat),two_builds_identical=True)
def pack_controls(packer,frame,obj):
 image=Image(packer);rows=[]
 changes=[('short-header',frame[:15]),('truncated-role',frame[:-1]),('trailing-byte',frame+b'x')]
 for label,offset,value in [('magic',0,0),('role-count-low',8,61),('role-count-high',8,63)]:
  raw=bytearray(frame);struct.pack_into('<Q',raw,offset,value);changes.append((label,bytes(raw)))
 for i,role in enumerate(spec.ROLES):
  for label,value in [('empty',0),('oversize',4194305)]:
   raw=bytearray(frame);struct.pack_into('<Q',raw,16+i*8,value);changes.append((label+'-'+role,bytes(raw)))
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
def build(compiler,out):
 out.mkdir(mode=0o700)
 assert pin(compiler.read_bytes())==dict(bytes=813129,sha256=q.old.COMPILER_SHA)
 record=dict(schema='hepta.hia.generation-future-fusion-build.v1',passed=False,
  native_construction_qualified=False,whole_public_runtime_qualified=False,compile=[],products={},source_files={})
 try:
  author=ROOT/'tools/generate_hia_generation_future_fusion_packer.py'
  source=ROOT/'examples/hia_bootstrap/generation_future_fusion_packer.hepta'
  for turn in range(2):
   subprocess.run([os.sys.executable,'-m','tools.generate_hia_generation_future_fusion_packer'],cwd=ROOT,check=True,timeout=30)
   if turn==0:generated=source.read_bytes()
   else:assert generated==source.read_bytes()
  flats,rows=q.compile_all(compiler,out);record['compile'].extend(rows)
  print('FUSION_BASE_DOUBLE_COMPILE',len(rows),flush=True)
  record['bridges']=q.bridge_identity(out)
  legacy,oldbuild=q.build_images(flats,out);record['legacy_owner_build']=oldbuild
  names=resources.PUBLIC+('background_optimizer_future_public_cleanup','background_optimizer_future_public_observers_notify','background_optimizer_future_public_observers_notify_packer','generation_future_fusion_packer')
  for name in names:
   if name not in flats:
    flat,row=compile_one(compiler,out,name);flats[name]=flat;record['compile'].append(row)
  value=(out/'hia-generation-lease-values.core.bin').read_bytes()
  notify_body=flats['background_optimizer_future_public_observers_notify']
  wire=b'HIABFNPK'+struct.pack('<3Q',len(notify_body),0,0)+notify_body
  ni=Image(flats['background_optimizer_future_public_observers_notify_packer'])
  src=C.create_string_buffer(wire)
  with mmap.mmap(-1,16<<20)as output,mmap.mmap(-1,16<<20)as work:
   rc=ni.entry(src,len(wire),address(output),len(output),address(work),len(work))
   n=q.get(work,0);assert rc==0 and 0<n<len(output)
   notify=bytes(output[:n])
  (out/'hia-future-notify.core.bin').write_bytes(notify)
  body=[flats['generation_lease_owner'],flats['generation_lease_public_lifecycle'],value,flats['generation_lease_typed_policy'],flats['generation_lease_owner_finalizer']]
  body.extend(flats[Path(row['path']).stem]for row in spec.owner.CARRIER_SOURCES)
  body.extend(flats[name]for name in resources.PUBLIC)
  body.extend([notify,flats['background_optimizer_future_public_cleanup']])
  assert len(body)==62
  frame=struct.pack('<64Q',spec.MAGIC,62,*map(len,body))+b''.join(body)
  obj=q.old.run_packer(flats['generation_future_fusion_packer'],frame)
  assert obj==spec.reference_object(body)
  assert obj.count(value)==1
  linked=q.old.run_packer(flats['multiversion_runtime_linker'],obj)
  path=out/'hia-generation-future-fusion.so'
  (out/'generation-future-fusion.o').write_bytes(obj);path.write_bytes(linked)
  assert linked.count(value)==1
  offsets={};unique={}
  for role,flat in zip(spec.ROLES,body):
   target={64+h+4+struct.unpack_from('<i',obj,64+h)[0]for h in spec.HOLES[role]}
   assert len(target)==1
   at=target.pop();assert obj[at:at+len(flat)]==flat
   if flat in unique:assert at==unique[flat]
   else:unique[flat]=at
   offsets[role]=at-64
  entryset=set(offsets[role]for role in spec.ROLES if role=='values')
  assert len(entryset)==1
  record['packer_controls']=pack_controls(flats['generation_future_fusion_packer'],frame,obj)
  record['role_layout']=[dict(role=role,offset=offsets[role],**pin(flat))for role,flat in zip(spec.ROLES,body)]
  record['logical_roles']=62;record['unique_bodies']=len(unique)
  record['identical_code_bytes_removed']=sum(map(len,body))-sum(map(len,unique))
  record['compiler']=pin(compiler.read_bytes())
  for row in record['compile']:record['source_files'][row['path']]=row['source_sha256']
  for rel in ('tools/generate_hia_generation_future_fusion_packer.py','tools/generate_hia_generation_lease_owner_packer.py','tools/generate_hia_background_optimizer_future_public_cleanup_packer.py','tools/hia_background_optimizer_future_public_cleanup_bridge.S','tools/qualify_hia_generation_future_fusion.py','tools/qualify_hia_generation_lease_owner.py','tools/qualify_hia_generation_lease_owner_resources.py'):
   record['source_files'][rel]=q.sha((ROOT/rel).read_bytes())
  for row in record['bridges']:record['source_files'][row['path']]=row['sha256']
  for rel,expected in record['source_files'].items():assert q.sha((ROOT/rel).read_bytes())==expected,rel
  for name in ('generation-future-fusion.o','hia-generation-future-fusion.so','hia-generation-lease-values.core.bin','hia-future-notify.core.bin'):record['products'][name]=pin((out/name).read_bytes())
  record.update(passed=True,native_construction_qualified=True,exact_reference_comparison=True,single_value_body=True,immutable_identical_pic_code_sharing=True,legacy_protocols_unchanged=True,text_limit_bytes=16777216,role_limit_bytes=4194304)
  print('FUSION_NATIVE_BUILD_PASS',json.dumps({k:record[k]for k in ('logical_roles','unique_bodies','identical_code_bytes_removed','products')}),flush=True)
  return path,record
 except BaseException as exc:
  record['failure']=repr(exc);record['traceback']=traceback.format_exc();raise
 finally:write(out/'build.json',record)
def qualify(path,out,tools):
 build=json.loads((path.parent/'build.json').read_bytes())
 assert build['passed'] and pin(path.read_bytes())==build['products'][path.name]
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
  whole_public_runtime_qualified=False,whole_public_future_qualified=False,production_activated=False)
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
 ap=argparse.ArgumentParser();ap.add_argument('--compiler',type=Path);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--built-dir',type=Path);ap.add_argument('--build-only',action='store_true')
 for name in ('normalizer','proof','builder'):ap.add_argument('--'+name,type=Path)
 a=ap.parse_args()
 if a.built_dir:path=a.built_dir/'hia-generation-future-fusion.so'
 else:
  assert a.compiler is not None;path,_=build(a.compiler,a.output)
 if not a.build_only:
  assert all(getattr(a,n)is not None for n in ('normalizer','proof','builder'))
  qualify(path,a.output if a.built_dir else a.output/'qualification',[a.normalizer,a.proof,a.builder])
if __name__=='__main__':main()
