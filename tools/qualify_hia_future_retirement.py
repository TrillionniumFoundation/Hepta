"""Native nine-role Future retirement and retained original Value-kind behavior.

This component gate executes the original native compiler and HIA packers.
The complete inherited campaign and syscall-failure gates remain independent.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,platform,struct,subprocess,sys
from tools import qualify_hia_future_value_kinds as kinds
from tools.hia_native_value_profiles import qualified_value_profile, qualified_value_sources
from tools.hia_native_future_profiles import (
 TRUTH_SOURCES,TRUTH_PACKER,TRUTH_PRODUCT,TRUTH_BRIDGE,truth_capsule_record,
)

ROOT=Path(__file__).resolve().parents[1]
BOOT=ROOT/'examples/hia_bootstrap'
COMPILER_SHA=kinds.COMPILER_SHA
ROLES=('owner','carrier','timeout','log','cell','kernel','value','notify','cleanup')
PUBLIC=kinds.PUBLIC
EXTRA=('result_value_records_packer','background_optimizer_future_public_observers_notify',
       'background_optimizer_future_public_observers_notify_packer',
       'background_optimizer_future_public_cleanup','background_optimizer_future_public_cleanup_packer')
AUTHORS=(
 'tools/generate_hia_background_optimizer_future_public_owner.py',
 'tools/generate_hia_background_optimizer_future_public_carrier.py',
 'tools/generate_hia_multiversion_background_future_cell.py',
 'tools/generate_hia_background_optimizer_future_public_cleanup.py',
 'tools/generate_hia_background_optimizer_future_public_cleanup_packer.py',
 'tools/hia_background_optimizer_future_public_cleanup_bridge.S',
 'tools/qualify_hia_future_retirement.py','tools/qualify_hia_future_value_kinds.py',
 'tools/hia_native_value_profiles.py',
 'tools/hia_native_future_profiles.py',
 'tools/generate_hia_background_optimizer_future_public_truth.py',
 'tools/generate_hia_background_optimizer_future_public_truth_packer.py',
 TRUTH_BRIDGE,
 'hepta/hia_background_optimizer.py','hepta/hia_multiversion.py',
)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return {'bytes':len(raw),'sha256':digest(raw)}
def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def cap(raw,at):return struct.unpack_from('<3Q',raw,at)
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def native_packer_controls(output):
 from tools.qualify_hia_multiversion_components import Image
 from tools.generate_hia_background_optimizer_future_public_cleanup_packer import reference_object,reference_flat
 image=Image(output/'background_optimizer_future_public_cleanup_packer.flat');rows=[]
 def invoke(wire,capacity,work_capacity=512,poison=0):
  src=C.create_string_buffer(wire,max(1,len(wire)))
  out=C.create_string_buffer(bytes([0xa5])*(capacity+32),capacity+32)
  work=C.create_string_buffer(bytes([poison])*work_capacity+b'\xa5'*32,work_capacity+32)
  rc=image.entry(src,len(wire),out,capacity,work,work_capacity)
  assert src.raw[:len(wire)]==wire and out.raw[capacity:]==b'\xa5'*32 and work.raw[work_capacity:]==b'\xa5'*32
  return rc,out.raw[:capacity]
 def wire(parts,mode):return b'HIABFPP3'+struct.pack('<11Q',9,*map(len,parts),mode)+b''.join(parts)
 for lengths in ((1,)*9,tuple(range(1,10)),tuple(17*i for i in range(1,10)),(2,3,5,7,11,127,128,129,257)):
  parts=[bytes((i*29+j)&255 for j in range(n))for i,n in enumerate(lengths)]
  for mode in (0,1):
   expected=reference_object(parts)if mode==0 else reference_flat(parts);source=wire(parts,mode)
   for poison in (0,0xa5,0xff):
    rc,out=invoke(source,len(expected),poison=poison);assert rc==len(expected)and out==expected
    rows.append({'case':'native-exact-layout','mode':mode,'lengths':lengths,'workspace_poison':poison,'passed':True})
   rc,out=invoke(source,len(expected)-1,poison=0xff);assert rc==0xfffffffe and out==b'\xa5'*len(out)
   rows.append({'case':'atomic-output-capacity-refusal','mode':mode,'lengths':lengths,'passed':True})
 valid=wire([bytes([i+1])*17 for i in range(9)],1);invalid=[valid[:n]for n in(0,7,8,15,80,88,95)]
 for at,value in ((0,0),(8,8),(8,10),(88,2),(16,0),(80,4194305),(72,(1<<64)-1)):
  data=bytearray(valid);struct.pack_into('<Q',data,at,value);invalid.append(bytes(data))
 invalid += [valid+b'x',valid[:-1],valid.replace(b'HIABFPP3',b'HIABFPP2',1)]
 for source in invalid:
  rc,out=invoke(source,4096);assert rc==0xffffffff and out==b'\xa5'*4096
  rows.append({'case':'new-profile-domain-refusal','input_sha256':digest(source),'passed':True})
 rc,out=invoke(valid,4096,511);assert rc==0xfffffffe and out==b'\xa5'*4096
 rows.append({'case':'workspace-capacity-refusal','passed':True})
 return rows

def build(compiler,output,*,value_qualification_path=None):
 from tools.qualify_hia_multiversion_components import Image
 from tools.generate_hia_background_optimizer_future_public_cleanup_packer import reference_flat,reference_object
 compiler=Path(compiler).resolve();compiler_raw=compiler.read_bytes()
 assert pin(compiler_raw)=={'bytes':813129,'sha256':COMPILER_SHA}
 source_files={p:digest((ROOT/p).read_bytes())for p in AUTHORS}
 value_roles=kinds.VALUE;value_packer='result_value_records_packer';value_protocol='HIABVP04'
 value_qualification=None;admitted={}
 if value_qualification_path is not None:
  qp=Path(value_qualification_path).resolve();qraw=qp.read_bytes();q=json.loads(qraw)
  assert qp.is_relative_to(ROOT) and q['component_qualified'] is True
  profile=qualified_value_profile(q)
  assert profile.protocol in ('HIABVP05','HIABVP09')
  assert q['construction']['compiler']['sha256']==COMPILER_SHA and q['construction']['compiler']['bytes']==813129
  value_roles=profile.roles;value_packer=profile.packer;value_protocol=profile.protocol
  assert q['value_packer']=='examples/hia_bootstrap/'+value_packer+'.hepta'
  table={row['source_path']:row for row in q['construction']['roles']}
  assert len(table)==len(q['construction']['roles'])
  for name in value_roles+(value_packer,):
   path='examples/hia_bootstrap/'+name+'.hepta';row=table[path];raw=(ROOT/path).read_bytes()
   assert row['two_compile_byteequal'] is True and len(raw)==row['source_bytes'] and digest(raw)==row['source_sha256'],path
   admitted[name]={'bytes':row['bytes'],'sha256':row['sha256']}
  for path,pin_value in qualified_value_sources(q).items():
   source_path=ROOT/path;assert source_path.resolve().is_relative_to(ROOT) and not source_path.is_symlink(),path
   source_raw=source_path.read_bytes()
   if isinstance(pin_value,dict):
    assert set(pin_value)=={'bytes','sha256'} and pin(source_raw)==pin_value,path
    expected=pin_value['sha256']
   else:
    assert isinstance(pin_value,str) and digest(source_raw)==pin_value,path
    expected=pin_value
   source_files[path]=expected
  source_files[str(qp.relative_to(ROOT))]=digest(qraw)
  value_qualification={'path':str(qp.relative_to(ROOT)),'sha256':digest(qraw),'product':q['construction']['products']['value-component.flat']}
  assert value_qualification['product']['native_pack'] is True and value_qualification['product']['independent_byte_comparison'] is True
 value_reference=importlib.import_module('tools.generate_hia_'+value_packer).reference_flat
 extras=(value_packer,)+EXTRA[1:]+(TRUTH_SOURCES[1],TRUTH_PACKER)
 flats={};rows=[]
 for name in value_roles+PUBLIC+extras:
  path=BOOT/(name+'.hepta');source=path.read_bytes();source_files[str(path.relative_to(ROOT))]=digest(source)
  results=[]
  for _ in range(2):
   p=subprocess.run([str(compiler),'compile'],input=source,capture_output=True,timeout=30)
   assert p.returncode==0 and p.stdout and not p.stderr,(name,p.returncode,p.stderr)
   results.append(p.stdout)
  assert results[0]==results[1],name
  flat=results[0]
  if name in admitted:assert pin(flat)==admitted[name],name
  flats[name]=flat;(output/(name+'.flat')).write_bytes(flat)
  rows.append({'source_path':str(path.relative_to(ROOT)),'source_bytes':len(source),'source_sha256':digest(source),
               'flat_bytes':len(flat),'flat_sha256':digest(flat),'double_compile_identical':True})
  print('RETIREMENT_NATIVE_COMPILE',name,len(flat),flush=True)
 def pack(name,wire,status_extent=False):
  image=Image(output/(name+'.flat'));out=C.create_string_buffer(16<<20);work=C.create_string_buffer(16<<20)
  rc=image(wire,out,work)
  size=word(work.raw,0)if status_extent else rc
  assert (not status_extent or rc==0)and 0<size<len(out),(name,rc,size)
  return out.raw[:size]
 parts=[flats[n]for n in value_roles]
 value=pack(value_packer,value_protocol.encode()+struct.pack('<'+str(len(parts)+2)+'Q',len(parts),*map(len,parts),1)+b''.join(parts))
 assert value==value_reference(parts)
 if value_qualification is not None:
  expected=value_qualification['product'];assert pin(value)=={'bytes':expected['bytes'],'sha256':expected['sha256']}
 n=flats['background_optimizer_future_public_observers_notify']
 notify=pack('background_optimizer_future_public_observers_notify_packer',b'HIABFNPK'+struct.pack('<3Q',len(n),0,0)+n,True)
 children=[flats[n]for n in TRUTH_SOURCES]
 cleanup=pack(TRUTH_PACKER,b'HIABFTPK'+struct.pack('<3Q',2,*map(len,children))+b''.join(children))
 capsule_reference=importlib.import_module('tools.generate_hia_'+TRUTH_PACKER).reference_flat
 assert cleanup==capsule_reference(children) and len(cleanup)<=4194304
 (output/TRUTH_PRODUCT).write_bytes(cleanup)
 capsule=truth_capsule_record(pin(cleanup))
 parts=[flats[n]for n in PUBLIC]+[value,notify,cleanup]
 wire=lambda mode:b'HIABFPP3'+struct.pack('<11Q',9,*map(len,parts),mode)+b''.join(parts)
 public=pack('background_optimizer_future_public_cleanup_packer',wire(1))
 obj=pack('background_optimizer_future_public_cleanup_packer',wire(0))
 assert public==reference_flat(parts)and obj==reference_object(parts)
 (output/'hia-future-public.o').write_bytes(obj)
 products={'hia-result-value.core.bin':value,'hia-future-notify.core.bin':notify,'hia-future-public.core.bin':public}
 for name,data in products.items():(output/name).write_bytes(data)
 for name,expected in source_files.items():assert digest((ROOT/name).read_bytes())==expected,name
 result={'schema':'hepta.hia.future-retirement-build.v1','compiler':pin(compiler_raw),'modules':rows,
         'source_files':source_files,'products':{n:pin(b)for n,b in products.items()},'roles':ROLES,
         'value_protocol':value_protocol,'value_roles':list(value_roles),'value_packer':value_packer,'value_qualification':value_qualification,
         'public_cleanup_capsule':capsule,
         'native_compile_and_pack':True,'independent_object_and_flat_comparison':True,
         'native_packer_controls':native_packer_controls(output)}
 save(output/'build.json',result);return result

class Public(kinds.Public):
 def typed(self,op,fid=(0,0,0),owned=(0,0,0),status=0):
  raw=bytearray(192);raw[:8]=b'HIABFP03';struct.pack_into('<Q',raw,8,op)
  struct.pack_into('<3Q',raw,16,*fid);struct.pack_into('<3Q',raw,40,*owned)
  source=C.create_string_buffer(bytes(raw),192);out=C.create_string_buffer(b'\xa5'*65568,65568)
  rc=self.image.entry(source,192,out,65536,self.ctx,256);r=out.raw[:65536]
  assert rc==0 and r[:8]==b'HIABFRP2'and out.raw[65536:]==b'\xa5'*32,(op,rc,r[:128].hex())
  assert source.raw==bytes(raw)and(status is None or word(r,8)==status),(op,status,r[:128].hex())
  assert all(word(r,x)<=1 for x in(96,104,112))
  return r
def facts(r,consumed,known=1,pending=0):
 assert (word(r,96),word(r,104),word(r,112))==(consumed,known,pending),r[:128].hex()
def cell_query(p,fac):
 r=p.call(17,*fac);assert word(r,16)==6
 fn,ctx,extent=cap(r,72)
 assert fn and ctx and extent==256
 raw=b'HIABFQ04'+struct.pack('<15Q',21,*([0]*14));src=C.create_string_buffer(raw,128);out=C.create_string_buffer(16384)
 f=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(fn)
 rc=f(src,128,out,16384,ctx,extent);r=out.raw
 assert rc==0 and r[:8]==b'HIABFR02'and word(r,8)==0
 assert (word(r,128),word(r,136),word(r,144),word(r,152))==(0,0,1,0)
 return True
def retirement_cases(output):
 from tools.qualify_hia_result_value_records import Values,NativeEngine
 from tools.qualify_hia_multiversion_components import Image
 image=Image(output/'hia-future-public.core.bin');rows=[]
 def setup():
  v=Values(NativeEngine(output/'hia-result-value.core.bin'));return v,Public(v,image)
 def row(name,**extra):
  rows.append({'case':name,'passed':True,**extra});print('RETIREMENT_CASE',name,flush=True)
 v,p=setup();fac=p.factory();r=p.call(2,*fac);alias_fac=(cap(r,24),cap(r,48))
 f=p.make(fac);r=p.call(5,*f);alias_f=(cap(r,24),cap(r,48))
 result=v.tuple([v.scalar('kept'),v.scalar(42)]);p.call(22,*f,value=result,kind=1)
 facts(p.typed(26,f[0],f[1]),1)
 facts(p.typed(26,f[0],f[1],status=3),0)
 got=v.keep(p.call(10,*alias_f),72);assert v.python_value(got)==('kept',42);v.drop(got)
 facts(p.typed(27,fac[0],fac[1]),1)
 got=v.keep(p.call(10,*alias_f),72);assert v.same(got,result);v.drop(got)
 facts(p.typed(26,alias_f[0],alias_f[1]),1);assert cell_query(p,alias_fac)
 facts(p.typed(27,alias_fac[0],alias_fac[1]),1);assert word(p.ctx.raw,16)==0
 facts(p.typed(29),1);facts(p.typed(29),0)
 assert word(p.ctx.raw,200)==word(p.ctx.raw,224)==0
 v.finish();row('independent-future-and-factory-references-exact-consumption',arena_unmapped=True)
 v,p=setup();fac=p.factory();f=p.make(fac);value=v.scalar('survives-owner-lease')
 p.call(22,*f,value=value,kind=1)
 r=p.typed(27,fac[0],fac[1]);facts(r,1,pending=1);assert cap(r,24)==fac[0]
 got=v.keep(p.call(10,*f),72);assert v.python(got)=='survives-owner-lease';v.drop(got)
 facts(p.typed(26,f[0],f[1]),1)
 r=p.typed(28,fac[0]);facts(r,0);assert word(p.ctx.raw,16)==0
 facts(p.typed(29),1);v.finish();row('last-factory-lease-preserves-live-future-and-retries-by-factory-identity',arena_unmapped=True)
 v,p=setup();other=Public(v,image);a=p.factory();b=other.factory();fa=p.make(a);fb=other.make(b)
 payload=v.scalar(123);p.call(22,*fa,value=payload,kind=1);other.call(22,*fb,value=payload,kind=1)
 facts(p.typed(26,fa[0],fa[1]),1);facts(p.typed(27,a[0],a[1]),1);facts(p.typed(29),1)
 got=v.keep(other.call(10,*fb),72);assert v.python(got)==123;v.drop(got)
 facts(other.typed(26,fb[0],fb[1]),1);facts(other.typed(27,b[0],b[1]),1);facts(other.typed(29),1)
 v.finish();row('two-public-owners-share-one-actual-value-arena-with-independent-lifetimes',arena_unmapped=True)
 v,p=setup();bad=[]
 for magic,op,at,value in ((b'HIABFP01',26,None,0),(b'HIABFP02',26,None,0),(b'HIABFP03',25,None,0),
                           (b'HIABFP03',28,40,1),(b'HIABFP03',29,16,1),(b'HIABFP03',26,64,1),
                           (b'HIABFP03',26,184,1)):
  raw=bytearray(192);raw[:8]=magic;struct.pack_into('<Q',raw,8,op)
  if at is not None:struct.pack_into('<Q',raw,at,value)
  source=C.create_string_buffer(bytes(raw),192);out=C.create_string_buffer(65536)
  rc=p.image.entry(source,192,out,65536,p.ctx,256);assert rc==0xfffffffd,(magic,op,at,rc)
  bad.append({'magic':magic.decode(),'operation':op,'reserved_offset':at})
 facts(p.typed(29),1)
 copied=C.create_string_buffer(p.ctx.raw,256);raw=b'HIABFP03'+struct.pack('<23Q',29,*([0]*22))
 out=C.create_string_buffer(65536);src=C.create_string_buffer(raw,192)
 rc=p.image.entry(src,192,out,65536,copied,256)
 assert rc==0 and out.raw[:8]==b'HIABFRP2'and word(out.raw,8)==1
 v.finish();row('new-profiles-reserved-domains-and-closed-context-copy-refusal',controls=bad,arena_unmapped=True)
 return rows
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--compiler',required=True);ap.add_argument('--output',required=True,type=Path)
 ap.add_argument('--receipt',type=Path);ap.add_argument('--reuse-build',action='store_true');ap.add_argument('--build-only',action='store_true')
 ap.add_argument('--value-qualification',type=Path,help='Exact separately qualified twelve-role resource Value receipt')
 args=ap.parse_args();assert platform.system()=='Linux'and platform.machine()=='x86_64'
 output=args.output.resolve()
 if args.reuse_build:
  result=json.loads((output/'build.json').read_bytes())
  if args.value_qualification is not None:
   qp=args.value_qualification.resolve();assert result['value_qualification']['path']==str(qp.relative_to(ROOT)) and result['value_qualification']['sha256']==digest(qp.read_bytes())
  for name,expected in result['source_files'].items():assert digest((ROOT/name).read_bytes())==expected,name
  for name,expected in result['products'].items():assert pin((output/name).read_bytes())==expected,name
 else:
  output.mkdir(parents=True,exist_ok=False);result=build(args.compiler,output,value_qualification_path=args.value_qualification)
 if args.build_only:return
 original,deferred=kinds.behavior(output);retirement=retirement_cases(output)
 report={'schema':'hepta.hia.future-retirement-qualification.v1','component_qualified':True,
         'python_version':sys.version,'platform':platform.platform(),
         'whole_public_future_closed':False,'whole_background_qualified':False,'whole_native_runtime':False,
         'scope':'native nine-role construction, retained original default Value-kind semantics and normal retirement lifecycles',
         'compiler':result['compiler'],'modules':result['modules'],'source_files':result['source_files'],
         'products':result['products'],'roles':ROLES,'value_image_sha256':result['products']['hia-result-value.core.bin']['sha256'],
         'value_protocol':result.get('value_protocol','HIABVP04'),'value_roles':result.get('value_roles',list(kinds.VALUE)),
         'value_packer':result.get('value_packer','result_value_records_packer'),'value_qualification':result.get('value_qualification'),
         'public_cleanup_capsule':result['public_cleanup_capsule'],
         'public_product':result['products']['hia-future-public.core.bin'],
         'original_value_kind_cases':original,'retirement_cases':retirement,
         'native_packer_controls':result['native_packer_controls'],
         'deferred_original_semantics':deferred,'original_27_campaign_requalified':False,
         'syscall_failure_requalified':False,'final_aggregate_claimed':False}
 save(output/'results.json',report)
 if args.receipt:
  target=args.receipt.resolve();target.relative_to(ROOT);save(target,report)
 print('FUTURE_RETIREMENT_PASS',len(original),len(retirement),flush=True)
if __name__=='__main__':main()
