"""Native public Path objects in the retained BackgroundOptimizer live bridge loop."""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,os,struct,subprocess,sys
from tools.qualify_hia_multiversion_components import Image
ROOT=Path(__file__).resolve().parents[1]
COMPILER_SHA='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
VALUE_SHA='e03d3c7802800720be340184a036151e0f0e4e788bf720ba6a7a135da7edbfe3'
SINGLE=('background_optimizer_constructor_binding','background_optimizer_bridge_paths','background_optimizer_public_constructor','background_optimizer_constructor_options','native_path_resolve')
PAIRS={'native_path_value':('native_path_value','native_path_value_error'),'native_posix_path_factory':('native_posix_path_factory','native_path_value_error')}
BARE=('native_path_string_codec','ndu_rank_native_owner_error')
CHECKS='background_optimizer_constructor_checks'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def u(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def cap(raw,at):return struct.unpack_from('<3Q',raw,at)
def addr(f):return C.cast(f,C.c_void_p).value
def put(buf,at,*values):struct.pack_into('<'+'Q'*len(values),buf,at,*values)
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def object_text(raw):
 sh=u(raw,40);offset,size=struct.unpack_from('<2Q',raw,sh+64+24)
 assert offset==64 and offset+size<=len(raw)
 return raw[offset:offset+size]
def build(compiler,value_build,out):
 compiler=Path(compiler);assert pin(compiler.read_bytes())=={'bytes':813129,'sha256':COMPILER_SHA}
 value_build=Path(value_build);vr=json.loads((value_build/'build.json').read_text())
 assert vr['native_hia_construction']
 for row in vr['roles']:
  assert row['two_compile_byteequal'] and sha((ROOT/row['source_path']).read_bytes())==row['source_sha256'],row['source_path']
 value=(value_build/'value-component.flat').read_bytes()
 assert pin(value)=={'bytes':2545589,'sha256':VALUE_SHA}
 assert vr['products']['value-component.flat']['sha256']==VALUE_SHA
 (out/'value-component.flat').write_bytes(value)
 names=list(dict.fromkeys([n for name in SINGLE for n in (name,name+'_packer')]+[n for name,roles in PAIRS.items()for n in (*roles,name+'_packer')]+list(BARE)+[CHECKS]))
 flats={};modules=[];sources={}
 for name in names:
  path=ROOT/'examples/hia_bootstrap'/(name+'.hepta');raw=path.read_bytes()
  rounds=[subprocess.run([str(compiler),'compile'],input=raw,capture_output=True,timeout=30)for _ in range(2)]
  assert all(r.returncode==0 and r.stdout and not r.stderr for r in rounds),(name,[(r.returncode,r.stderr)for r in rounds])
  assert rounds[0].stdout==rounds[1].stdout
  flat=rounds[0].stdout;flats[name]=flat;(out/(name+'.flat')).write_bytes(flat)
  modules.append({'source_path':str(path.relative_to(ROOT)),'source_bytes':len(raw),'source_sha256':sha(raw),'flat_bytes':len(flat),'flat_sha256':sha(flat),'double_compile_identical':True})
  sources[str(path.relative_to(ROOT))]=sha(raw);print('BG_PUBLIC_NATIVE_COMPILE',name,len(flat),flush=True)
 products={'value-component.flat':pin(value)}
 for name in SINGLE+tuple(PAIRS):
  packer=importlib.import_module('tools.generate_hia_'+name+'_packer')
  roles=(name,CHECKS)if name=='background_optimizer_constructor_binding'else PAIRS.get(name,(name,))
  parts=[flats[n]for n in roles]
  if name in PAIRS:
   magic=b'HIANPP01'if name=='native_path_value'else b'HIANXP01'
   wire=magic+struct.pack('<4Q',2,*map(len,parts),0)+b''.join(parts)
  else:
   assert len(parts)==len(packer.ROLES) and not packer.RELOCATIONS
   wire=struct.pack('<'+'Q'*(2+len(parts)),packer.MAGIC,len(parts),*map(len,parts))+b''.join(parts)
  expected=packer.reference_object(parts);ob=C.create_string_buffer(len(expected));wb=C.create_string_buffer(1<<20)
  rc=Image(out/(name+'_packer.flat'))(wire,ob,wb)
  assert rc==len(expected)and ob.raw==expected,(name,rc,len(expected))
  flat=object_text(ob.raw)
  (out/(name+'.component.o')).write_bytes(ob.raw);(out/(name+'.component.flat')).write_bytes(flat)
  products[name]={'object':pin(ob.raw),'flat':pin(flat),'independent_object_comparison':True}
  print('BG_PUBLIC_NATIVE_PACK',name,len(flat),flush=True)
  sources['tools/generate_hia_'+name+'_packer.py']=sha((ROOT/'tools'/('generate_hia_'+name+'_packer.py')).read_bytes())
 for name in ('tools/generate_hia_background_optimizer_bridge_paths.py','tools/generate_hia_background_optimizer_public_constructor.py','tools/generate_hia_background_optimizer_constructor_binding.py','tools/hia_background_optimizer_public_constructor_bridge.S','tools/qualify_hia_background_public_paths.py'):
  sources[name]=sha((ROOT/name).read_bytes())
 result={'schema':'hepta.hia.background-public-paths-build.v1','compiler':pin(compiler.read_bytes()),'modules':modules,'products':products,'source_files':sources,'value_build':{'path':str(value_build/'build.json'),'sha256':sha((value_build/'build.json').read_bytes())},'native_compile_and_pack':True,'whole_background_qualified':False}
 save(out/'build.json',result);return result

def retained_path_gates(out):
 from tools import qualify_hia_background_optimizer_bridge_paths as qa
 from tools.qualify_hia_result_value_records import Values as Classes
 images={'bridge':str(out/'background_optimizer_bridge_paths.component.flat'),'value':str(out/'value-component.flat'),'path_value':str(out/'native_path_value.component.flat'),'resolve':str(out/'native_path_resolve.component.flat'),'codec':str(out/'native_path_string_codec.flat'),'error':str(out/'ndu_rank_native_owner_error.flat')}
 Base=qa.Bridge
 class DirectBridge(Base):
  def __init__(self,images=None):
   assert images is not None
   super().__init__(images)
   self.path.value_func=self.path.engine.image.entry
   self.path.context=self.path.engine.context
   for target in (self.path.w,self.w):
    put(target,8,addr(self.path.value_func),C.addressof(self.path.context),256)
 class PublicBridge(DirectBridge):
  verified_types=0
  def __init__(self,images=None):
   super().__init__(images)
   self.factory=qa.Flat((out/'native_posix_path_factory.component.flat').read_bytes())
   self.w[:8]=b'HIABBPC2';put(self.w,80,addr(self.factory.f))
  def call(self,dictionary=qa.ZERO,op=0):
   self.calls+=1
   raw=bytearray(128);raw[:8]=b'HIABBPQ2';put(raw,8,op);put(raw,16,*dictionary)
   src=C.create_string_buffer(bytes(raw),128);dest=C.create_string_buffer(b'\xa5'*262176,262176)
   before=self.w.raw[:64]+self.w.raw[72:128]
   rc=self.image.f(src,128,dest,262144,self.w,262144)
   assert rc==0 and dest.raw[:8]==b'HIABBPR1',(rc,dest.raw[:128].hex())
   assert src.raw==bytes(raw)and dest.raw[262144:]==b'\xa5'*32
   assert self.w.raw[:64]+self.w.raw[72:128]==before
   assert not self.failures and not self.path.failures
   assert dest.raw[112:128]==bytes(16)
   return dest.raw[:128]
  def decode(self,reply):
   if u(reply,8)!=0:return super().decode(reply)
   assert u(reply,104)==1
   cv=Classes(self.path.engine);cv.held=self.values.held
   root=cv.keep(reply,16);n=u(cv.raw(7,a=root),48)
   entries=cv.raw(23,a=root,arg1=n,on=max(16384,8192+n*64))
   result={};canonical=cv.builtin(18)
   for i in range(n):
    key=cv.keep(entries,8192+i*64+16);value=cv.keep(entries,8192+i*64+40)
    actual_type=cv.keep(cv.raw(36,a=value))
    assert cv.same(actual_type,canonical)
    descriptor=cv.raw(26,a=value)
    assert descriptor[8192:8200]==b'HIAVNO01'and u(descriptor,8200)==14
    children=[cv.keep(descriptor,8224+j*24)for j in range(3)]
    assert u(cv.raw(7,a=children[1]),16)==5
    raw_paths=cv.python_value(children[1]);assert type(raw_paths)is list and len(raw_paths)==1 and type(raw_paths[0])is str
    result[cv.python_value(key)]=raw_paths[0]
    PublicBridge.verified_types+=1
    for owned in children+[key,value,actual_type]:cv.drop(owned)
   cv.drop(canonical);cv.drop(root)
   return 'ok',result
  def finish(self):
   assert u(self.w.raw,12288+128)==u(self.w.raw,12288+136)==0
   super().finish()
 previous=sys.argv;reports=[]
 try:
  for name,cls in (('retained-string-profile',DirectBridge),('public-posixpath-profile',PublicBridge)):
   qa.Bridge=cls
   report=out/(name+'.json')
   sys.argv=['retained-native-path-comparisons','--report',str(report)]
   for key,value in images.items():sys.argv+=['--'+key.replace('_','-')+'-image',value]
   qa.main()
   result=json.loads(report.read_text())
   assert result['native_hia_executed'] and result['passed']>0
   reports.append({'profile':name,'passed':result['passed'],'report_sha256':sha(report.read_bytes()),'original_source_sha256':result['original_source_sha256']})
 finally:qa.Bridge=Base;sys.argv=previous
 assert PublicBridge.verified_types>0
 result={'passed':True,'profiles':reports,'real_posixpath_type_identity_checks':PublicBridge.verified_types,'direct_fixed_native_value_entry_and_arena':True,'python_value_forwarder_used':False,'whole_background_qualified':False}
 save(out/'path-results.json',result);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--compiler',required=True);ap.add_argument('--value-build',required=True,type=Path);ap.add_argument('--output',required=True,type=Path);ap.add_argument('--reuse-build',action='store_true');ap.add_argument('--build-only',action='store_true')
 args=ap.parse_args();out=args.output.resolve()
 if args.reuse_build:
  built=json.loads((out/'build.json').read_text())
  for path,digest in built['source_files'].items():assert sha((ROOT/path).read_bytes())==digest,path
 else:
  out.mkdir(exist_ok=False);built=build(args.compiler,args.value_build,out)
 if not args.build_only:
  result=retained_path_gates(out);print('BG_PUBLIC_PATHS_PASS',json.dumps(result),flush=True)
if __name__=='__main__':main()
