"""Actual Value-only Runtime constructor through the installed native parent."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,traceback
from tools import qualify_hia_generation_runtime_directory_installed as installed
from tools import qualify_hia_generation_runtime_directory as directory
from tools import qualify_hia_result_value_exceptions as exceptions
from tools.qualify_hia_clang_capture_faults import isolated
from hepta.hia_multiversion import ScalarMultiversionRuntime,MultiversionRejected
q=directory.q
ZERO=(0,0,0)
class Values(directory.Values,exceptions.Values):
 pass
def private_value(owner,op,cap=ZERO,arg0=0):
 raw=bytearray(128);raw[:8]=b'HIABVQ05';struct.pack_into('<Q',raw,8,op);struct.pack_into('<3Q',raw,24,*cap);struct.pack_into('<Q',raw,104,arg0)
 src=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(16384)
 F=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
 entry=F(q.get(owner.context,40));rc=int(entry(src,128,out,16384,C.addressof(owner.context)+512,256))
 assert rc==0 and out.raw[:8]==b'HIABVR01',(rc,out.raw[:128].hex())
 return out.raw
def construct(f,caps,op=0):
 raw=bytearray(256);raw[:8]=b'HIARTCQ1';struct.pack_into('<Q',raw,8,op)
 for i,cap in enumerate(caps):struct.pack_into('<3Q',raw,24+24*i,*cap)
 src=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(1<<20)
 entry=f.entry('hia_scalar_multiversion_runtime_create')
 rc=int(entry(src,256,out,len(out),f.front,len(f.front)))
 assert src.raw==bytes(raw)+b'\0'
 row={k:q.get(out,at)for k,at in dict(status=8,disposition=16,state=48,carrier=56,child=64,profile=72,pending=80,known=88,delivered=96,retired=104,detail=112).items()}
 row['cap']=struct.unpack_from('<3Q',out.raw,24)
 return rc,row,out.raw
def exception_data(v,cap):
 ns,args,name=v.parts(cap)
 cls=v.keep(v.raw(36,a=cap));cn=v.keep(v.raw(38,a=cls))
 got=v.python(cn),v.python_value(args)
 for c in(ns,args,name,cls,cn):v.drop(c)
 return got
def one(path,out,name):
 f=installed.InstalledFixture(path,out);v=Values(q.ValueTransport(f.owner));baseline=q.get(v.raw(47),48)
 report=dict(passed=False,calls=[],name=name)
 def save():(out/'case.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 try:
  base=v.scalar(directory.current_core());folder=v.scalar(str(f.parent));caps=[base,folder]
  target=v.builtin(20)
  if name=='actual-subclass':
   target=v.cls('ActualNativeRuntimeSubclass',[target]);caps=[base,folder,ZERO,ZERO,ZERO,ZERO,target]
  elif name=='option-error':
   bad=v.scalar(True);caps=[base,folder,ZERO,bad]
  rc,row,raw=construct(f,caps)
  report['calls'].append(dict(rc=rc,**row));report['factory_header']=f.front.raw[524288:524800].hex();save()
  assert rc==0 and raw[:8]==b'HIARTCR1',(rc,row,raw[:128].hex())
  assert row['known']==row['delivered']==row['retired']==1 and row['pending']==0 and row['state']==3,row
  primary=v.keep(raw)
  if name=='option-error':
   assert row['status']!=0 and row['disposition']==2,row
   try:ScalarMultiversionRuntime(None,None,validation_timeout_ms=True)
   except MultiversionRejected as error:expected=type(error).__name__,error.args
   else:raise AssertionError('original timeout error absent')
   actual=exception_data(v,primary);assert actual==expected,(actual,expected)
   f.guard(0);report['actual_original_exception']=actual
  else:
   assert row['status']==0 and row['disposition']==1 and row['carrier']==row['child']==0,row
   actualclass=v.keep(v.raw(36,a=primary));assert v.same(actualclass,target)
   parts=v.parts(primary);assert v.python(parts[0])=='clang'
   for part in parts:v.drop(part)
   f.guard(1)
   captured=private_value(f.owner,49,primary,1)
   assert q.get(captured,8)==0 and q.get(captured,16)==1,captured[:128].hex()
   carrier=struct.unpack_from('<3Q',captured,24);assert all(carrier)
   lease=q.old.lease(f.c,carrier);f.c.call(lease,37)
   v.drop(primary);f.guard(1);f.c.call(lease,43)
   q.old.ok(f.api.call(6,lease));f.guard(0)
   report.update(actual_canonical_or_subclass=True,actual_clang_env=True,actual_native_lease_calls=True,actual_last_runtime_value_drop_before_lease_close=True)
  while v.held:v.drop(next(iter(v.held)))
  assert q.get(v.raw(47),48)==baseline,(baseline,q.get(v.raw(47),48))
  report.update(passed=True,**f.finish());save();return report
 except BaseException as e:
  report.update(error=repr(e),traceback=traceback.format_exc());save();raise
CASES=('canonical','actual-subclass','option-error')
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES);a=p.parse_args()
 path=a.build/'install/hia-generation-component-root.so';build=json.loads((a.build/'build.json').read_bytes())
 assert directory.custody.pin(path.read_bytes())==build['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir()
  rows.append(isolated(name,lambda name=name,here=here:one(path,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
  print('PUBLIC_RUNTIME_FACTORY_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=directory.custody.pin(path.read_bytes()),construction=directory.custody.pin((a.build/'build.json').read_bytes()),qualifier=directory.custody.pin(Path(__file__).read_bytes()),
 actual_value_runtime_factory=True,public_constructor_qualified=False,structured_original_input_binding_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 print('PUBLIC_RUNTIME_FACTORY_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
