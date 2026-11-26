"""Actual native Clang Value protocol qualification; Python is a QA driver only."""
from pathlib import Path
import ctypes as C,mmap,os,json,struct,hashlib,traceback,shutil
from tools.qualify_hia_result_value_invocations import Values,Bound,make_engine,sweep,echo_field
from tools.qualify_hia_clang_compile import small
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import HIAProgramLLVMRejected
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--library',type=Path,required=True)
parser.add_argument('--owner',type=Path,required=True)
parser.add_argument('--owner-sha256',default='da5f0d0a144a1bd82b590cc87f0d1d55f98166348bba3ad346179339deb32897')
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=args.output;root.mkdir(mode=0o700)
owner=args.owner;assert hashlib.sha256(owner.read_bytes()).hexdigest()==args.owner_sha256
library=args.library;lib=C.CDLL(str(library))
for name in ['hia_clang_value_bind_owner','hia_clang_value_compile','hia_clang_value_exception']:
 f=getattr(lib,name);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32
before=set(os.listdir('/proc/self/fd'));b=Bound(owner);a=b.call(0);assert a['status']==0 and a['state']==2 and a['pending']==0,a
v=Values(make_engine(b));program=verify_program(small(7));cases=[];report=dict(passed=False,cases=cases,product=dict(bytes=library.stat().st_size,sha256=hashlib.sha256(library.read_bytes()).hexdigest()),whole_public_runtime_qualified=False)
def save():(root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
class Pathlike:
 def __init__(self,result):self.result=result
 def __fspath__(self):return self.result
def oracle(value):
 try:
  found=shutil.which(value)
  if found is None:raise HIAProgramLLVMRejected('E_HIA_PROGRAM_LLVM: actual Clang 20+ is required')
  return str(Path(found).resolve())
 except BaseException as e:return e
def scalar(value):
 if type(value)is list:return v.lst([scalar(x)for x in value])
 if type(value)is dict:return v.dictionary(list(value.items()))
 return v.scalar(value)
def run(name,cap,expected,identity=None):
 work=mmap.mmap(-1,538968064);wp=C.addressof(C.c_char.from_buffer(work));bind=C.create_string_buffer(b'HIACVOB1'+bytes(24));r=lib.hia_clang_value_bind_owner(bind,32,wp,538968064,b.owner.context,2048);assert r==0,(name,'bind',r)
 raw=program.canonical_bytes;path=os.fsencode(root/(name+'.so'));src=bytearray(256);src[:8]=b'HIAMVBC1'
 for at,n in [(40,len(raw)),(56,len(path))]:struct.pack_into('<Q',src,at,n)
 struct.pack_into('<3Q',src,64,*cap);src+=raw+path;input_=C.create_string_buffer(bytes(src));out=C.create_string_buffer(1049088)
 rc=lib.hia_clang_value_compile(input_,len(src),out,len(out),wp,len(work));header=struct.unpack('<64Q',bytes(out)[:512]);phase=struct.unpack_from('<Q',work,256)[0]
 print('CASE_RESULT',name,rc,header[1],header[2],phase,flush=True)
 assert rc==0 and bytes(out)[:8]==b'HIAMVCR1',(name,rc,phase)
 row=dict(case=name,status=header[1],detail=header[2],phase=phase)
 if isinstance(expected,BaseException):
  q=C.create_string_buffer(b'HIAMVCE1'+struct.pack('<15Q',1,*([0]*14)));answer=C.create_string_buffer(128)
  assert lib.hia_clang_value_exception(q,128,answer,128,wp,len(work))==0
  vals=struct.unpack('<16Q',bytes(answer));assert vals[2]==2 and vals[11]==1 and vals[12]==0,(name,vals)
  q=C.create_string_buffer(b'HIAMVCE1'+bytes(120));assert lib.hia_clang_value_exception(q,128,answer,128,wp,len(work))==0
  vals=struct.unpack('<16Q',bytes(answer));assert vals[2]==2 and vals[12]==1,(name,vals)
  ex=v.keep(bytes(answer));env,args_,typename=v.parts(ex);actualargs=v.python_value(args_);actualname=v.python(typename)
  assert actualname==type(expected).__name__ and actualargs==expected.args,(name,actualname,actualargs,type(expected).__name__,expected.args)
  if identity is not None:assert v.same(ex,identity),(name,'exception identity changed')
  assert lib.hia_clang_value_exception(q,128,answer,128,wp,len(work))==0;assert struct.unpack_from('<Q',answer,16)[0]==0 and struct.unpack_from('<Q',answer,96)[0]==0
  row.update(exception_type=actualname,exception_args=repr(actualargs),actual_exception_object=True)
  assert not (root/(name+'.so')).exists(),name
 else:
  assert header[1]==0,(name,header)
  receipt=json.loads(bytes(out)[512:512+header[10]]);assert receipt['input_sha256']==program.sha256 and receipt['core_sha256']==program.sha256
  native=C.CDLL(str(root/(name+'.so')));calc=native.calculate;calc.argtypes=[C.c_uint64];calc.restype=C.c_uint64;assert calc(35)==42 and calc((1<<64)-1)==6
  row.update(actual_compiler=True,actual_native_execution=True)
 q=C.create_string_buffer(b'HIAMVBC1'+struct.pack('<31Q',1,*([0]*30)));answer=C.create_string_buffer(512)
 assert lib.hia_clang_value_compile(q,256,answer,512,wp,len(work))==0
 vals=struct.unpack('<64Q',bytes(answer));assert vals[43]==1 and vals[44]==1 and vals[45]==0,(name,vals[42:48])
 work.close();sweep(v,b);assert set(os.listdir('/proc/self/fd'))==before,(name,before,set(os.listdir('/proc/self/fd')))
 row.update(passed=True,all_caps_and_code_retired=True,fd_balanced=True);cases.append(row);save()
def custom(name,result,py_result=None,baseclass=None,parts=None,raise_=None):
 cls=v.cls(name,[] if baseclass is None else [v.builtin(baseclass)])
 if raise_ is not None:
  cls_id={BaseException:21,Exception:22,TypeError:23}[type(raise_)];result=v.exception(v.builtin(cls_id),v.tuple([v.scalar(x)for x in raise_.args]));function=v.function(echo_field(1,2),env=result)
 else:function=v.function(echo_field(1),env=result)
 v.attr(cls,'__fspath__',function);obj=v.instance(cls,base=v.lst([v.scalar(p)for p in parts]) if parts is not None else (0,0,0))
 return obj,result
try:
 for i,value in enumerate(['clang',None,1,True,[],{},'not-a-compiler-hia-test',b'clang',b'not-a-compiler-hia-test','bad\ud800','bad\udcff']):
  run('scalar_'+str(i),scalar(value),oracle(value))
 for i,parts in enumerate([['/usr','bin','clang'],['/discard','/usr/bin/clang'],['//usr','bin','./clang'],['/usr','bin','..','bin','clang'],[]]):
  cap=v.instance(v.builtin(18),v.lst([v.scalar(x)for x in parts]));run('posix_'+str(i),cap,oracle(Path(*parts)))
 for i,value in enumerate(['clang',b'clang',b'/usr/bin/clang',b'not-a-compiler-hia-test',1,None]):
  returned=scalar(value);cap,_=custom('Pathlike',returned);run('fspath_'+str(i),cap,oracle(Pathlike(value)))
 value=v.scalar('clang');cap,_=custom('Override',value,baseclass=18,parts=['/does-not-exist']);run('posix_override',cap,'success')
 cls=v.cls('StringAlias',[v.builtin(6)]);cap=v.inherited(cls,v.scalar('clang'));run('string_subclass',cap,'success')
 cls=v.cls('ReturnString',[v.builtin(6)]);returned=v.inherited(cls,v.scalar('clang'));cap,_=custom('Pathlike',returned);run('fspath_string_subclass',cap,'success')
 for i,raised in enumerate([BaseException('base'),Exception('ordinary'),TypeError('identity')]):
  cap,ex=custom('Raising',None,raise_=raised);run('fspath_raise_'+str(i),cap,raised,ex)
 for i,item in enumerate([None,1,False]):
  cls=v.cls('Bad'+str(i),[]);v.attr(cls,'__fspath__',scalar(item));cap=v.instance(cls);original=type('Bad'+str(i),(),{'__fspath__':item})();run('fspath_not_callable_'+str(i),cap,oracle(original))
 b.close();assert set(os.listdir('/proc/self/fd'))==before
 report.update(passed=True,groups=len(cases),actual_value_calls=True,no_host_binding_writes=True)
except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();save();raise
finally:save()
print('CLANG_VALUE_PROTOCOL_PASS',len(cases),flush=True)
