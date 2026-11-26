"""Actual native Clang Value advanced qualification; Python is a QA driver only."""
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
parser.add_argument('--bridge-dir',type=Path,required=True)
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

from tools.qualify_hia_native_callable_code_owner import deny_native
import subprocess,queue,threading
bridge=(args.bridge_dir/'bridge.bin').read_bytes();symbols={}
for line in subprocess.check_output(['/usr/bin/nm','-n',str(args.bridge_dir/'bridge.o')],text=True).splitlines():
 f=line.split()
 if len(f)==3:symbols[f[2]]=int(f[0],16)
at=bridge.index(b'\x0f\x05',symbols['.Av_syscall']);assert at<symbols['.Av_busy'];ip=C.cast(lib.hia_clang_value_compile,C.c_void_p).value+at+2
def isolated(nr,err,fn):
 q=queue.Queue()
 def go():
  try:deny_native(ip,nr,err);q.put(fn())
  except BaseException as e:q.put(e)
 t=threading.Thread(target=go);t.start();t.join(120);assert not t.is_alive()
 result=q.get_nowait()
 if isinstance(result,BaseException):raise result
 return result
def session(cap,name):
 work=mmap.mmap(-1,538968064);wp=C.addressof(C.c_char.from_buffer(work));rq=C.create_string_buffer(b'HIACVOB1'+bytes(24))
 assert lib.hia_clang_value_bind_owner(rq,32,wp,len(work),b.owner.context,2048)==0
 path=os.fsencode(root/(name+'.so'));raw=program.canonical_bytes;data=bytearray(256);data[:8]=b'HIAMVBC1'
 struct.pack_into('<Q',data,40,len(raw));struct.pack_into('<Q',data,56,len(path));struct.pack_into('<3Q',data,64,*cap);data+=raw+path
 return work,wp,bytes(data)
def invoke(work,wp,data):
 s=C.create_string_buffer(data);out=C.create_string_buffer(1049088 if len(data)>256 else 512)
 rc=lib.hia_clang_value_compile(s,len(data),out,len(out),wp,len(work));return rc,bytes(out)
retire=b'HIAMVBC1'+struct.pack('<31Q',1,*([0]*30))
def get_exception(work,wp):
 s=C.create_string_buffer(b'HIAMVCE1'+bytes(120));out=C.create_string_buffer(128)
 assert lib.hia_clang_value_exception(s,128,out,128,wp,len(work))==0
 assert struct.unpack_from('<Q',out,96)[0]==1,bytes(out).hex()
 cap=v.keep(bytes(out));env,args_,name=v.parts(cap);return cap,v.python(name),v.python_value(args_)
def ended(work,wp):
 rc,out=invoke(work,wp,retire);facts=struct.unpack('<64Q',out[:512]);assert rc==0 and facts[43:46]==(1,1,0),facts[42:48]
 work.close();sweep(v,b);assert set(os.listdir('/proc/self/fd'))==before
def passed(name,**kw):
 cases.append(dict(case=name,passed=True,**kw));save();print('ADVANCED_PASS',name,flush=True)
try:
 for name in ['A'*20000,'pkg.'+'界'*90,'pkg.'+'😀'*51]:
  returned=v.scalar(1);cap,_=custom(name,returned);original=type(name,(),{'__fspath__':lambda self:1})()
  run('longname_'+str(len(cases)),cap,oracle(original))
 for pathvalue in ['',None,':']:
  old=os.environ.get('PATH')
  try:
   if pathvalue is None:os.environ.pop('PATH',None)
   else:os.environ['PATH']=pathvalue
   returned=v.scalar(b'not-a-compiler-hia-test');cap,_=custom('Pathlike',returned);run('live_path_'+str(len(cases)),cap,oracle(Pathlike(b'not-a-compiler-hia-test')))
  finally:
   if old is None:os.environ.pop('PATH',None)
   else:os.environ['PATH']=old
 for count in [3968,3969,8192,20000]:
  parts=['x'*count,'/usr/bin/clang'];cap=v.instance(v.builtin(18),v.lst([v.scalar(x)for x in parts]));run('path_growth_'+str(count),cap,'success')
 run('real_non_clang',v.scalar('/bin/true'),HIAProgramLLVMRejected('E_HIA_PROGRAM_LLVM: expected an actual Clang 20+ GNU/Linux driver matching the measured native host'))
 cap=v.scalar('clang');work,wp,data=session(cap,'mmap_fail')
 rc,out=isolated(9,12,lambda:invoke(work,wp,data));assert rc==0 and struct.unpack_from('<Q',out,8)[0]==18
 ex,name,args_=get_exception(work,wp);assert name=='MemoryError' and args_==()
 ended(work,wp);passed('actual-kernel-mmap-enomem-true-MemoryError-and-owned-retirement')
 cap=v.instance(v.builtin(18),v.lst([v.scalar('x'*5000),v.scalar('/usr/bin/clang')]));work,wp,data=session(cap,'mremap_fail')
 rc,out=isolated(25,12,lambda:invoke(work,wp,data));assert rc==0 and struct.unpack_from('<Q',out,8)[0]==18
 ex,name,args_=get_exception(work,wp);assert name=='MemoryError' and args_==()
 ended(work,wp);passed('actual-kernel-path-mremap-enomem-true-MemoryError-and-owned-retirement')
 cap=v.scalar('not-a-compiler-hia-test');work,wp,data=session(cap,'failed_retirement')
 rc,out=invoke(work,wp,data);assert rc==0 and struct.unpack_from('<Q',out,8)[0]==4
 rc,out=isolated(11,5,lambda:invoke(work,wp,retire));facts=struct.unpack('<64Q',out[:512]);assert rc==0 and facts[43:46]==(1,0,1) and facts[46:48]==(12,5),facts[42:48]
 ex,name,args_=get_exception(work,wp);assert name=='HIAProgramLLVMRejected' and args_==('E_HIA_PROGRAM_LLVM: actual Clang 20+ is required',)
 ended(work,wp);passed('actual-kernel-munmap-eio-retains-map-and-exception-until-real-retry')
 cap=v.scalar('clang');work,wp,data=session(cap,'wire_guards');before_prefix=bytes(work[:4096]);invalid=[]
 for index in [16,88,96,248]:
  bad=bytearray(data);struct.pack_into('<Q',bad,index,1);invalid.append(bytes(bad))
 for index,value in [(40,0),(40,8388609),(48,5137),(56,0),(64,0)]:
  bad=bytearray(data);struct.pack_into('<Q',bad,index,value);invalid.append(bytes(bad))
 invalid += [data[:-1],data+b'\0',data[:255],data[:128]]
 for bad in invalid:
  inp=C.create_string_buffer(bad);out=C.create_string_buffer(b'\xa5'*1049088);rc=lib.hia_clang_value_compile(inp,len(bad),out,1049088,wp,len(work))
  assert rc==0xfffffffd and bytes(out)[:-1]==b'\xa5'*1049088 and bytes(work[:4096])==before_prefix,(len(bad),hex(rc))
 for index in [8,16,120]:
  bad=bytearray(b'HIAMVCE1'+bytes(120));struct.pack_into('<Q',bad,index,2 if index==8 else 1);inp=C.create_string_buffer(bytes(bad));out=C.create_string_buffer(b'\xa5'*128)
  rc=lib.hia_clang_value_exception(inp,128,out,128,wp,len(work));assert rc==0xfffffffd and out.raw==b'\xa5'*128+b'\0' and bytes(work[:4096])==before_prefix
 copied=mmap.mmap(-1,len(work));copied[:4096]=work[:4096];cp=C.addressof(C.c_char.from_buffer(copied));inp=C.create_string_buffer(retire);out=C.create_string_buffer(b'\xa5'*512)
 rc=lib.hia_clang_value_compile(inp,256,out,512,cp,len(copied));assert rc==0xfffffffd and out.raw==b'\xa5'*512+b'\0' and copied[:4096]==before_prefix;copied.close()
 pid=os.fork()
 if pid==0:
  rc,out=invoke(work,wp,retire);os._exit(0 if rc==0xfffffffd and bytes(work[:4096])==before_prefix else 99)
 assert os.waitpid(pid,0)[1]==0
 ended(work,wp);passed('exact-wire-no-output-or-context-writes-copy-fork-refusal',controls=len(invalid)+5)
 old=os.environ.get('CCC_OVERRIDE_OPTIONS')
 try:
  os.environ['CCC_OVERRIDE_OPTIONS']='+-mcpu=hia_invalid_cpu'
  cap=v.scalar('clang');work,wp,data=session(cap,'real_clang_reject');rc,out=invoke(work,wp,data);facts=struct.unpack('<64Q',out[:512])
  print('REAL_CLANG_REJECTION',rc,facts[:17],flush=True)
  assert rc==0 and facts[1]==7 and facts[4]==1 and facts[3]!=0,(rc,facts[:17])
  raw=os.pread(facts[12],facts[15],0);expected='E_HIA_PROGRAM_NATIVE: Clang rejected independently verified HIA LLVM: '+raw.decode('utf-8',errors='replace').replace('\r\n','\n').replace('\r','\n')[:3000]
  ex,name,args_=get_exception(work,wp);assert name=='HIAProgramLLVMRejected' and args_==(expected,),(name,args_,expected)
  ended(work,wp);passed('actual-Clang-native-rejection-real-decoded-stderr-and-exception-args',stderr_bytes=len(raw),status=facts[3])
 finally:
  if old is None:os.environ.pop('CCC_OVERRIDE_OPTIONS',None)
  else:os.environ['CCC_OVERRIDE_OPTIONS']=old
 b.close();assert set(os.listdir('/proc/self/fd'))==before;report.update(passed=True,groups=len(cases),real_kernel_failures=3)
except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();save();raise
finally:save()
print('CLANG_VALUE_ADVANCED_PASS',len(cases),flush=True)
