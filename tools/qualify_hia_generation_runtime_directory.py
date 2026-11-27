"""Real late Runtime directory handling through the native constructor carrier.

Expected Path results are computed only in this development oracle. The product
receives actual Value capabilities and performs all conversions itself.
"""
from pathlib import Path,PurePosixPath,PureWindowsPath
from types import SimpleNamespace
import argparse,ctypes as C,hashlib,json,mmap,os,struct,tempfile
from tools import qualify_hia_generation_runtime_custody as custody
from tools import qualify_hia_result_value_classes as classes
from tools import qualify_hia_result_value_invocations as inv
from tools.qualify_hia_clang_capture_faults import isolated
q=custody.q
ZERO=(0,0,0)
class Values(classes.Values):
 def raw(self,op,*,want=0,on=16384,**kw):
  request=bytearray(classes.frame(op,**kw))
  if 40<=op<=47:request[:8]=b'HIABVQ04'
  if op>=48:request[:8]=b'HIABVQ05'
  rc,out=self.engine.call(bytes(request),on=on)
  assert rc==0 and out[:8]==(b'HIABVR02'if 29<=op<=31 else b'HIABVR01'),(op,rc,out[:128].hex())
  assert q.get(out,8)==want,(op,q.get(out,8),want)
  return out
def current_core():
 from hepta.hia_program import verify_program
 return verify_program(q.old.scalar_program(None)).canonical_bytes
def create(f,directory,clang,core=None):
 payload=q.old.public_request(0,files=f.files,parent=os.fsencode(f.parent),raw=current_core()if core is None else core)
 frame=bytearray(128);frame[:8]=b'HIAMVHC1';struct.pack_into('<Q',frame,8,1)
 struct.pack_into('<3Q',frame,24,*directory);struct.pack_into('<3Q',frame,48,*clang);struct.pack_into('<Q',frame,72,len(payload))
 request=bytes(frame)+payload;src=C.create_string_buffer(request)
 with mmap.mmap(-1,96<<20)as out:
  rc=int(f.p.entry(src,len(request),q.address(out),len(out),f.p.context,256))
  head=bytes(out[:128]);child=bytes(out[1<<20:(1<<20)+1024])
 assert src.raw==request+b'\0'
 assert rc==0 and head[:8]==b'HIAMVHR1',(rc,head.hex())
 return dict(rc=rc,header=head,child=child,cap=struct.unpack_from('<3Q',head,24))
def callable_value(v,env,body):
 name=v.scalar('__fspath__')
 return v.keep(v.raw(68,a=env,b=name,tail=body))
def marker_body():
 return inv.policy('actual_runtime_directory_marker',f'''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or readword(s,0)!={inv.INPUT} or length(o)<NC_LIMIT:
        return 2
    phase=get(w,0)
    if phase==0:
        put(w,0,1)
        zero(o,128,129)
        put(o,0,NC_BODY_VALUE)
        put(o,8,129)
        put(o,128,MAGIC)
        put(o,136,2)
        put(o,224,1)
        put(o,232,2)
        store(o,256,49)
        return 1
    if phase==1:
        if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
            return 2
        put(w,0,2)
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,12)
        put(o,152,readword(s,24))
        put(o,160,readword(s,32))
        put(o,168,readword(s,40))
        put(o,176,get(o,524312))
        put(o,184,get(o,524320))
        put(o,192,get(o,524328))
        return 1
    if phase==2:
        if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
            return 2
        put(w,0,3)
        put(w,56,get(o,524312))
        put(w,64,get(o,524320))
        put(w,72,get(o,524328))
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,2)
        return 1
    if phase==3:
        if get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
            return 2
        put(w,0,4)
        zero(o,128,128)
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        put(o,128,MAGIC)
        put(o,136,16)
        put(o,152,get(w,56))
        put(o,160,get(w,64))
        put(o,168,get(w,72))
        put(o,176,get(o,524312))
        put(o,184,get(o,524320))
        put(o,192,get(o,524328))
        return 1
    if phase!=4 or get(o,112)!=0 or get(o,524288)!=REPLY or get(o,524296)!=0:
        return 2
    zero(o,0,128)
    put(o,0,NC_BODY_REPLY)
    put(o,8,1)
    put(o,24,get(w,56))
    put(o,32,get(w,64))
    put(o,40,get(w,72))
    return 0
''')
def raised_value(v):
 cls=v.builtin(23)
 message=v.scalar('actual native directory callback exception')
 args=v.keep(v.raw(40,a=v.lst([message])))
 return v.keep(v.raw(75,a=cls,b=args))
def finish_failure(f,v,bootstrap,baseline,kind,result,exception=None,marker=None):
 head=result['header'];child=result['child']
 assert q.get(head,8)==0 and q.get(head,48)!=0 and not result['cap'][0],(kind,head.hex(),child[:320].hex())
 if kind=='program-before-pathlike':
  assert child[160:168]!=b'HIARTDE1',child[:320].hex()
  assert q.get(v.raw(17,a=marker),48)==0,'directory callback ran before failed admission'
 else:
  assert child[160:168]==b'HIARTDE1' and child[168:176]==b'HIARTDR1',child[:320].hex()
  reply=child[168:296]
  assert q.get(reply,8)!=0 and q.get(reply,80)==0 and q.get(reply,88)==q.get(reply,104)==1,reply.hex()
  if exception is not None:
   assert q.get(reply,96)==1 and q.get(reply,120)==0,reply.hex()
   actual=v.keep(reply,24);assert v.same(actual,exception)
  elif marker is not None:
   assert q.get(v.raw(17,a=marker),48)==1,'actual native callback mutation absent'
   if q.get(reply,120)==1:
    actual=v.keep(reply,56);assert v.same(actual,marker)
   if q.get(reply,96)==1:v.keep(reply,24)
 retry=f.p.call(7);assert retry['known']==1 and retry['pending']==0,retry
 f.close_runtime(bootstrap);row=f.p.call(3,1,bootstrap);assert row['consumed']==1 and row['pending']==0,row
 while v.held:v.drop(next(iter(v.held)))
 assert q.get(v.raw(47),48)==baseline,(kind,baseline,q.get(v.raw(47),48))
 return dict(passed=True,kind=kind,actual_exception_identity=exception is not None,actual_admission_precedes_callback=kind=='program-before-pathlike',**f.finish())

def one(path,out,kind):
 f=custody.Fixture(path,out);v=Values(q.ValueTransport(f.owner))
 baseline=q.get(v.raw(47),48)
 bootstrap=f.create();f.register(bootstrap);f.guard(1)
 prior=os.getcwd();os.chdir(out)
 try:
  spelling='artifacts/./../artifacts'
  marker=None;exception=None;core=None
  if kind=='absolute':
   oracle=str(f.parent);directory=v.scalar(oracle)
  elif kind=='relative':
   oracle=spelling;directory=v.scalar(oracle)
  elif kind=='none':
   oracle=None;directory=v.scalar(None)
  elif kind=='string-subclass':
   oracle=spelling;base=v.scalar(spelling);cls=v.cls('NativeDirectoryString',[v.builtin(6)]);directory=v.instance(cls,base=base)
  elif kind in ('pathlike-return','pathlike-raise','program-before-pathlike','pathlike-wrong-return'):
   cls=v.cls('NativeRuntimePathLike',[])
   oracle=spelling
   if kind=='pathlike-return':fn=callable_value(v,v.scalar(spelling),inv.echo_field(1))
   elif kind=='pathlike-raise':
    exception=raised_value(v);fn=callable_value(v,exception,inv.echo_field(1,2))
   else:
    marker=v.lst([]);fn=callable_value(v,marker,marker_body())
    if kind=='program-before-pathlike':core=b'{}'
   v.attr(cls,'__fspath__',fn);directory=v.instance(cls)
  elif kind in ('windows-parts','windows-unicode-drive'):
   parts=['C:dir','c:artifacts']if kind=='windows-parts'else['\u03a3:dir','\u03c3:artifacts']
   oracle=PureWindowsPath(*parts)
   Path(oracle).absolute().mkdir(parents=True,exist_ok=False)
   cls=v.builtin(16);base=v.lst([v.scalar(x)for x in parts]);directory=v.instance(cls,base=base)
  elif kind in ('posix-path','posix-subclass','path-subclass-ignores-fspath'):
   parts=['artifacts','.','..','artifacts']
   oracle=PurePosixPath(*parts)
   cls=v.builtin(18)
   if kind!='posix-path':cls=v.cls('NativeDirectoryPath',[cls])
   if kind=='path-subclass-ignores-fspath':
    marker=v.lst([]);v.attr(cls,'__fspath__',callable_value(v,marker,marker_body()))
   strings=[v.scalar(x)for x in parts];base=v.lst(strings);directory=v.instance(cls,base=base)
  else:raise AssertionError(kind)
  clang=v.scalar('clang');result=create(f,directory,clang,core)
  if kind in ('pathlike-raise','program-before-pathlike','pathlike-wrong-return'):
   return finish_failure(f,v,bootstrap,baseline,kind,result,exception,marker)
  if kind=='path-subclass-ignores-fspath':assert q.get(v.raw(17,a=marker),48)==0
  head=result['header'];child=result['child']
  assert q.get(head,8)==0 and q.get(head,48)==0 and result['cap'][0],(kind,head.hex(),child[:320].hex())
  row=f.register(result['cap']);f.guard(2)
  context=row['object']+256
  n=struct.unpack('<Q',C.string_at(context+216,8))[0];assert 0<n<=4045,n
  actual=C.string_at(context+73728,n)
  expected=os.fsencode(Path(tempfile.gettempdir()if oracle is None else oracle).absolute())
  assert actual==expected,(kind,actual,expected)
  lease=q.old.lease(f.c,result['cap']);f.c.call(lease,29)
  f.close_runtime(result['cap']);ret=f.p.call(3,1,result['cap']);assert ret['consumed']==1 and ret['pending']==0,ret
  f.guard(2);f.c.call(lease,31);q.old.ok(f.api.call(6,lease));f.guard(1)
  f.close_runtime(bootstrap);ret=f.p.call(3,1,bootstrap);assert ret['consumed']==1 and ret['pending']==0,ret
  while v.held:v.drop(next(iter(v.held)))
  assert q.get(v.raw(47),48)==baseline,(kind,baseline,q.get(v.raw(47),48))
  return dict(passed=True,kind=kind,actual_parent_fs_hex=actual.hex(),expected_parent_fs_hex=expected.hex(),actual_sidecar_lifetime_guard=True,**f.finish())
 finally:os.chdir(prior)
CASES=('absolute','relative','none','string-subclass','posix-path','posix-subclass','pathlike-return','pathlike-raise','program-before-pathlike','path-subclass-ignores-fspath','pathlike-wrong-return','windows-parts','windows-unicode-drive')
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=CASES);a=p.parse_args()
 spec=json.loads((a.build/'build.json').read_bytes());path=a.build/'install/hia-generation-component-root.so'
 assert custody.pin(path.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name in a.cases or CASES:
  here=a.output/name;here.mkdir();rows.append(isolated(name,lambda name=name,here=here:one(path,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n');print('RUNTIME_DIRECTORY_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=custody.pin(path.read_bytes()),construction=custody.pin((a.build/'build.json').read_bytes()),qualifier=custody.pin(Path(__file__).read_bytes()),actual_late_directory_conversion=True,public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print('RUNTIME_DIRECTORY_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
