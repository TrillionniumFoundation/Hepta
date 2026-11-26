"""Real fixed Clang preparation, holder retirement and failure custody gates.

Python supplies source/oracle data and observes actual native/kernel results. It
does not install handlers, edit binding fields, fake an ACK or repair custody.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,os,queue,select,shutil,struct,subprocess,sys,threading,time,traceback
from tools.qualify_hia_result_value_invocations import Values,Bound,make_engine,sweep,echo_field
from tools.qualify_hia_clang_compile import small
from tools.qualify_hia_multiversion_prepare_intake import abi_bytes
from tools.qualify_hia_native_callable_code_owner import deny_native
from tools.qualify_hia_generation_lease_owner import deny_syscall
from tools import qualify_hia_native_seccomp_notify as notify
from hepta.hia_program import verify_program,execute_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_multiversion import ScalarABI
BAD=0xfffffffd;WORK=512<<20;OUT=1050624;CTRL=400<<20;NONE=(1<<64)-1
def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ptr(m):return C.addressof(C.c_char.from_buffer(m))
def control(op):return b'HIAMVGF2'+struct.pack('<31Q',op,*([0]*30))
def thread_call(fn,filters=(),ip=None,all_syscalls=()):
 result=queue.Queue()
 def go():
  try:
   for nr,err in filters:deny_native(ip,nr,err)
   for nr,err in all_syscalls:deny_syscall(nr,err)
   result.put((True,fn()))
  except BaseException as e:result.put((False,e))
 t=threading.Thread(target=go);t.start();t.join(180)
 assert not t.is_alive(),'actual native operation failed to return'
 good,data=result.get_nowait()
 if not good:raise data
 return data

class Session:
 def __init__(self,suite,label,bind=True,source=None):
  self.suite=suite;self.path=suite.output/(label+'.so');self.work=mmap.mmap(-1,WORK,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS)
  self.wp=ptr(self.work)
  if bind:assert self.bind(source)==0
 def bind(self,source=None):
  fd=os.open(source or self.suite.source,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
  try:
   raw=b'HIAGPOB1'+struct.pack('<3Q',fd,0,0);s=C.create_string_buffer(raw)
   rc=int(self.suite.bind(s,32,self.wp,WORK,self.suite.bound.owner.context,2048))&0xffffffff
   assert s.raw==raw+b'\0'
   return rc
  finally:os.close(fd)
 def frame(self,cap):
  program=self.suite.program;core=program.canonical_bytes;abi=self.suite.abi;path=os.fsencode(self.path)
  head=bytearray(256);head[:8]=b'HIAMVGF2'
  for at,n in [(24,time.monotonic_ns()+2000000000),(40,len(core)),(48,len(abi)),(56,len(path))]:struct.pack_into('<Q',head,at,n)
  struct.pack_into('<3Q',head,64,*cap)
  return bytes(head)+core+abi+path
 def call(self,raw,alias=False):
  n=OUT if len(raw)>256 else 2048
  if alias:
   self.work[480<<20:(480<<20)+len(raw)]=raw
   source=self.wp+(480<<20);output=self.wp+(384<<20)
   self.work[384<<20:(384<<20)+n+64]=b'\xa5'*(n+64)
   rc=int(self.suite.entry(source,len(raw),output,n,self.wp,WORK))&0xffffffff
   data=bytes(self.work[384<<20:(384<<20)+n])
   assert self.work[(384<<20)+n:(384<<20)+n+64]==b'\xa5'*64
   assert self.work[480<<20:(480<<20)+len(raw)]==raw
  else:
   source=C.create_string_buffer(raw);output=C.create_string_buffer(b'\xa5'*(n+64))
   rc=int(self.suite.entry(source,len(raw),output,n,self.wp,WORK))&0xffffffff
   assert source.raw==raw+b'\0' and output.raw[n:]==b'\xa5'*64+b'\0'
   data=output.raw[:n]
  return rc,data
 def compile(self,cap,alias=False):return self.call(self.frame(cap),alias)
 def success(self,result):
  rc,head=result
  assert rc==0 and head[:8]==b'HIAMVGR2'and word(head,8)==0,(rc,head[:128].hex())
  assert tuple(word(head,a)for a in(40,336,344,352,360,384,392,400,408,416))==(1,3,1,0,0,1,0,0,0,1)
  receipt=json.loads(head[2048:2048+word(head,72)])
  assert receipt['core_sha256']==self.suite.program.sha256
  assert receipt['input_sha256']==self.suite.program.sha256
  assert receipt['llvm_ir_sha256']==emit_program_llvm(self.suite.program).sha256
  assert head[512:520]==b'HIAMVIR1'and word(head,512+200)==1
  assert head[1024:1032]==b'HIAMVPR1'and word(head,1024+8)==0 and word(head,88)>0
  function=C.CFUNCTYPE(C.c_uint64,C.c_uint64)(word(head,512+256))
  for x in(35,NONE):
   got=function(x);expected=execute_program(self.suite.program,'calculate',[x],max_steps=4224)['result']
   assert got==expected,(x,got,expected)
  del function
  return dict(receipt_sha256=hashlib.sha256(head[2048:2048+word(head,72)]).hexdigest(),
   probe_calls=word(head,88),probe_steps=word(head,96),actual_fresh_llvm=True,actual_native_and_vm=True)
 def retire(self):
  rc,head=self.call(control(1))
  assert rc==0 and head[:8]==b'HIAMVGR2'and word(head,8)==0,(rc,list(struct.unpack_from('<64Q',head)))
  assert tuple(word(head,a)for a in(336,344,352,360,384,392,400,408,416))==(6,1,1,0,0,0,0,0,0)
  if word(head,448):
   assert word(head,464)==1 and word(head,472)==0 and word(head,480)==0
  assert not self.path.exists()
  return head
 def close(self):
  head=self.retire();again=self.retire()
  assert head==again,'idempotent actual retirement changed its receipt'
  self.work.close();return dict(actual_retired=True,mapping_absence_observed=word(head,456)==1,descriptor_retired=word(head,472)==0)
 def exception(self,op):
  raw=b'HIAMVGE1'+struct.pack('<15Q',op,*([0]*14));s=C.create_string_buffer(raw);o=C.create_string_buffer(128)
  rc=int(self.suite.exception(s,128,o,128,self.wp,WORK))&0xffffffff
  assert rc==0 and o.raw[:8]==b'HIAMVGER'
  return o.raw[:128]

class Suite:
 def __init__(self,args):
  self.args=args;self.output=args.output;self.output.mkdir(mode=0o700)
  self.source=args.source_directory;self.lib=C.CDLL(str(args.component))
  self.entry=self.lib.hia_generation_lease_clang_prepare
  self.bind=self.lib.hia_generation_lease_clang_prepare_bind_owner
  self.exception=self.lib.hia_generation_lease_clang_prepare_exception
  for f in(self.entry,self.bind,self.exception):f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32
  self.before=set(os.listdir('/proc/self/fd'))
  self.bound=Bound(args.owner);row=self.bound.call(0);assert row['status']==0 and row['state']==2 and row['pending']==0,row
  self.values=Values(make_engine(self.bound));self.program=verify_program(small(7))
  self.abi=abi_bytes(self.program,(ScalarABI('calculate',('u64',),'u64'),))
  from tools.generate_hia_generation_lease_owner_clang_prepare_packer import OUTER
  body=C.string_at(C.cast(self.entry,C.c_void_p).value,len(OUTER))
  positions=[i for i in range(len(body)-1)if body[i:i+2]==b'\x0f\x05'];assert len(positions)==3,positions
  self.ip=C.cast(self.entry,C.c_void_p).value+positions[1]+2
  self.rows=[]
 def clean(self):
  sweep(self.values,self.bound)
  assert set(os.listdir('/proc/self/fd'))==self.before,(self.before,set(os.listdir('/proc/self/fd')))
 def basic(self,alias=False):
  cap=self.values.scalar('clang');before=word(self.values.raw(47),48)
  s=Session(self,'alias'if alias else'ordinary')
  assert word(self.values.raw(47),48)==before+2
  result=s.success(s.compile(cap,alias))
  assert word(self.values.raw(47),48)==before+1
  result.update(s.close());assert word(self.values.raw(47),48)==before
  return result
 def error(self,custom=False,discard=False):
  v=self.values
  if custom:
   expected=TypeError('native prepare preserves this exception')
   original=v.exception(v.builtin(23),v.tuple([v.scalar(x)for x in expected.args]))
   cls=v.cls('PreparePathlike',[]);fn=v.function(echo_field(1,2),env=original)
   v.attr(cls,'__fspath__',fn);cap=v.instance(cls)
  else:
   cap=v.scalar(None)
   try:shutil.which(None)
   except BaseException as e:expected=e
   else:raise AssertionError('original None should fail')
  s=Session(self,'discard'if discard else'custom-error'if custom else'type-error')
  rc,head=s.compile(cap);assert rc==0 and word(head,8)!=0 and word(head,40)==0 and word(head,392)==1 and word(head,400)==1
  assert word(s.exception(1),16)==2
  if not discard:
   ex=s.exception(0);assert word(ex,88)==word(ex,96)==1 and word(ex,16)==2
   cap_=v.keep(ex);env,args,name=v.parts(cap_)
   assert v.python(name)==type(expected).__name__ and v.python_value(args)==expected.args
   if custom:assert v.same(cap_,original)
   assert word(s.exception(0),16)==0 and word(s.exception(1),96)==0
  result=s.close();result.update(actual_exception_identity=custom,actual_type_and_args=not discard,unclaimed_exception_native_drop=discard)
  return result
 def bind_mmap(self):
  s=Session(self,'bind-mmap',bind=False);before=word(self.values.raw(47),48)
  rc=thread_call(s.bind,[(9,5)],self.ip)
  assert rc==0xfffffffb and word(s.work,CTRL+344)==1 and word(s.work,CTRL+104)==0
  assert word(self.values.raw(47),48)==before+1
  result=s.close();assert word(self.values.raw(47),48)==before
  return dict(result,actual_mmap_eio=True,real_token_retained_until_retry=True)
 def post_compile_munmap(self):
  cap=self.values.scalar('clang');s=Session(self,'prepare-munmap')
  rc,head=thread_call(lambda:s.compile(cap),[(11,5)],self.ip)
  assert rc==0 and word(head,8)!=0 and word(head,336)==4 and word(head,360)==1 and word(head,408)!=0
  assert word(s.work,CTRL+120)==1 and word(head,416)==1 and word(head,392)==1
  result=s.close();return dict(result,actual_munmap_eio=True,child_context_retired_before_failed_unmap=True)
 def retirement_fault(self,nr,label,fallback=False):
  cap=self.values.scalar('clang');s=Session(self,label);s.success(s.compile(cap))
  filters=[(436,38)]if fallback else[(nr,5)]
  rc,head=thread_call(lambda:s.call(control(1)),filters,self.ip)
  assert rc==0
  if fallback:
   assert word(head,352)==1 and word(head,360)==0
  else:
   assert word(head,352)==0 and word(head,360)==1 and word(head,344)==1 and word(head,416)==1
   if nr==5:assert word(head,448)==0 and s.path.exists()
   else:assert word(head,448)==1 and not s.path.exists()
   if nr==436:assert word(head,472)==1
  result=s.close();return dict(result,actual_kernel_error=nr,actual_retry=True,fallback=fallback)
 def guards(self):
  cap=self.values.scalar('clang');s=Session(self,'guards');valid=s.frame(cap)
  controls=[('short',valid[:255]),('trailing',valid+b'x'),('magic',b'INVALID!'+valid[8:])]
  for at,n in [(8,3),(16,1),(24,0),(32,1),(40,0),(40,8388609),(48,335),(48,5137),(56,4096),(64,0),(88,1)]+[(a,1)for a in range(96,256,8)]:
   raw=bytearray(valid);struct.pack_into('<Q',raw,at,n);controls.append((str(at),bytes(raw)))
  core_n=word(valid,40);abi_n=word(valid,48)
  for at,label in [(256+core_n,'bad-abi-magic'),(256+core_n+8,'bad-abi-count'),(256+core_n+abi_n,'path-nul')]:
   raw=bytearray(valid);raw[at]=0;controls.append((label,bytes(raw)))
  for label,raw in controls:
   before=bytes(s.work[CTRL:CTRL+4096]);rc,head=s.call(raw)
   assert rc==BAD and head==b'\xa5'*len(head),(label,rc,head[:32].hex())
   assert bytes(s.work[CTRL:CTRL+4096])==before,(label,'changed state')
  result=s.close();return dict(result,controls=len(controls),actual_no_context_or_output_write=True)
 def copy_fork(self):
  cap=self.values.scalar('clang');s=Session(self,'copy-fork')
  with mmap.mmap(-1,WORK,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS)as copied:
   copied[CTRL:CTRL+4096]=s.work[CTRL:CTRL+4096];before=bytes(copied[CTRL:CTRL+4096])
   src=C.create_string_buffer(control(2));out=C.create_string_buffer(b'\xa5'*2048)
   rc=int(self.entry(src,256,out,2048,ptr(copied),WORK))&0xffffffff
   assert rc==BAD and out.raw==b'\xa5'*2048+b'\0'and copied[CTRL:CTRL+4096]==before
  child=os.fork()
  if child==0:
   try:
    before=bytes(s.work[CTRL:CTRL+4096]);rc,head=s.call(control(2))
    assert rc==BAD and head==b'\xa5'*2048 and s.work[CTRL:CTRL+4096]==before
    os._exit(0)
   except BaseException:os._exit(1)
  assert os.waitpid(child,0)[1]==0
  return dict(s.close(),actual_copy_refused=True,actual_fork_refused=True)
 def concurrent(self):
  cap=self.values.scalar('clang');s=Session(self,'concurrent');s.success(s.compile(cap))
  ready=queue.Queue();done=queue.Queue()
  def worker():
   try:
    fd=notify.install(self.ip,self.ip+1,5);ready.put(fd)
    result=s.call(control(1));done.put((True,result))
   except BaseException as e:done.put((False,e))
  t=threading.Thread(target=worker);t.start();fd=ready.get(timeout=30)
  try:
   assert select.select([fd],[],[],30)[0]
   assert done.empty(),'retirement returned before its actual syscall notification'
   n=notify.receive(fd);assert n.data.nr==5 and n.data.ip==self.ip
   assert word(s.work,CTRL+312)==1
   before=bytes(s.work[CTRL:CTRL+4096]);rc,head=s.call(control(2))
   assert rc==BAD and head==b'\xa5'*2048 and s.work[CTRL:CTRL+4096]==before
   notify.continue_syscall(fd,n);t.join(30);assert not t.is_alive()
   ok,result=done.get_nowait()
   if not ok:raise result
   assert result[0]==0 and word(result[1],352)==1
  finally:os.close(fd)
  return dict(s.close(),actual_kernel_notification=True,actual_concurrent_busy_refusal=True)
 def stream(self):
  cap=self.values.scalar('clang');s=Session(self,'stream');s.success(s.compile(cap))
  regions=[]
  try:
   for i in range(4096):
    regions.append(mmap.mmap(-1,4096,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,
       prot=mmap.PROT_READ if i%2 else mmap.PROT_READ|mmap.PROT_WRITE))
    if i%128==127 and len(Path('/proc/self/maps').read_bytes())>196608:break
   n=len(Path('/proc/self/maps').read_bytes());assert n>131072,n
   result=s.close()
  finally:
   for region in regions:region.close()
  return dict(result,actual_maps_bytes=n,actual_kernel_mappings=len(regions),stream_larger_than_two_read_chunks=True)
 def quarantine(self,which):
  cap=self.values.scalar('clang');s=Session(self,which);s.success(s.compile(cap))
  if which=='mapping-still-present':
   rc,head=thread_call(lambda:s.call(control(1)),all_syscalls=[(11,5)])
   assert word(head,448)==1 and word(head,456)==1 and word(head,464)==0 and word(head,480)==1
   stat=bytes(s.work[CTRL+1024:CTRL+1168]);dev=word(stat,0);ino=word(stat,8)
   assert any(int(line.split()[4])==ino and line.split()[3]==f'{os.major(dev):02x}:{os.minor(dev):02x}'
    for line in Path('/proc/self/maps').read_text().splitlines())
  else:
   rc,head=thread_call(lambda:s.call(control(1)),[(436,38),(3,5)],self.ip)
   assert word(head,472)==1
  assert rc==0 and word(head,336)==7 and word(head,344)==0 and word(head,352)==0 and word(head,360)==1 and word(head,416)==1
  again=s.call(control(1));assert again[0]==0 and word(again[1],352)==0 and word(again[1],344)==0
  return dict(passed=True,case=which,expected_quarantine=True,context_and_token_preserved=True,
   child_consumed=word(head,448),mapping_observed_absent=word(head,464),mapping_result=word(head,480),
   real_kernel_failure=True,actual_retired=False)
 def finish(self):
  self.clean();self.bound.close();assert set(os.listdir('/proc/self/fd'))==self.before

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--component',type=Path,required=True);parser.add_argument('--owner',type=Path,required=True)
 parser.add_argument('--source-directory',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
 parser.add_argument('--quarantine-case',choices=('mapping-still-present','fallback-close-unknown'))
 args=parser.parse_args();suite=Suite(args)
 report=dict(passed=False,cases=suite.rows,product=pin(args.component.read_bytes()),owner_product=pin(args.owner.read_bytes()),
  parent_registration_qualified=False,public_constructor_qualified=False,whole_public_runtime_qualified=False)
 def save():(args.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 try:
  if args.quarantine_case:
   report['cases'].append(suite.quarantine(args.quarantine_case));report['passed']=True
   report['expected_quarantine_not_retired']=True;save();print('EXPECTED_QUARANTINE_PASS',args.quarantine_case,flush=True);return
  groups=[
   ('actual-clang-fresh-llvm-vm-retirement',lambda:suite.basic()),
   ('actual-parent-input-output-spans',lambda:suite.basic(True)),
   ('actual-type-error-object',lambda:suite.error()),
   ('actual-user-exception-identity',lambda:suite.error(True)),
   ('actual-unclaimed-exception-drop',lambda:suite.error(False,True)),
   ('native-bind-mmap-eio',suite.bind_mmap),
   ('native-post-compile-munmap-eio',suite.post_compile_munmap),
   ('native-retire-fstat-eio',lambda:suite.retirement_fault(5,'fstat')),
   ('native-post-retire-maps-read-eio',lambda:suite.retirement_fault(0,'read')),
   ('native-post-retire-maps-close-range-eio',lambda:suite.retirement_fault(436,'close-range')),
   ('native-post-retire-close-fallback',lambda:suite.retirement_fault(436,'fallback',True)),
   ('static-and-semantic-wire-no-write',suite.guards),
   ('actual-copy-and-fork-refusal',suite.copy_fork),
   ('actual-same-context-contention',suite.concurrent),
   ('actual-streaming-large-maps',suite.stream)]
  for label,fn in groups:
   print('PREPARE_START',label,flush=True);result=fn();suite.clean()
   suite.rows.append(dict(case=label,passed=True,**result));save();print('PREPARE_PASS',label,flush=True)
  suite.finish()
  for label in ('mapping-still-present','fallback-close-unknown'):
   destination=args.output/label
   command=[sys.executable,'-u',str(Path(__file__).resolve()),'--component',str(args.component),
    '--owner',str(args.owner),'--source-directory',str(args.source_directory),'--output',str(destination),'--quarantine-case',label]
   run=subprocess.run(command,capture_output=True,text=True,timeout=180)
   (args.output/(label+'.stdout')).write_text(run.stdout);(args.output/(label+'.stderr')).write_text(run.stderr)
   assert run.returncode==0,(label,run.returncode,run.stdout[-2000:],run.stderr[-4000:])
   child=json.loads((destination/'report.json').read_text());assert child['passed'] and child['expected_quarantine_not_retired']
   suite.rows.extend(child['cases']);save();print('PREPARE_PASS',label,flush=True)
  report.update(passed=True,actual_native_component_qualified=True,mapping_observed_holder_retirement_qualified=True,
    actual_normal_and_fault_custody=True,fd_and_value_code_balance=True)
 except BaseException as e:
  report['failure']=repr(e);report['traceback']=traceback.format_exc();raise
 finally:save()
 print('CLANG_PREPARE_COMPONENT_PASS',len(suite.rows),flush=True)
if __name__=='__main__':main()
