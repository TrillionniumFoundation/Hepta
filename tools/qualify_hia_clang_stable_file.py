"""Real filesystem, kernel race and retirement gates for native stable files."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,queue,select,shutil,struct,threading,time,traceback
from tools.qualify_hia_clang_capture_faults import isolated
from tools import qualify_hia_native_seccomp_notify as notify
from tools import generate_hia_clang_stable_file_packer as spec
WORK=1056768
class StableFile:
 def __init__(self,library):
  self.lib=C.CDLL(str(library));self.entry=self.lib.hia_clang_stable_file
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
 def frame(self,path,op=0,expected=b'',maximum=1<<30,allow_empty=False,identity=None,compare=0):
  path=os.fsencode(path);words=[int.from_bytes(b'HIASFL01','little'),op,maximum,int(allow_empty),len(path),len(expected),compare,0]+list(identity or(0,)*8)+[0]*8
  assert len(words)==24
  return struct.pack('<24Q',*words)+path+b'\0'+expected
class Session:
 def __init__(self,client,path,**kwargs):
  self.client=client;self.wire=client.frame(path,**kwargs);self.src=C.create_string_buffer(self.wire)
  self.out=C.create_string_buffer(256);self.work=C.create_string_buffer(WORK)
 def run(self):
  rc=self.client.entry(self.src,len(self.wire),self.out,256,self.work,WORK);assert rc==0,hex(rc)
  assert bytes(self.out)[:8]==b'HIASFR01';return struct.unpack('<32Q',bytes(self.out))
 def retire(self):
  wire=b'HIASFL01'+struct.pack('<23Q',3,*([0]*22));source=C.create_string_buffer(wire)
  rc=self.client.entry(source,len(wire),self.out,256,self.work,WORK);assert rc==0,hex(rc)
  return struct.unpack('<32Q',bytes(self.out))
 def closed(self):
  v=self.retire();assert v[1]==0 and v[20]==0 and v[21]==1 and v[22]==1,v
  assert not any(bytes(self.work)[:8192])
def basic(client,root):
 rows=[];before=set(os.listdir('/proc/self/fd'))
 for index,raw in enumerate((b'abc',b'',bytes(range(256))*9000,b'\0'*4097)):
  path=root/('data-'+str(index));path.write_bytes(raw)
  for op in (0,1,2):
   kw=dict(op=op,maximum=64<<20,allow_empty=True)
   if op==2:kw['expected']=raw
   s=Session(client,path,**kw);v=s.run()
   assert v[1]==0 and v[4]==len(raw) and v[24]==len(raw),(index,op,v)
   assert bytes(s.out)[128:160]==hashlib.sha256(raw).digest(),(index,op)
   if op==1:assert v[5] and C.string_at(v[5],len(raw))==raw
   else:assert v[5]==0 and v[20]==0
   identity=v[8:16];s.closed();rows.append(dict(bytes=len(raw),op=op))
   if op==2:
    s=Session(client,path,op=2,expected=raw,maximum=64<<20,allow_empty=True,identity=identity,compare=1);assert s.run()[1]==0;s.closed()
 path=root/'unicode-文件';path.write_bytes(b'unicode');s=Session(client,path);assert s.run()[1]==0;s.closed()
 rawpath=os.fsencode(root)+b'/surrogate-\xff';fd=os.open(rawpath,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,b'raw');os.close(fd)
 s=Session(client,rawpath);assert s.run()[1]==0;s.closed()
 for name,op,expected,error in [('data-0',2,b'bad',4),('data-1',0,b'',3)]:
  s=Session(client,root/name,op=op,expected=expected);v=s.run();assert v[1]==error,v;s.closed()
 for name,kind in [('symlink','symlink'),('fifo','fifo'),('directory','directory'),('missing','missing')]:
  path=root/name
  if kind=='symlink':path.symlink_to(root/'data-0')
  elif kind=='fifo':os.mkfifo(path)
  elif kind=='directory':path.mkdir()
  s=Session(client,path);v=s.run();assert v[1]!=0,(name,v);s.closed()
 sparse=root/'oversize';fd=os.open(sparse,os.O_CREAT|os.O_WRONLY,0o600);os.ftruncate(fd,(1<<30)+1);os.close(fd)
 s=Session(client,sparse);assert s.run()[1]==3;s.closed()
 stage=root/'data-0';s=Session(client,stage,op=2,expected=b'abc');v=s.run();identity=v[8:16];s.closed()
 alias=root/'hardlink';os.link(stage,alias)
 s=Session(client,stage,op=2,expected=b'abc',identity=identity,compare=1);assert s.run()[1]==4;s.closed()
 s=Session(client,stage,op=2,expected=b'abc',identity=identity,compare=2);v=s.run();assert v[1]==0;s.closed()
 s=Session(client,alias,op=2,expected=b'abc',identity=v[8:16],compare=1);assert s.run()[1]==0;s.closed()
 compiler=Path(shutil.which('clang')).resolve();s=Session(client,compiler);v=s.run();assert v[1]==0,v
 assert bytes(s.out)[128:160]==hashlib.sha256(compiler.read_bytes()).digest();s.closed()
 assert set(os.listdir('/proc/self/fd'))==before
 return dict(successful_vectors=rows,actual_compiler=str(compiler),actual_compiler_bytes=v[4],exact_hash=True,fd_balanced=True)
def guards(client,path):
 s=Session(client,path,op=1,maximum=64<<20);v=s.run();assert v[1]==0
 copy=C.create_string_buffer(bytes(s.work));wire=b'HIASFL01'+struct.pack('<23Q',3,*([0]*22));source=C.create_string_buffer(wire);out=C.create_string_buffer(b'\xa5'*256,256)
 rc=client.entry(source,len(wire),out,256,copy,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*256
 pid=os.fork()
 if pid==0:
  rc=client.entry(source,len(wire),out,256,s.work,WORK);os._exit(0 if rc==0xfffffffd and bytes(out)==b'\xa5'*256 else 1)
 _,status=os.waitpid(pid,0);assert os.WIFEXITED(status)and os.WEXITSTATUS(status)==0
 assert C.string_at(v[5],v[4])==path.read_bytes();s.closed()
 baseline=Session(client,path);raw=baseline.wire
 cases=[('short',raw[:191]),('truncated',raw[:-1]),('trailing',raw+b'x')]
 for name,offset,value in [('magic',0,0),('op',8,4),('zero-limit',16,0),('oversize-limit',16,(1<<30)+1),('allow-empty',24,2),('path-extent',32,1<<40),('expected-extent',40,1),('compare',48,4),('reserved',56,1),('identity-without-mode',64,1),('reserved-tail',184,1)]:
  bad=bytearray(raw);struct.pack_into('<Q',bad,offset,value);cases.append((name,bytes(bad)))
 for name,bad in cases:
  src=C.create_string_buffer(bad);work=C.create_string_buffer(WORK);out.raw=b'\xa5'*256
  rc=client.entry(src,len(bad),out,256,work,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*256,(name,rc)
 view=[('null-input',None,len(raw),out,256,baseline.work,WORK),('null-output',baseline.src,len(raw),None,256,baseline.work,WORK),('short-output',baseline.src,len(raw),out,255,baseline.work,WORK),('short-work',baseline.src,len(raw),out,256,baseline.work,WORK-1),('null-work',baseline.src,len(raw),out,256,None,WORK),('input-output-alias',out,256,out,256,baseline.work,WORK),('output-work-alias',baseline.src,len(raw),baseline.work,256,baseline.work,WORK),('source-overflow',C.c_void_p((1<<64)-32),64,out,256,baseline.work,WORK)]
 for name,*args in view:
  out.raw=b'\xa5'*256;rc=client.entry(*args);assert rc==0xfffffffd and bytes(out)==b'\xa5'*256,(name,rc)
 return dict(wire_controls=len(cases),view_controls=len(view),copied_context_refused=True,forked_context_refused=True)
def native_seccomp(client,rules):
 class F(C.Structure):_fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
 class P(C.Structure):_fields_=[('len',C.c_ushort),('filter',C.POINTER(F))]
 start=C.cast(client.entry,C.c_void_p).value;end=start+len(spec.BRIDGE)
 assert start>>32==(end-1)>>32
 rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(6,0,0,0x80000000),
       (0x20,0,0,12),(0x15,0,0,start>>32),(0x20,0,0,8),(0x35,0,0,start&0xffffffff),(0x35,0,0,end&0xffffffff)]
 for nr,err,match in rules:
  if match is None:rows.extend([(0x20,0,0,0),(0x15,0,1,nr),(6,0,0,0x50000|err)])
  else:
   index,value=match
   rows.extend([(0x20,0,0,0),(0x15,0,3,nr),(0x20,0,0,16+8*index),(0x15,0,1,value&0xffffffff),(6,0,0,0x50000|err)])
 final=len(rows);rows.append((6,0,0,0x7fff0000))
 rows[4]=(0x15,0,final-5,start>>32);rows[6]=(0x35,0,final-7,start&0xffffffff);rows[7]=(0x35,final-8,0,end&0xffffffff)
 array=(F*len(rows))(*(F(*r)for r in rows));program=P(len(rows),array);libc=C.CDLL(None,use_errno=True)
 assert libc.prctl(38,1,0,0,0)==0,C.get_errno()
 assert libc.prctl(22,2,C.byref(program),0,0)==0,C.get_errno()
def kernel_error(client,path,nr,expected,op=0):
 s=Session(client,path,op=op,maximum=64<<20);before=set(os.listdir('/proc/self/fd'))
 native_seccomp(client,[(nr,13,None)]);v=s.run();assert v[1]==expected and v[2]==13,v
 s.closed();assert set(os.listdir('/proc/self/fd'))==before
 return dict(syscall=nr,error=v[1],errno=v[2],fd_balanced=True)
def retry_error(client,path,kind):
 s=Session(client,path,op=1 if kind=='munmap'else 0,maximum=64<<20)
 before=set(os.listdir('/proc/self/fd'));go=threading.Event();done=threading.Event();result=[]
 def retry():
  go.wait()
  try:result.append(s.retire())
  except BaseException as e:result.append(repr(e))
  finally:done.set()
 thread=threading.Thread(target=retry);thread.start()
 if kind=='munmap':
  v=s.run();assert v[1]==0 and v[5]
  native_seccomp(client,[(11,13,None)])
 else:
  native_seccomp(client,[(436,13,None)]);v=s.run();assert v[1]==6 and v[20]==1,v
 first=s.retire();assert first[1]==6 and first[2]==13 and first[20]==1 and first[21]==1,first
 assert any(bytes(s.work)[:8192])
 go.set();assert done.wait(10);thread.join()
 assert len(result)==1 and isinstance(result[0],tuple)and result[0][1]==0 and result[0][22]==1,result
 assert not any(bytes(s.work)[:8192])and set(os.listdir('/proc/self/fd'))==before
 return dict(resource=kind,real_errno=13,same_context_other_thread_retirement=True,fd_balanced=True)
def ambiguous_close(client,path):
 s=Session(client,path);native_seccomp(client,[(436,38,None),(3,4,None)]);v=s.run()
 assert v[1]==6 and v[20]==1 and v[21]==0 and v[23]==1,v
 again=s.retire();assert again[20]==1 and again[21]==0 and again[22]==0,again
 return dict(legacy_close_errno=4,unknown_quarantined=True,no_blind_retry=True)
def actual_race(client,root,kind):
 path=root/('race-'+kind);path.write_bytes(b'A'*4096)
 replacement=root/('replacement-'+kind);replacement.write_bytes(b'B'*4096)
 if kind in ('truncate-after-open','replace-after-open','chmod-before-final-stat'):nr=5
 elif kind=='swap-fifo-before-open':nr=2
 elif kind=='growth-after-fstat':nr=0
 else:nr=6
 s=Session(client,path);ready=queue.Queue();stop=threading.Event();errors=[];notices=[]
 def observe():
  listener=ready.get()
  try:
   count=0
   while not stop.is_set():
    if not select.select([listener],[],[],.1)[0]:continue
    note=notify.receive(listener);count+=1
    action=count==(2 if kind in ('chmod-before-final-stat','replace-before-final-lstat')else 1)
    if action:
     if kind=='truncate-after-open':os.truncate(path,1)
     elif kind in ('replace-after-open','replace-before-final-lstat'):os.replace(replacement,path)
     elif kind=='swap-fifo-before-open':path.unlink();os.mkfifo(path)
     elif kind=='growth-after-fstat':
      with path.open('ab')as f:f.write(b'B'*10)
     elif kind=='chmod-before-final-stat':os.chmod(path,0o400)
    notices.append(dict(nr=note.data.nr,ip=note.data.ip,acted=action,flags=int(note.data.args[1])if nr==2 else None))
    notify.continue_syscall(listener,note)
  except BaseException as e:errors.append(repr(e))
 thread=threading.Thread(target=observe);thread.start()
 entry=C.cast(client.entry,C.c_void_p).value;listener=notify.install(entry,entry+len(spec.BRIDGE),nr);ready.put(listener)
 try:v=s.run()
 finally:stop.set();thread.join(5)
 assert not thread.is_alive() and not errors,(errors,notices);os.close(listener)
 assert v[1]in(2,4)and sum(n['acted']for n in notices)==1,(v,notices)
 if kind=='swap-fifo-before-open':assert notices[0]['flags']&os.O_NONBLOCK
 s.closed()
 return dict(race=kind,native_error=v[1],actual_kernel_continues=notices,nonblocking_open=True if nr==2 else None)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700);client=StableFile(a.library);rows=[]
 report=dict(schema='hepta.hia.clang-stable-file-qualification.v1',passed=False,whole_clang_outer_qualified=False,product=dict(bytes=a.library.stat().st_size,sha256=hashlib.sha256(a.library.read_bytes()).hexdigest()),groups=rows)
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  root=a.output/'files';root.mkdir()
  rows.append(dict(name='ordinary-capture-verify-and-identity',passed=True,result=basic(client,root)));save()
  rows.append(dict(name='wire-view-process-and-copy-guards',passed=True,result=guards(client,root/'data-0')));save()
  for nr,error,op in [(6,2,0),(2,2,0),(5,2,0),(0,2,0),(9,7,1)]:
   rows.append(isolated('kernel-'+str(nr),lambda nr=nr,error=error,op=op:kernel_error(client,root/'data-0',nr,error,op)));save()
  for kind in ('close_range','munmap'):
   rows.append(isolated('retry-'+kind,lambda kind=kind:retry_error(client,root/'data-0',kind)));save()
  rows.append(isolated('ambiguous-legacy-close',lambda:ambiguous_close(client,root/'data-0')));save()
  for kind in ('truncate-after-open','replace-after-open','swap-fifo-before-open','growth-after-fstat','chmod-before-final-stat','replace-before-final-lstat'):
   rows.append(isolated(kind,lambda kind=kind:actual_race(client,root,kind)));save()
  report['passed']=True;print('STABLE_FILE_ACTUAL_QUALIFICATION_PASS',len(rows),flush=True)
 except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();raise
 finally:save()
if __name__=='__main__':main()
