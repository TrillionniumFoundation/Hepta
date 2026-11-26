"""Actual kernel failure and custody controls for the native capture image."""
from pathlib import Path
import argparse,ctypes as C,json,os,select,signal,struct,sys,threading,time,traceback,resource
from tools.qualify_hia_clang_capture import NativeCapture
class Session:
 def __init__(self,client,args,**kw):
  self.client=client;self.wire=client.frame(args,**kw);self.src=C.create_string_buffer(self.wire);self.out=C.create_string_buffer(256);self.work=C.create_string_buffer(65536)
 def run(self):
  rc=self.client.entry(self.src,len(self.wire),self.out,len(self.out),self.work,len(self.work));assert rc==0,hex(rc)
  self.result=struct.unpack('<32Q',bytes(self.out));assert bytes(self.out)[:8]==b'HIACAR01';return self.result
 def retire(self):
  raw=b'HIACAP01'+struct.pack('<15Q',1,*([0]*14));src=C.create_string_buffer(raw)
  rc=self.client.entry(src,len(raw),self.out,len(self.out),self.work,len(self.work));assert rc==0,hex(rc)
  result=struct.unpack('<32Q',bytes(self.out));return result
 def closed(self):
  v=self.retire();assert v[1]==0 and not any(bytes(self.work)[:4096]),v
def seccomp(rules):
 class F(C.Structure):_fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
 class P(C.Structure):_fields_=[('len',C.c_ushort),('filter',C.POINTER(F))]
 rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(6,0,0,0x80000000)]
 for nr,err,match in rules:
  if match is None:rows.extend([(0x20,0,0,0),(0x15,0,1,nr),(6,0,0,0x50000|err)])
  else:
   index,value=match
   rows.extend([(0x20,0,0,0),(0x15,0,3,nr),(0x20,0,0,16+8*index),(0x15,0,1,value&0xffffffff),(6,0,0,0x50000|err)])
 rows.append((6,0,0,0x7fff0000));array=(F*len(rows))(*(F(*r)for r in rows));p=P(len(rows),array)
 libc=C.CDLL(None,use_errno=True)
 assert libc.prctl(38,1,0,0,0)==0,C.get_errno()
 assert libc.prctl(22,2,C.byref(p),0,0)==0,C.get_errno()
def isolated(label,fn):
 read,write=os.pipe2(os.O_CLOEXEC);pid=os.fork()
 if pid==0:
  os.close(read)
  try:data={'name':label,'passed':True,'result':fn()}
  except BaseException as e:data={'name':label,'passed':False,'error':repr(e),'traceback':traceback.format_exc()}
  raw=json.dumps(data).encode();at=0
  while at<len(raw):at+=os.write(write,raw[at:])
  os._exit(0 if data['passed']else 1)
 os.close(write);data=bytearray();deadline=time.monotonic()+30
 while True:
  if time.monotonic()>deadline:
   os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);raise AssertionError((label,'owned QA child exceeded 30s'))
  ready,_,_=select.select([read],[],[],.2)
  if ready:
   b=os.read(read,65536)
   if not b:break
   data.extend(b)
 os.close(read);_,status=os.waitpid(pid,0)
 assert data and os.WIFEXITED(status),(label,status,data)
 result=json.loads(data);assert result['passed'],result
 print('CAPTURE_ACTUAL_CONTROL_PASS',label,flush=True);return result
def run_fault(client,rules,error):
 before=set(os.listdir('/proc/self/fd'));s=Session(client,['/usr/bin/true'],timeout=3);seccomp(rules);v=s.run()
 assert v[1]==error,(error,v);s.closed();assert set(os.listdir('/proc/self/fd'))==before
 return {'error':v[1],'errno':v[2],'known':v[3],'group_attempted':v[19]}
def retry_fault(client,number):
 before=set(os.listdir('/proc/self/fd'));s=Session(client,['/usr/bin/printf','retained'],timeout=3);go=threading.Event();done=threading.Event();answers=[]
 def retry():
  go.wait()
  try:answers.append(s.retire())
  except BaseException as e:answers.append(repr(e))
  finally:done.set()
 thread=threading.Thread(target=retry);thread.start()
 if number==11:
  v=s.run();assert v[1]==0;seccomp([(11,13,None)])
 else:
  seccomp([(436,13,None)]);v=s.run();assert v[1]!=0 and v[17]==1
 failed=s.retire();assert failed[1]==11 and failed[2]==13 and failed[17]==1,failed
 assert any(bytes(s.work)[:4096])
 go.set();assert done.wait(10);thread.join()
 assert len(answers)==1 and isinstance(answers[0],tuple)and answers[0][1]==0,answers
 assert not any(bytes(s.work)[:4096]) and set(os.listdir('/proc/self/fd'))==before
 return {'initial_error':v[1],'first_retirement_error':failed[1],'actual_errno':failed[2],'other_thread_retirement':answers[0][1]}
def inherited_descriptors(client,method):
 holders=[os.open('/dev/null',os.O_RDONLY)for _ in range(80)]
 for fd in holders:os.set_inheritable(fd,True)
 chosen=holders[-1];assert chosen>64
 s=Session(client,[sys.executable,'-I','-c','import os,sys\ntry:os.fstat(int(sys.argv[1]))\nexcept OSError:print("closed")\nelse:print("leaked")',str(chosen)])
 if method=='proc':seccomp([(436,13,(1,0xffffffff))])
 if method=='rlimit':
  resource.setrlimit(resource.RLIMIT_NOFILE,(128,resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
  seccomp([(436,13,(1,0xffffffff)),(257,13,(1,C.addressof(s.work)+1664))])
 if method=='enosys':seccomp([(436,38,None)])
 v=s.run();assert v[1]==0,v
 assert C.string_at(v[13],v[14])==b'closed\n'
 s.closed()
 for fd in holders:os.close(fd)
 return {'inherited_fd':chosen,'method':method,'closed_on_exec':True}
def stdio(client,mask):
 for fd in range(3):
  if mask&(1<<fd):os.close(fd)
 s=Session(client,['/usr/bin/printf','stdio-normalized']);v=s.run();assert v[1]==0,v
 assert C.string_at(v[13],v[14])==b'stdio-normalized';s.closed()
 return {'initially_closed_stdio_mask':mask,'normalized':True}
def ownership_guard(client):
 s=Session(client,['/usr/bin/printf','guard']);v=s.run();assert v[1]==0
 raw=b'HIACAP01'+struct.pack('<15Q',1,*([0]*14));src=C.create_string_buffer(raw);copy=C.create_string_buffer(bytes(s.work));out=C.create_string_buffer(b'\xa5'*256,256)
 rc=client.entry(src,len(raw),out,256,copy,len(copy));assert rc==0xfffffffd and bytes(out)==b'\xa5'*256
 read,write=os.pipe();pid=os.fork()
 if pid==0:
  os.close(read);out.raw=b'\xa5'*256
  rc=client.entry(src,len(raw),out,256,s.work,len(s.work))
  os.write(write,struct.pack('<I',rc)+bytes(out));os._exit(0)
 os.close(write);data=os.read(read,300);os.close(read);os.waitpid(pid,0)
 assert data==struct.pack('<I',0xfffffffd)+b'\xa5'*256
 assert C.string_at(v[13],v[14])==b'guard';s.closed()
 return {'copied_context_rejected':True,'forked_context_rejected':True,'original_maps_preserved':True}
def spans(client):
 s=Session(client,['/usr/bin/true']);cases=[]
 for name,src,n,out,outn,work,workn in [
  ('null-source',None,len(s.wire),s.out,256,s.work,65536),
  ('short-source',s.src,127,s.out,256,s.work,65536),
  ('null-output',s.src,len(s.wire),None,256,s.work,65536),
  ('short-output',s.src,len(s.wire),s.out,255,s.work,65536),
  ('null-work',s.src,len(s.wire),s.out,256,None,65536),
  ('short-work',s.src,len(s.wire),s.out,256,s.work,4095),
  ('unaligned-work',s.src,len(s.wire),s.out,256,C.addressof(s.work)+1,65535),
  ('source-output-overlap',s.src,len(s.wire),s.src,256,s.work,65536),
  ('output-work-overlap',s.src,len(s.wire),s.work,256,s.work,65536),
  ('source-span-overflow',C.c_void_p((1<<64)-64),128,s.out,256,s.work,65536)]:
  s.out.raw=b'\xa5'*256;before=bytes(s.work);source=bytes(s.src)
  rc=client.entry(src,n,out,outn,work,workn)
  assert rc==0xfffffffd and bytes(s.out)==b'\xa5'*256 and bytes(s.work)==before and bytes(s.src)==source,(name,rc)
  cases.append(name)
 return cases
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.mkdir(mode=0o700)
 client=NativeCapture(a.library);rows=[];record={'passed':False,'whole_capture_qualified':False,'cases':rows}
 try:
  rows.append({'name':'span-controls','passed':True,'result':spans(client)})
  for name,rules,error in [('fork-eacces',[(57,13,None)],7),('waitid-eacces',[(247,13,None)],6),('memfd-eacces',[(319,13,None)],12),('mmap-enomem',[(9,12,None)],13),('kill-eacces',[(62,13,None)],11)]:
   rows.append(isolated(name,lambda r=rules,e=error:run_fault(client,r,e)))
  for number in (11,436):rows.append(isolated('retire-retry-'+str(number),lambda n=number:retry_fault(client,n)))
  for method in ('native','proc','rlimit','enosys'):rows.append(isolated('inherited-fds-'+method,lambda m=method:inherited_descriptors(client,m)))
  for mask in (1,2,4,7):rows.append(isolated('stdio-'+str(mask),lambda m=mask:stdio(client,m)))
  rows.append(isolated('actual-ownership-guards',lambda:ownership_guard(client)))
  record['passed']=True
 except BaseException as e:record['error']=repr(e);record['traceback']=traceback.format_exc();raise
 finally:(a.output/'report.json').write_text(json.dumps(record,indent=2)+'\n')
 print('CAPTURE_CUSTODY_CONTROL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
