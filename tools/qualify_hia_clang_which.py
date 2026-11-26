"""Real libc environment, filesystem and ownership gates for HIA which."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,queue,select,shutil,struct,threading,traceback
from tools.qualify_hia_clang_capture_faults import isolated
from tools import qualify_hia_clang_stable_file as faults
from tools import qualify_hia_native_seccomp_notify as notify
from tools import generate_hia_clang_which_packer as spec
WORK=4096
class Which:
 def __init__(self,path):
  self.lib=C.CDLL(str(path));self.entry=self.lib.hia_clang_which
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
 def session(self,name):return Session(self,os.fsencode(name))
class Session:
 def __init__(self,client,raw):
  self.client=client;self.wire=b'HIACWH01'+struct.pack('<3Q',0,len(raw),0)+raw
  self.src=C.create_string_buffer(self.wire);self.out=C.create_string_buffer(128);self.work=C.create_string_buffer(WORK)
 def run(self):
  rc=self.client.entry(self.src,len(self.wire),self.out,128,self.work,WORK);assert rc==0,hex(rc)
  assert bytes(self.out)[:8]==b'HIACWR01'
  return struct.unpack('<16Q',bytes(self.out))
 def retire(self):
  raw=b'HIACWH01'+struct.pack('<3Q',1,0,0);s=C.create_string_buffer(raw)
  rc=self.client.entry(s,len(raw),self.out,128,self.work,WORK);assert rc==0,hex(rc)
  return struct.unpack('<16Q',bytes(self.out))
 def close(self):
  v=self.retire();assert v[1]==0 and v[7]==0 and v[8]==1 and v[9]==1,v
  assert not any(bytes(self.work))
def native_filter(client,rules):
 old=faults.spec
 try:faults.spec=spec;faults.native_seccomp(client,rules)
 finally:faults.spec=old
def compare(client,name):
 expected=shutil.which(name);s=client.session(name);v=s.run()
 if expected is None:assert v[1]==1 and v[3]==0 and v[4]==0,(name,v)
 else:
  assert v[1]==0 and v[4]and C.string_at(v[4],v[3])==os.fsencode(expected),(name,v,expected)
  assert C.string_at(v[4]+v[3],1)==b'\0'
 s.close()
 return expected
def ordinary(client,root):
 before=set(os.listdir('/proc/self/fd'));old=os.environb.get(b'PATH');cwd=os.getcwd();cases=0;observed=[]
 a=root/'a';b=root/'b';a.mkdir();b.mkdir()
 for folder,mode in [(a,0o600),(b,0o700)]:
  (folder/'tool').write_bytes(b'#!/bin/sh\nexit 0\n');os.chmod(folder/'tool',mode)
 (b/'alias').symlink_to('tool');(b/'broken').symlink_to('absent');(b/'directory').mkdir()
 (b/'loop').symlink_to('loop');(b/'目录').write_bytes(b'x');os.chmod(b/'目录',0o700)
 rawname=os.fsencode(b)+b'/raw-\xff';fd=os.open(rawname,os.O_CREAT|os.O_WRONLY,0o700);os.close(fd)
 try:
  os.chdir(root)
  envs=[None,b'',os.fsencode(a)+b':'+os.fsencode(b),os.fsencode(a)+b':'+os.fsencode(a)+b':'+os.fsencode(b),b':b:b:',b'a:b',b'./a:./b',os.fsencode(b)+b'/',b'missing:'+os.fsencode(b)]
  for env in envs:
   if env is None:os.environb.pop(b'PATH',None)
   else:os.environb[b'PATH']=env
   for name in ['tool','alias','broken','directory','loop','目录',b'raw-\xff','','no-such-tool',str(b/'tool'),'b/tool','b/../b/alias','a/tool',b'bad\0name']:
    expected=compare(client,name);cases+=1
   observed.append(dict(path=env.hex()if env is not None else None))
  long_path=b':'.join(b'not-there-'+str(i).encode()+b'-'+b'x'*80 for i in range(3000))+b':'+os.fsencode(b)
  os.environb[b'PATH']=long_path;assert compare(client,'tool')==str(b/'tool');cases+=1
  os.environb[b'PATH']=os.fsencode(b)
  for name in ['x'*5000,b'/' +b'x'*5000]:compare(client,name);cases+=1
 finally:
  os.chdir(cwd)
  if old is None:os.environb.pop(b'PATH',None)
  else:os.environb[b'PATH']=old
 assert set(os.listdir('/proc/self/fd'))==before
 return dict(actual_oracle_cases=cases,live_path_variants=len(envs),long_path_bytes=len(long_path),default_confstr=os.confstr('CS_PATH'),empty_path_refused=True,fd_balanced=True)
def guards(client,root):
 s=client.session(str(root/'b/tool'));v=s.run();assert v[1]==0
 raw=b'HIACWH01'+struct.pack('<3Q',1,0,0);source=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*128,128);copy=C.create_string_buffer(bytes(s.work))
 rc=client.entry(source,32,out,128,copy,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*128
 pid=os.fork()
 if pid==0:
  rc=client.entry(source,32,out,128,s.work,WORK);os._exit(0 if rc==0xfffffffd and bytes(out)==b'\xa5'*128 else 1)
 _,status=os.waitpid(pid,0);assert os.WIFEXITED(status)and os.WEXITSTATUS(status)==0
 assert C.string_at(v[4],v[3])==os.fsencode(root/'b/tool');s.close()
 good=client.session('clang');bad=[good.wire[:31],good.wire[:-1],good.wire+b'x']
 for offset,value in [(0,0),(8,2),(16,1<<40),(24,1)]:
  raw=bytearray(good.wire);struct.pack_into('<Q',raw,offset,value);bad.append(bytes(raw))
 for raw in bad:
  source=C.create_string_buffer(raw);work=C.create_string_buffer(WORK);out.raw=b'\xa5'*128
  rc=client.entry(source,len(raw),out,128,work,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*128
 return dict(copied_and_forked_owner_refused=True,wire_no_write_controls=len(bad))
def refused_map(client,root):
 s=client.session(str(root/'b/tool'));native_filter(client,[(9,13,None)]);v=s.run()
 assert v[1]==3 and v[2]==13 and v[7]==0,v;s.close()
 return dict(actual_mmap_errno=13,no_mapping_forgotten=True)
def retry_map(client,root):
 s=client.session(str(root/'b/tool'));v=s.run();assert v[1]==0 and v[7]==1
 go=threading.Event();done=threading.Event();answers=[]
 def release():
  go.wait()
  try:answers.append(s.retire())
  except BaseException as e:answers.append(repr(e))
  finally:done.set()
 t=threading.Thread(target=release);t.start();native_filter(client,[(11,13,None)])
 v=s.retire();assert v[1]==4 and v[2]==13 and v[7]==1 and v[8]==1 and v[9]==0,v
 assert any(bytes(s.work));go.set();assert done.wait(10);t.join()
 assert len(answers)==1 and isinstance(answers[0],tuple)and answers[0][9]==1 and answers[0][7]==0,answers
 assert not any(bytes(s.work))
 return dict(actual_munmap_errno=13,same_context_other_thread_ack=True)
def duplicates(client,root):
 old=os.environb.get(b'PATH');a=os.fsencode(root/'a');b=os.fsencode(root/'b')
 os.environb[b'PATH']=a+b':'+a+b':'+b
 ready=queue.Queue();stop=threading.Event();seen=[];errors=[]
 def observe():
  listener=ready.get()
  try:
   while not stop.is_set():
    if not select.select([listener],[],[],.1)[0]:continue
    n=notify.receive(listener);seen.append(C.string_at(n.data.args[0]));notify.continue_syscall(listener,n)
  except BaseException as e:errors.append(repr(e))
 t=threading.Thread(target=observe);t.start();start=C.cast(client.entry,C.c_void_p).value;listener=notify.install(start,start+len(spec.BRIDGE),4);ready.put(listener)
 try:assert compare(client,'tool')==os.fsdecode(b+b'/tool')
 finally:
  stop.set();t.join(5);os.close(listener)
  if old is None:os.environb.pop(b'PATH',None)
  else:os.environb[b'PATH']=old
 assert not t.is_alive()and not errors,(errors,seen)
 assert seen==[a+b'/tool',b+b'/tool',b+b'/tool'],seen
 return dict(actual_stat_order=[os.fsdecode(x)for x in seen],duplicates_not_retried=True,actual_kernel_continue=True)
def concurrent(client,root):
 before=set(os.listdir('/proc/self/fd'));errors=[];calls=[]
 def run():
  try:
   for _ in range(16):calls.append(compare(client,str(root/'b/tool')))
  except BaseException as e:errors.append(repr(e))
 ts=[threading.Thread(target=run)for _ in range(8)]
 for t in ts:t.start()
 for t in ts:t.join(20)
 assert not errors and len(calls)==128 and all(not t.is_alive()for t in ts),(errors,len(calls))
 assert set(os.listdir('/proc/self/fd'))==before
 return dict(threads=8,actual_calls=len(calls),fd_balanced=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700)
 client=Which(a.library);root=a.output/'files';root.mkdir();rows=[]
 report=dict(schema='hepta.hia.clang-which-qualification.v1',passed=False,whole_clang_outer_qualified=False,product=dict(bytes=a.library.stat().st_size,sha256=hashlib.sha256(a.library.read_bytes()).hexdigest()),groups=rows)
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  rows.append(dict(name='actual-environment-and-filesystem',passed=True,result=ordinary(client,root)));save()
  rows.append(dict(name='wire-and-owner-guards',passed=True,result=guards(client,root)));save()
  rows.append(isolated('actual-mmap-refusal',lambda:refused_map(client,root)));save()
  rows.append(isolated('actual-munmap-retry',lambda:retry_map(client,root)));save()
  rows.append(isolated('actual-duplicate-path-stat-order',lambda:duplicates(client,root)));save()
  rows.append(dict(name='concurrent-lookups',passed=True,result=concurrent(client,root)));save()
  report['passed']=True;save();print(json.dumps(dict(passed=True,groups=len(rows),report=str(a.output/'report.json'))),flush=True)
 except BaseException:
  report['error']=traceback.format_exc();save();raise
if __name__=='__main__':main()
