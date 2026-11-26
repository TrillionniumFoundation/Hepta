"""Qualification of borrowed Path.resolve results and real descriptor retirement."""
from pathlib import Path
import argparse,ctypes as C,json,os,struct,threading,traceback,hashlib
from tools.qualify_hia_clang_capture_faults import isolated
from tools import qualify_hia_clang_stable_file as faults
from tools import generate_hia_native_path_resolve_owned_packer as spec
WORK=200704;NONE=(1<<64)-1
class Resolver:
 def __init__(self,library):
  self.lib=C.CDLL(str(library));self.entry=self.lib.hia_native_path_resolve
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
 def session(self,path,mode=0):
  raw=os.fsencode(path) if mode==0 else json.dumps(path,ensure_ascii=True).encode()
  return Session(self,raw,mode)
class Session:
 def __init__(self,client,raw,mode):
  self.client=client;self.raw=b'HIAPTO01'+struct.pack('<3Q',mode,len(raw),0)+raw
  self.source=C.create_string_buffer(self.raw);self.output=C.create_string_buffer(128);self.work=C.create_string_buffer(WORK)
 def run(self):
  rc=self.client.entry(self.source,len(self.raw),self.output,128,self.work,WORK)
  assert rc==0,hex(rc)
  assert bytes(self.output)[:8]==b'HIAPOR01'
  return struct.unpack('<16Q',bytes(self.output))
 def retire(self):
  raw=b'HIAPTO01'+struct.pack('<3Q',2,0,0);s=C.create_string_buffer(raw)
  rc=self.client.entry(s,len(raw),self.output,128,self.work,WORK);assert rc==0,hex(rc)
  return struct.unpack('<16Q',bytes(self.output))
 def close(self):
  v=self.retire();assert v[1]==0 and v[11]==0 and v[12]==1 and v[13]==1 and v[14]==0 and v[15]==0,v
  assert not any(bytes(self.work)[:4096])
def native_filter(client,rules):
 old=faults.spec
 try:
  faults.spec=spec;faults.native_seccomp(client,rules)
 finally:faults.spec=old
def ordinary(client,root):
 before=set(os.listdir('/proc/self/fd'));count=0
 (root/'a').mkdir();(root/'a/file').write_bytes(b'x');(root/'link').symlink_to('a')
 (root/'chain').symlink_to('link');(root/'dangling').symlink_to('absent/x')
 (root/'loop').symlink_to('loop')
 paths=['','.', '..','/','//','///','a','a/..','a/file/..','missing/../a','link/../a','chain/file','dangling/..','a//missing///../file']
 for a in ['','a','missing','link','chain','.','..']:
  for b in ['','a','missing','file','.','..']:paths.append(a+'/'+b)
 for item in paths:
  path=str(root/item) if item and not item.startswith('/') else item
  expected=os.fsencode(Path(path).resolve(strict=False))
  for mode in [0,1]:
   s=client.session(path,mode);v=s.run();assert v[1]==0 and v[4]!=NONE and v[11]==1 and v[12]==1 and v[13]==0 and v[14]==1,(path,mode,v)
   assert os.pread(v[4],v[5]+1,0)==expected,(path,mode,expected,os.pread(v[4],v[5]+1,0))
   assert v[5]==len(expected)and v[6]==15
   fd=v[4];s.close()
   try:os.fstat(fd)
   except OSError as e:assert e.errno==9
   else:raise AssertionError('borrowed descriptor remained live after ACK')
   count+=1
 rawpath=os.fsencode(root)+b'/raw-\xff'
 fd=os.open(rawpath,os.O_CREAT|os.O_WRONLY,0o600);os.close(fd)
 for path in [rawpath,os.fsencode(root)+b'/not-\xfe/../raw-\xff']:
  s=client.session(path);v=s.run();assert v[1]==0;assert os.pread(v[4],v[5]+1,0)==os.fsencode(Path(os.fsdecode(path)).resolve());s.close();count+=1
 for path in [str(root/'loop'),str(root/'loop/x')]:
  expected=os.fsencode(Path(path).resolve(strict=False))
  s=client.session(path);v=s.run();assert v[1]==0 and os.pread(v[4],v[5]+1,0)==expected,(path,v,expected);s.close();count+=1
 assert set(os.listdir('/proc/self/fd'))==before
 return dict(actual_resolutions=count,python_path_oracle=True,result_read_only_sealed=True,borrowed_fd_closed_only_on_ack=True,fd_balanced=True)
def guards(client,root):
 s=client.session(str(root));v=s.run();assert v[1]==0
 raw=b'HIAPTO01'+struct.pack('<3Q',2,0,0);source=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*128,128);copied=C.create_string_buffer(bytes(s.work))
 rc=client.entry(source,len(raw),out,128,copied,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*128
 pid=os.fork()
 if pid==0:
  rc=client.entry(source,len(raw),out,128,s.work,WORK);os._exit(0 if rc==0xfffffffd and bytes(out)==b'\xa5'*128 else 1)
 _,status=os.waitpid(pid,0);assert os.WIFEXITED(status)and os.WEXITSTATUS(status)==0
 assert os.fstat(v[4]);s.close()
 valid=client.session(str(root));raw=valid.raw
 bads=[raw[:31],raw[:-1],raw+b'x']
 for at,value in [(0,0),(8,3),(16,1<<40),(24,1)]:
  bad=bytearray(raw);struct.pack_into('<Q',bad,at,value);bads.append(bytes(bad))
 for bad in bads:
  src=C.create_string_buffer(bad);work=C.create_string_buffer(WORK);out.raw=b'\xa5'*128
  rc=client.entry(src,len(bad),out,128,work,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*128
 return dict(copied_context_refused=True,forked_context_refused=True,wire_no_write_controls=len(bads))
def retry(client,root,when):
 before=set(os.listdir('/proc/self/fd'));s=client.session(str(root/'a/file'))
 go=threading.Event();done=threading.Event();answers=[]
 def finish():
  go.wait()
  try:answers.append(s.retire())
  except BaseException as e:answers.append(repr(e))
  finally:done.set()
 t=threading.Thread(target=finish);t.start()
 if when=='resolution':
  native_filter(client,[(436,13,None)]);v=s.run();assert v[1]!=0 and v[14]>=3 and v[12]==1,v
 else:
  v=s.run();assert v[1]==0 and v[14]==1
  native_filter(client,[(436,13,None)])
 bad=s.retire();assert bad[1]==4 and bad[2]==(1<<64)-13 and bad[11]==1 and bad[12]==1 and bad[13]==0 and bad[14]>=1,bad
 assert any(bytes(s.work)[:4096]);go.set();assert done.wait(10);t.join()
 assert len(answers)==1 and isinstance(answers[0],tuple)and answers[0][13]==1 and answers[0][14]==0,answers
 assert not any(bytes(s.work)[:4096])and set(os.listdir('/proc/self/fd'))==before
 return dict(failure_at=when,retained_descriptors=bad[14],actual_errno=13,unfiltered_thread_ack=True,fd_balanced=True)
def fallback(client,root,ambiguous=False):
 before=set(os.listdir('/proc/self/fd'));s=client.session(str(root))
 rules=[(436,38,None)]
 if ambiguous:rules.append((3,4,None))
 native_filter(client,rules);v=s.run()
 if ambiguous:
  assert v[1]!=0 and v[11]==2 and v[12]==0 and v[15]==1,v
  later=s.retire();assert later[11]==2 and later[12]==0 and later[13]==0 and later[15]==1,later
  return dict(actual_enosys_then_eintr=True,unknown_quarantined=True,no_false_retirement=True)
 assert v[1]==0,v;s.close();assert set(os.listdir('/proc/self/fd'))==before
 return dict(actual_enosys_legacy_fallback=True,fd_balanced=True)
def kernel_failure(client,root,nr):
 before=set(os.listdir('/proc/self/fd'));s=client.session(str(root/'link/file'));native_filter(client,[(nr,13,None)])
 v=s.run();assert v[1]!=0 and v[2]==(1<<64)-13,(nr,v);s.close()
 assert set(os.listdir('/proc/self/fd'))==before
 return dict(actual_syscall=nr,actual_errno=13,fd_balanced=True)
def readlink_refusal(client,root):
 before=set(os.listdir('/proc/self/fd'));s=client.session(str(root/'link/file'));native_filter(client,[(267,13,None)])
 v=s.run();assert v[1]==0 and os.pread(v[4],v[5]+1,0)==os.fsencode(root/'link/file'),v
 s.close();assert set(os.listdir('/proc/self/fd'))==before
 return dict(actual_readlink_errno=13,strict_false_keeps_unresolved_link=True,fd_balanced=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(mode=0o700)
 client=Resolver(a.library);root=a.output/'paths';root.mkdir()
 rows=[];report=dict(schema='hepta.hia.native-path-owned-qualification.v1',passed=False,whole_clang_outer_qualified=False,product=dict(bytes=a.library.stat().st_size,sha256=hashlib.sha256(a.library.read_bytes()).hexdigest()),groups=rows)
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  rows.append(dict(name='path-semantics-and-borrowed-result',passed=True,result=ordinary(client,root)));save()
  rows.append(dict(name='same-owner-retirement-guards',passed=True,result=guards(client,root)));save()
  for when in ['resolution','retirement']:
   rows.append(isolated('close-range-'+when,lambda when=when:retry(client,root,when)));save()
  rows.append(isolated('legacy-success',lambda:fallback(client,root)));save()
  rows.append(isolated('ambiguous-close-quarantine',lambda:fallback(client,root,True)));save()
  for nr in [319,17,18,72]:
   rows.append(isolated('kernel-'+str(nr),lambda nr=nr:kernel_failure(client,root,nr)));save()
  rows.append(isolated('strict-false-readlink-refusal',lambda:readlink_refusal(client,root)));save()
  report['passed']=True;save();print(json.dumps(dict(passed=True,groups=len(rows),report=str(a.output/'report.json'))),flush=True)
 except BaseException:
  report['error']=traceback.format_exc();save();raise
if __name__=='__main__':main()
