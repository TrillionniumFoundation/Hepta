"""Actual native source catalog digest and owned resource retirement gates."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,threading,traceback
from tools.qualify_hia_clang_capture_faults import isolated
WORK=2<<20
class Identity:
 def __init__(self,library):
  self.lib=C.CDLL(str(library));self.entry=self.lib.hia_clang_implementation_identity
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
 def frame(self,records):
  body=b''
  for name,path in records:
   path=os.fsencode(path);f=b'HIASFL01'+struct.pack('<23Q',0,1<<30,1,len(path),*([0]*19))+path+b'\0'
   assert len(f)==193+len(path)
   body+=struct.pack('<2Q',len(name),len(f))+name+f
  return b'HIAIDQ01'+struct.pack('<3Q',0,len(records),32+len(body))+body
class Session:
 def __init__(self,client,records):
  self.client=client;self.wire=client.frame(records);self.src=C.create_string_buffer(self.wire)
  self.out=C.create_string_buffer(128);self.work=C.create_string_buffer(WORK)
 def run(self):
  rc=self.client.entry(self.src,len(self.wire),self.out,128,self.work,WORK);assert rc==0,hex(rc)
  assert bytes(self.out)[:8]==b'HIAIDR01';return struct.unpack('<16Q',bytes(self.out))
 def retire(self):
  wire=b'HIAIDQ01'+struct.pack('<3Q',1,0,0);src=C.create_string_buffer(wire)
  rc=self.client.entry(src,len(wire),self.out,128,self.work,WORK);assert rc==0,hex(rc)
  return struct.unpack('<16Q',bytes(self.out))
 def closed(self):
  v=self.retire();assert v[1]==0 and v[8]==0 and v[9]==1 and v[10]==1,v
  assert not any(bytes(self.work)[:65536])
def digest(records):
 s=hashlib.sha256()
 for name,path in records:
  raw=Path(os.fsdecode(path)).read_bytes();s.update(struct.pack('<Q',len(name)));s.update(name);s.update(struct.pack('<Q',len(raw)));s.update(hashlib.sha256(raw).digest())
 return s.digest()
def basics(client,root):
 before=set(os.listdir('/proc/self/fd'));records=[]
 for i,data in enumerate([b'',b'abc',bytes(range(256))*9000]):
  p=root/str(i);p.write_bytes(data);records.append((('logical-'+str(i)).encode(),p))
 p=os.fsencode(root)+b'/raw-\xff';fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.write(fd,b'raw');os.close(fd);records.append((b'logical-raw',p))
 cases=[records[:1],records,records[::-1],[(b'\xff'+b'x'*65537,records[2][1])]]
 for rows in cases:
  s=Session(client,rows);v=s.run();assert v[1]==0 and v[3]==len(rows) and v[8]==0 and v[9]==1,v
  assert bytes(s.out)[32:64]==digest(rows);s.closed()
 old=digest(records);(root/'1').write_bytes(b'abc changed');s=Session(client,records);assert s.run()[1]==0;assert bytes(s.out)[32:64]==digest(records)!=old;s.closed()
 for name,make in [('missing',None),('directory','dir'),('symlink','sym')]:
  p=root/name
  if make=='dir':p.mkdir()
  elif make=='sym':p.symlink_to(root/'1')
  s=Session(client,[(b'rejected',p)]);v=s.run();assert v[1]==2 and v[8]==0 and v[9]==1,v;s.closed()
 assert before==set(os.listdir('/proc/self/fd'))
 return dict(digest_vectors=len(cases)+1,actual_content_change=True,unbounded_name_chunks=65538,filesystem_bytes=True,failed_files=3,fd_balanced=True)
def guards(client,path):
 s=Session(client,[(b'a',path)]);assert s.run()[1]==0
 copied=C.create_string_buffer(bytes(s.work));wire=b'HIAIDQ01'+struct.pack('<3Q',1,0,0);source=C.create_string_buffer(wire);out=C.create_string_buffer(b'\xa5'*128,128)
 rc=client.entry(source,len(wire),out,128,copied,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*128
 pid=os.fork()
 if pid==0:
  rc=client.entry(source,len(wire),out,128,s.work,WORK);os._exit(0 if rc==0xfffffffd and bytes(out)==b'\xa5'*128 else 1)
 _,status=os.waitpid(pid,0);assert os.WIFEXITED(status)and os.WEXITSTATUS(status)==0
 s.closed();raw=s.wire;cases=[raw[:31],raw[:-1],raw+b'x']
 for at,value in [(0,0),(8,2),(16,0),(16,1<<40),(24,len(raw)+1),(32,0),(40,1<<40),(49,0),(57,1),(65,0),(73,0),(89,1)]:
  b=bytearray(raw);struct.pack_into('<Q',b,at,value);cases.append(bytes(b))
 for b in cases:
  source=C.create_string_buffer(b);work=C.create_string_buffer(WORK);out.raw=b'\xa5'*128
  rc=client.entry(source,len(b),out,128,work,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*128,(rc,b[:100])
 return dict(wire_controls=len(cases),copy_and_fork_refused_before_output=True)
def seccomp(client,flat_n,rules):
 class F(C.Structure):_fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
 class P(C.Structure):_fields_=[('len',C.c_ushort),('filter',C.POINTER(F))]
 start=C.cast(client.entry,C.c_void_p).value;end=start+flat_n;assert start>>32==(end-1)>>32
 rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(6,0,0,0x80000000),(0x20,0,0,12),(0x15,0,0,start>>32),(0x20,0,0,8),(0x35,0,0,start&0xffffffff),(0x35,0,0,end&0xffffffff)]
 for nr,error in rules:rows.extend([(0x20,0,0,0),(0x15,0,1,nr),(6,0,0,0x50000|error)])
 endidx=len(rows);rows.append((6,0,0,0x7fff0000));rows[4]=(0x15,0,endidx-5,start>>32);rows[6]=(0x35,0,endidx-7,start&0xffffffff);rows[7]=(0x35,endidx-8,0,end&0xffffffff)
 array=(F*len(rows))(*(F(*r)for r in rows));program=P(len(rows),array);libc=C.CDLL(None,use_errno=True)
 assert libc.prctl(38,1,0,0,0)==0 and libc.prctl(22,2,C.byref(program),0,0)==0,C.get_errno()
def retry(client,path,flat_n):
 before=set(os.listdir('/proc/self/fd'));s=Session(client,[(b'path',path)]);go=threading.Event();done=threading.Event();results=[]
 def other():
  go.wait()
  try:results.append(s.retire())
  except BaseException as e:results.append(repr(e))
  finally:done.set()
 t=threading.Thread(target=other);t.start();seccomp(client,flat_n,[(436,13)]);v=s.run()
 assert v[1]==5 and v[8]==1 and v[9]==1,v
 v=s.retire();assert v[1]==5 and v[8]==1 and v[9]==1 and v[10]==0,v
 go.set();assert done.wait(10);t.join();v=results[0];assert isinstance(v,tuple)and v[1]==0 and v[8]==0 and v[9]==1 and v[10]==1,results
 assert before==set(os.listdir('/proc/self/fd'))and not any(bytes(s.work)[:65536])
 return dict(actual_close_range_errno=13,retained_child_context=True,actual_other_thread_retry_ack=True,fd_balanced=True)
def unknown(client,path,flat_n):
 s=Session(client,[(b'path',path)]);seccomp(client,flat_n,[(436,38),(3,4)]);v=s.run()
 assert v[1]==3 and v[8]==1 and v[9]==0,v
 v=s.retire();assert v[1]==3 and v[8]==1 and v[9]==0 and v[10]==0,v
 return dict(actual_legacy_eintr=4,unknown_quarantined=True,no_false_retired_ack=True)
def open_error(client,path,flat_n):
 before=set(os.listdir('/proc/self/fd'));s=Session(client,[(b'path',path)]);seccomp(client,flat_n,[(2,13)]);v=s.run();assert v[1]==2 and v[2]==13 and v[8]==0,v
 s.closed();assert before==set(os.listdir('/proc/self/fd'));return dict(actual_open_errno=13,fd_balanced=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--flat',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 a.output.mkdir(mode=0o700);root=a.output/'files';root.mkdir();client=Identity(a.library);rows=[];report=dict(schema='hepta.hia.native-clang-implementation-identity.v1',passed=False,whole_clang_qualified=False,fixed_production_catalog_qualified=False,groups=rows,library_sha256=hashlib.sha256(a.library.read_bytes()).hexdigest())
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  rows.append(dict(name='actual-source-catalog-digest',passed=True,result=basics(client,root)));save()
  rows.append(dict(name='wire-copy-fork-guards',passed=True,result=guards(client,root/'1')));save()
  for name,fn in [('actual-open-failure',open_error),('actual-close-retry',retry),('actual-legacy-close-quarantine',unknown)]:
   rows.append(isolated(name,lambda fn=fn:fn(client,root/'1',a.flat.stat().st_size)));save()
  report['passed']=True;print('CLANG_IDENTITY_QUALIFIED',len(rows),flush=True)
 except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();raise
 finally:save()
if __name__=='__main__':main()
