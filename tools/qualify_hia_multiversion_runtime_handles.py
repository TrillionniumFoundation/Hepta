from pathlib import Path
import os,sys,struct,json,ctypes as C,mmap,time,hashlib,threading,argparse,concurrent.futures
B=Path("/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z");V=B/'native-multiversion-source';sys.path.insert(0,str(V))
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_runtime_generation import scalar_program,rawdoc
get=lambda b,i:struct.unpack_from('<Q',b,i)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
def inner(op,*,files=(),parent=b'',raw=b'',fn=b'',args=b'',expected=(0,0),token=0,budget=0,measurement=b'',maxlive=8,prove=False,handoff=NONE):
 h=bytearray(256);struct.pack_into('<8sQ',h,0,b'HIAMVEX1',op)
 if op==0:
  struct.pack_into('<6Q',h,16,*[fd for fd,b in files],2000,maxlive,int(prove));h[128:224]=b''.join(hashlib.sha256(b).digest() for fd,b in files)
 else:struct.pack_into('<4Q',h,40,*expected,budget,token)
 struct.pack_into('<Q',h,72,handoff);struct.pack_into('<6Q',h,80,len(raw),len(parent),len(fn),len(args),len(measurement),int(bool(measurement)))
 return bytes(h)+raw+parent+fn+args+measurement
class Carrier:
 def __init__(self,image,rows):
  self.lib=C.CDLL(str(image));self.f=self.lib.hia_mv_runtime_handles;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.w=C.create_string_buffer(256);self.rows=rows;self.lock=threading.Lock()
 def q(self,op,cap=(0,0,0),payload=b'',want=0,child=None):
  h=bytearray(128);struct.pack_into('<8sQ',h,0,b'HIAMVHQ1',op);struct.pack_into('<3Q',h,24,*cap);struct.pack_into('<Q',h,72,len(payload));raw=bytes(h)+payload;s=C.create_string_buffer(raw)
  mem=mmap.mmap(-1,96<<20);o=(C.c_char*(96<<20)).from_buffer(mem)
  start=time.monotonic_ns();rc=self.f(s,len(raw),o,len(o),self.w,len(self.w));elapsed=time.monotonic_ns()-start
  head=bytes(o[:128]);assert s.raw==raw+b'\0'
  if rc==0:
   assert head[:8]==b'HIAMVHR1';outcap=tuple(get(head,i) for i in (24,32,40));status=get(head,8);cp=get(head,56)
   ch=bytes(o[cp:cp+1024]) if cp else b'';value=bytes(o[cp+get(ch,120):cp+get(ch,120)+get(ch,112)]) if ch and get(ch,112) else b'';snap=bytes(o[cp+get(ch,128):cp+get(ch,128)+get(ch,136)]) if ch and get(ch,136) else b''
   streams=[]
   if ch:
    assert ch[:8]==b'HIAMVER1'
    for at in (96,104):
     fd=get(ch,at)
     if fd!=NONE:
      n=os.fstat(fd).st_size;streams.append(dict(bytes=n,sha256=sha(os.pread(fd,n,0))));os.close(fd)
   row=dict(op=op,rc=rc,status=status,child_status=get(head,48),kind=get(head,16),result=bool(outcap[0]),retained=get(head,72),finalizer=get(head,80),value=value.decode(),elapsed_ns=elapsed,streams=streams)
  else:
   row=dict(op=op,rc=rc,elapsed_ns=elapsed);outcap=(0,0,0);value=b'';ch=b'';snap=b'';status=None
  with self.lock:self.rows.append(row)
  del o;mem.close()
  assert rc==0,row
  if want is not None:assert status==want,row
  if child is not None:assert get(head,48)==child,row
  return dict(cap=outcap,header=head,child=ch,value=value,snapshot=snap,row=row)
 def create(self,files,parent,program):
  return self.q(1,payload=inner(0,files=files,parent=os.fsencode(parent),raw=rawdoc(program)),child=0)['cap']
 def lease(self,cap):
  return self.q(4,cap,inner(3),child=0)['cap']
 def call(self,cap,arg,want=0):
  r=self.q(4,cap,inner(4,fn=b'calculate',args=json.dumps([arg]).encode()),child=want)
  if want==0:assert json.loads(r['value'])==arg,r
  return r
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--component',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();D=a.output;D.mkdir(exist_ok=False);P=D/'parent';P.mkdir(mode=0o700)
 paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];rows=[];r=Carrier(a.component,rows);r.q(0)
 def mark(name):
  (D/'calls.json').write_text(json.dumps(rows,indent=2)+'\n');print('HANDLES_PASS',name,len(rows),flush=True)
 before=set(os.listdir('/proc/self/fd'));runtime=r.create(files,P,scalar_program(None));assert runtime[0];mark('actual-constructor')
 other=r.q(2,runtime)['cap'];assert other!=runtime;r.q(6,other);mark('runtime-clone')
 lease=r.lease(runtime);cloned=r.q(2,lease)['cap'];r.call(lease,17);r.call(cloned,2**64-1);mark('actual-lease-and-call')
 r.q(3,lease);r.q(6,lease,want=1);r.call(cloned,42);mark('independent-lease-reference')
 r.q(3,runtime);r.q(6,runtime,want=1);r.q(4,other,inner(8),child=0);r.q(3,other)
 r.q(5,want=5);r.call(cloned,43);mark('closed-runtime-last-user-keeps-lease')
 r.q(4,cloned,inner(5),child=0);r.q(4,cloned,inner(6),child=0);r.call(cloned,19,want=32);r.q(3,cloned);r.q(6,cloned,want=1)
 assert get(r.w,16)==get(r.w,40)==get(r.w,64)==0 and not list(P.iterdir())
 assert set(os.listdir('/proc/self/fd'))==before;mark('lease-finalizer-closes-runtime')
 r.q(5);r.q(0,want=5)
 for fd,b in files:os.close(fd)
 report=dict(schema='hepta.hia.multiversion-runtime-handles-smoke.v1',whole_native_runtime=False,passed=7,failed=0,actual_calls=len(rows),actual_embedded_effects=True,image_sha256=sha(a.component.read_bytes()),rows=rows)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('HANDLES_SMOKE_PASS',len(rows),flush=True)
if __name__=='__main__':main()
