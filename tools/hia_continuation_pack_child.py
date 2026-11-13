"""Bounded aggregate-bundle call; not a widened compiler input transport."""
import ctypes,hashlib,json,mmap,os,resource,sys,time
from pathlib import Path
MAX_BUNDLE=64<<20;MAX_IMAGE=1<<20;WORK=1<<20
request=json.loads(Path(sys.argv[1]).read_text())
resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(10,10));resource.setrlimit(resource.RLIMIT_AS,(512<<20,512<<20));resource.setrlimit(resource.RLIMIT_FSIZE,(65<<20,65<<20))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)];libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
image=Path(request['image']).read_bytes();source=Path(request['source']).read_bytes();capacity=request['capacity']
sha=lambda b:hashlib.sha256(b).hexdigest()
assert 0<len(image)<=MAX_IMAGE and len(source)<=MAX_BUNDLE
assert sha(image)==request['image_sha256'] and sha(source)==request['source_sha256']
assert type(capacity)is int and 0<capacity<=MAX_BUNDLE
page=mmap.PAGESIZE
class Guarded:
 def __init__(self,size,fill):
  self.size=size;self.span=((size+64+page-1)//page)*page
  self.mapping=mmap.mmap(-1,self.span+page*2,prot=mmap.PROT_READ|mmap.PROT_WRITE)
  self.base=ctypes.addressof(ctypes.c_char.from_buffer(self.mapping));self.address=self.base+page+32
  assert libc.mprotect(self.base,page,0)==0 and libc.mprotect(self.base+page+self.span,page,0)==0
  ctypes.memset(self.base+page,0x6d,self.span);ctypes.memset(self.address,fill,size)
 def guard_ok(self):
  return ctypes.string_at(self.base+page,32)==b'\x6d'*32 and ctypes.string_at(self.address+self.size,self.span-self.size-32)==b'\x6d'*(self.span-self.size-32)
 def raw(self):return ctypes.string_at(self.address,self.size)
s=Guarded(len(source),0);o=Guarded(capacity,0xa5);w=Guarded(WORK,0)
ctypes.memmove(s.address,source,len(source));assert libc.mprotect(s.base+page,s.span,mmap.PROT_READ)==0
code=mmap.mmap(-1,len(image),prot=mmap.PROT_READ|mmap.PROT_WRITE);code.write(image);address=ctypes.addressof(ctypes.c_char.from_buffer(code));assert libc.mprotect(address,len(image),mmap.PROT_READ|mmap.PROT_EXEC)==0
entry=ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_void_p,ctypes.c_uint64]*3))(address)
forbidden=lambda:[n for n in sys.modules if n.startswith(('hepta.','generate_hia_'))]
assert not forbidden();started=time.monotonic_ns();returned=entry(s.address,len(source),o.address,capacity,w.address,WORK);elapsed=time.monotonic_ns()-started
assert s.raw()==source and all(x.guard_ok() for x in (s,o,w))
assert returned>>32==0 and 0<returned<=capacity
out=o.raw();assert out[returned:]==b'\xa5'*(capacity-returned)
with Path(request['output']).open('xb') as f:f.write(out)
print(json.dumps(dict(status='returned',result_u64=returned,abi_status=returned>>32,core_u32=returned,image_sha256=sha(image),source_sha256=sha(source),input_sha256=sha(source),input_bytes=len(source),output_sha256=sha(out),source_unchanged=True,buffer_redzones_unchanged=True,output_tail_unchanged=True,input_pages_read_only=True,forbidden_compiler_modules_loaded=forbidden(),native_elapsed_ns=elapsed,transport_profile='bounded-aggregate-packer-v1',limits=dict(input_bytes=MAX_BUNDLE,output_bytes=MAX_BUNDLE,image_bytes=MAX_IMAGE,workspace_bytes=WORK,cpu_seconds=10,address_bytes=512<<20)),sort_keys=True))
