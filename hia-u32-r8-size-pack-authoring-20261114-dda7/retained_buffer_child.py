"""Disposable observer only; compiled HIA contains the actual fixed syscalls."""
from pathlib import Path
import ctypes,hashlib,json,mmap,os,resource,signal,sys,time
request_path=Path(sys.argv[1]);raw=request_path.read_bytes();assert hashlib.sha256(raw).hexdigest()==sys.argv[2];req=json.loads(raw)
assert req['schema']=='hia.linux-stdio.native-request.v1'
resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(10,10));resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20));resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20));resource.setrlimit(resource.RLIMIT_FSIZE,(16<<20,16<<20));resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
libc=ctypes.CDLL(None,use_errno=True);libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong];libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0
image=Path(req['image']).read_bytes();assert len(image)<=1048576 and hashlib.sha256(image).hexdigest()==req['image_sha256']
code=mmap.mmap(-1,len(image),prot=mmap.PROT_READ|mmap.PROT_WRITE);code[:]=image;address=ctypes.addressof(ctypes.c_char.from_buffer(code))
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int;assert libc.mprotect(address,len(image),mmap.PROT_READ|mmap.PROT_EXEC)==0
entry=ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_void_p,ctypes.c_uint64]*3))(address)
handles=[];maps=[];buffers=[];extents=[]
for row in req['buffers']:
 path=Path(row['path']);before=path.read_bytes();assert hashlib.sha256(before).hexdigest()==row['sha256'] and len(before)==row['bytes'];assert type(row['extent'])is int and 0<=row['extent']<=1048576
 f=path.open('r+b');handles.append(f);mapping=mmap.mmap(f.fileno(),len(before));maps.append(mapping);buffers.append(ctypes.addressof(ctypes.c_char.from_buffer(mapping))+64);extents.append(row['extent'])
mode=req['mode'];signal.signal(signal.SIGPIPE,signal.SIG_IGN)
owned=[]
if mode=='closed-stdin':os.close(0)
elif mode=='closed-stdout':os.close(1)
elif mode=='interrupt-read':
 r,w=os.pipe();os.dup2(r,0);os.close(r);owned.append(w)
 signal.signal(signal.SIGALRM,lambda *_:None);signal.siginterrupt(signal.SIGALRM,True);signal.setitimer(signal.ITIMER_REAL,.03)
elif mode=='signal-pipe':
 r,w=os.pipe();os.close(r);os.dup2(w,1);os.close(w);signal.signal(signal.SIGPIPE,signal.SIG_DFL)
elif mode!='ordinary':raise ValueError(mode)
started=time.monotonic_ns();returned=entry(buffers[0],extents[0],buffers[1],extents[1],buffers[2],extents[2]);elapsed=time.monotonic_ns()-started
signal.setitimer(signal.ITIMER_REAL,0)
for fd in owned:os.close(fd)
for mapping in maps:mapping.flush()
report={'schema':'hia.linux-stdio.native-observation.v1','status':'returned','result_u64':returned,'native_elapsed_ns':elapsed,'image_sha256':req['image_sha256'],'request_sha256':hashlib.sha256(raw).hexdigest(),'limits':{'wall_seconds':20,'cpu_seconds':10,'source_output_workspace_bytes':1048576,'address_bytes':256<<20,'stack_bytes':8<<20,'core_dumpable':False},'forbidden_modules_loaded':[name for name in sys.modules if name=='hepta' or name.startswith('hepta.') or name=='tools' or name.startswith('tools.')],'matched_cold':False,'whole':False}
Path(req['report']).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
