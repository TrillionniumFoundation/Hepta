"""Disposable fixed-ABI observation; no project modules or JSON semantic provider."""
from pathlib import Path
import ctypes,hashlib,json,mmap,os,resource,sys,time
request_path=Path(sys.argv[1]);raw=request_path.read_bytes()
assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
req=json.loads(raw);assert req['schema']=='hia.cli-discovery.native-request.v1'
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
resource.setrlimit(resource.RLIMIT_FSIZE,(16<<20,16<<20))
resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0
image=Path(req['image']).read_bytes()
assert len(image)<=1048576 and hashlib.sha256(image).hexdigest()==req['image_sha256']
code=mmap.mmap(-1,len(image),prot=mmap.PROT_READ|mmap.PROT_WRITE);code[:]=image
address=ctypes.addressof(ctypes.c_char.from_buffer(code))
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
assert libc.mprotect(address,len(image),mmap.PROT_READ|mmap.PROT_EXEC)==0
entry=ctypes.CFUNCTYPE(ctypes.c_uint32,*([ctypes.c_void_p,ctypes.c_uint64]*3))(address)
files=[];maps=[];arguments=[]
for item in req['buffers']:
    path=Path(item['path']);before=path.read_bytes()
    assert len(before)==item['bytes'] and hashlib.sha256(before).hexdigest()==item['sha256']
    assert type(item['extent'])is int and 0<=item['extent']<=1048576
    stream=path.open('r+b');files.append(stream)
    mapped=mmap.mmap(stream.fileno(),len(before));maps.append(mapped)
    arguments.extend([ctypes.addressof(ctypes.c_char.from_buffer(mapped))+64,item['extent']])
started=time.monotonic_ns();result=entry(*arguments);elapsed=time.monotonic_ns()-started
for mapped in maps:mapped.flush()
report={'schema':'hia.cli-discovery.native-observation.v1','status':'returned','result':result,
        'image_sha256':req['image_sha256'],'request_sha256':hashlib.sha256(raw).hexdigest(),
        'actual_native_entries':1,'elapsed_ns':elapsed,
        'forbidden_project_modules_loaded':[name for name in sys.modules if name=='hepta' or name.startswith('hepta.') or name=='tools' or name.startswith('tools.')],
        'observation_only':True,'cold_qualification':False,'whole_cli':False}
Path(req['report']).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')

