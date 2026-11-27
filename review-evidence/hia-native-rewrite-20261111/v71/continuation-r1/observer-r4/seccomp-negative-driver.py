from pathlib import Path
from hashlib import sha256
import ctypes,fcntl,json,os,struct,subprocess,sys,time,traceback
BASE=Path('/tmp/hia-linked-observer-local-v71-20261112-r1')
ROOT=BASE/'source-r4'; OUT=BASE/'evidence/r4-seccomp-errno-r1'
OUT.mkdir(mode=0o700,exist_ok=False);os.umask(0o077)
sys.path.insert(0,str(ROOT))
from tools import hia_selfhost_linked_native_observer as native
observer=BASE/'evidence/r4-component-r1/actual/candidate/build/linked-native-observer.elf'
target=BASE/'evidence/r4-component-r1/actual/candidate/seals-error/not-entered.so'
def digest(data):return sha256(data).hexdigest()
def record(path):
 raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':digest(raw)}
def write(name,value):
 raw=value if isinstance(value,bytes) else (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
 with (OUT/name).open('xb') as f:f.write(raw)
class Filter(ctypes.Structure):
 _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint32)]
class Program(ctypes.Structure):
 _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
instructions=((0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
 (0x20,0,0,0),(0x15,0,3,72),(0x20,0,0,24),(0x15,0,1,1034),
 (0x06,0,0,0x00050001),(0x06,0,0,0x7fff0000))
code=(Filter*len(instructions))(*(Filter(*row) for row in instructions))
program=Program(len(code),code)
libc=ctypes.CDLL(None,use_errno=True)
prctl=libc.prctl;prctl.restype=ctypes.c_int
prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_ulong]
def install():
 if prctl(38,1,None,0,0)!=0:raise OSError(ctypes.get_errno(),'PR_SET_NO_NEW_PRIVS')
 if prctl(22,2,ctypes.byref(program),0,0)!=0:raise OSError(ctypes.get_errno(),'PR_SET_SECCOMP')
report={'schema':'hia.linked-observer.seccomp-errno-diagnostic.v1','status':'HOLD',
 'scope':'new restricted child fault-injection; original ptrace refusal retained',
 'original_remote18':'UNKNOWN','product_source_changed':False,
 'filter':'x86_64 only; fcntl syscall72 command1034 -> errno EPERM; every other x86_64 syscall inherits existing kernel policy',
 'BPF':list(instructions),'filter_bytes':bytes(code).hex(),'python':sys.version}
before={str(p):record(p) for p in (observer,target,ROOT/'tools/hia_selfhost_linked_native_observer.py')}
fds_before=len(list(Path('/proc/self/fd').iterdir()))
began=time.monotonic_ns()
try:
 probe=os.memfd_create('hia-seals-errno-probe',os.MFD_ALLOW_SEALING)
 try:
  fcntl.fcntl(probe,1033,15)
  child='import fcntl,json,sys\ntry:r={"value":fcntl.fcntl(int(sys.argv[1]),1034)}\nexcept OSError as e:r={"errno":e.errno}\nprint(json.dumps(r))'
  values=[]
  for name,setup in (('baseline',None),('restricted',install)):
   result=subprocess.run([sys.executable,'-I','-S','-B','-c',child,str(probe)],capture_output=True,
                         pass_fds=(probe,),preexec_fn=setup,timeout=20,cwd=OUT)
   write(name+'.stdout',result.stdout);write(name+'.stderr',result.stderr)
   values.append({'name':name,'returncode':result.returncode,'observation':json.loads(result.stdout)})
  report['actual_fcntl_controls']=values
  assert values[0]['returncode']==values[1]['returncode']==0
  assert values[0]['observation']=={'value':15} and values[1]['observation']=={'errno':1}
 finally:os.close(probe)
 original=observer.read_bytes()
 prefix=bytes.fromhex('be0a040000b8480000000f05')
 assert original.count(prefix)==1
 at=original.index(prefix)+len(prefix)
 assert original[at:at+5]==bytes.fromhex('4885c00f88')
 mutant=OUT/'sensitive-removed-signed-error-guard.elf'
 raw=original[:at]+b'\x90'*9+original[at+9:]
 with mutant.open('xb') as f:f.write(raw)
 mutant.chmod(0o700)
 report['sensitivity_mutation']={'original':record(observer),'mutant':record(mutant),'offset':at,
   'removed_hex':original[at:at+9].hex(),'replacement_hex':(b'\x90'*9).hex()}
 outcomes=[]
 for name,image in (('guarded',observer),('sensitive-negative',mutant)):
  folder=OUT/name;folder.mkdir(mode=0o700)
  with native.output_snapshot(os.sysconf('SC_PAGE_SIZE')) as snapshot:
   payload=native._linked_frame(target.read_bytes(),b'',os.sysconf('SC_PAGE_SIZE'),0,0,None,snapshot)
   result=subprocess.run([str(image)],input=payload,capture_output=True,pass_fds=(snapshot,),
                         preexec_fn=install,timeout=20,cwd=folder)
   (folder/'stdout.raw').write_bytes(result.stdout);(folder/'stderr.raw').write_bytes(result.stderr)
   snap=native.read_output_snapshot(snapshot,os.sysconf('SC_PAGE_SIZE'))
  event=(folder/'events.bin').read_bytes() if (folder/'events.bin').exists() else None
  outcomes.append({'name':name,'returncode':result.returncode,'stdout_bytes':len(result.stdout),
    'stdout_sha256':digest(result.stdout),'stderr_bytes':len(result.stderr),
    'events':None if event is None else event.decode(),'snapshot_available':snap is not None})
 report['actual_observer_controls']=outcomes
 assert outcomes[0]['returncode']==4 and outcomes[0]['stdout_bytes']==0 and outcomes[0]['events'] is None and not outcomes[0]['snapshot_available']
 assert outcomes[1]['returncode']==0 and outcomes[1]['events']=='CFD' and outcomes[1]['snapshot_available']
 report['status']='ACTUAL_KERNEL_ERRNO_AND_SENSITIVE_GUARD_PASS'
except BaseException as error:
 report['error']={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
finally:
 after={str(p):record(p) for p in (observer,target,ROOT/'tools/hia_selfhost_linked_native_observer.py')}
 report['source_and_images_unchanged']=after==before
 report['descriptor_count_before']=fds_before;report['descriptor_count_after']=len(list(Path('/proc/self/fd').iterdir()))
 report['descriptor_count_unchanged']=report['descriptor_count_before']==report['descriptor_count_after']
 report['elapsed_ns']=time.monotonic_ns()-began
 if not report['source_and_images_unchanged'] or not report['descriptor_count_unchanged']:report['status']='HOLD'
 write('report.json',report)
print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='ACTUAL_KERNEL_ERRNO_AND_SENSITIVE_GUARD_PASS' else 1)
