from pathlib import Path
import runpy,json,ctypes as C,os,threading,concurrent.futures,time,hashlib
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');x=runpy.run_path(str(Path(__file__).with_name('qualify_hia_multiversion_runtime_effects.py')));Runtime=x['Runtime'];scalar_program=x['scalar_program'];rawdoc=x['rawdoc'];sealed=x['sealed'];get=x['get'];NONE=x['NONE']
D=B/'native-multiversion-runtime-effects-concurrency-v3';D.mkdir(exist_ok=False);P=D/'parent';P.mkdir(mode=0o700)
paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];lib=C.CDLL(str(B/'native-multiversion-runtime-effects-v7/runtime-effects.so'));identity=C.CDLL(str(B/'native-multiversion-runtime-identity-v5/identity-component.so'))
rows=[];r=Runtime(lib,identity,files,P,rows);start=time.monotonic_ns();r.q(0,raw=rawdoc(scalar_program(None)))
baselinefds=set(os.listdir('/proc/self/fd'));leases=[r.lease() for _ in range(300)]
v=r.view();assert v['generations'][0]['active_leases']==300,v
for lease in leases:r.closelease(lease,drop=False)
assert r.view()['generations'][0]['active_leases']==0
barrier=threading.Barrier(8)
def mixed(k):
 barrier.wait()
 if k<4:
  for lease in leases[k::4]:r.q(12,lease=lease)
 else:
  for i in range(80):
   lease=r.lease();assert r.call(lease,k*1000+i)==k*1000+i;r.closelease(lease)
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(mixed,range(8)))
assert get(r.w,280)==0
v=r.view();assert v['generations'][0]['active_leases']==0,v
assert set(os.listdir('/proc/self/fd'))==baselinefds
lease=r.lease();gate=threading.Barrier(6);calls=[];lock=threading.Lock()
def racing(k):
 gate.wait()
 if k==5:
  r.q(5,lease=lease);return
 local=[]
 for i in range(100):
  out,val,rc=r.q(4,lease=lease,fn=b'calculate',args=b'[17]',want=None)
  assert rc in (0,32),(rc,local)
  if rc==0:assert val==b'17'
  local.append(rc)
 with lock:calls.extend(local)
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:list(pool.map(racing,range(6)))
assert len(calls)==500 and get(C.string_at(lease[0],256),136)==2
r.q(4,lease=lease,fn=b'calculate',args=b'[17]',want=32)
r.q(6,lease=lease);r.q(12,lease=lease)
assert get(r.w,280)==0 and r.view()['generations'][0]['active_leases']==0
r.q(8);r.q(13);assert not list(P.iterdir())
for fd,b in files:os.close(fd)
report=dict(schema='hepta.hia.multiversion-runtime-effects-concurrency.v1',whole_native_runtime=False,passed=3,failed=0,actual_calls=len(rows),elapsed_ns=time.monotonic_ns()-start,retained_reference_growth=300,registry_threads=8,same_lease_threads=6,same_lease_calls=500,accepted=calls.count(0),closed_refusals=calls.count(32),actual_dlclose_path_fd=True,image_sha256=hashlib.sha256((B/'native-multiversion-runtime-effects-v7/runtime-effects.so').read_bytes()).hexdigest(),cases=rows)
(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('EFFECTS_CONCURRENCY_PASS',len(rows),report['elapsed_ns'],flush=True)
