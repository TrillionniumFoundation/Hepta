from pathlib import Path
import os,sys,runpy,ctypes as C,struct,mmap,time,json,hashlib,threading,concurrent.futures
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');V=B/'native-multiversion-source';sys.path.insert(0,str(V))
q=runpy.run_path(str(B/'qualify-runtime-decimal-view-v2.py'));Runtime=q['DecimalRuntime'];Token=q['Token'];sealed=q['sealed'];rawdoc=q['rawdoc'];scalar_program=q['scalar_program'];get=q['get'];NONE=q['NONE'];frame=q['frame'];sha=q['sha']
D=B/'native-multiversion-runtime-decimal-concurrency-v1';D.mkdir(exist_ok=False)
paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths]
image=B/'native-multiversion-runtime-effects-v9/runtime-effects.so';lib=C.CDLL(str(image));identity=C.CDLL(str(B/'native-multiversion-runtime-identity-v5/identity-component.so'));future=C.CDLL(str(B/'native-multiversion-future-v2/future-component.so'))
rows=[];checks=[];base=rawdoc(scalar_program(None));other=rawdoc(scalar_program('bit.xor'));began=time.monotonic_ns()
def make(name):
 p=D/name;p.mkdir(mode=0o700);r=Runtime(lib,identity,files,p,rows);r.q(0,raw=base);return r,p
def finish(r,p):
 r.q(8);r.q(13);assert not list(p.iterdir())
def done(name,**fields):
 checks.append(dict(name=name,**fields));(D/'progress.json').write_text(json.dumps(checks,indent=2)+'\n');print('DECIMAL_CONCURRENCY_PASS',name,flush=True)
r,p=make('queued-writer');n=Token(future);result=[]
def first():r.q(1,raw=other)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 f=pool.submit(first)
 until=time.monotonic()+10
 while get(r.w,256)!=1 and not f.done() and time.monotonic()<until:time.sleep(.0005)
 assert get(r.w,256)==1 and not f.done(),'writer did not enter real preparation'
 waiting=pool.submit(r.extended,2,b'1',b'1',base,n.address)
 f.result();out,payload,rc=waiting.result();assert get(out,24)==1 and get(n.w,64)==2
v=r.bg();assert v['generation']==v['epoch']==b'2',v
finish(r,p);n.q(10);done('expected-values-observed-after-queued-writer',snapshot_sha256=v['sha256'])
r,p=make('cas-race');ns=[Token(future),Token(future)];barrier=threading.Barrier(2)
def publish(k):
 barrier.wait();return r.extended(2,b'0',b'0',other,ns[k].address,want=None)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:outcomes=list(pool.map(publish,range(2)))
assert sorted(x[2] for x in outcomes)==[0,19] and sorted(get(n.w,64) for n in ns)==[0,2]
assert r.bg()['epoch']==b'1'
finish(r,p)
for n in ns:n.q(10)
done('same-snapshot-two-actual-writers-one-commit',statuses=[x[2] for x in outcomes])
r,p=make('snapshots-during-publication');initial=r.bg();allowed={initial['current_core']};# Compute second program's identity through an actual first publication.
r.q(1,raw=other);second=r.bg();allowed.add(second['current_core'])
records=[];lock=threading.Lock();barrier=threading.Barrier(5)
def worker(k):
 barrier.wait()
 if k==4:
  for i in range(4):r.q(1,raw=base if i%2==0 else other)
  return
 local=[]
 for i in range(100):
  v=r.bg();assert v['flags']==6 and v['generation']==v['epoch'] and v['current_core'] in allowed
  assert v['baseline_core']==initial['baseline_core'] and v['baseline_input']==initial['baseline_input']
  assert v['current_input']==v['current_core'] and v['current_artifact']!='00'*32
  local.append(dict(generation=v['generation'].decode(),epoch=v['epoch'].decode(),sha256=v['sha256']))
 with lock:records.extend(local)
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:list(pool.map(worker,range(5)))
assert len(records)==400 and r.bg()['generation']==b'5'
finish(r,p);done('four-readers-during-actual-build-selection-retirement',snapshots=400,observations=records)
# All private malformed decimal/extent requests are refused before mutation.
r,p=make('guards');token=Token(future);valid=frame(2,b'0',b'0',base,token.address)
mem=mmap.mmap(-1,40<<20);o=(C.c_char*(40<<20)).from_buffer(mem);guardrows=[]
def patch(b,at,n):
 b=bytearray(b);struct.pack_into('<Q',b,at,n);return bytes(b)
def reject(label,b):
 s=C.create_string_buffer(b);C.memset(o,0xa5,32768);struct.pack_into('<Q',o,128,0);pre=bytes(o[:32768]);prior=r.w.raw
 rc=r.f(s,len(b),o,len(o),r.w,len(r.w))
 assert rc==0xfffffffd and bytes(o[:32768])==pre and r.w.raw==prior and s.raw==b+b'\0',(label,rc)
 guardrows.append(dict(name=label,bytes=len(b),sha256=sha(b)))
for g in (b'',b'00',b'01',b'-1',b'+1',b' 1',b'1 ',b'1.0',b'\0',b'1e2',b'\xff',b'9'*4096+b'x'):
 reject('bad-gen-'+str(len(guardrows)),frame(2,g,b'0',base,token.address))
for e in (b'',b'00',b'-1',b'1\n',b'1e0',b'\xff'):
 reject('bad-epoch-'+str(len(guardrows)),frame(2,b'0',e,base,token.address))
for at in (224,232):
 for n in (0,3,2**63,2**64-1):reject('bad-extent-'+str(at)+'-'+str(n),patch(valid,at,n))
for at in (40,48,240,248):reject('reserved-'+str(at),patch(valid,at,1))
for op in list(range(15))+[2**32,2**64-1]:
 if op not in (2,14):reject('unknown-op-'+str(op),patch(frame(14),8,op))
reject('snapshot-tail',frame(14)+b'0')
for at in (80,88,96,104,112,224,232):reject('snapshot-extent-'+str(at),patch(frame(14),at,1))
for n in (0,1,7,15,63,127,255):reject('short-'+str(n),valid[:n])
reject('old-private-tail',b'HIAMVEX1'+valid[8:])
del o;mem.close();finish(r,p);token.q(10);done('private-atomic-decimal-and-extent-refusals',gates=len(guardrows),records=guardrows)
for fd,b in files:os.close(fd)
report=dict(schema='hepta.hia.multiversion-runtime-decimal-concurrency.v1',whole_native_runtime=False,passed=len(checks),failed=0,actual_calls=len(rows),image_sha256=sha(image.read_bytes()),elapsed_ns=time.monotonic_ns()-began,cases=checks,calls=rows)
(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('DECIMAL_CONCURRENCY_QUALIFIED',len(checks),len(rows),flush=True)
