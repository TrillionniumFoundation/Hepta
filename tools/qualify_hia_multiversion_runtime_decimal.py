"""Actual decimal conditional-publication and lock-consistent BG snapshot gates.
The privileged counter seeds use the real immutable value owner. No caller
supplies a proof, artifact observation, successor identity or success outcome.
"""
from pathlib import Path
import os,sys,runpy,ctypes as C,struct,mmap,time,json,hashlib,threading,concurrent.futures,argparse
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z')
V=B/'native-multiversion-source';sys.path.insert(0,str(V))
x=runpy.run_path(str(B/'qualify-runtime-effects-actual-v2.py'))
Runtime=x['Runtime'];scalar_program=x['scalar_program'];rawdoc=x['rawdoc'];sealed=x['sealed'];get=x['get'];NONE=x['NONE'];original_view=x['original_view']
from hepta.hia_multiversion import ScalarMultiversionRuntime,MultiversionRejected,PublicationCancellation
from tools import generate_hia_multiversion_runtime_identity_packer as IP
sha=lambda b:hashlib.sha256(b).hexdigest()
libc=C.CDLL(None);libc.free.argtypes=[C.c_void_p];libc.free.restype=None
class Token:
 def __init__(self,lib):
  self.w=C.create_string_buffer(512);self.f=lib.hia_mv_future;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32;self.q(0)
 def q(self,op):
  b=struct.pack('<8s7Q',b'HIAMVFQ1',op,0,0,0,0,0,0);s=C.create_string_buffer(b);o=C.create_string_buffer(512)
  rc=self.f(s,len(b),o,len(o),self.w,len(self.w));assert rc==0,(op,rc,o.raw[:80].hex());return o.raw
 @property
 def address(self):return C.addressof(self.w)
def frame(op,gen=b'',epoch=b'',raw=b'',token=0,budget=20_000_000_000):
 h=bytearray(256);struct.pack_into('<8sQ',h,0,b'HIAMVEX2',op);struct.pack_into('<Q',h,72,NONE)
 if op==2:
  struct.pack_into('<QQ',h,56,budget,token);struct.pack_into('<Q',h,80,len(raw));struct.pack_into('<QQ',h,224,len(gen),len(epoch))
 return bytes(h)+raw+gen+epoch
class DecimalRuntime(Runtime):
 def idq(self,op,selector=0,cap=(0,0,0)):
  req=struct.pack('<8s7Q',b'HIAMVID1',op,selector,*cap,0,0);source=C.create_string_buffer(req)
  # QA observation capacity covers this suite's 16,386-digit live values.
  out=C.create_string_buffer(65536 if op==13 else 4096)
  rc=self.id(source,len(req),out,len(out),C.addressof(self.w)+32768,32768)
  assert rc==0 and out.raw[:8]==b'HIAMVIDR' and get(out,8)==0,(op,rc,out.raw[:128].hex())
  return out.raw
 def extended(self,op,gen=b'',epoch=b'',raw=b'',token=0,budget=20_000_000_000,want=0):
  b=frame(op,gen,epoch,raw,token,budget);s=C.create_string_buffer(b);mem=mmap.mmap(-1,40<<20);o=(C.c_char*(40<<20)).from_buffer(mem)
  started=time.monotonic_ns();rc=self.f(s,len(b),o,len(o),self.w,len(self.w));elapsed=time.monotonic_ns()-started
  out=C.string_at(C.addressof(o),1024);ptr,n=get(out,144),get(out,152)
  assert bool(ptr)==bool(n),(op,rc,ptr,n)
  payload=C.string_at(ptr,n) if n else b''
  if ptr:libc.free(ptr)
  streams=[]
  for at in (96,104):
   fd=get(out,at)
   if fd!=NONE:
    nfd=os.fstat(fd).st_size;streams.append(dict(bytes=nfd,sha256=sha(os.pread(fd,nfd,0))));os.close(fd)
  row=dict(op=op,extended=True,rc=rc,error=get(out,16),committed=get(out,24),generation_digits=len(gen),epoch_digits=len(epoch),payload_bytes=len(payload),payload_sha256=sha(payload),elapsed_ns=elapsed,streams=streams)
  with self.row_lock:self.rows.append(row)
  assert s.raw==b+b'\0';del o;mem.close()
  if want is not None:assert rc==want,row
  return out,payload,rc
 def bg(self):
  h,b,rc=self.extended(14)
  assert b[:8]==b'HIAMVBS1' and get(b,40)==len(b) and len(b)==256+get(b,24)+get(b,32)
  assert all(get(b,i)==0 for i in (8,48,56,224,232,240,248))
  gn,en=get(b,24),get(b,32);g=b[256:256+gn];e=b[256+gn:]
  def canonical(t):return t and all(48<=c<=57 for c in t) and (len(t)==1 or t[0]!=48)
  assert canonical(e) and (canonical(g) if get(b,16)&4 else not g),b[:256].hex()
  return dict(flags=get(b,16),generation=g,epoch=e,baseline_core=b[64:96].hex(),baseline_input=b[96:128].hex(),current_core=b[128:160].hex(),current_input=b[160:192].hex(),current_artifact=b[192:224].hex(),bytes=len(b),sha256=sha(b))
 def seed(self,where,digits,ledger_at=None):
  # QA-only initialization of counters that cannot be reached by a short run.
  addr=C.cast(self.id,C.c_void_p).value;hole=IP.OUTER_HOLES['values'];rel=struct.unpack('<i',C.string_at(addr+hole,4))[0]
  vf=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(addr+hole+4+rel)
  def value(op,cap=(0,0,0),data=b''):
   h=bytearray(128);struct.pack_into('<8sQ',h,0,b'HIAMVU01',op);struct.pack_into('<3Q',h,24,*cap);struct.pack_into('<Q',h,72,len(data));b=bytes(h)+data;s=C.create_string_buffer(b);o=C.create_string_buffer(512)
   rc=vf(s,len(b),o,len(o),C.addressof(self.w)+32768+64,256);assert rc==0 and o.raw[:8]==b'HIAMVUR1' and get(o,8)==0,(op,rc,o.raw[:64].hex())
   return tuple(get(o,i) for i in (16,24,32,40))
  at=32768+where;prior=tuple(get(self.w,at+i) for i in (0,8,16));fresh=value(1,data=digits);struct.pack_into('<4Q',self.w,at,*fresh);value(3,prior)
  if ledger_at is not None:
   at=32768+ledger_at;prior=tuple(get(self.w,at+i) for i in (0,8,16));clone=value(2,fresh[:3]);struct.pack_into('<4Q',self.w,at,*clone);value(3,prior)
   struct.pack_into('<Q',self.w,8192+40,get(self.idq(7,64),16))
def main():
 p=argparse.ArgumentParser();p.add_argument('--component',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();D=a.output;D.mkdir(exist_ok=False)
 if hasattr(sys,'set_int_max_str_digits'):sys.set_int_max_str_digits(0)
 paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths]
 lib=C.CDLL(str(a.component));identity=C.CDLL(str(B/'native-multiversion-runtime-identity-v5/identity-component.so'));future=C.CDLL(str(B/'native-multiversion-future-v2/future-component.so'))
 np=D/'native';op=D/'original';np.mkdir(mode=0o700);op.mkdir(mode=0o700)
 rows=[];checks=[];r=DecimalRuntime(lib,identity,files,np,rows);base=scalar_program(None);equiv=scalar_program('bit.xor');orig=ScalarMultiversionRuntime(base,op)
 tokens=[];started=time.monotonic_ns()
 def done(name,**extra):
  checks.append(dict(name=name,**extra));(D/'calls.json').write_text(json.dumps(rows,indent=2)+'\n');(D/'checks.json').write_text(json.dumps(checks,indent=2)+'\n');print('DECIMAL_PASS',name,flush=True)
 def tok():
  n=Token(future);tokens.append(n);return n,PublicationCancellation()
 def compare(name):
  expected=orig.snapshot();actual=r.bg();gen=expected['current_generation']
  assert actual['generation']==(b'' if gen is None else str(gen).encode()) and actual['epoch']==str(expected['selection_epoch']).encode(),(name,actual,gen,expected['selection_epoch'])
  baseline=next((v for v in expected['generations'] if v['baseline']),None);current=next((v for v in expected['generations'] if v['generation']==gen),None)
  assert actual['flags']==int(expected['closed'])+2*bool(baseline)+4*bool(current),(name,actual)
  for prefix,item in [('baseline',baseline),('current',current)]:
   for key,original in [('core','program_sha256'),('input','input_sha256')]:
    assert actual[prefix+'_'+key]==(item[original] if item else '00'*32),(name,prefix,key,actual)
  if current:
   slot=get(r.w,8192+48);gp=get(r.w,65536+slot*16);gw=get(C.string_at(gp,256),32)
   assert actual['current_artifact']==C.string_at(gw+(500<<20)+736,32).hex()
   artifact=next(np.rglob('generation-'+str(gen)+'.so'));assert sha(artifact.read_bytes())==actual['current_artifact']
  else:assert actual['current_artifact']=='00'*32
  assert original_view(orig)==r.view(),name
  done(name,actual={k:(v.decode() if isinstance(v,bytes) and len(v)<160 else {'digits':len(v),'sha256':sha(v)} if isinstance(v,bytes) else v) for k,v in actual.items()})
 r.q(0,raw=rawdoc(base));compare('initial-actual-snapshot')
 n,t=tok();out,pay,rc=r.extended(2,b'0',b'0',rawdoc(equiv),n.address);res=orig.publish_if_current(equiv,0,expected_epoch=0,max_prepare_ns=20_000_000_000,cancellation=t)
 assert get(n.w,64)==2 and t.committed() and get(out,24)==1;compare('actual-conditional-commit')
 for name,g,e in [('stale-generation',b'0',b'1'),('stale-epoch',b'1',b'0'),('u64-plus-stale',str(1<<64).encode(),b'1'),('u128-plus-stale',b'1',str(1<<128).encode())]:
  n,t=tok()
  try:orig.publish_if_current(base,int(g),expected_epoch=int(e),max_prepare_ns=20_000_000_000,cancellation=t)
  except MultiversionRejected as ex:assert str(ex)=='E_HIA_MULTIVERSION: stale generation or selection epoch'
  else:raise AssertionError(name)
  r.extended(2,g,e,rawdoc(base),n.address,want=19);compare(name)
 orig.rollback();r.q(7);compare('actual-rollback-ABA-epoch')
 n,t=tok()
 try:orig.publish_if_current(base,0,expected_epoch=0,max_prepare_ns=20_000_000_000,cancellation=t)
 except MultiversionRejected as ex:assert 'stale generation or selection epoch' in str(ex)
 else:raise AssertionError('rollback ABA')
 r.extended(2,b'0',b'0',rawdoc(base),n.address,want=19);compare('rollback-ABA-rejected')
 n,t=tok();n.q(8);assert t.cancel()
 try:orig.publish_if_current(base,0,expected_epoch=2,max_prepare_ns=20_000_000_000,cancellation=t)
 except MultiversionRejected as ex:assert str(ex)=='E_HIA_MULTIVERSION: publication cancelled before selection'
 else:raise AssertionError('cancel')
 r.extended(2,b'0',b'2',rawdoc(base),n.address,want=21);compare('cancel-after-actual-expected-match')
 n,t=tok()
 try:orig.publish_if_current(base,0,expected_epoch=2,max_prepare_ns=0,cancellation=t)
 except MultiversionRejected as ex:assert str(ex)=='E_HIA_MULTIVERSION: actual preparation budget exceeded before selection'
 else:raise AssertionError('budget')
 r.extended(2,b'0',b'2',rawdoc(base),n.address,budget=0,want=20);compare('zero-budget-after-actual-expected-match')
 # Existing committed token must be observed only after snapshot/budget checks.
 n=tokens[0];t=PublicationCancellation();t._committed=True
 try:orig.publish_if_current(base,0,expected_epoch=2,max_prepare_ns=20_000_000_000,cancellation=t)
 except MultiversionRejected as ex:assert str(ex)=='E_HIA_MULTIVERSION: publication cancellation token was already committed'
 else:raise AssertionError('committed')
 r.extended(2,b'0',b'2',rawdoc(base),n.address,want=22);compare('actual-token-committed')
 big=(1<<128)+17;r.seed(320,str(big).encode());r.seed(352,str(big).encode(),10240);orig._next=big;orig._epoch=big
 compare('beyond-u128-actual-object-seeds')
 n,t=tok();r.extended(2,b'0',str(big).encode(),rawdoc(base),n.address);orig.publish_if_current(base,0,expected_epoch=big,max_prepare_ns=20_000_000_000,cancellation=t)
 compare('beyond-u128-native-build-file-and-commit')
 # Long epoch does not create a filesystem component; both owners use the same full integer.
 long=b'9'*16385;r.seed(352,long,10240);orig._epoch=int(long);compare('long-epoch-owned-snapshot')
 n,t=tok();r.extended(2,str(big).encode(),long,rawdoc(equiv),n.address);orig.publish_if_current(equiv,big,expected_epoch=int(long),max_prepare_ns=20_000_000_000,cancellation=t)
 compare('long-epoch-full-compare-and-carry')
 # Actual concurrent selection and snapshot: no mixed generation/epoch/header identities.
 orig.close();r.q(8);compare('closed-snapshot-owned-by-caller')
 n,t=tok()
 try:orig.publish_if_current(base,999,expected_epoch=0,max_prepare_ns=0,cancellation=t)
 except MultiversionRejected as ex:assert str(ex)=='E_HIA_MULTIVERSION: runtime is closed'
 else:raise AssertionError('closed')
 r.extended(2,b'999',b'0',rawdoc(base),n.address,budget=0,want=18);done('closed-priority-before-decimal-mismatch')
 r.q(13);assert not list(np.iterdir()) and not list(op.iterdir())
 for n in tokens:n.q(10)
 for fd,b in files:os.close(fd)
 report=dict(schema='hepta.hia.multiversion-runtime-decimal-projection.v1',whole_native_runtime=False,passed=len(checks),failed=0,actual_calls=len(rows),image_sha256=sha(a.component.read_bytes()),elapsed_ns=time.monotonic_ns()-started,actual_original_runtime=True,projection_is_full_public_snapshot=False,checks=checks,calls=rows)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('DECIMAL_QUALIFIED',len(checks),len(rows),flush=True)
if __name__=='__main__':main()
