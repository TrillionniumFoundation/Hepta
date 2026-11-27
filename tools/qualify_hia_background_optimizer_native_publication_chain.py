"""Actual installed rank proof, conditional publication and complete retirement."""
from pathlib import Path
import os,sys,ctypes as C,struct,json,hashlib,signal,argparse,shutil,fcntl
parser=argparse.ArgumentParser()
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--evidence-root',type=Path,required=True)
parser.add_argument('--reference-root',type=Path,required=True)
args=parser.parse_args()
B=Path(__file__).resolve().parents[1];R=args.reference_root;E=args.evidence_root
D=args.output;D.mkdir(exist_ok=False);signal.alarm(400)
install=D/'install'
shutil.copytree(args.root.parent,install,symlinks=True,copy_function=os.link)
path=install/args.root.name
path.unlink();shutil.copy2(args.root,path)
assert hashlib.sha256(path.read_bytes()).digest()==hashlib.sha256(args.root.read_bytes()).digest()
def actual_fd_rows():
 rows={}
 for p in Path('/proc/self/fd').iterdir():
  try:rows[p.name]=os.readlink(p)
  except FileNotFoundError:pass
 return rows
os.environ['Z3_LIBRARY_PATH']=str(E/'z3-qa-runtime')
os.chdir(B);sys.path[:0]=[str(B),str(R),str(E/'z3-qa-runtime/python')]
import tools;tools.__path__=[str(B/'tools'),str(R/'tools')]
import importlib.abc,importlib.machinery
class FrozenTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname.startswith('tools.'):
            return importlib.machinery.PathFinder.find_spec(fullname,[str(B/'tools'),str(R/'tools')])
sys.meta_path.insert(0,FrozenTools())
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_runtime_global as globalqa
from tools import qualify_hia_native_runtime_resources as resources
tools.__path__=[str(B/'tools'),str(R/'tools')]

n=q.Owner(path);n.initialize();g=globalqa.Global(n)
initial_fd_rows=actual_fd_rows()
print('OWNER_INIT',{'state':q.get(n.context,80),'active':q.get(n.context,72)},flush=True)
r=g.call(0);print('GLOBAL_INIT',r,flush=True);resources.ready(r)
sc=globalqa.sidecar(n,0);print('SIDECAR_INIT',sc,flush=True);assert sc['status']==0 and sc['state']==2
fn=n.lib.hia_generation_background_bind;fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
rows=[]
def call(op):
 raw=struct.pack('<16Q',int.from_bytes(b'HIAGBNQ1','little'),op,*([0]*14))
 s=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*(3<<20),3<<20)
 rc=int(fn(s,len(raw),out,len(out),n.context,2048))
 head=[q.get(out,off)for off in range(0,128,8)]
 r=dict(op=op,rc=rc,magic=out.raw[:8].decode('ascii','replace'),head=head,root_active=q.get(n.context,72),sidecar_active=q.get(n.context,1208),mask=q.get(n.context,680),
 metadata=[q.get(out,off)for off in range(2097152,2097720,8)])
 gp=q.get(n.context,1088)
 if gp:
  ar=C.string_at(gp+7340544,512);r['anchor']=[q.get(ar,off)for off in range(0,512,8)]
  if q.get(ar,32):r['loader_prefix']=[q.get(C.string_at(q.get(ar,32)+4096,512),off)for off in range(0,512,8)]
 r['child_head']=[q.get(out,off)for off in range(2113536,2113792,8)]
 r['wire_head']=[q.get(out,off)for off in range(2101248,2101504,8)]
 rows.append(r);(D/'calls.json').write_text(json.dumps(rows,indent=2)+'\n');print('BG_BINDER_CALL',json.dumps(r),flush=True)
 assert s.raw==raw+b'\0'and rc==0 and out.raw[:8]==b'HIAGBNR1',(rc,out.raw[:128].hex())
 return out.raw

a=call(0);assert q.get(a,8)==0 and q.get(a,16)==2 and q.get(a,80)==254
proof_anchor=C.string_at(q.get(n.context,1088)+7340544,512)
proof_fd=q.get(proof_anchor,424);st=os.fstat(proof_fd)
proof_pin=dict(bytes=st.st_size,sha256=hashlib.sha256(os.pread(proof_fd,st.st_size,0)).hexdigest())
assert proof_pin==dict(bytes=16159172,sha256='744900be77472942723f0f9b3d640825cb48a75ae5bcb4a166092a0ddf0dc4f6')
assert st.st_nlink==0 and st.st_mode&0o777==0o500 and fcntl.fcntl(proof_fd,1034)==15
scalar_fd=q.get(n.context,96)
assert proof_fd!=scalar_fd and hashlib.sha256(os.pread(scalar_fd,os.fstat(scalar_fd).st_size,0)).hexdigest()=='3fc158954dbecbde001d51065347a4e10e728f3c503816525da853babf2ffb3a'
installed_proof=install/'components/hia-rank-public-proof.bin'
installed_proof.rename(installed_proof.with_name('hia-rank-public-proof-held.bin'))
installed_proof.write_bytes(b'changed installation pathname after native sealed admission\n')
installed_proof.chmod(0o500)
assert hashlib.sha256(os.pread(proof_fd,st.st_size,0)).hexdigest()==proof_pin['sha256']
from types import SimpleNamespace
from tools import qualify_hia_result_value_invocations as inv
from tools import qualify_hia_generation_future_managed_binding as binding
from tools.qualify_hia_background_public_constructor import make
from hepta.hia_program import verify_program
from hepta.hia_background_optimizer import BackgroundOptimizer
from hepta.hia_multiversion import ScalarMultiversionRuntime
bound=SimpleNamespace(owner=n,value=q.get(n.context,40))
engine=inv.Engine(bound);v=inv.Values(engine)
assert C.addressof(engine.context)==C.addressof(n.context)+512
cap_rows=[]
def checkpoint(name):
 rr=v.raw(47);row=dict(name=name,count=q.get(rr,48),queue=q.get(engine.context,176),continuations=q.get(engine.context,184),held=len(v.held))
 cap_rows.append(row);(D/'cap-census.json').write_text(json.dumps(cap_rows,indent=2)+'\n');print('REAL_CAP_CENSUS',row,flush=True)
 return row['count']
initial_caps=checkpoint('bound-no-Runtime-inputs')
gp=q.get(n.context,1088);anchor=(C.c_char*512).from_address(gp+7340544)
bgctx=(C.c_char*512).from_address(q.get(anchor,32))
assert q.get(bgctx,32)==q.get(n.context,40)and q.get(bgctx,40)==C.addressof(engine.context)
public_rows=[]
def public(op,caps=(),want=0):
 raw=bytearray(192);raw[:8]=b'HIABGPQ1';struct.pack_into('<Q',raw,8,op)
 for i,cap_ in enumerate(caps):struct.pack_into('<3Q',raw,24+24*i,*cap_)
 s=C.create_string_buffer(bytes(raw),192);out=C.create_string_buffer(b'\xa5'*((3<<20)+32),(3<<20)+32)
 rc=int(fn(s,192,out,3<<20,n.context,2048));r=out.raw[:2<<20]
 row=dict(op=op,rc=rc,status=q.get(r,8),kind=q.get(r,16),cap=struct.unpack_from('<3Q',r,24),
  delivered=q.get(r,48),known=q.get(r,56),map=q.get(r,64),queue=q.get(r,72),unknown=q.get(r,80),
  cleanup=q.get(r,88),detail=q.get(r,96),raw_owned=q.get(r,104),error_format=q.get(r,112),error_n=q.get(r,120))
 public_rows.append(row);(D/'public-calls.json').write_text(json.dumps(public_rows,indent=2)+'\n')
 print('ACTUAL_CANONICAL_BG_CALL',row,flush=True)
 if rc!=0 or q.get(r,8)!=want or q.get(r,80)!=0:
  (D/('failure-op'+str(op)+'.json')).write_text(json.dumps(dict(row=row,
    outer=[q.get(r,i)for i in range(0,640,8)],raw=[q.get(r,65536+i)for i in range(0,256,8)],
    method=[q.get(r,98304+i)for i in range(0,256,8)],
    child=[q.get(r,163840+i)for i in range(0,512,8)],
    owner=[q.get(n.context,i)for i in range(512,768,8)],
    global_=[q.get(bgctx,i)for i in range(0,512,8)]),indent=2)+'\n')
 assert rc==0 and r[:8]==b'HIABGPR1'and s.raw==bytes(raw)and out.raw[3<<20:]==b'\xa5'*32
 assert q.get(r,8)==want and q.get(r,56)==1 and q.get(r,80)==0,row
 return r
def snapshot(bg):
 r=public(1,[bg]);assert q.get(r,48)==1 and q.get(r,16)==1
 c=v.keep(r);out=v.python_value(c);v.drop(c);return out
borrow=g.call(2);resources.ready(borrow);assert borrow['consumed']==1
files=[(q.get(n.context,88+8*i),(E/'shared-custody'/name).read_bytes())for i,name in enumerate(('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'))]
carrier=q.Carrier(n);parent=D/'native-runtime';parent.mkdir()
raw_runtime=q.old.create(carrier,files,parent)
checkpoint('raw-Runtime-created')
cloned=carrier.q(2,raw_runtime);assert cloned['row']['kind']==1
captured=v.raw(48,arg0=1,tail=struct.pack('<3Q',*cloned['cap']))
assert (q.get(captured,80),q.get(captured,88),q.get(captured,96))==(0,1,1)
runtime=v.keep(captured);baseline=q.old.scalar_program(None)
initial_runtime_snapshot=json.loads(q.old.release_detached(carrier.q(4,raw_runtime,q.old.public_request(10),child=0)))
(D/'runtime-before.json').write_text(json.dumps(initial_runtime_snapshot,indent=2)+'\n')
bridge={'binary':str(path.parent/'hia-ndu-evaluator'),'build_receipt':str(path.parent/'hia-ndu-evaluator-build.json')}
inputs=[runtime,make(v,baseline),make(v,'calculate'),make(v,bridge),(0,0,0),(0,0,0),(0,0,0)]
oracle_parent=D/'original-runtime';oracle_parent.mkdir()
oldruntime=ScalarMultiversionRuntime(baseline,oracle_parent)
original=BackgroundOptimizer(oldruntime,baseline,function='calculate',bridge=bridge)
before=q.get(v.raw(47),48);checkpoint('before-BG-construction');fd_before=set(os.listdir('/proc/self/fd'))
def fdrows():
 out={}
 for p in Path('/proc/self/fd').iterdir():
  try:out[p.name]=os.readlink(p)
  except FileNotFoundError:pass
 return out
fd_before_rows=fdrows()
(D/'fd-before.json').write_text(json.dumps(fd_before_rows,indent=2)+'\n')

r=public(0,inputs);assert q.get(r,48)==1 and q.get(r,16)==1 and q.get(r,104)==0
bg=v.keep(r);weak=struct.unpack_from('<3Q',v.raw(80,a=bg),24)
actual_class=v.keep(v.raw(36,a=bg));expected_class=v.keep(v.raw(57,arg0=35))
assert v.same(actual_class,expected_class)
v.drop(actual_class);v.drop(expected_class)
assert q.get(bgctx,192)==1 and q.get(bgctx,184)==0
print('ACTUAL_CANONICAL_BG_KIND6_AND_WORKER_READY',flush=True)
checkpoint('BG-ready-before-job')
observed=snapshot(bg);expected=original.snapshot()
assert observed==expected,(observed,expected)
assert observed['worker_alive']is True and observed['closed']is False
cases=[dict(case='native-global-loader-NI2-kind6-actual-pthread-and-original-snapshot',passed=True,snapshot=observed)]


from hepta.hia_background_optimizer import TARGET
from tools import qualify_hia_future_managed_edges as managed
import time
canonical=verify_program(baseline)
candidates=[dict(id='A',action='identity',program=baseline)]
observations={'abstain':dict(runtime_ns=1000000000,uncertainty_ns=1000,search_ns=0,program_sha256=canonical.sha256),
 'A':dict(runtime_ns=1,uncertainty_ns=0,search_ns=0,program_sha256=canonical.sha256)}
objective=dict(expected_calls=100,resource_cap_ns=60000000000,target=TARGET,measurement_profile='measure')
job_held_before=set(v.held);job_caps=[make(v,candidates),make(v,observations),make(v,objective)]
job_input_held=[c for c in v.held if c not in job_held_before]
wait_false=make(v,False);cancel_false=make(v,False);limit=v.scalar(30.0)
owned=binding.Fixture.__new__(binding.Fixture);owned.v=v;owned.engine=engine
sidecarptr=q.get(n.context,1152);owned.provider_ctx=(C.c_char*512).from_address(sidecarptr+1536)
owned.provider=SimpleNamespace(entry=inv.ENTRY(q.get(engine.context,224)))
pp=managed.PrivatePublic.__new__(managed.PrivatePublic);pp.value=v;pp.calls=0;pp.factories=[];pp.futures=[]
pp.ctx=(C.c_char*256).from_address(sidecarptr+1280);pp.image=SimpleNamespace(entry=n.lib.hia_background_optimizer_future_public)
pp.image.entry.argtypes=[C.c_void_p,C.c_uint64]*3;pp.image.entry.restype=C.c_uint32
owned.public=pp
rawbg=struct.unpack_from('<3Q',v.raw(49,a=bg),24)
rq=bytearray(128);rq[:8]=b'HIABGRG1';struct.pack_into('<Q',rq,8,6);struct.pack_into('<3Q',rq,24,*rawbg)
s=C.create_string_buffer(bytes(rq),128);out=C.create_string_buffer(8192)
rc=inv.ENTRY(q.get(bgctx,144))(s,128,out,8192,q.get(bgctx,152),256)
assert rc==0 and out.raw[:8]==b'HIABGRR1'and q.get(out,8)==0 and q.get(out,40)==32 and q.get(out,80)==1
payload=C.string_at(q.get(out,64),32);recptr=q.get(payload,0);assert q.get(payload,8)==2097152
cfg=C.string_at(q.get(bgctx,240),512);queue_entry=inv.ENTRY(q.get(cfg,136))
def queue_tx(op):
 raw=struct.pack('<16Q',int.from_bytes(b'HIABGQ04','little'),op,*([0]*14))
 s=C.create_string_buffer(raw,128);o=C.create_string_buffer(4096)
 rc=queue_entry(s,128,o,4096,recptr+4096,4096)
 assert rc==0 and o.raw[:8]==b'HIABGQR2'and q.get(o,8)==0 and q.get(o,56)==q.get(o,64)==0,(op,rc,o.raw[:128].hex())
 return o.raw
def root_sample():
 r=queue_tx(10)
 try:return dict(pending=q.get(r,32),queued=q.get(r,40),active=q.get(r,48),worker=q.get(r,72),
  root=struct.unpack('<3Q',C.string_at(recptr+16384+888,24)))
 finally:queue_tx(11)

policy_inputs=dict(baseline=baseline,candidates=candidates,observations=observations,objective=objective,
 function='calculate',bridge=bridge,generation=1,expected_generation=0,expected_epoch=0,timeout_ms=2000,bridge_timeout_s=10.0)
(D/'actual-submitted-inputs.json').write_text(json.dumps(policy_inputs,indent=2)+'\n')
ref=original.submit(candidates,observations,objective)
future=v.keep(public(3,[bg,*job_caps]))
strong,pair=owned.acquire(future)
wire=bytearray(192);wire[:8]=b'HIABFP04';struct.pack_into('<Q',wire,8,10)
struct.pack_into('<3Q',wire,16,*pair[0]);struct.pack_into('<3Q',wire,40,*pair[1]);struct.pack_into('<3Q',wire,104,*limit)
s=C.create_string_buffer(bytes(wire),192);o=C.create_string_buffer(65536)
rc=pp.image.entry(s,192,o,65536,pp.ctx,256);reply=o.raw
(D/'future-result-reply.bin').write_bytes(reply)
expected_result=ref.result(timeout=30)
(D/'original-result.json').write_text(json.dumps(expected_result,indent=2)+'\n')
if not(rc==0 and reply[:8]==b'HIABFRP3'and q.get(reply,8)==0 and q.get(reply,16)==4):
 details=dict(reply=[q.get(reply,i)for i in range(0,256,8)],
  bg=[q.get(C.string_at(recptr,512),i)for i in range(0,512,8)],
  queue=[q.get(C.string_at(recptr+4096,2048),i)for i in range(0,2048,8)],
  business=[q.get(C.string_at(recptr+24576,1024),i)for i in range(0,1024,8)],
  business_output=[q.get(C.string_at(recptr+40960,8192),i)for i in range(0,8192,8)],
  decision_work=[q.get(C.string_at(recptr+1495040,16384),i)for i in range(0,16384,8)],
  decision_output=[q.get(C.string_at(recptr+40960+524288+262144,8192),i)for i in range(0,8192,8)],
  exec_work=[q.get(C.string_at(recptr+1089536,2048),i)for i in range(0,2048,8)],
  exec_output=[q.get(C.string_at(recptr+40960+524288,8192),i)for i in range(0,8192,8)],
  exec_provider=[q.get(C.string_at(recptr+40960+524288+65536,256),i)for i in range(0,256,8)],
  engine=[q.get(engine.context,i)for i in range(0,256,8)])
 (D/'failure-state.json').write_text(json.dumps(details,indent=2)+'\n')
 if q.get(reply,16)==200:
  exc=struct.unpack_from('<3Q',reply,72)
  if exc[0]:
   detail=v.raw(26,a=exc)
   (D/'exception-descriptor.bin').write_bytes(detail)
   print('ACTUAL_EXCEPTION_DESCRIPTOR',[q.get(detail,i)for i in range(8192,8320,8)],flush=True)
assert rc==0 and reply[:8]==b'HIABFRP3'and q.get(reply,8)==0 and q.get(reply,16)==4,reply[:192].hex()
result=v.keep(reply,72);actual_result=v.python_value(result)
(D/'native-result.json').write_text(json.dumps(actual_result,indent=2)+'\n')
print('NATIVE_POSITIVE_OUTCOME',actual_result.get('status'),actual_result.get('reason'),actual_result.get('selected_id'),flush=True)
print('ORIGINAL_POSITIVE_OUTCOME',expected_result.get('status'),expected_result.get('reason'),expected_result.get('selected_id'),flush=True)
assert actual_result['status']=='published',actual_result
assert actual_result['selected_id']=='A'
checkpoint('published-and-result-retained')
assert expected_result['status']=='rejected' and expected_result['detail']=='E_HIA_NDU: bridge build receipt has wrong source, scope or build gates',expected_result
actual_runtime_snapshot=json.loads(q.old.release_detached(carrier.q(4,raw_runtime,q.old.public_request(10),child=0)))
(D/'native-runtime-snapshot.json').write_text(json.dumps(actual_runtime_snapshot,indent=2)+'\n')
assert actual_runtime_snapshot['current_generation']==1 and actual_runtime_snapshot['selection_epoch']==1,actual_runtime_snapshot
checkpoint('after-runtime-snapshot')
new_lease=q.old.lease(carrier,raw_runtime)
checkpoint('after-new-Lease')
for arg in [0,37,18446744073709551615]:
 outcall=carrier.q(4,new_lease,q.old.inner(4,fn=b'calculate',args=json.dumps([arg]).encode()),child=0)
 assert json.loads(outcall['value'])==arg,outcall
 checkpoint('after-real-Lease-call-'+str(arg))
carrier.q(3,new_lease)
checkpoint('after-new-Lease-drop')
actual_snapshot=snapshot(bg);expected_snapshot=original.snapshot()
(D/'native-snapshot.json').write_text(json.dumps(actual_snapshot,indent=2)+'\n')
(D/'original-snapshot.json').write_text(json.dumps(expected_snapshot,indent=2)+'\n')
from tools import qualify_hia_background_optimizer_recorded_policy as policy_oracle
policy_report=policy_oracle.compare(actual_result,policy_inputs,D/'original-policy',initial_runtime_snapshot,actual_snapshot)
assert policy_report['passed']is True
for cap_ in(result,strong,future):v.drop(cap_)
checkpoint('after-result-and-Future-drop')
deadline=time.monotonic()+10
while True:
 sampled=root_sample()
 if sampled['pending']==0 and sampled['root']==(0,0,0):break
 assert time.monotonic()<deadline,sampled
 time.sleep(.002)
assert sampled['active']==(1<<64)-1 and sampled['queued']==0,sampled
r=public(2,[bg,wait_false,cancel_false]);none=v.keep(r);assert v.python_value(none)is None;v.drop(none)
release=engine.call(inv.frame(29,a=bg))
assert release[0]==0 and release[1][:8]==b'HIABVR02'and q.get(release[1],88)==q.get(release[1],96)==1
v.held.remove(bg)
deadline=time.monotonic()+30
while q.get(bgctx,192)or q.get(engine.context,176)or q.get(engine.context,184):
 assert time.monotonic()<deadline
 time.sleep(.002)
original.shutdown(wait=True,cancel_pending=False)
for cap_ in [limit,wait_false,cancel_false,*job_input_held]:v.drop(cap_)
actual_after=q.get(v.raw(47),48);checkpoint('after-BG-job-input-retirement')
# One newly retained generation owns the component, prepare, and Clang
# context tokens. Compare again at the identical no-Runtime boundary below.
assert actual_after==before+3,(before,actual_after)
oldruntime.close();carrier.q(3,raw_runtime)
checkpoint('after-original-and-raw-Runtime-drop')
for cap_ in list(v.held):v.drop(cap_)
final_caps=checkpoint('after-all-real-Value-and-Runtime-retirement')
assert final_caps==initial_caps,(initial_caps,final_caps)
assert not list(parent.iterdir())and not list(oracle_parent.iterdir())
drop=g.call(3,borrow['cap']);resources.ready(drop);assert drop['consumed']==1
a=call(1);assert q.get(a,8)==0 and q.get(a,16)==4 and q.get(a,40)==1 and q.get(a,80)==190
sc=globalqa.sidecar(n,1);assert sc['status']==0 and sc['retired']==1,sc
r=g.call(1);globalqa.closed(n,g,r)
assert actual_fd_rows()==initial_fd_rows,(initial_fd_rows,actual_fd_rows())
report=dict(schema='hia.BG.installed-native-publication.v1',passed=True,initial_caps=initial_caps,final_caps=final_caps,cap_census=cap_rows,actual_public_proof=proof_pin,installation_path_replaced_after_native_admission=True,original_policy=policy_report,
 actual=actual_result,original=expected_result,final_caps_before=before,final_caps_after=actual_after,
 root_product=dict(path=str(args.root),bytes=args.root.stat().st_size,sha256=hashlib.sha256(args.root.read_bytes()).hexdigest()),
 actual_installation=str(install),
 actual_single_Value=True,legacy_reference_admission_rejection_preserved=True,actual_new_generation_calls=[0,37,18446744073709551615],full_original_worker_and_rank_policy_comparison=True,legacy_Rust_receipt_domain_remains_separate=True,whole_background_closed=False)
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
signal.alarm(0);print('ACTUAL_INSTALLED_NATIVE_BG_PUBLICATION_FULL_RETIREMENT_PASS',flush=True)
