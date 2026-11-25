from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,os,resource,struct,sys,time,ast,copy,inspect,types,errno
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');P=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-multiversion-proof-source');D=T/'ndu-rank-main-qualification-v4';D.mkdir(exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from tools.generate_hia_ndu_rank_tasks import CONSTANTS as K
from tools.generate_hia_ndu_rank_owner_common import C as OWNER_CONSTANTS
K.update(OWNER_CONSTANTS)
from tools.generate_hia_ndu_rank_decide import C as DECIDE_CONSTANTS
K.update(DECIDE_CONSTANTS)
lib=C.CDLL(None,use_errno=True);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p;lib.mremap.argtypes=(C.c_void_p,C.c_size_t,C.c_size_t,C.c_int);lib.mremap.restype=C.c_void_p;lib.munmap.argtypes=(C.c_void_p,C.c_size_t);lib.munmap.restype=C.c_int;lib.syscall.restype=C.c_longlong
FUNC=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin;fd=os.memfd_create('rank-tasks-actual-flat',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value);os.close(fd);return FUNC(address)
entry=load(T/'ndu-rank-main-v2/ndu_rank_tasks.flat','3efdd308f30a1e2893dc373e12d40662c3d7968cd83a925189efb2a55654effb')
main_rows=json.loads((T/'ndu-rank-main-v4/build.json').read_text())['roles']
main=load(T/'ndu-rank-main-v4/ndu_rank_main.flat',next(x['flat_sha256']for x in main_rows if x['role']=='ndu_rank_main'))
roles={
8:load(T/'ndu-rank-binary64-v1/agent_binary64_format.flat','ab4877e353a65a3834cf318bd02ad3ccacb16c2709aebbb669af7ed3b8a6eb2c'),
10:load(T/'ndu-rank-clock-budget-v1/ndu_rank_clock_budget.flat','f3dfec793b05805db93a2b4b0e794201b13e495dba40a74909f2bf2117b4902e'),
12:load(T/'ndu-rank-binding-v1/ndu_rank_binding.flat','d8b8b223bbace19a922d15eb6b150c1e27a0f6453161e8e2de7ee90a33702cbd'),
13:load(T/'ndu-rank-selection-v1/ndu_rank_selection.flat','e4c7125ccc6295fe7fea4188f096a5a65735923e9a8f4f70c7c482bde451271e'),
17:load(T/'ndu-evaluator-qa/native-owner-pack-v2/effects.flat','4ed619dce9eeb997c5d3c9ffd04f46e3ff130c4774b3ebe2ec071f0702f432a0'),
19:load(T/'ndu-evaluator-qa/owner-error-v1/flat.bin','bf7e7e86535091c46df9a8be42e20c1c95dbfa6dd1e1f25d4a55c449ddef75ad'),
11:load(T/'ndu-rank-canonical-unchanged-v2/ndu_rank_unchanged.flat','381902ad4e92287af2491e17ac92b7baca1ac036adeaa8af01d0ef694fb9869a'),
20:load(Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-background-json-capture-v4/background_optimizer_json_capture.flat'),'62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f'),
5:load(Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-background-freeze-v2/background_optimizer_freeze.flat'),'f32bf4a811481a3baa007919710549a8e231caa3cb44c6afcb180f4c124d210d'),
3:load(T/'ndu-rank-main-v2/ndu_rank_snapshot.flat','c6ab6ba1f7c89117ac687665b2c0489f27ca54740dc900bcd2501f41b99fbf64'),
4:load(Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-background-structure-v3/background_optimizer_structure.flat'),'501694a31b52ec095f31a6e650e1ca15f7c0999c1cee62c6afcbe077a838afde'),
6:load(T/'ndu-rank-admission-staged-v2/ndu_rank_admission.flat','18c70f0fb94c80d386b3f5eabb6accef4989c78cb4f4f76b93b27126f2aab2e1'),
7:load(T/'ndu-rank-binary64-v1/agent_binary64.flat','9184c68f231af5e42a0b2a419700d0601390fbbe4942387777d80e55f012559a'),
1:load(T/'ndu-rank-json-v4/ndu_rank_json.flat','2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144'),
2:load(T/'ndu-rank-canonical-unchanged-v2/ndu_rank_canonical.flat','2b9b658fd0c5211d020b60238472119f136075b3e89c638f84ed0ad7835f4fa0')if False else load(T/'ndu-rank-canonical-unchanged-v2/ndu_rank_canonical.flat','2b9b658fd0c5211d020b60238472119f136075b3e89f638f84ed0ad7835f4fa0'),
9:load(T/'ndu-rank-cost-v1/ndu_rank_cost.flat','f6c4aa1ac0f0de5e0971456d615407d8d67954b6be58fc609e5cdbe7f441d29b'),
14:load(T/'ndu-rank-owner-support-v1/ndu_rank_report.flat','908e9b52943be2e477b045042147751e2e44e9ab9148c1ac40e6ceaba040d720'),
15:load(T/'ndu-evaluator-qa/owner-main-v1/sha.flat','214aea20ce10da438d1a96e98b0a25ed1151776e1fd577047c336d57cd54ae19')}
roles[19]=C.CFUNCTYPE(C.c_uint64,*([C.c_void_p,C.c_uint64]*3))(C.cast(roles[19],C.c_void_p).value)
proc=C.CDLL(str(T/'ndu-rank-process-qualification-v2/process-component.so'));pf=proc.hia_ndu_rank_process;pf.argtypes=[C.c_void_p,C.c_uint64]*3;pf.restype=C.c_uint32;roles[16]=pf
NONE=(1<<64)-1;rows=[]
def u(raw,off):return struct.unpack_from('<Q',raw,off)[0]
def sealed(raw):
 fd=os.memfd_create('rank-task-child',os.MFD_ALLOW_SEALING);os.write(fd,raw);os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);return fd
class Driver:
 def __init__(self,raw,capacity=1048576,fail_grow_at=None):
  self.raw=raw;self.s=C.create_string_buffer(raw);self.o=C.create_string_buffer(65536);self.capacity=capacity;self.w=lib.mmap(None,capacity,3,0x22,-1,0);assert self.w not in(None,C.c_void_p(-1).value);self.events=[];self.fail_grow_at=fail_grow_at;self.grows=0;self.clocks=[];self.proofs=[]
 def put(self,key,value):struct.pack_into('<Q',self.o,K.get(key,key)if isinstance(key,str)else key,value)
 def get(self,key):return struct.unpack_from('<Q',self.o,K.get(key,key)if isinstance(key,str)else key)[0]
 def close(self):assert lib.munmap(self.w,self.capacity)==0
 def start(self,task,base=None,**kwargs):
  self.put('TASK',task);self.put('STEP',0);self.put('RESUME',777);self.put('BASE',self.get('TOP')if base is None else base);self.put('RET_STATUS',NONE)
  for key,value in kwargs.items():self.put(key,value)
  self.run();assert self.get('PHASE')==777;return self.get('RET_STATUS')
 def translate(self,value,region):return value+[0,self.w,C.addressof(self.s),C.addressof(self.o)][region]
 def run(self):
  for iteration in range(2000000):
   if not self.get('TASK')and self.get('PHASE')==777:return
   if not self.get('TASK')and self.get('PHASE')==407:
    r=K['ROWS']+self.get('PROOF_ROW')*K['ROW_SIZE']
    self.proofs.append({'before':self.o.raw[K['ROWS']+112:K['ROWS']+144].hex(),'after':self.o.raw[r+112:r+144].hex(),'timeout':self.get('PROOF_TIMEOUT'),'proved':bool(self.get('PROOF_PROVED')),'proof':json.loads(self.bytes(self.get('PROOF_JSON'),self.get('PROOF_N')))})
   action=main(self.s,len(self.raw),self.o,65536,self.w,self.capacity)
   if action==7:action=entry(self.s,len(self.raw),self.o,65536,self.w,self.capacity)
   self.events.append((action,self.get('PHASE'),self.get('TASK'),self.get('STEP')))
   if action==0:return
   if action==3:continue
   if action==2:
    self.grows+=1
    if self.grows==self.fail_grow_at:self.put('ALLOC_FAILED',1);continue
    size=self.get('DESC');new=lib.mremap(self.w,self.capacity,size,1)
    if new in(None,C.c_void_p(-1).value):self.put('ALLOC_FAILED',1);continue
    self.w=new;self.capacity=size;self.put('CAPACITY',size);continue
   selector=self.get('SELECTORS');args=[self.get(K['ARG0']+8*i)for i in range(6)]
   if action==5:
    dst=self.translate(args[0],selector&3);src=self.translate(args[1],(selector>>2)&3);C.memmove(dst,src,args[2]);self.put('FEEDBACK',args[2]);continue
   args=[self.translate(x,(selector>>(i*2))&3)for i,x in enumerate(args)]
   if action==4:
    role=self.get('ROLE_ID');assert role in roles,(role,self.events[-30:]);rc=roles[role](*args);self.put('FEEDBACK',rc);continue
   if action==1:
    nr=self.get('ROLE_ID');assert nr in(3,17,228),nr;C.set_errno(0);rc=lib.syscall(C.c_longlong(nr),*[C.c_ulonglong(x)for x in args]);rc=-C.get_errno()if rc==-1 else rc;self.put('FEEDBACK',rc&NONE)
    if nr==228 and rc==0:self.clocks.append((self.get('PHASE'),self.get(3200)*1000000000+self.get(3208)))
    continue
   raise AssertionError(('unexpected mechanical action',action,self.events[-30:]))
  raise AssertionError('continuation loop')
 def bytes(self,at,n):return C.string_at(self.w+at,n)
def record(label,d,**kw):rows.append({'case':label,'passed':True,'transitions':len(d.events),'grows':d.grows,**kw});print('RANK_TASK_PASS',label,len(d.events),flush=True)
def enc(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

import hepta.hia_ndu_optimizer as original
from hepta.hia_program import verify_program
fn=ast.parse(inspect.getsource(original.rank_candidates)).body[0];fn.name='reference_rank'
tree=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]));reference_source=ast.unparse(tree);(D/'original-reference.py').write_text(reference_source)
baseline=(Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z')/'native-multiversion-prepare-process-v4/normalizer-samples/primitive.input').read_bytes()
before=verify_program(baseline);normal=sealed((T/'normalizer-84619bd.bin').read_bytes());proof=sealed((T/'facade-image-v8/hia-public-proof').read_bytes())
threshold_raw=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-background-source/examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat').read_bytes()
assert len(threshold_raw)==10100891 and sha256(threshold_raw).hexdigest()=='735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706';threshold=C.create_string_buffer(threshold_raw)
source_root=os.open(T/'ndu-evaluator-source',os.O_PATH|os.O_DIRECTORY)
base={'candidates':[{'id':'A','action':'identity','program':json.loads(baseline)},{'id':'B','action':'second','program':json.loads(baseline)}],'observations':{},'function':'calculate','bridge':{'binary':'/unused','build_receipt':'/unused'},'objective':{'expected_calls':1,'resource_cap_ns':0,'target':'host','measurement_profile':'measure'},'generation':1,'timeout_ms':2000,'bridge_timeout_s':10.0}
for cid in ['abstain','A','B']:base['observations'][cid]={'runtime_ns':100000,'uncertainty_ns':1,'search_ns':0,'program_sha256':before.sha256}
def owned_args(args):
 policy=sys.get_int_max_str_digits()
 try:
  sys.set_int_max_str_digits(0)
  return json.dumps(args,ensure_ascii=False,separators=(',',':'),allow_nan=True).encode('utf-8','surrogatepass')
 finally:sys.set_int_max_str_digits(policy)
def check(label,args,rawbase=baseline,bridge_oracle='recorded'):
 ar=owned_args(args);packet=struct.pack('<8s15Q',b'HIANRK01',1,len(rawbase),len(ar),*([0]*12))+rawbase+ar
 d=Driver(packet);d.put('NORMALIZER_FD',normal);d.put('PROOF_FD',proof);d.put('SOURCE_ROOT_FD',source_root);d.put('INT_DIGITS',4300);d.put('THRESHOLD_PTR',C.addressof(threshold));d.put('THRESHOLD_N',len(threshold_raw))
 beforefds=set(os.listdir('/proc/self/fd'));d.run();assert beforefds==set(os.listdir('/proc/self/fd')),(label,'FD leak')
 native_status=d.get('RESULT_STATUS');body=d.bytes(d.get('RESULT_AT'),d.get('RESULT_N'))
 if native_status not in(0,1):
  debug={'label':label,'control':{str(k):d.get(k)for k in range(0,8192,8)},'request':d.bytes(d.get('REQUEST_AT'),d.get('REQUEST_N')).decode('utf-8','backslashreplace'),'events':d.events[-120:]};(D/'internal-debug.json').write_text(json.dumps(debug,ensure_ascii=True,indent=2)+'\n')
 assert native_status in (0,1),(label,'native internal/base exception',native_status,d.get('PHASE'),body[:2048],d.events[-40:])
 actual=json.loads(body)
 clocks=iter(t for phase,t in d.clocks if phase!=9991);used=[]
 def tick():
  t=next(clocks);used.append(t);return t
 proof_replay=iter(d.proofs)
 def replay_proof(before,after,function,timeout):
  row=next(proof_replay);assert row['before']==before.sha256 and row['after']==after.sha256 and row['timeout']==timeout and function==args['function'];return row['proved'],row['proof']
 def replay_native(bridge,request,timeout_s):
  if bridge_oracle=='actual-error':return original._native_rank(bridge,request,timeout_s=timeout_s)
  assert native_status==0,(label,'unexpected native exception',actual)
  assert request==actual['native_request'] and timeout_s==actual['native_rank_admission']['timeout_s']
  if actual['native_rank_admission']['reason']=='native_identity_admission_exhausted_budget':raise original._NativeBudgetExhausted()
  assert actual['native_rank_admission']['invoked'] is True
  return actual['native_response'],actual['bridge']
 scope=dict(vars(original));scope['time']=types.SimpleNamespace(perf_counter_ns=tick);scope['_native_rank']=replay_native;scope['_fresh_proof']=replay_proof
 exec(compile(tree,'original-full-rank','exec'),scope)
 try:
  expected=scope['reference_rank'](rawbase,args.get('candidates'),args.get('observations'),function=args.get('function'),bridge=args.get('bridge'),objective=args.get('objective'),generation=args.get('generation',1),timeout_ms=args.get('timeout_ms',2000),bridge_timeout_s=args.get('bridge_timeout_s',10.0));status=0
 except AssertionError:raise
 except Exception as e:expected={'type':type(e).__name__,'message':str(e)};status=1
 if actual!=expected or native_status!=status:
  (D/(label+'.actual.json')).write_text(json.dumps(actual,ensure_ascii=True,indent=2)+'\n');(D/(label+'.expected.json')).write_text(json.dumps(expected,ensure_ascii=True,indent=2)+'\n')
  raise AssertionError((label,'complete output mismatch',native_status,status,[(k,actual.get(k),expected.get(k))for k in set(actual)|set(expected)if actual.get(k)!=expected.get(k)][:6]))
 assert next(proof_replay,None)is None,(label,'unused actual proof')
 assert next(clocks,None)is None,(label,'unused rank clock',d.clocks,len(used))
 assert d.get('RESULT_ELAPSED')>=max(0,d.clocks[-1][1]-d.clocks[0][1])
 record(label,d,rank_status=status,clock_samples=len(used),actual_proof_calls=len(d.proofs),admitted=actual.get('admitted'),selected_id=actual.get('selected_id'),reason=actual.get('reason'),result_bytes=len(body),result_sha256=sha256(body).hexdigest());(D/(label+'.actual.json')).write_text(json.dumps(actual,ensure_ascii=True,indent=2)+'\n');d.close()

base['bridge']={'binary':str(T/'ndu-evaluator-qa/native-cli-v1/hia-ndu-evaluator'),'build_receipt':str(T/'ndu-evaluator-qa/native-cli-v1/hia-ndu-evaluator-build.json')}
base['objective']['resource_cap_ns']=5_000_000_000
base['objective']['expected_calls']=100
base['observations']['abstain']['runtime_ns']=1_000_000_000
base['observations']['abstain']['uncertainty_ns']=1000
for cid in('A','B'):base['observations'][cid]['runtime_ns']=1;base['observations'][cid]['uncertainty_ns']=0
a=copy.deepcopy(base);a['candidates']=[];a['observations']={'abstain':a['observations']['abstain']};check('actual-native-empty',a)
a=copy.deepcopy(base);a['candidates']=a['candidates'][:1];del a['observations']['B'];check('actual-native-one-proved',a)
check('actual-native-two-proved',copy.deepcopy(base))
a=copy.deepcopy(base);a['candidates'][0]['program']={};check('actual-native-rejected-and-proved',a)
a=copy.deepcopy(base);a['bridge_timeout_s']=1e-300;check('actual-identity-exhaustion-no-child',a)
for bridge in(None,{},[],{'binary':None,'build_receipt':'/unused'},{'binary':'/surely-absent-hia-file','build_receipt':'/unused'}):
 a=copy.deepcopy(base);a['candidates']=[];a['observations']={'abstain':a['observations']['abstain']};a['bridge']=bridge;check('actual-native-bridge-error-'+str(len(rows)),a,bridge_oracle='actual-error')
report={'schema':'hepta.hia.ndu-rank-main.integration-debug.v1','passed':True,'count':len(rows),'scope':'All actual native roles, real normalizer/proof/evaluator subprocesses and identity source reads. Real proof and native response observations are replayed only into unchanged legacy rank reference to compare complete rank report and timing fields; product has no mocks. Owner debug image pending its independent whole qualification.','whole_native_rank_closed':False,'cases':rows}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');os.close(normal);os.close(proof);os.close(source_root);print('RANK_MAIN_ACTUAL_NATIVE_CHAIN_PASS',len(rows),flush=True)
