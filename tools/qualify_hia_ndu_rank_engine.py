from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,os,resource,struct,sys,time,ast,copy,inspect,types,errno
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');P=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-multiversion-proof-source');D=T/'ndu-rank-engine-qualification-v1';D.mkdir(exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from tools.generate_hia_ndu_rank_tasks import CONSTANTS as K
from tools.generate_hia_ndu_rank_owner_common import C as OWNER_CONSTANTS
K.update(OWNER_CONSTANTS)
from tools.generate_hia_ndu_rank_decide import C as DECIDE_CONSTANTS
K.update(DECIDE_CONSTANTS)
lib=C.CDLL(None,use_errno=True);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p;lib.mremap.argtypes=(C.c_void_p,C.c_size_t,C.c_size_t,C.c_int);lib.mremap.restype=C.c_void_p;lib.munmap.argtypes=(C.c_void_p,C.c_size_t);lib.munmap.restype=C.c_int;lib.syscall.restype=C.c_longlong
FUNC=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin;fd=os.memfd_create('rank-tasks-actual-flat',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value);os.close(fd);return FUNC(address)
engine=load(T/'ndu-rank-engine-native-v2/rank-engine.flat','8338a80a992218ca6faefea66235fd18fcfb5c5d59f2bcc1d10a184f28e294ff')
NONE=(1<<64)-1;rows=[]
def u(raw,off):return struct.unpack_from('<Q',raw,off)[0]
def sealed(raw):
 fd=os.memfd_create('rank-task-child',os.MFD_ALLOW_SEALING);os.write(fd,raw);os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);return fd
class Driver:
 def __init__(self,raw,capacity=0,fail_grow_at=None):
  self.raw=raw;self.s=C.create_string_buffer(raw);self.o=C.create_string_buffer(65536);self.capacity=0;self.w=0;self.events=[];self.fail_grow_at=None;self.grows=None;self.clocks=[];self.proofs=[];self.entry_delay=0
 def put(self,key,value):struct.pack_into('<Q',self.o,K.get(key,key)if isinstance(key,str)else key,value)
 def get(self,key):return struct.unpack_from('<Q',self.o,K.get(key,key)if isinstance(key,str)else key)[0]
 def close(self):assert lib.munmap(self.w,self.capacity)==0
 def start(self,task,base=None,**kwargs):
  self.put('TASK',task);self.put('STEP',0);self.put('RESUME',777);self.put('BASE',self.get('TOP')if base is None else base);self.put('RET_STATUS',NONE)
  for key,value in kwargs.items():self.put(key,value)
  self.run();assert self.get('PHASE')==777;return self.get('RET_STATUS')
 def translate(self,value,region):return value+[0,self.w,C.addressof(self.s),C.addressof(self.o)][region]
 def run(self):
  started=time.monotonic_ns();self.put('START',started)
  if self.entry_delay:time.sleep(self.entry_delay)
  rc=engine(self.s,len(self.raw),self.o,65536,None,0)
  assert rc==0,('native engine ABI failure',rc)
  self.w=self.get(40);self.capacity=self.get('CAPACITY');assert self.w and self.capacity>=1048576 and self.get('START')==started
  assert self.get('RESULT_AT')<=self.capacity and self.get('RESULT_N')<=self.capacity-self.get('RESULT_AT')
  self.events.append(('complete-fixed-native-engine',self.get('PHASE'),self.get('RESULT_STATUS')))
  self.clocks.append((1,started));supplied=self.get('SUPPLIED')
  def wide(at):return self.get(at)+(self.get(at+8)<<64)
  def proof_record(row,at,n,timeout,proved):
   self.proofs.append({'before':self.o.raw[K['ROWS']+112:K['ROWS']+144].hex(),'after':self.o.raw[row+112:row+144].hex(),'timeout':timeout,'proved':bool(proved),'proof':json.loads(self.bytes(at,n))})
  for index in range(1,self.get('COUNT')+1):
   r=K['ROWS']+index*K['ROW_SIZE']
   if self.get(r+K['R_HAS_COST']):
    stamp=started+wide(r+K['R_COST_REPLY']+48)-supplied;self.clocks.append((306,stamp))
    if self.get(r+K['R_PROOF_STARTED'])and self.get(r+K['R_PROOF_N']):
     self.clocks.extend([(401,stamp),(407,stamp+self.get(r+K['R_WALL']))])
     proof_record(r,self.get(r+K['R_PROOF']),self.get(r+K['R_PROOF_N']),self.get(r+K['R_TIMEOUT']),self.get(r+K['R_EQ']))
  if self.get('SEARCH_LOW')or self.get('SEARCH_HIGH'):self.clocks.append((390,started+wide(K['SEARCH_LOW'])-supplied))
  if self.get('NATIVE_TIMEOUT_N'):
   remaining=wide(K['NATIVE_REMAIN_LOW'])*(-1 if self.get('NATIVE_REMAIN_SIGN')else 1)
   self.clocks.append((585,started+self.get('CAP')-supplied-remaining))
  if self.get('FINAL_TARGET'):
   stamp=started+wide(K['FINAL_COST']+48)-supplied;self.clocks.append((701,stamp))
   if self.get('FINAL_SOLVER')and self.get('FINAL_PROOF_N'):
    self.clocks.extend([(401,stamp),(407,stamp+self.get('FINAL_WALL'))])
    r=K['ROWS']+self.get('FINAL_TARGET')*K['ROW_SIZE']
    proof_record(r,self.get('FINAL_PROOF_AT'),self.get('FINAL_PROOF_N'),self.get('FINAL_TIMEOUT'),self.get('PROOF_PROVED'))
  if self.get('ACTUAL_ADAPTER'):self.clocks.append((720,started+self.get('ACTUAL_ADAPTER')))
  self.clocks.append((9991,started+self.get('RESULT_ELAPSED')))
  assert all(a[1]<=b[1]for a,b in zip(self.clocks,self.clocks[1:])),self.clocks
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
 d.entry_delay=0.02 if label=='held-entry-clock'else 0
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


# Complete products run one native entry call; Python has no role/effect dispatch.
check('native-engine-cap-zero',copy.deepcopy(base))
check('held-entry-clock',copy.deepcopy(base))
a=copy.deepcopy(base);a['candidates'][0]['action']='\ud800';check('native-engine-late-action-unicode',a)
a=copy.deepcopy(base);a['objective']['target']='\ud800';check('native-engine-early-objective-unicode',a)
check('native-engine-bad-baseline',copy.deepcopy(base),b'{"broken":')
base['bridge']={'binary':str(T/'ndu-evaluator-qa/native-cli-v1/hia-ndu-evaluator'),'build_receipt':str(T/'ndu-evaluator-qa/native-cli-v1/hia-ndu-evaluator-build.json')}
base['objective']['resource_cap_ns']=5_000_000_000
base['objective']['expected_calls']=100
base['observations']['abstain']['runtime_ns']=1_000_000_000
base['observations']['abstain']['uncertainty_ns']=1000
for cid in('A','B'):base['observations'][cid]['runtime_ns']=1;base['observations'][cid]['uncertainty_ns']=0
a=copy.deepcopy(base);a['candidates']=[];a['observations']={'abstain':a['observations']['abstain']};check('native-engine-native-empty',a)
a=copy.deepcopy(base);a['candidates']=a['candidates'][:1];del a['observations']['B'];check('native-engine-one-proved',a)
check('native-engine-two-proved',copy.deepcopy(base))
a=copy.deepcopy(base);a['candidates'][0]['program']={};check('native-engine-rejected-and-proved',a)
a=copy.deepcopy(base);a['bridge_timeout_s']=1e-300;check('native-engine-identity-budget',a)
for bridge in(None,{'binary':float('nan'),'build_receipt':'/unused'},{'binary':'/surely-absent-hia-file','build_receipt':'/unused'}):
 a=copy.deepcopy(base);a['candidates']=[];a['observations']={'abstain':a['observations']['abstain']};a['bridge']=bridge;check('native-engine-bridge-error-'+str(len(rows)),a,bridge_oracle='actual-error')
a=copy.deepcopy(base);a['objective']['resource_cap_ns']=0
for row in a['observations'].values():row['search_ns']=1234567
check('native-engine-all-loser-costs-once',a)
for count,size in[(1,9<<20),(8,9<<20)]:
 a=copy.deepcopy(base);a['objective']['resource_cap_ns']=0;a['candidates']=[{'id':'C'+str(i),'action':'large-rejected','program':'x'*size}for i in range(count)];a['observations']={'abstain':a['observations']['abstain']}
 for i in range(count):a['observations']['C'+str(i)]={'runtime_ns':1,'uncertainty_ns':0,'search_ns':0,'program_sha256':before.sha256}
 check('native-engine-owned-args-'+str(count*size),a)
a=copy.deepcopy(base);a['objective']['resource_cap_ns']=0;a['candidates']=[{'id':'C'+str(i),'action':'bounded','program':json.loads(baseline)}for i in range(32)];a['observations']={'abstain':a['observations']['abstain']}
for i in range(32):a['observations']['C'+str(i)]={'runtime_ns':1,'uncertainty_ns':0,'search_ns':0,'program_sha256':before.sha256}
check('native-engine-all-32-proposals',a)
report={'schema':'hepta.hia.ndu-rank-engine.actual-qualification.v1','passed':True,'count':len(rows),'engine_bytes':4461559,'engine_sha256':'8338a80a992218ca6faefea66235fd18fcfb5c5d59f2bcc1d10a184f28e294ff','scope':'Each product call is one sealed native engine invocation with fixed HIA roles and actual syscalls/children. No host language effect or role dispatch. Reference-only clocks reconstructed from actual captured costs and proof wall intervals preserve every observable elapsed field; actual product clock is unchanged CLOCK_MONOTONIC. Root-owned context and external result lifetime remain separate.','whole_native_rank_closed':False,'cases':rows}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');os.close(normal);os.close(proof);os.close(source_root);print('RANK_ENGINE_ACTUAL_ENTRY_PASS',len(rows),flush=True)
