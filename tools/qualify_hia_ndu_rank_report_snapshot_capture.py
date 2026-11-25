from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,os,random,resource,struct,sys,time
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');P=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-multiversion-proof-source');D=T/'ndu-rank-report-snapshot-qualification-v2';D.mkdir(exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from hepta.hia_program import _bounded_detached_snapshot,HIAProgramRejected
from hepta.hia_ndu_optimizer import _bytes
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin;fd=os.memfd_create('rank-owner-report-snapshot',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
 return C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
build=json.loads((T/'ndu-rank-owner-support-v1/build.json').read_text())['roles'];pins={r['role']:r['flat_sha256']for r in build}
render=load(T/'ndu-rank-owner-support-v1/ndu_rank_report.flat',pins['ndu_rank_report'])
snapshot=load(T/'ndu-rank-main-v2/ndu_rank_snapshot.flat','c6ab6ba1f7c89117ac687665b2c0489f27ca54740dc900bcd2501f41b99fbf64')
decoder=load(Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-background-json-capture-v4/background_optimizer_json_capture.flat'),'62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f')
build[1]=next(x for x in json.loads((T/'ndu-rank-main-v2/build.json').read_text())['roles']if x['role']=='ndu_rank_snapshot')
rows=[];groups={};report={'passed':False,'whole_native_rank_closed':False,'scope':'Actual report constructors and JSON-owned detached snapshot traversal. No foreign mutable-object capture or complete rank closure claim.','roles':build[:2],'cases':rows,'groups':groups}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def record(label,group,**kw):
 rows.append({'case':label,'group':group,'passed':True,**kw});groups[group]=groups.get(group,0)+1
 if len(rows)%100==0:save();print('RANK_SUPPORT_CASE',len(rows),label,flush=True)
def arena(raw):
 ib=C.create_string_buffer(raw);size=C.create_string_buffer(64);sw=C.create_string_buffer(128);assert decoder(ib,len(raw),size,64,sw,128)==0
 h=struct.unpack('<8s7Q',size.raw);assert h[0]==b'HIANJS01';ob=C.create_string_buffer(h[4]);wb=C.create_string_buffer(h[5]);struct.pack_into('<QQ',wb,48,h[1],h[3]);struct.pack_into('<QQ',wb,96,h[2],1)
 rc=decoder(ib,len(raw),ob,len(ob),wb,len(wb));assert rc==0,(len(raw),rc);used=struct.unpack_from('<Q',ob,24)[0];return ob.raw[:used]
U=(1<<64)-1
def cost(mode,spent,budget,margin):
 out=bytearray(256);struct.pack_into('<8sQ',out,0,b'HIANRR01',mode)
 for at,value in [(48,spent),(64,0),(80,0)]:struct.pack_into('<QQ',out,at,value&U,value>>64)
 for at,value in [(96,budget),(120,margin)]:struct.pack_into('<QQQ',out,at,int(value<0),abs(value)&U,abs(value)>>64)
 return bytes(out)
def packet(action,parts,nums=(),hashes=(),extra=(),co=None,mode=0):
 h=bytearray(768);struct.pack_into('<8sQQQ',h,0,b'HIANRP01',action,mode,len(parts))
 for i,v in enumerate(nums):struct.pack_into('<Q',h,64+i*8,v)
 for i,v in enumerate(hashes):assert len(v)==32;h[128+i*32:160+i*32]=v
 for i,v in enumerate(extra):struct.pack_into('<Q',h,320+i*8,v)
 if co is not None:h[384:640]=co
 at=768+16*len(parts);table=b''
 for x in parts:table+=struct.pack('<QQ',at,len(x));at+=len(x)
 return bytes(h)+table+b''.join(parts)
def check(label,action,parts,expected,nums=(),hashes=(),extra=(),co=None,group='reports'):
 raw=packet(action,parts,nums,hashes,extra,co);s=C.create_string_buffer(raw);o=C.create_string_buffer(b'D'*96);w=C.create_string_buffer(4096)
 rc=render(s,len(raw),C.addressof(o)+16,64,w,len(w));assert rc==0,(label,rc);head=struct.unpack_from('<8s7Q',o,16);want=_bytes(expected)
 assert head[:3]==(b'HIANPR01',len(want),action)and head[3:]==(0,0,0,0,0),(label,head,len(want));assert o.raw[:16]+o.raw[80:96]==b'D'*32
 struct.pack_into('<Q',s,16,1);out=C.create_string_buffer(len(want)+96);C.memset(out,0xdb,len(out))
 rc=render(s,len(raw),C.addressof(out)+16,len(want)+64,w,len(w));assert rc==0,(label,rc)
 got=out.raw[80:80+len(want)];assert got==want,(label,got[:1000],want[:1000])
 assert out.raw[:16]+out.raw[-16:]==b'\xdb'*32
 assert s.raw[:16]+s.raw[24:len(raw)]==raw[:16]+raw[24:]
 record(label,group,bytes=len(want),sha256=sha256(got).hexdigest())
 return raw
H=[sha256(bytes([i])).digest()for i in range(6)];hexes=[x.hex()for x in H]
obj={'expected_calls':313,'resource_cap_ns':1<<34,'target':'targeté','measurement_profile':'p😀'}
obs={'runtime_ns':123,'uncertainty_ns':7,'search_ns':19,'program_sha256':hexes[0]}
check('objective',0,[_bytes(obj),'f😀'.encode()],{'schema':'hepta.hia.ndu-optimization.v1','objective':obj,'function':'f😀','before_sha256':hexes[0],'before_input_sha256':hexes[1]},hashes=H)
check('support',1,[_bytes(obs)],{'program':hexes[0],'observation':obs},hashes=H)
reasons={1:'canonical_verifier_rejected',2:'unselected_function_or_module_changed',3:'search_budget_exhausted_before_proof',4:'cost_dominated_before_proof',5:'search_budget_insufficient_for_proof',6:'cost_margin_insufficient_for_proof',7:'proved',8:'behavior_not_proved'}
rng=random.Random(2026112511);lastcandidate=None
for reason in range(1,9):
 for i in range(16):
  spent=rng.getrandbits(127);budget=rng.getrandbits(127)*(-1 if i&1 else 1);margin=rng.getrandbits(127)*(-1 if i&2 else 1)
  verified=reason!=1;has=reason>=3;started=reason>=7;proved=reason==7;timeout=1+i;wall=(1<<64)-1-i
  detail=('é😀x\x00\b\t\n\f\r\\"'*200)+str(i);proof={'status':'proved' if proved else 'unknown'} if started else None
  value={'id':'candidate'+str(i),'action':'actioné😀\t"','core_verified':verified,'observation':obs,'equivalence_proved':proved,'proof':proof,'reason':reasons[reason]}
  if reason==1:value['detail']=detail[:1024]
  if has:value.update(preproof_cost_lower_bound_ns=spent,proof_remaining_budget_ns=budget,proof_remaining_margin_ns=margin)
  if started:value.update(proof_timeout_ms=timeout,proof_wall_ns=wall)
  check('candidate-'+str(reason)+'-'+str(i),2,[value['id'].encode(),value['action'].encode(),_bytes(obs),_bytes(proof),detail.encode()],value,[int(verified),int(proved),reason,int(has),int(started),timeout,wall],co=cost(1,spent,budget,margin))
  lastcandidate=value
for i in range(40):
 n=[rng.randrange(1<<63)for _ in range(3)]+[i%2];v={'id':'abstain'if i==0 else 'c'+str(i),'cost_q32':n[0],'uncertainty_q32':n[1],'resource_q32':n[2],'hard_violation':bool(n[3]),'support_sha256':hexes[0]}
 check('row-'+str(i),3,[v['id'].encode()],v,n,H)
nativeRows=[{'id':'abstain','cost_q32':0,'uncertainty_q32':0,'resource_q32':0,'hard_violation':False,'support_sha256':hexes[0]}]
for count in (1,2,16,33):
 value={'schema':'hepta.hia.ndu-request.v1','objective_sha256':hexes[0],'generation':U,'resource_cap_q32':(1<<63)-1,'candidates':nativeRows*count}
 check('request-'+str(count),4,[_bytes(x)for x in value['candidates']],value,[U,(1<<63)-1],H)
nativeReason=['search_budget_exhausted_before_native','native_identity_admission_exhausted_budget','actual_native_response_received']
for why in range(3):
 for remaining in (0,1,-1,1<<64,-(1<<64),-(1<<127),1<<127):
  v={'invoked':why==2,'remaining_budget_ns':remaining,'timeout_s':None if why==0 else 1e-9,'reason':nativeReason[why]}
  check('native-admit-'+str(why)+'-'+str(remaining),5,[_bytes(v['timeout_s'])],v,[int(v['invoked']),why],extra=[int(remaining<0),abs(remaining)&U,abs(remaining)>>64])
for i in range(40):
 spent=rng.getrandbits(128);budget=rng.getrandbits(127)*(-1 if i&1 else 1);margin=rng.getrandbits(127)*(-1 if i&2 else 1);started=i%2
 v={'candidate_id':'c','spent_search_ns':spent,'remaining_budget_ns':budget,'remaining_margin_ns':margin,'solver_started':bool(started)}
 if started:v.update(timeout_ms=5000,wall_ns=U)
 check('selected-proof-'+str(i),6,[b'c'],v,[started,5000,U],co=cost(2,spent,budget,margin))
for i in range(80):
 values=[rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(128),rng.getrandbits(128)]
 v={'supplied_search_ns':values[0],'actual_adapter_ns':values[1],'total_search_ns':values[2],'search_at_native_rank_ns':values[3],'publication_preparation_included':False}
 check('costs-'+str(i),7,[],v,[values[0],values[1],values[2]&U,values[2]>>64,values[3]&U,values[3]>>64])
costs=v
finalReasons=['search_budget_exhausted_before_native','native_identity_admission_exhausted_budget','caller_pareto_tie_retained_incumbent','native_evaluator_abstained','actual_search_budget_exceeded','no_robust_net_saving_after_search','selected_proof_budget_insufficient','selected_proof_margin_insufficient','selected_candidate_fresh_proof_failed','fresh_proof_and_robust_cost_gate_passed']
claims={'ndu_is_advisory':True,'unproved_candidate_admitted':False,'all_other_functions_unchanged':True,'resource_bounds_proved':False,'measurements_independently_attested':False,'native_backend_refinement_proved':False,'global_optimality_established':False,'incremental_advantage_established':False}
for why in range(10):
 for admitted in (False,True):
  parts=[b'function',_bytes(obj),b'candidate' if admitted else b'abstain',b'{"program":"owned"}',_bytes(costs),_bytes([lastcandidate]),b'null',b'null',_bytes({'invoked':False}),_bytes({'native':'request'}),b'null',b'null',b'null']
  margin=(1<<128)-1
  v={'schema':'hepta.hia.ndu-optimization.v1','before_sha256':hexes[0],'before_input_sha256':hexes[1],'function':'function','generation':U,'objective':obj,'objective_sha256':hexes[2],'observations_sha256':hexes[3],'selected_id':'candidate' if admitted else 'abstain','admitted':admitted,'reason':finalReasons[why],'selected_program':{'program':'owned'},'net_margin_ns':margin if admitted else 0,'costs':costs,'candidate_reports':[lastcandidate],'selected_fresh_proof':None,'selected_proof_admission':None,'native_rank_admission':{'invoked':False},'native_request':{'native':'request'},'request_sha256':hexes[4],'native_response':None,'bridge':None,'selection_resolution':None,'claims':claims,'cost_model':'incumbent lower bound versus candidate upper bound; all search charged once; trusted host observations'}
  check('final-'+str(why)+'-'+str(admitted),8,parts,v,[U,int(admitted),why],H,extra=[U,U])
for count in (0,1,32,64):check('array-'+str(count),9,[_bytes(i)for i in range(count)],list(range(count)))
for value in ('','\x00\b\t\n\f\r\\"','é😀', 'x'*(9<<20)):
 check('exception-'+str(len(value)),10,[b'OptimizationRejected',value.encode()],{'type':'OptimizationRejected','message':value},group='escaped_dynamic_reports')
base=packet(10,[b'T',b'M'])
for off,val in [(0,0),(8,11),(16,2),(24,65),(32,1),(640,1),(760,1),(768,0),(776,U)]:
 raw=bytearray(base);struct.pack_into('<Q',raw,off,val);s=C.create_string_buffer(bytes(raw));o=C.create_string_buffer(b'D'*512);w=C.create_string_buffer(4096)
 rc=render(s,len(raw),o,512,w,len(w));assert rc==0xfffffffd and o.raw[:512]==b'D'*512,(off,rc);record('render-guard-'+str(off),'private_guards')
for outcap,workcap in [(63,4096),(512,4095),(0,4096),(512,0)]:
 s=C.create_string_buffer(base);o=C.create_string_buffer(b'D'*512);w=C.create_string_buffer(4096);rc=render(s,len(base),o,outcap,w,workcap);assert rc==0xfffffffd and o.raw[:512]==b'D'*512;record('render-extent-'+str(outcap)+'-'+str(workcap),'private_guards')
s=C.create_string_buffer(base);struct.pack_into('<Q',s,16,1);o=C.create_string_buffer(b'D'*128);w=C.create_string_buffer(4096);rc=render(s,len(base),o,64,w,4096);assert rc==0xfffffffe and o.raw[:128]==b'D'*128;record('render-atomic-short','private_guards')
def snap(label,value,root=0,raw=None,group='snapshot'):
 if raw is None:raw=json.dumps(value,ensure_ascii=True,separators=(',',':')).encode()
 ar=arena(raw);values=[]
 def visit(v):
  values.append(v)
  if type(v) is dict:
   for item in v.values():visit(item)
  elif type(v) is list:
   for item in v:visit(item)
 visit(value);selected=values[root];error=None
 if type(selected)in(dict,list):
  try:got=_bounded_detached_snapshot(selected);assert got==selected
  except HIAProgramRejected as e:error=str(e)
 h=struct.pack('<8s15Q',b'HIANVS01',root,len(raw),len(ar),*([0]*12));packet=h+raw+ar;s=C.create_string_buffer(packet);o=C.create_string_buffer(b'D'*2080);wc=131072+struct.unpack_from('<Q',ar,8)[0];w=C.create_string_buffer(wc+32);C.memset(w,0xa5,len(w));rc=snapshot(s,len(packet),C.addressof(o)+16,2048,C.addressof(w)+16,wc)
 assert rc==0,(label,rc);out=o.raw[16:2064];got=struct.unpack_from('<8s15Q',out);assert got[0]==b'HIANVR01'and got[1]==int(error is not None),(label,got,error)
 if error is not None:
  err=json.loads(out[128:128+got[6]]);assert err['type']=='HIAProgramRejected'and err['message']==error,(label,err,error)
 assert o.raw[:16]+o.raw[2064:2080]==b'D'*32 and w.raw[:16]+w.raw[-16:]==b'\xa5'*32 and s.raw[:len(packet)]==packet
 record(label,group,error=error,nodes=struct.unpack_from('<Q',ar,8)[0],visited=got[4],queued=got[5])
 return packet,wc
atoms=[None,False,True,0,1,-1,0.0,-0.0,1.3,'','é','😀',[],{},float('nan'),float('inf'),float('-inf'),'\ud800','\udfff']
for i,v in enumerate(atoms):snap('snapshot-root-'+str(i),v)
for i,v in enumerate(atoms):snap('snapshot-nested-'+str(i),{'child':[v]})
for width in (262142,262143,262144,262145,1048577):snap('snapshot-width-'+str(width),[0]*width,group='snapshot_limits')
for depth in (63,64,65,66,300):
 value=0
 for _ in range(depth):value=[value]
 snap('snapshot-depth-'+str(depth),value,group='snapshot_limits')
snap('snapshot-left-first',[0.0,[0]*262144],group='snapshot_priority')
snap('snapshot-queued-before-left',[[0]*262143,0.0],group='snapshot_priority')
snap('snapshot-right-after-left',[[0]*262144,0.0],group='snapshot_priority')
snap('snapshot-irrelevant-nonfinite-sibling',{'bad':1.5,'selected':{'k':[True,1,None]}},2,group='snapshot_subtree')
snap('snapshot-child-string',{'outside':[0.0],'selected':'program'},3,group='snapshot_subtree')
for i in range(100):
 value=[rng.choice(atoms)for _ in range(rng.randrange(12))]
 snap('snapshot-random-'+str(i),value)
for i,value in enumerate((float('nan'),float('inf'),float('-inf'))):
 snap('capture-nonfinite-left-first-'+str(i),[value,[0]*262144],group='snapshot_priority')
 snap('capture-queued-before-nonfinite-'+str(i),[[0]*262143,value],group='snapshot_priority')
base,wc=snap('snapshot-guard-base',{'a':[1,2]})
for off,val in [(0,0),(8,U),(16,0),(24,0),(32,1),(120,1)]:
 damaged=bytearray(base);struct.pack_into('<Q',damaged,off,val);s=C.create_string_buffer(bytes(damaged));o=C.create_string_buffer(b'D'*2048);w=C.create_string_buffer(wc);rc=snapshot(s,len(damaged),o,2048,w,wc);assert rc==0xfffffffd and o.raw[:2048]==b'D'*2048,(off,rc);record('snapshot-guard-'+str(off),'private_guards')
report['passed']=True;report['count']=len(rows);save();print('RANK_REPORT_SNAPSHOT_PASS',len(rows),groups,flush=True)
