from pathlib import Path
from hashlib import sha256
import ast,copy,ctypes as C,fcntl,inspect,json,math,os,random,resource,struct,subprocess,sys,time
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');P=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-multiversion-proof-source');B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');D=T/'ndu-rank-admission-staged-qualification-v3';D.mkdir(exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
import hepta.hia_ndu_optimizer as original
from hepta.hia_program import verify_program
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin
 fd=os.memfd_create('native-ndu-admission-component',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
 return C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
pin='18c70f0fb94c80d386b3f5eabb6accef4989c78cb4f4f76b93b27126f2aab2e1'
entry=load(T/'ndu-rank-admission-staged-v2/ndu_rank_admission.flat',pin)
decoder=load(T/'facade-image-v5/inputs/native_public_proof_json','bbb894c08d02cff36080a8dfa3eb3c6846ac1aa2095eb2851414585fb45c4f04')
binary64=load(T/'ndu-rank-binary64-v1/agent_binary64.flat','9184c68f231af5e42a0b2a419700d0601390fbbe4942387777d80e55f012559a')
jo=C.create_string_buffer(80<<20);jw=C.create_string_buffer(8<<20);ob=C.create_string_buffer(8192+32);wb=C.create_string_buffer((8<<20)+32);bo=C.create_string_buffer(8);bw=C.create_string_buffer(4096)
def enc(x):return json.dumps(x,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def arena(raw):
 ib=C.create_string_buffer(raw);C.memset(jw,0,128);struct.pack_into('<QQ',jw,48,131073,128);struct.pack_into('<Q',jw,120,int.from_bytes(b'HIAJLG01','little'));n=decoder(ib,len(raw),jo,len(jo),jw,len(jw));assert 64<=n<80<<20;return jo.raw[:n]
baseline=(B/'native-multiversion-prepare-process-v4/normalizer-samples/primitive.input').read_bytes();before=verify_program(baseline)
native=(T/'normalizer-84619bd.bin').read_bytes();assert sha256(native).hexdigest()=='84619bd15d8408f52c04519af11664cc4fa52cac352e7ad6680b6d50429123c6'
fd=os.memfd_create('actual-baseline-normalizer',os.MFD_ALLOW_SEALING);os.write(fd,native);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
r=subprocess.run(['hia-admit-agent-json'],executable='/proc/self/fd/'+str(fd),input=baseline,capture_output=True,pass_fds=(fd,),env={'PATH':''},timeout=120);(D/'normalizer.stdout').write_bytes(r.stdout);(D/'normalizer.stderr').write_bytes(r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr)
(D/'normalizer.stdout').write_bytes(r.stdout);h=struct.unpack_from('<8s7Q',r.stdout);assert h[0]==b'HIAVCF01';core=r.stdout[64+h[4]:];assert core==before.canonical_bytes;ca=arena(core)
# Extract original statements without reimplementing their conditions or ordering.
fn=ast.parse(inspect.getsource(original.rank_candidates)).body[0]
stop=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='ns_to_ms_q32')
prefix=copy.deepcopy(fn);prefix.name='reference_options';prefix.body=prefix.body[:stop]+[ast.parse("return {'generation':generation,'timeout_ms':timeout_ms,'bridge_timeout_s':bridge_timeout_s,'calls':calls,'cap':cap}").body[0]]
cstart=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.If) and 'type(candidates)' in ast.unparse(n.test))
cbody=copy.deepcopy(fn.body[cstart:cstart+3]);assert isinstance(cbody[-1],ast.For)
cut=next(i for i,n in enumerate(cbody[-1].body) if isinstance(n,ast.Try));cbody[-1].body=cbody[-1].body[:cut]
candidate_ref=ast.parse('def reference_candidates(candidates):\n return None\n').body[0];candidate_ref.body=cbody+[ast.parse('return seen').body[0]]
ostart=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.If) and 'type(observations)' in ast.unparse(n.test))
ostop=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='base_lower' for t in n.targets))
observation_ref=ast.parse('def reference_observations(before,candidates,observations):\n return None\n').body[0];observation_ref.body=ast.parse("seen={'abstain'} | {c['id'] for c in candidates}").body+copy.deepcopy(fn.body[ostart:ostop])+ast.parse("return {'observed':observed,'total':supplied_search_ns}").body
freeze_stop=next(i for i,n in enumerate(fn.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='objective'for t in n.targets))
pre=copy.deepcopy(fn);pre.name='reference_before_freeze';pre.body=pre.body[:freeze_stop]+[ast.parse('return True').body[0]]
tree=ast.fix_missing_locations(ast.Module(body=[prefix,candidate_ref,observation_ref,pre],type_ignores=[]));source=ast.unparse(tree);(D/'original-reference-fragments.py').write_text(source);scope=dict(vars(original));exec(compile(tree,'unchanged-original-rank-statements','exec'),scope)
def packet(args,action,index=0,bits=0,invalid=0):
 raw=enc(args);aa=arena(raw);head=bytearray(128);struct.pack_into('<8s7Q',head,0,b'HIANRA01',action,index,len(raw),len(aa),len(core),len(ca),bits);head[64:96]=bytes.fromhex(before.sha256);struct.pack_into('<Q',head,96,invalid);return bytes(head)+raw+aa+core+ca,raw
calls=0
def invoke(args,action,index=0,bits=0,invalid=0):
 global calls
 data,raw=packet(args,action,index,bits,invalid);ib=C.create_string_buffer(data);C.memset(ob,0xdb,len(ob));C.memset(wb,0xa5,16);C.memset(C.addressof(wb)+len(wb)-16,0xa5,16)
 started=time.monotonic_ns();n=entry(ib,len(data),C.addressof(ob)+16,8192,C.addressof(wb)+16,8<<20);elapsed=time.monotonic_ns()-started;calls+=1
 assert n==8192,(action,index,n)
 assert ib.raw[:len(data)]==data and ob.raw[:16]+ob.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32
 out=ob.raw[16:8208];assert out[:8]==b'HIANDR01'
 words=struct.unpack_from('<32Q',out);error=None
 if words[1]==1:error=json.loads(out[1024:1024+words[31]])
 return words,out,error,raw,elapsed
base={'candidates':[{'id':'A','action':'identity','program':json.loads(baseline)},{'id':'B','action':'second','program':json.loads(baseline)}],'observations':{},'function':'calculate','bridge':{'binary':'/not-used','build_receipt':'/not-used'},'objective':{'expected_calls':1,'resource_cap_ns':1_000_000_000,'target':'host','measurement_profile':'measure'},'generation':1,'timeout_ms':2000,'bridge_timeout_s':10.0}
for cid in ['abstain','A','B']:base['observations'][cid]={'runtime_ns':100000,'uncertainty_ns':1,'search_ns':0,'program_sha256':before.sha256}
rows=[];counts={};report={'passed':False,'flat_sha256':pin,'whole_native_rank_closed':False,'native_evaluator_invoked':False,'scope':'Actual HIA typed admission with native decoder, native decimal-to-binary64 and a genuinely normalized baseline; comparisons use unchanged original option/candidate/observation statements cut at the next orchestration boundary. Canonical candidate verification, identity, proof and process composition remain separate.','original_source_sha256':sha256((P/'hepta/hia_ndu_optimizer.py').read_bytes()).hexdigest(),'original_fragment_sha256':sha256(source.encode()).hexdigest(),'rows':rows,'counts':counts}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def observe(label,args,stage):
 if stage==0:
  try:scope['reference_before_freeze'](baseline,args.get('candidates'),args.get('observations'),function=args.get('function'),bridge=args.get('bridge'),objective=args.get('objective'),generation=args.get('generation',1),timeout_ms=args.get('timeout_ms',2000),bridge_timeout_s=args.get('bridge_timeout_s',10.0))
  except original.OptimizationRejected as exc:pre_error={'type':type(exc).__name__,'message':str(exc)}
  else:pre_error=None
  prewords,preout,preactual,preraw,_=invoke(args,4)
  if prewords[1]==2:
   t=preraw[prewords[21]:prewords[21]+prewords[22]];bs=C.create_string_buffer(t);bc=binary64(bs,len(t),bo,8,bw,4096);bits=struct.unpack('<Q',bo.raw)[0]if bc==8 else 0
   prewords,preout,preactual,_,_=invoke(args,5,bits=bits,invalid=int(bc!=8))
  assert preactual==pre_error and (pre_error is not None or prewords[1]==4),(label,preactual,pre_error,prewords[1])
  rows.append({'case':'before-freeze-'+label,'group':'before_freeze','passed':True,'status':prewords[1],'error':preactual});counts['before_freeze']=counts.get('before_freeze',0)+1
 expected=None
 try:
  if stage==0:expected=scope['reference_options'](baseline,args.get('candidates'),args.get('observations'),function=args.get('function'),bridge=args.get('bridge'),objective=args.get('objective'),generation=args.get('generation',1),timeout_ms=args.get('timeout_ms',2000),bridge_timeout_s=args.get('bridge_timeout_s',10.0))
  elif stage==2:expected=scope['reference_candidates'](args.get('candidates'))
  else:expected=scope['reference_observations'](before,args['candidates'],args.get('observations'))
 except original.OptimizationRejected as exc:expected_error={'type':type(exc).__name__,'message':str(exc)}
 else:expected_error=None
 started=time.monotonic_ns()
 if stage==0:
  words,out,error,raw,elapsed=invoke(args,0)
  if words[1]==2:
   text=raw[words[21]:words[21]+words[22]];ib=C.create_string_buffer(text);result=binary64(ib,len(text),bo,8,bw,4096);bits=struct.unpack('<Q',bo.raw)[0] if result==8 else 0
   words,out,error,_,elapsed=invoke(args,1,bits=bits,invalid=int(result!=8))
  if expected_error is None:
   assert words[1]==0 and words[4]==expected['generation'] and words[5]==expected['timeout_ms'] and words[6]==expected['calls'] and words[7]==expected['cap'],(label,words,expected)
   assert words[8]==struct.unpack('<Q',struct.pack('<d',expected['bridge_timeout_s']))[0] and words[9]==int(type(expected['bridge_timeout_s'])is int),(label,words[8:10],expected)
   assert out[512:512+words[12]]==args['function'].encode()
 elif stage==2:
  for index in range(34):
   words,out,error,raw,elapsed=invoke(args,2,index=index)
   if words[1] in(1,3):break
   row=args['candidates'][index];assert words[1]==0 and words[10]==len(args['candidates'])
   value=json.loads(raw[words[21]:words[21]+words[22]]);assert value==row['program'],(label,index,value,row['program'])
  if expected_error is None:assert words[1]==3 and words[10]==len(args['candidates'])
 else:
  words,out,error,raw,elapsed=invoke(args,3)
  if expected_error is None:
   assert words[1]==0 and words[27]==expected['total']
   for index,cid in enumerate(['abstain']+[c['id'] for c in args['candidates']]):
    values=struct.unpack_from('<12Q',out,2048+index*96);row=expected['observed'][cid];assert values[1:4]==(row['runtime_ns'],row['uncertainty_ns'],row['search_ns']),(label,cid,values,row)
 assert error==expected_error,(label,error,expected_error)
 group=('options','candidates','observations')[{0:0,2:1,3:2}[stage]];counts[group]=counts.get(group,0)+1;rows.append({'case':label,'group':group,'passed':True,'status':words[1],'error':error,'elapsed_ns':time.monotonic_ns()-started})
 if len(rows)%100==0:save();print('NDU_ADMISSION_CASES',len(rows),flush=True)
for field,values in [('function',[None,True,0,[],{},'', 'é','calculate','a'*128,'a'*129]),('generation',[None,True,False,0,-1,1,2,1.0,'1',(1<<64)-1,1<<64,10**500]),('timeout_ms',[None,True,0,-1,1,5000,5001,1.0,'1']),('bridge_timeout_s',[None,True,False,0,-1,1,60,61,0.0,-0.0,1e-300,1e-9,0.1,59.99999999999999,60.0,60.00000000000001,'10',[],{}]),('objective',[None,True,[],{},dict(base['objective'],extra=1)])]:
 for value in values:
  args=copy.deepcopy(base);args[field]=value;observe(field+'-'+str(len(rows)),args,0)
for key in ('generation','timeout_ms','bridge_timeout_s'):
 args=copy.deepcopy(base);del args[key];observe('default-'+key,args,0)
for field,values in [('expected_calls',[None,True,0,-1,1,(1<<63)-1,1<<63,1.0,'1']),('resource_cap_ns',[None,True,-1,0,(1<<63)-1,1<<63,0.0,'0']),('target',[None,True,'','a'*256,'a'*257,'😀'*256,'😀'*257]),('measurement_profile',[None,{},'','é'*256,'é'*257])]:
 for value in values:
  args=copy.deepcopy(base);args['objective'][field]=value;observe('objective-'+field+'-'+str(len(rows)),args,0)
rng=random.Random(2026112505)
for i in range(200):
 args=copy.deepcopy(base);args['generation']=rng.randrange(1,1<<64);args['timeout_ms']=rng.randrange(1,5001);args['bridge_timeout_s']=rng.uniform(1e-30,60);args['objective']['expected_calls']=rng.randrange(1,1<<63);args['objective']['resource_cap_ns']=rng.randrange(1<<63);observe('random-options-'+str(i),args,0)
for a,b in [('function','generation'),('generation','timeout_ms'),('timeout_ms','bridge_timeout_s'),('bridge_timeout_s','objective')]:
 args=copy.deepcopy(base);args[a]=None;args[b]=None;observe('priority-'+a+'-'+b,args,0)
for value in [None,True,{},[],[base['candidates'][0]]*33]:
 args=copy.deepcopy(base);args['candidates']=value;observe('candidate-list-'+str(len(rows)),args,2)
for value in [None,True,[],{},dict(base['candidates'][1],extra=1)]:
 args=copy.deepcopy(base);args['candidates'][1]=value;observe('candidate-shape-'+str(len(rows)),args,2)
for key in ['id','action','program']:
 args=copy.deepcopy(base);del args['candidates'][1][key];observe('missing-candidate-'+key,args,2)
for key,values in [('id',[None,True,'','abstain','A','1a','_a','a b','é','z'*64,'z'*65,'A.z_0:-']),('action',[None,True,[],{},'','x'*256,'x'*257,'😀'*256,'😀'*257]),('program',[None,True,[],{},'{}',0,1.0,{'raw':'unverified'}])]:
 for value in values:
  args=copy.deepcopy(base);args['candidates'][1][key]=value;observe('candidate-'+key+'-'+str(len(rows)),args,2)
for n in (0,1,2,31,32):
 args=copy.deepcopy(base);args['candidates']=[{'id':'C'+str(i),'action':'a','program':json.loads(baseline)} for i in range(n)];observe('candidate-count-'+str(n),args,2)
for value in [None,True,[],{},dict(base['observations'],extra={})]:
 args=copy.deepcopy(base);args['observations']=value;observe('observations-shape-'+str(len(rows)),args,3)
for value in [None,True,[],{},dict(base['observations']['A'],extra=0)]:
 args=copy.deepcopy(base);args['observations']['A']=value;observe('observation-row-'+str(len(rows)),args,3)
for key in ['runtime_ns','uncertainty_ns','search_ns','program_sha256']:
 args=copy.deepcopy(base);del args['observations']['A'][key];observe('missing-observation-'+key,args,3)
for key,values in [('runtime_ns',[None,True,-1,0,(1<<63)-1,1<<63,1.0,'0']),('uncertainty_ns',[None,True,-1,(1<<63)-1,1<<63,1.0,'0']),('search_ns',[None,True,-1,(1<<63)-1,1<<63,1.0,'0']),('program_sha256',[None,True,'A'*64,'f'*63,'f'*65,'0'*64])]:
 for value in values:
  args=copy.deepcopy(base);args['observations']['A'][key]=value;observe('observation-'+key+'-'+str(len(rows)),args,3)
args=copy.deepcopy(base);args['observations']['abstain']['program_sha256']='0'*64;observe('baseline-binding',args,3)
for n in(1,2,32):
 args=copy.deepcopy(base);args['candidates']=[{'id':'C'+str(i),'action':'a','program':json.loads(baseline)}for i in range(n)];args['observations']={cid:{'runtime_ns':(1<<63)-1,'uncertainty_ns':0,'search_ns':(1<<63)-1,'program_sha256':before.sha256} for cid in ['abstain']+[c['id']for c in args['candidates']]}
 observe('aggregate-overflow-'+str(n),args,3)
 args['observations']['abstain']['program_sha256']='0'*64;observe('binding-before-overflow-'+str(n),args,3)
for i in range(100):
 args=copy.deepcopy(base)
 for row in args['observations'].values():
  row['runtime_ns']=rng.randrange(1<<63);row['uncertainty_ns']=rng.randrange(1<<63);row['search_ns']=rng.randrange(1<<60)
 items=list(args['observations'].items());rng.shuffle(items);args['observations']=dict(items);observe('random-observations-'+str(i),args,3)
# Whole-call source buffers remain immutable; private refusal never writes output.
data,_=packet(base,0)
for off,value in [(0,0),(8,6),(16,1),(24,0),(32,0),(40,0),(48,0),(56,1),(96,1),(104,1),(112,1),(120,1)]:
 damaged=bytearray(data);struct.pack_into('<Q',damaged,off,value);ib=C.create_string_buffer(bytes(damaged));C.memset(ob,0xdb,len(ob));result=entry(ib,len(damaged),C.addressof(ob)+16,8192,C.addressof(wb)+16,8<<20);assert result==0xfffffffd and ob.raw==b'\xdb'*len(ob),(off,result)
 rows.append({'case':'private-frame-'+str(off),'group':'private_guards','passed':True});counts['private_guards']=counts.get('private_guards',0)+1
report.update(passed=True,count=len(rows),actual_hia_admission_calls=calls,seed=2026112505);save();print('NDU_ADMISSION_ALL_PASS',len(rows),counts,calls,flush=True)
