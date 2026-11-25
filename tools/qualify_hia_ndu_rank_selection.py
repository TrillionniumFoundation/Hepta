from pathlib import Path
from hashlib import sha256
import copy,ctypes as C,fcntl,json,os,random,resource,struct,sys,time
import argparse
parser=argparse.ArgumentParser();parser.add_argument('--flat',type=Path,required=True);parser.add_argument('--decoder',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
P=Path(__file__).resolve().parents[1];D=args.output;D.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from hepta.hia_ndu_scalar_selection import resolve_scalar_selection,ScalarSelectionRejected
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin
 fd=os.memfd_create('ndu-selection-component',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
 return C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
pin='e4c7125ccc6295fe7fea4188f096a5a65735923e9a8f4f70c7c482bde451271e'
entry=load(args.flat,pin)
decode=load(args.decoder,'bbb894c08d02cff36080a8dfa3eb3c6846ac1aa2095eb2851414585fb45c4f04')
jo=C.create_string_buffer(80<<20);jw=C.create_string_buffer(8<<20);ob=C.create_string_buffer(32768+96);wb=C.create_string_buffer((8<<20)+32)
def enc(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(x):return sha256(enc(x)).hexdigest()
def arena(raw):
 ib=C.create_string_buffer(raw);C.memset(jw,0,128);struct.pack_into('<QQ',jw,48,131073,128);struct.pack_into('<Q',jw,120,int.from_bytes(b'HIAJLG01','little'))
 used=decode(ib,len(raw),jo,len(jo),jw,len(jw));assert 64<=used<80<<20,('decode',used,raw[:100]);return jo.raw[:used]
def packet(q,r,qr=None,rr=None):
 qr=enc(q) if qr is None else qr;rr=enc(r) if rr is None else rr;qa=arena(qr);ra=arena(rr)
 return struct.pack('<8s7Q32s32s',b'HIANSQ01',len(qr),len(qa),len(rr),len(ra),0,0,0,bytes.fromhex(digest(q)),bytes.fromhex(digest(r)))+qr+qa+rr+ra
rows=[];counts={};report={'passed':False,'flat_sha256':pin,'whole_native_rank_closed':False,'native_evaluator_invoked':False,'scope':'Actual sealed HIA selection policy and actual native JSON decoder, compared to the original scalar caller resolver. Evaluator responses are labelled component fixtures; no process or image identity authority is claimed.','rows':rows,'counts':counts}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def run(label,q,r,group='semantic',qr=None,rr=None):
 data=packet(q,r,qr,rr);ib=C.create_string_buffer(data);C.memset(ob,0xdb,len(ob));C.memset(wb,0xa5,16);C.memset(C.addressof(wb)+len(wb)-16,0xa5,16)
 try:expected=resolve_scalar_selection(q,r);status=0
 except ScalarSelectionRejected as exc:expected={'type':type(exc).__name__,'message':str(exc)};status=1
 started=time.monotonic_ns();used=entry(ib,len(data),C.addressof(ob)+16,len(ob)-32,C.addressof(wb)+16,8<<20);elapsed=time.monotonic_ns()-started
 assert 64<=used<=len(ob)-32,(label,used,expected)
 assert ib.raw[:len(data)]==data and ob.raw[:16]+ob.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32,(label,'canary')
 magic,actual,n,index,feasible,frontier,source,reserved=struct.unpack('<8s7Q',ob.raw[16:80]);assert magic==b'HIANSR01' and reserved==0 and used==64+n and actual==status,(label,actual,status)
 result=json.loads(ob.raw[80:80+n]);assert result==expected,(label,result,expected)
 if status==0:
  assert q['candidates'][index]['id']==expected['selected_id']
  assert frontier==len(expected['validated_pareto_frontier']) and source in (1,2,3)
 rows.append({'case':label,'group':group,'passed':True,'status':status,'input_sha256':sha256(data).hexdigest(),'output_sha256':sha256(ob.raw[16:16+used]).hexdigest(),'elapsed_ns':elapsed});counts[group]=counts.get(group,0)+1
 if len(rows)%100==0:save();print('NDU_SELECTION_CASES',len(rows),flush=True)
def response(q):
 rows={x['id']:x for x in q['candidates']};feasible={k:v for k,v in rows.items() if not v['hard_violation'] and v['resource_q32']<=q['resource_cap_q32']}
 minimum=min(x['cost_q32'] for x in feasible.values());frontier=sorted(k for k,x in feasible.items() if x['cost_q32']==minimum)
 dispo='InfeasibleExplicitAbstain' if len(feasible)==1 else 'UniqueParetoRecommendation' if len(frontier)==1 else 'ParetoSetRequiresSlowPath'
 return {'request_sha256':digest(q),'objective_sha256':q['objective_sha256'],'generation':q['generation'],'advisory_recommendation':'abstain' if len(feasible)==1 else frontier[0] if len(frontier)==1 else None,'pareto_frontier':frontier,'rejected':[{'id':k,'reasons':'fixture hard/resource exclusion'} for k in sorted(set(rows)-set(feasible))],'disposition':dispo}
base={'schema':'hepta.hia.ndu-request.v1','objective_sha256':'a'*64,'generation':1,'resource_cap_q32':100,'candidates':[{'id':'abstain','cost_q32':100,'uncertainty_q32':0,'resource_q32':0,'hard_violation':False,'support_sha256':'b'*64},{'id':'A.z_0:-','cost_q32':50,'uncertainty_q32':0,'resource_q32':1,'hard_violation':False,'support_sha256':'c'*64}]}
run('baseline',base,response(base),'accepted')
rng=random.Random(2026112504);MAX=(1<<63)-1
for i in range(360):
 q=copy.deepcopy(base);q['generation']=rng.choice([1,2,(1<<63)-1,(1<<64)-1]);q['resource_cap_q32']=rng.choice([0,1,100,MAX]);q['candidates']=[]
 count=[1,2,3,31,32,127,128][i%7]
 for n in range(count):
  cid='abstain' if n==0 else rng.choice('AZaz')+str(n)+rng.choice('_.:-')+'end'
  q['candidates'].append({'id':cid,'cost_q32':rng.choice([0,1,10,100,MAX]),'uncertainty_q32':rng.choice([0,1,MAX]),'resource_q32':0 if n==0 else rng.choice([0,1,99,100,101,MAX]),'hard_violation':False if n==0 else bool(rng.randrange(2)),'support_sha256':sha256(str((i,n)).encode()).hexdigest()})
 rng.shuffle(q['candidates']);run('random-'+str(i),q,response(q),'accepted')
for value in [None,False,0,[],{},dict(base,extra=1)]:
 run('request-shape-'+str(len(rows)),value,response(base),'request_refusal')
for key in base:
 q=copy.deepcopy(base);del q[key];run('missing-request-'+key,q,response(base),'request_refusal')
for key,values in [('schema',[None,0,'hepta.hia.ndu-request.v2']),('objective_sha256',[None,False,'A'*64,'a'*63,'a'*65]),('generation',[None,True,False,0,-1,1.0,'1',1<<64]),('resource_cap_q32',[None,True,-1,0.0,'0',1<<63]),('candidates',[None,{},[],[{}]*129])]:
 for value in values:
  q=copy.deepcopy(base);q[key]=value;run('request-'+key+'-'+str(len(rows)),q,response(base),'request_refusal')
for value in [None,False,0,[],{},dict(base['candidates'][0],extra=0)]:
 q=copy.deepcopy(base);q['candidates'][1]=value;run('row-shape-'+str(len(rows)),q,response(base),'row_refusal')
for key in base['candidates'][1]:
 q=copy.deepcopy(base);del q['candidates'][1][key];run('missing-row-'+key,q,response(base),'row_refusal')
for key,values in [('id',[None,0,True,'','a'*65,'1a','_a','é','A/','a b','abstain']),('cost_q32',[None,True,-1,1.0,'0',1<<63]),('uncertainty_q32',[None,True,-1,1.0,'0',1<<63]),('resource_q32',[None,True,-1,1.0,'0',1<<63]),('hard_violation',[None,0,1,'false']),('support_sha256',[None,0,'B'*64,'a'*63,'a'*65])]:
 for value in values:
  q=copy.deepcopy(base);q['candidates'][1][key]=value;run('row-'+key+'-'+str(len(rows)),q,response(base),'row_refusal')
for change in ('missing','hard','resource'):
 q=copy.deepcopy(base)
 if change=='missing':q['candidates'][0]['id']='other'
 elif change=='hard':q['candidates'][0]['hard_violation']=True
 else:q['candidates'][0]['resource_q32']=101
 run('incumbent-'+change,q,response(base),'row_refusal')
for value in [None,False,0,[],{}]:
 run('response-shape-'+str(len(rows)),base,value,'response_refusal')
for key in response(base):
 r=response(base);del r[key];run('missing-response-'+key,base,r,'response_refusal')
for key,values in [('request_sha256',[None,'0'*64]),('objective_sha256',[None,'0'*64]),('generation',[None,True,1.0,'1',2]),('advisory_recommendation',[True,{},[],'','a'*65,'abstain','unknown',None]),('pareto_frontier',[None,{},[],['abstain'],['A.z_0:-','A.z_0:-'],[True]]),('rejected',[None,{},[{}]*129,[{}],[{'id':'unknown','reasons':'x'}],[{'id':'abstain','reasons':''}],[{'id':'abstain','reasons':True}],[{'id':'abstain','reasons':'x','extra':0}]]),('disposition',[None,0,'InfeasibleExplicitAbstain','ParetoSetRequiresSlowPath'])]:
 for value in values:
  r=response(base);r[key]=value;run('response-'+key+'-'+str(len(rows)),base,r,'response_refusal')
for variant in ('incumbent-tie','nonincumbent-tie','explicit-abstain'):
 q=copy.deepcopy(base)
 if variant=='incumbent-tie':q['candidates'][1]['cost_q32']=100
 elif variant=='nonincumbent-tie':q['candidates'].append(dict(q['candidates'][1],id='AA'))
 else:q['candidates'][1]['hard_violation']=True
 for disposition in ['InfeasibleExplicitAbstain','UniqueParetoRecommendation','ParetoSetRequiresSlowPath','other']:
  for recommend in ['abstain','A.z_0:-',None]:
   r=response(q);r['disposition']=disposition;r['advisory_recommendation']=recommend;run(variant+'-'+str(len(rows)),q,r,'disposition_priority')
q=copy.deepcopy(base);r=response(q);r['ignored']={'nested':['é','\x00',True,False,None,10**40,-0.0]};run('response-extra-fields',q,r,'accepted')
q=copy.deepcopy(base);q['candidates'][1]['cost_q32']=0;r=response(q);qr=enc(q).replace(b'"cost_q32":0',b'"cost_q32":-0');run('exact-negative-zero',q,r,'accepted',qr=qr)
# Large unknown response content is hashed by the caller; the policy still binds its known fields.
r=response(base);r['ignored']='z'*900000;run('large-response-extra',base,r,'accepted')
# Every valid result must be output-capacity atomic.
data=packet(base,response(base));ib=C.create_string_buffer(data)
for capacity in (0,1,63,64,127,512):
 C.memset(ob,0xdb,len(ob));used=entry(ib,len(data),C.addressof(ob)+16,capacity,C.addressof(wb)+16,8<<20);assert used==0xfffffffe and ob.raw==b'\xdb'*len(ob),(capacity,used)
 rows.append({'case':'atomic-short-output-'+str(capacity),'group':'private_guards','passed':True});counts['private_guards']=counts.get('private_guards',0)+1
for offset,value in [(0,0),(8,0),(16,0),(24,0),(32,0),(40,1),(48,1),(56,1)]:
 bad=bytearray(data);struct.pack_into('<Q',bad,offset,value);ib=C.create_string_buffer(bytes(bad));C.memset(ob,0xdb,len(ob));used=entry(ib,len(bad),C.addressof(ob)+16,len(ob)-32,C.addressof(wb)+16,8<<20);assert used==0xfffffffd and ob.raw==b'\xdb'*len(ob),(offset,used)
 rows.append({'case':'private-frame-'+str(offset),'group':'private_guards','passed':True});counts['private_guards']+=1
report.update(passed=True,count=len(rows),seed=2026112504,original_scalar_selection_used=True);save();print('NDU_SELECTION_ALL_PASS',len(rows),counts,flush=True)
