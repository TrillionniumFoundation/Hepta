from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,os,resource,struct,sys,itertools,copy,random,importlib.util
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');P=T/'ndu-rank-order-source';D=T/'ndu-rank-order-qualification-v1';D.mkdir(exist_ok=False)
sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
spec=importlib.util.spec_from_file_location('order_reference',T/'rank-order-reference-v1.py');ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin
 fd=os.memfd_create('rank-public-order',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
 at=lib.mmap(None,len(raw),5,2,fd,0);os.close(fd);assert at not in(None,C.c_void_p(-1).value)
 return C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(at)
render=load(T/'ndu-rank-order-v5/ndu_rank_report.flat','a77ae70414cb35efb80ce6b4988d6294f6b568dab5dd062b03e82afe1e2d0e1c')
decoder=load(Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-background-json-capture-v4/background_optimizer_json_capture.flat'),'62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f')
def enc(x,sort=False):return json.dumps(x,ensure_ascii=False,separators=(',',':'),sort_keys=sort,allow_nan=False).encode('utf-8','surrogatepass')
def arena(raw):
 s=C.create_string_buffer(raw);o=C.create_string_buffer(64);w=C.create_string_buffer(128)
 assert decoder(s,len(raw),o,64,w,128)==0
 h=struct.unpack('<8s7Q',o.raw);assert h[0]==b'HIANJS01'
 out=C.create_string_buffer(h[4]);work=C.create_string_buffer(h[5]);struct.pack_into('<QQ',work,48,h[1],h[3]);struct.pack_into('<QQ',work,96,h[2],1)
 assert decoder(s,len(raw),out,len(out),work,len(work))==0
 return out.raw[:struct.unpack_from('<Q',out,24)[0]]
def packet(raw,args,mode=0):
 a=arena(raw);b=arena(args);items=(raw,a,args,b)
 h=struct.pack('<8s95Q',b'HIANRP01',11,mode,4,*([0]*92));at=832;table=b''
 for item in items:table+=struct.pack('<QQ',at,len(item));at+=len(item)
 n=struct.unpack_from('<Q',a,8)[0];m=struct.unpack_from('<Q',b,8)[0]
 return h+table+b''.join(items),max(131072+max(n,m),16384+len(a)+n*16)
rows=[];groups={}
def record(label,group,**kw):
 rows.append({'case':label,'group':group,'passed':True,**kw});groups[group]=groups.get(group,0)+1
 if len(rows)%50==0:save();print('PUBLIC_ORDER_CASE',len(rows),label,flush=True)
def save():
 (D/'report.json').write_text(json.dumps({'passed':False,'whole_rank_closed':False,'count':len(rows),'groups':groups,'cases':rows},indent=2)+'\n')
def check(label,value,args,raw=None,expected=None,group='original_order'):
 if raw is None:raw=enc(value,True)
 parsed=json.loads(raw)
 if expected is None:expected=ref.result_order(parsed,args)
 data,wc=packet(raw,enc(args));s=C.create_string_buffer(data);o=C.create_string_buffer(b'Q'*96,96);w=C.create_string_buffer(wc+32);C.memset(w,0xa5,len(w))
 rc=render(s,len(data),C.addressof(o)+16,64,C.addressof(w)+16,wc);assert rc==0,(label,rc)
 h=struct.unpack_from('<8s7Q',o,16);assert h[:3]==(b'HIANPR01',len(enc(expected)),11)and h[3:]==(0,)*5,(label,h,len(enc(expected)))
 assert o.raw[:16]+o.raw[-16:]==b'Q'*32
 struct.pack_into('<Q',s,16,1);out=C.create_string_buffer(h[1]+96);C.memset(out,0x79,len(out));C.memset(w,0xab,len(w))
 rc=render(s,len(data),C.addressof(out)+16,len(out)-32,C.addressof(w)+16,wc);assert rc==0,(label,rc)
 got=out.raw[80:80+h[1]];actual=json.loads(got);assert actual==parsed
 ref.assert_order(actual,expected)
 assert enc(actual,True)==enc(parsed,True),(label,'canonical digest input changed')
 assert sha256(enc(actual['native_request'],True)).hexdigest()==actual['request_sha256']if'candidate_reports'in actual else True
 assert out.raw[:16]+out.raw[-16:]==b'y'*32
 assert w.raw[:16]+w.raw[-16:]==b'\xab'*32
 assert s.raw[:16]+s.raw[24:len(data)]==data[:16]+data[24:]
 record(label,group,bytes=len(got),sha256=sha256(got).hexdigest())
 return data,wc
value=json.loads((T/'ndu-rank-engine-qualification-v1/native-engine-one-proved.actual.json').read_bytes())
original_obs=value['candidate_reports'][0]['observation']
keys=('runtime_ns','uncertainty_ns','search_ns','program_sha256')
for i,perm in enumerate(itertools.permutations(keys)):
 args={'observations':{'A':{k:original_obs[k]for k in perm},'abstain':{k:original_obs[k]for k in reversed(perm)}}}
 check('all-observation-permutations-'+str(i),value,args)
args={'observations':{'A':{k:original_obs[k]for k in keys}}}
# All candidate source branches; values are format fixtures, not proof admission.
for reason in range(8):
 v=copy.deepcopy(value);r=v['candidate_reports'][0]
 if reason<2:
  for key in('preproof_cost_lower_bound_ns','proof_remaining_budget_ns','proof_remaining_margin_ns','proof_timeout_ms','proof_wall_ns'):r.pop(key,None)
 elif reason<6:
  for key in('proof_timeout_ms','proof_wall_ns'):r.pop(key,None)
 if reason==0:r['detail']='E_HIA_LIMIT: fixture';r['core_verified']=False
 if reason<6:r['proof']=None;r['equivalence_proved']=False
 # This pure transport does not recalculate source-owned support digests.
 check('candidate-original-branch-'+str(reason),v,args,group='candidate_branches')
# Render the actual original unknown receipt, including its optional error order.
for mode in range(6):
 p=ref.translation._receipt('calculate',2000)
 if mode&1:p['validation_error']={'code':'E_TEST','message':'error'}
 if mode&2:p['error_type']='ValueError'
 if mode&4:p['wall_ns']=123
 p=ref.contract.finish_scalar_proof(p,{'name':'validate_translation','source_identity':{}})
 if mode==4:p['solver']['query_preprocessing']=ref.translation._partition_entry_equality(None,None,[],[],None)[1]
 if mode==5:
  p['solver']['query_preprocessing']={'strategy':'exhaustive_entry_input_equality_split','parameter_index':0,'type':'u64','value':3,'input_assumptions':[],'partition_count':2}
  p['counterexample']={'arguments':[1],'parameter_types':['u64'],'before':{'status':'returned','values':[1]},'after':{'status':'trapped','code':'user'}}
 v=copy.deepcopy(value);v['candidate_reports'][0]['proof']=p;v['selected_fresh_proof']=copy.deepcopy(p)
 check('original-proof-formatter-'+str(mode),v,args,group='proof_formatters')
# Arbitrary unknown maps and scalars retain their existing captured order/lexeme.
for i,extra in enumerate([{'z':[1,{'y':2,'x':3}],'a':False},{'é':'\ud800','😀':None},{'q':-0.0,'e':1e100}, {'x':'a'*(9<<20)}]):
 v={'outside':extra};raw=enc(v);check('unknown-map-'+str(i),v,{},raw=raw,expected=v,group='unknown_large')
# Hash collisions do not assign a known label without full key equality.
def bucket(s):
 h=14695981039346656037
 for b in s.encode():h=((h^b)*1099511628211)&((1<<64)-1)
 return h&511
collisions=[];i=0
while len(collisions)<30:
 key='unknown'+str(i)
 if bucket(key)==bucket('schema'):collisions.append(key)
 i+=1
v={k:{'right':2,'left':1}for k in collisions};check('exact-key-collisions',v,{},raw=enc(v),expected=v,group='exact_keys')
base,wc=check('guard-base',value,args)
def refused(label,data,oc=1024,wn=wc,code=0xfffffffd):
 s=C.create_string_buffer(data);o=C.create_string_buffer(b'D'*max(1024,oc),max(1024,oc));w=C.create_string_buffer(max(wn,1));rc=render(s,len(data),o,oc,w,wn)
 assert rc==code and o.raw==b'D'*len(o),(label,rc,code)
 record(label,'private_guards')
for off,val in [(0,0),(8,12),(16,2),(24,3),(32,1),(760,1),(768,0),(776,(1<<64)-1),(784,0),(808,0),(816,0)]:
 b=bytearray(base);struct.pack_into('<Q',b,off,val);refused('bad-header-'+str(off),bytes(b))
for data in(b'',base[:831],base[:-1],base+b'x'):refused('bad-extent-'+str(len(data)),data)
for oc,wn in[(63,wc),(0,wc),(1024,0),(1024,131071),(1024,wc-1)]:refused('bad-view-'+str(oc)+'-'+str(wn),base,oc,wn)
b=bytearray(base);struct.pack_into('<Q',b,16,1);refused('short-output-atomic',bytes(b),64,wc,0xfffffffe)
# Structurally forged arenas are rejected before output; no trusting caller links.
aoff=struct.unpack_from('<Q',base,784)[0]
for rel,val in[(0,0),(8,0),(16,1),(24,(1<<64)-1),(64,5),(64+72+8,999999),(64+72+40,(1<<64)-1)]:
 b=bytearray(base);struct.pack_into('<Q',b,aoff+rel,val);refused('bad-arena-'+str(rel),bytes(b))
save();report=json.loads((D/'report.json').read_text());report.update(passed=True,scope='Actual new report action11. Expected common key order comes from original rank AST, original scalar proof formatter, and original scalar selection. All original values and canonical digest bytes remain exact. No proof outcome is inferred by this serializer test.',report_flat_bytes=368061,report_flat_sha256='a77ae70414cb35efb80ce6b4988d6294f6b568dab5dd062b03e82afe1e2d0e1c');(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PUBLIC_ORDER_PURE_PASS',len(rows),groups,flush=True)
