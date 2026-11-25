from pathlib import Path
from hashlib import sha256
import ast,copy,ctypes as C,fcntl,inspect,json,math,os,random,resource,struct,subprocess,sys,time
import argparse
cli=argparse.ArgumentParser(description='Qualify exact NDU response and fresh proof bindings through actual HIA execution.')
for flag in ('flat','decoder','evaluator','evaluator-receipt','proof','baseline','output'):
 cli.add_argument('--'+flag,required=True)
args=cli.parse_args()
P=Path(__file__).resolve().parents[1];D=Path(args.output);D.mkdir(exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
import hepta.hia_ndu_optimizer as original
from hepta.hia_program import verify_program
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
def seal(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin
 fd=os.memfd_create('actual-rank-binding-component',os.MFD_ALLOW_SEALING);at=0
 while at<len(raw):at+=os.write(fd,raw[at:])
 os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);return fd,len(raw)
def load(path,pin):
 fd,n=seal(path,pin);address=lib.mmap(None,n,5,2,fd,0);assert address not in(None,C.c_void_p(-1).value);return C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
entry=load(Path(args.flat),'d8b8b223bbace19a922d15eb6b150c1e27a0f6453161e8e2de7ee90a33702cbd')
decoder=load(Path(args.decoder),'2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144')
# Original response checks are unchanged except the explicitly migrated HIA
# schema/entry identity and required reference_entry_point provenance field.
source=inspect.getsource(original._validate_native_rank_response);tree=ast.parse(source)
class Identity(ast.NodeTransformer):
 def visit_Constant(self,n):
  if n.value=='hepta.hia.ndu-response.v1':n.value='hepta.hia.ndu-native-response.v1'
  elif n.value=='codex_hepta_ndu::evaluate_candidates_with_policy':n.value='hepta.hia.ndu_evaluator.v1'
  return n
tree=Identity().visit(tree)
assignment=next(n for n in tree.body[0].body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='expected'for t in n.targets))
assignment.value.keys.append(ast.Constant('reference_entry_point'));assignment.value.values.append(ast.Constant('codex_hepta_ndu::evaluate_candidates_with_policy'))
reference=ast.unparse(ast.fix_missing_locations(tree));(D/'reference-source.py').write_text(reference+'\n');scope=dict(original.__dict__);exec(compile(tree,'reference-source.py','exec'),scope);oracle=scope['_validate_native_rank_response']
def enc(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
rows=[];groups={};nativecalls=[];report={'passed':False,'whole_native_rank_closed':False,'flat_sha256':'d8b8b223bbace19a922d15eb6b150c1e27a0f6453161e8e2de7ee90a33702cbd','reference_sha256':sha256((reference+'\n').encode()).hexdigest(),'identity_migration_only':['schema','entry_point','reference_entry_point'],'scope':'Actual HIA binding role, fresh native public proof and actual sealed HIA NDU evaluator outputs. Mutation fixtures test rejection and are not evaluator outputs. This is not native-owner identity/process or complete-rank qualification.','rows':rows,'groups':groups,'actual_native_evaluator_calls':nativecalls}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def record(label,group,**kw):
 rows.append({'case':label,'group':group,'passed':True,**kw});groups[group]=groups.get(group,0)+1
 if len(rows)%100==0:save();print('NDU_BINDING_CASE',len(rows),label,flush=True)
def arena(raw):
 ib=C.create_string_buffer(raw);out=C.create_string_buffer(64);work=C.create_string_buffer(128);assert decoder(ib,len(raw),out,64,work,128)==0;h=struct.unpack('<8s7Q',out.raw)
 ob=C.create_string_buffer(h[4]);wb=C.create_string_buffer(h[5]);struct.pack_into('<QQ',wb,48,h[1],h[3]);struct.pack_into('<QQ',wb,96,h[2],1);rc=decoder(ib,len(raw),ob,len(ob),wb,len(wb));assert rc==0,(rc,raw[:100]);return ob.raw[:struct.unpack_from('<Q',ob,24)[0]]
def invoke(data):
 ib=C.create_string_buffer(data);ob=C.create_string_buffer(4128);C.memset(ob,0xdb,len(ob));wb=C.create_string_buffer((4<<20)+32);C.memset(wb,0xa5,16);C.memset(C.addressof(wb)+len(wb)-16,0xa5,16)
 rc=entry(ib,len(data),C.addressof(ob)+16,4096,C.addressof(wb)+16,4<<20);assert rc==0,(rc,len(data));assert ib.raw[:len(data)]==data and ob.raw[:16]+ob.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32
 h=struct.unpack('<8s15Q',ob.raw[16:144]);assert h[0]==b'HIANBDR1' and h[5:]==(0,)*11,h
 return h,json.loads(ob.raw[144:144+h[4]])if h[4]else None
identity={'upstream_commit':'d3c2d760eca5065fc966820379c35c6e8d56e855'}
def response_case(label,request,response=None,raw=None,group='response_mutations'):
 request_raw=enc(request);raw=enc(response)if raw is None else raw;qa=arena(request_raw);ra=arena(raw);header=bytearray(256);header[:8]=b'HIANBD01';struct.pack_into('<6Q',header,8,1,len(request_raw),len(qa),len(raw),len(ra),request['generation']);header[64:96]=sha256(request_raw).digest();data=bytes(header)+request_raw+qa+raw+ra
 try:oracle(request,request_raw,raw,identity);expected=None
 except Exception as e:expected={'type':type(e).__name__,'message':str(e)}
 h,actual=invoke(data);assert actual==expected,(label,h,actual,expected)
 assert h[1]==(0 if expected is None else 2 if expected['type']=='TypeError'else 1)and h[2]==int(expected is None)
 record(label,group,status=h[1],error=actual);return data
receipt=json.loads(Path(args.evaluator_receipt).read_text());assert receipt['binary_sha256']=='7dbe3f18f329be0124ba1af55bad4358654262e1b0503a7745b56b9f3b76057e'
for name,pin in receipt['source_files'].items():assert sha256((P/name).read_bytes()).hexdigest()==pin,name
leaf,n=seal(Path(args.evaluator),receipt['binary_sha256'])
def evaluate(label,request):
 raw=enc(request);r=subprocess.run(['/proc/self/fd/'+str(leaf)],input=raw,capture_output=True,pass_fds=(leaf,),env={'PATH':''},timeout=10);assert r.returncode==0 and not r.stderr,(label,r.returncode,r.stderr)
 result=json.loads(r.stdout);nativecalls.append({'case':label,'request_sha256':sha256(raw).hexdigest(),'stdout_sha256':sha256(r.stdout).hexdigest(),'stdout_bytes':len(r.stdout)})
 response_case(label,request,raw=r.stdout,group='actual_evaluator');return result
request={'schema':'hepta.hia.ndu-request.v1','objective_sha256':'1'*64,'generation':1,'resource_cap_q32':1000,'candidates':[{'id':'abstain','cost_q32':400,'uncertainty_q32':10,'resource_q32':0,'hard_violation':False,'support_sha256':'2'*64},{'id':'A','cost_q32':200,'uncertainty_q32':20,'resource_q32':10,'hard_violation':False,'support_sha256':'3'*64},{'id':'B','cost_q32':100,'uncertainty_q32':0,'resource_q32':20,'hard_violation':True,'support_sha256':'4'*64}]}
response=evaluate('actual-base',request)
for generation in (1,2,(1<<32)-1,1<<32,(1<<53)-1,1<<53,(1<<53)+1,(1<<63)-1,(1<<64)-1):
 q=copy.deepcopy(request);q['generation']=generation;ans=evaluate('actual-generation-'+str(generation),q)
 for value in (float(generation),True,False,0,1.0,generation):
  changed=copy.deepcopy(ans);changed['generation']=value;response_case('numeric-generation-'+str(generation)+'-'+str(value),q,changed,group='python_numeric_equality')
for count in (1,2,32,128):
 q=copy.deepcopy(request);q['candidates']=[dict(request['candidates'][0],id='abstain')]+[dict(request['candidates'][1],id='C'+str(i),cost_q32=i)for i in range(count-1)];evaluate('actual-row-count-'+str(count),q)
fields=['schema','upstream_commit','entry_point','reference_entry_point','objective_sha256','generation','request_sha256','authority','proves_program_safety','global_optimality_established','evaluation_digest_v2','evaluation_policy_digest','utility_profile_digest','advisory_recommendation']
for key in fields:
 changed=copy.deepcopy(response);del changed[key];response_case('missing-'+key,request,changed)
 for value in (None,False,True,0,1,0.0,1.0,'','bad',[],{},'A'*64):
  changed=copy.deepcopy(response);changed[key]=value;response_case('field-'+key+'-'+str(len(rows)),request,changed)
for key in ('proves_program_safety','global_optimality_established'):
 for token in (b'-0',b'0.0',b'-0.0',b'1e-9999',b'1e309',b'-1e309',b'1.0',b'-1'):
  changed=copy.deepcopy(response);changed[key]='__NUMBER__';raw=enc(changed).replace(b'"__NUMBER__"',token);response_case('numeric-false-'+key+'-'+token.decode(),request,raw=raw,group='python_numeric_equality')
for value in ('abstain','A','B','missing',None,[],{}):
 changed=copy.deepcopy(response);changed['advisory_recommendation']=value;response_case('recommendation-'+str(len(rows)),request,changed)
for error_key in ('schema','evaluation_digest_v2'):
 for recommendation in ([],{},'B'):
  changed=copy.deepcopy(response);changed[error_key]='bad';changed['advisory_recommendation']=recommendation;response_case('priority-'+error_key+'-'+str(len(rows)),request,changed)
changed=copy.deepcopy(response);changed['ignored_padding']='z'*900000;response_case('large-unknown-response-field',request,changed,group='large_response')
for value in (None,True,1,[],{}):response_case('nonobject-response-'+str(len(rows)),request,value)
# A genuinely fresh native translation proof, with expected original identity fields.
valid=Path(args.baseline).read_bytes();before=verify_program(valid)
proof_fd,n=seal(Path(args.proof),'744900be77472942723f0f9b3d640825cb48a75ae5bcb4a166092a0ddf0dc4f6')
name=b'calculate';packet=struct.pack('<8s7Q',b'HIAPPR01',2,2000,len(name),len(valid),len(valid),0,0)+name+valid+valid
r=subprocess.run(['/proc/self/fd/'+str(proof_fd)],input=packet,capture_output=True,pass_fds=(proof_fd,),env={'PATH':''},timeout=75);assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr);(D/'actual-proof.stdout').write_bytes(r.stdout);proof=json.loads(r.stdout[64:]);assert proof['status']=='proved'
expected={'schema':original.PROOF_SCHEMA,'profile':original.PROOF_PROFILE,'status':'proved','scope':'selected_public_scalar_function','function':'calculate','before_sha256':before.sha256,'after_sha256':before.sha256,'before_input_sha256':before.input_sha256,'after_input_sha256':before.input_sha256}
def proof_case(label,value):
 raw=enc(value);ar=arena(raw);header=bytearray(256);header[:8]=b'HIANBD01';struct.pack_into('<6Q',header,8,0,len(raw),len(ar),0,0,0);struct.pack_into('<Q',header,56,len(name))
 for i,key in enumerate(('before_sha256','after_sha256','before_input_sha256','after_input_sha256')):header[64+i*32:96+i*32]=bytes.fromhex(expected[key])
 h,error=invoke(bytes(header)+name+raw+ar);want=type(value)is dict and all(value.get(k)==v for k,v in expected.items());assert h[1]==0 and h[2]==int(want)and error is None,(label,h,want,error);record(label,'fresh_proof_binding',proved=want)
proof_case('actual-fresh-proof',proof)
for key in expected:
 changed=copy.deepcopy(proof);del changed[key];proof_case('proof-missing-'+key,changed)
 for value in (None,False,True,0,'',[],{},'0'*64,'changed'):
  changed=copy.deepcopy(proof);changed[key]=value;proof_case('proof-'+key+'-'+str(len(rows)),changed)
for value in (None,True,0,[],{}):proof_case('proof-nonobject-'+str(len(rows)),value)
changed=copy.deepcopy(proof);changed['ignored']={'deep':[1,2,3]};proof_case('proof-extra-field',changed)
data=response_case('final-private-source',request,response)
for off,value in ((0,0),(8,2),(16,0),(24,0),(32,0),(40,0),(48,0),(56,1),(96,1),(192,1),(248,1)):
 damaged=bytearray(data);struct.pack_into('<Q',damaged,off,value);ib=C.create_string_buffer(bytes(damaged));ob=C.create_string_buffer(4096);C.memset(ob,0xdb,len(ob));wb=C.create_string_buffer(4<<20);rc=entry(ib,len(damaged),ob,len(ob),wb,len(wb));assert rc==0xfffffffd and ob.raw==b'\xdb'*len(ob),(off,rc);record('private-frame-'+str(off),'private_guards')
report.update(passed=True,count=len(rows),fresh_native_proof_invocations=1,source_files_checked=len(receipt['source_files']));save();print('NDU_BINDING_ALL_PASS',len(rows),groups,len(nativecalls),flush=True)
