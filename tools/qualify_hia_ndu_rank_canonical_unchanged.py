from pathlib import Path
from hashlib import sha256
import copy,ctypes as C,fcntl,json,math,os,random,resource,struct,subprocess,sys,time
import argparse
cli=argparse.ArgumentParser(description='Qualify canonical subtrees and unselected Core equality through actual HIA roles.')
for flag in ('canonical','unchanged','decoder','normalizer','baseline','output'):
 cli.add_argument('--'+flag,required=True)
args=cli.parse_args()
P=Path(__file__).resolve().parents[1];D=Path(args.output);D.mkdir(exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from hepta.hia_program import verify_program
from hepta.hia_ndu_optimizer import _same_other_functions
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin;fd=os.memfd_create('native-rank-render-check',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
 return C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
build=[{'role': 'ndu_rank_canonical', 'source_sha256': 'b69afb7c3637a5c06c59d3673813b5f4f8fdd26d5ac1e164ce80ccd5fb0f02ff', 'profile': {'functions': 45, 'blocks': 583, 'ops': 2216, 'max_block_params': 16}, 'flat_bytes': 216748, 'flat_sha256': '2b9b658fd0c5211d020b60238472119f136075b3e89f638f84ed0ad7835f4fa0'}, {'role': 'ndu_rank_unchanged', 'source_sha256': '76d325e5f11fdf3aac830618e99e5a80b8afe5d1b1e6fe4ddbd610152820ba30', 'profile': {'functions': 13, 'blocks': 353, 'ops': 979, 'max_block_params': 16}, 'flat_bytes': 108658, 'flat_sha256': '381902ad4e92287af2491e17ac92b7baca1ac036adeaa8af01d0ef694fb9869a'}];pins={r['role']:r['flat_sha256']for r in build}
canonical=load(Path(args.canonical),pins['ndu_rank_canonical'])
unchanged=load(Path(args.unchanged),pins['ndu_rank_unchanged'])
decoder=load(Path(args.decoder),'2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144')
rows=[];groups={};report={'passed':False,'whole_native_rank_closed':False,'roles':build,'scope':'Actual HIA canonical subtree serialization, and module/unselected-function equality over freshly normalized native Core. The original host implementations are external oracles only. No evaluator, proof or full rank claim.','rows':rows,'groups':groups}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def record(label,group,**kw):
 rows.append({'case':label,'group':group,'passed':True,**kw});groups[group]=groups.get(group,0)+1
 if len(rows)%100==0:save();print('NDU_RENDER_CASE',len(rows),label,flush=True)
def enc(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def arena(raw):
 ib=C.create_string_buffer(raw);size=C.create_string_buffer(64);sw=C.create_string_buffer(128);assert decoder(ib,len(raw),size,64,sw,128)==0
 h=struct.unpack('<8s7Q',size.raw);assert h[0]==b'HIANJS01';ob=C.create_string_buffer(h[4]);wb=C.create_string_buffer(h[5]);struct.pack_into('<QQ',wb,48,h[1],h[3]);struct.pack_into('<QQ',wb,96,h[2],1)
 rc=decoder(ib,len(raw),ob,len(ob),wb,len(wb));assert rc==0,(len(raw),rc);used=struct.unpack_from('<Q',ob,24)[0];return ob.raw[:used]
def canon(label,raw,expected,root=0,group='canonical',ar=None):
 if ar is None:ar=arena(raw)
 data=struct.pack('<8s15Q',b'HIANJQ01',0,root,len(raw),len(ar),*([0]*11))+raw+ar
 ib=C.create_string_buffer(data);sb=C.create_string_buffer(96);C.memset(sb,0xdb,len(sb));work=max(131072+struct.unpack_from('<Q',ar,8)[0],len(ar)+16384);wb=C.create_string_buffer(work+32);C.memset(wb,0xa5,16);C.memset(C.addressof(wb)+work+16,0xa5,16)
 rc=canonical(ib,len(data),C.addressof(sb)+16,64,C.addressof(wb)+16,work)
 if expected is None:
  assert rc==0xfffffff0 and sb.raw==b'\xdb'*len(sb),(label,rc)
  record(label,group,nonfinite_rejected=True);return
 assert rc==0,(label,'measure',rc);h=struct.unpack('<8s7Q',sb.raw[16:80]);assert h[0]==b'HIANKJ01' and h[1]==len(expected) and h[2]==root and h[3]==len(raw) and h[4]==len(ar) and h[5:]==(0,0,0),(label,h,len(expected))
 assert sb.raw[:16]+sb.raw[-16:]==b'\xdb'*32
 struct.pack_into('<Q',ib,8,1);out=C.create_string_buffer(64+len(expected)+32);C.memset(out,0xdb,16);C.memset(C.addressof(out)+80+len(expected),0xdb,16)
 rc=canonical(ib,len(data),C.addressof(out)+16,64+len(expected),C.addressof(wb)+16,work);assert rc==0,(label,'emit',rc)
 actual=out.raw[80:80+len(expected)];assert actual==expected,(label,actual[:400],expected[:400]);assert out.raw[:16]+out.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32
 assert ib.raw[:8]+ib.raw[16:len(data)]==data[:8]+data[16:],(label,'source changed')
 record(label,group,input_bytes=len(raw),root=root,output_bytes=len(actual),output_sha256=sha256(actual).hexdigest())
rng=random.Random(2026112507)
atoms=[None,False,True,0,-1,1,(1<<128)+7,0.0,-0.0,1e-300,1.7976931348623157e308,'','x','é','😀','\x00\b\t\n\f\r\\\"']
def val(depth=0):
 if depth>=4 or rng.randrange(3)==0:return rng.choice(atoms)
 if rng.randrange(2):return [val(depth+1)for _ in range(rng.randrange(6))]
 return {str(i)+rng.choice(['é','😀','z','a','\x00']):val(depth+1)for i in range(rng.randrange(6))}
for i,x in enumerate(atoms+[[],{},[0],{'z':0,'a':1}]):
 canon('scalar-'+str(i),json.dumps(x,ensure_ascii=bool(i%2),indent=2).encode(),enc(x))
for i in range(400):
 x=val();raw=json.dumps(x,ensure_ascii=bool(i%2),indent=2 if i%5==0 else None).encode();canon('random-tree-'+str(i),raw,enc(x))
for i in range(600):
 bits=rng.getrandbits(64);x=struct.unpack('<d',struct.pack('<Q',bits))[0]
 if not math.isfinite(x):continue
 raw=json.dumps(x).encode();canon('binary64-'+str(i),raw,enc(x),group='binary64')
for raw in (b'-0',b'1.00000',b'1E+2',b'1e-0002',b'0.00100',b'-0.00e88',b'1e-99999',b'1e309',b'-1e309',b'1.7976931348623159e308',b'2.2250738585072012e-308',b'4.9406564584124654e-324'):
 x=json.loads(raw);canon('number-lexeme-'+str(len(rows)),raw,enc(x) if not isinstance(x,float) or math.isfinite(x) else None,group='binary64')
for i in range(40):
 x={'z':[val(),{'b':val(),'a':val()}],'a':val()};raw=json.dumps(x,ensure_ascii=bool(i%2),indent=2).encode();ar=arena(raw);values=[]
 def walk(v):
  values.append(v)
  if isinstance(v,dict):
   for child in v.values():walk(child)
  elif isinstance(v,list):
   for child in v:walk(child)
 walk(x);assert len(values)==struct.unpack_from('<Q',ar,8)[0]
 for root in sorted(set([0,1,len(values)-1,len(values)//2])):canon('subtree-'+str(i)+'-'+str(root),raw,enc(values[root]),root,'subtree',ar)
canon('irrelevant-nonfinite-sibling',b'{"bad":1e999,"selected":{"b":2,"a":1}}',b'{"a":1,"b":2}',2,'subtree')
# This is transport serialization. Public typed integer bounds remain separate.
raw=b'9'*100000;canon('unbounded-decimal-token',raw,raw,group='large_transport')
raw=b'1.'+b'0'*(9<<20);canon('nine-mib-floating-token',raw,b'1.0',group='large_transport')
raw=b'"'+b'x'*((64<<20)+1)+b'"';canon('over-sixtyfour-mib-json-value',raw,raw,group='large_transport')
small=b'{"b":[1,2],"a":"x"}';ar=arena(small);data=struct.pack('<8s15Q',b'HIANJQ01',1,0,len(small),len(ar),*([0]*11))+small+ar
for off,value in [(0,0),(8,2),(16,99999),(24,0),(32,0),(40,1),(120,1)]:
 damaged=bytearray(data);struct.pack_into('<Q',damaged,off,value);ib=C.create_string_buffer(bytes(damaged));out=C.create_string_buffer(512);C.memset(out,0xdb,512);wb=C.create_string_buffer(1<<20);rc=canonical(ib,len(damaged),out,512,wb,len(wb));assert rc==0xfffffffd and out.raw==b'\xdb'*512,(off,rc);record('canonical-frame-'+str(off),'private_guards')
ib=C.create_string_buffer(data);out=C.create_string_buffer(128);wb=C.create_string_buffer(1<<20);C.memset(out,0xdb,128);rc=canonical(ib,len(data),out,64+len(enc(json.loads(small)))-1,wb,len(wb));assert rc==0xfffffffe and out.raw==b'\xdb'*128;record('canonical-short-output','private_guards')
# Fresh actual native normalization for all semantic Core comparison fixtures.
raw=Path(args.normalizer).read_bytes();assert sha256(raw).hexdigest()=='84619bd15d8408f52c04519af11664cc4fa52cac352e7ad6680b6d50429123c6'
fd=os.memfd_create('rank-equality-normalizer',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
base=json.loads(Path(args.baseline).read_bytes())
original_fn=copy.deepcopy(base['functions'][0])
def renamed(name):
 f=copy.deepcopy(original_fn);f['name']=name;return f
base['functions']=[renamed('calculate'),renamed('helperA'),renamed('helperB')]
cache={}
def normalize(doc):
 source=enc(doc);key=sha256(source).hexdigest()
 if key in cache:return cache[key]
 before=verify_program(source);r=subprocess.run(['hia-admit-agent-json'],executable='/proc/self/fd/'+str(fd),input=source,capture_output=True,pass_fds=(fd,),env={'PATH':''},timeout=120);assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr)
 h=struct.unpack_from('<8s7Q',r.stdout);assert h[0]==b'HIAVCF01';core=r.stdout[64+h[4]:];assert core==before.canonical_bytes;cache[key]=(before,core,arena(core));return cache[key]
def compare(label,before,after,function='calculate'):
 bp,bj,ba=normalize(before);ap,aj,aa=normalize(after);name=function.encode();data=struct.pack('<8s15Q',b'HIANUC01',len(name),len(bj),len(ba),len(aj),len(aa),*([0]*10))+name+bj+ba+aj+aa
 ib=C.create_string_buffer(data);out=C.create_string_buffer(96);C.memset(out,0xdb,96);wb=C.create_string_buffer(131072+max(struct.unpack_from('<Q',x,8)[0]for x in(ba,aa))+32);C.memset(wb,0xa5,16);C.memset(C.addressof(wb)+len(wb)-16,0xa5,16)
 rc=unchanged(ib,len(data),C.addressof(out)+16,64,C.addressof(wb)+16,len(wb)-32);assert rc==0,(label,rc);h=struct.unpack('<8s7Q',out.raw[16:80]);expected=_same_other_functions(bp,ap,function);assert h[0]==b'HIANUR01' and h[1] in(0,1)and bool(h[1])==expected,(label,h,expected)
 assert out.raw[:16]+out.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32 and ib.raw[:len(data)]==data
 record(label,'unchanged_core',equal=expected,reason=h[2],before_sha256=bp.sha256,after_sha256=ap.sha256)
 return data
compare('same-core',base,base)
for index in range(3):
 changed=copy.deepcopy(base);fn=changed['functions'][index];fn['entry']='newblock';fn['blocks'][0]['id']='newblock';compare('changed-body-'+str(index),base,changed)
 changed=copy.deepcopy(base);fn=changed['functions'][index];fn['params'][0]['name']='arg';fn['blocks'][0]['params'][0]['name']='arg';fn['blocks'][0]['term']['values']=['arg'];compare('changed-param-'+str(index),base,changed)
for order in ([1,0,2],[1,2,0],[2,1,0],[0,2,1],[1,2],[0,1],[0,2]):
 changed=copy.deepcopy(base);changed['functions']=[changed['functions'][i]for i in order];compare('function-order-'+''.join(map(str,order)),base,changed)
changed=copy.deepcopy(base);changed['module']='another_module';compare('module-changed',base,changed)
changed=copy.deepcopy(base);changed['functions'].append(renamed('extra'));compare('other-function-added',base,changed)
for n in (1,16,64,128):
 large=copy.deepcopy(base);large['functions']=[renamed('calculate')]+[renamed('F'+str(i))for i in range(n-1)];compare('wide-functions-'+str(n),large,large)
 if n>1:
  changed=copy.deepcopy(large);changed['functions']=changed['functions'][1:]+changed['functions'][:1];compare('wide-selected-reordered-'+str(n),large,changed)
  changed['functions'][0]['entry']='changed';changed['functions'][0]['blocks'][0]['id']='changed';compare('wide-unselected-change-'+str(n),large,changed)
for i in range(50):
 changed=copy.deepcopy(base);rng.shuffle(changed['functions'])
 if i%3==0:changed['functions']=[f for f in changed['functions']if f['name']!='calculate']
 if i%5==0:changed['module']='mod'+str(i)
 compare('random-core-'+str(i),base,changed)
data=compare('final-atomic-source',base,base)
for off,value in [(0,0),(8,0),(8,129),(16,0),(24,0),(32,0),(40,0),(48,1),(120,1)]:
 bad=bytearray(data);struct.pack_into('<Q',bad,off,value);ib=C.create_string_buffer(bytes(bad));out=C.create_string_buffer(64);C.memset(out,0xdb,64);wb=C.create_string_buffer(1<<20);rc=unchanged(ib,len(bad),out,64,wb,len(wb));assert rc==0xfffffffd and out.raw==b'\xdb'*64,(off,value,rc);record('unchanged-frame-'+str(off)+'-'+str(value),'private_guards')
report.update(passed=True,count=len(rows),actual_native_normalizations=len(cache),seed=2026112507);save();print('NDU_CANONICAL_UNCHANGED_ALL_PASS',len(rows),groups,len(cache),flush=True)
