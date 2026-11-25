from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,mmap,os,random,resource,struct,time
import argparse
cli=argparse.ArgumentParser(description='Qualify size-derived NDU transport JSON against the existing native decoder.')
for flag in ('flat','decoder','output'):
 cli.add_argument('--'+flag,required=True)
args=cli.parse_args();D=Path(args.output);D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
def load(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin;fd=os.memfd_create('native-wide-json',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
 return C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
pin='2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144';entry=load(Path(args.flat),pin)
old=load(Path(args.decoder),'bbb894c08d02cff36080a8dfa3eb3c6846ac1aa2095eb2851414585fb45c4f04')
oldout=C.create_string_buffer(80<<20);oldwork=C.create_string_buffer(8<<20)
rows=[];counts={};report={'passed':False,'flat_sha256':pin,'whole_native_rank_closed':False,'scope':'Separate size-derived NDU transport decoder; original per-Core/proof/evaluator/submit limits are unchanged. Actual sealed role, small existing-native decoder byte comparison, large private graphs and full-width offset probes.','rows':rows,'counts':counts}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def run(label,raw,group='small',compare=True,check=None):
 ib=C.create_string_buffer(raw);sb=C.create_string_buffer(96);sw=C.create_string_buffer(128);C.memset(sb,0xdb,len(sb))
 result=entry(ib,len(raw),C.addressof(sb)+16,64,sw,128);assert result==0,(label,'sizes',result)
 magic,nodes,keys,depth,cap,work,source,zero=struct.unpack('<8s7Q',sb.raw[16:80]);assert magic==b'HIANJS01' and source==len(raw) and zero==0 and cap>=128 and work>=128 and sb.raw[:16]+sb.raw[-16:]==b'\xdb'*32,(label,magic,cap,work)
 ob=C.create_string_buffer(cap+32);wb=C.create_string_buffer(work+32);C.memset(ob,0xdb,16);C.memset(C.addressof(ob)+cap+16,0xdb,16);C.memset(wb,0xa5,16);C.memset(C.addressof(wb)+work+16,0xa5,16);struct.pack_into('<QQ',wb,16+48,nodes,depth);struct.pack_into('<QQ',wb,16+96,keys,1)
 start=time.monotonic_ns();result=entry(ib,len(raw),C.addressof(ob)+16,cap,C.addressof(wb)+16,work);elapsed=time.monotonic_ns()-start
 assert ib.raw[:len(raw)]==raw and ob.raw[:16]+ob.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32,(label,'canaries')
 used=0;digest=None;actual_count=None
 if result==0:
  header=struct.unpack('<8Q',ob.raw[16:80]);actual_count=header[1];used=header[3];assert header[0]==5208772604367785521
  assert 64<=used<=cap and header[2]==64+72*actual_count and header[3]==header[4] and header[5]==len(raw) and header[6:]==(1,0)
  output=ob.raw[16:16+used];digest=sha256(output).hexdigest()
  if check is not None:check(output,actual_count)
 if compare:
  assert len(raw)<=1<<20 and cap<=80<<20
  C.memset(oldout,0,cap);C.memset(oldwork,0,128);struct.pack_into('<QQ',oldwork,48,131073,128);struct.pack_into('<Q',oldwork,120,int.from_bytes(b'HIAJLG01','little'))
  prior=old(ib,len(raw),oldout,len(oldout),oldwork,len(oldwork))
  if prior<0xfffffffc:
   assert result==0 and used==prior and output==oldout.raw[:prior],(label,'native arena mismatch',result,used,prior)
  else:assert result==prior,(label,'native refusal mismatch',result,prior)
 else:assert result==0,(label,result)
 rows.append({'case':label,'group':group,'passed':True,'input_bytes':len(raw),'input_sha256':sha256(raw).hexdigest(),'status':result,'nodes':actual_count,'arena_capacity':cap,'work_capacity':work,'arena_bytes':used,'arena_sha256':digest,'elapsed_ns':elapsed});counts[group]=counts.get(group,0)+1
 if len(rows)%100==0 or not compare:save();print('NDU_JSON_CASE',len(rows),label,result,len(raw),used,elapsed,flush=True)
rng=random.Random(2026112506)
atoms=[None,False,True,0,-1,1,10**80,0.0,-0.0,1e-300,1.7976931348623157e308,'','a','é','😀','\x00\n\\\"']
def value(depth=0):
 if depth>3 or rng.randrange(3)==0:return rng.choice(atoms)
 if rng.randrange(2):return [value(depth+1) for _ in range(rng.randrange(8))]
 return {str(i)+rng.choice(['a','é','😀','\x00']):value(depth+1) for i in range(rng.randrange(8))}
for i,x in enumerate(atoms+[[],{},[0],{'x':1}]):
 for ascii in (False,True):run('scalar-'+str(i)+'-'+str(ascii),json.dumps(x,ensure_ascii=ascii,separators=(',',':'),allow_nan=False).encode())
for i in range(600):
 x=value();raw=json.dumps(x,ensure_ascii=bool(i%2),sort_keys=bool(i%3),indent=2 if i%5==0 else None,separators=None if i%5==0 else (',',':'),allow_nan=False).encode();run('random-'+str(i),raw)
invalid=[b'',b' ',b'{',b'[',b'"',b'[,]',b'[1,]',b'{"x":}',b'{"x" 1}',b'{"x":1,}',b'{,}',b'[]x',b'00',b'01',b'-',b'1.',b'1e',b'1e+',b'NaN',b'Infinity',b'False',b'nullnull',b'\xff',b'"\xff"',b'"\\u"',b'"\\uD800"',b'"\\uDC00"',b'"\\uD800\\u0041"',b'"\x00"',b'"\\x"',b'{"a":1,"a":2}',b'{"a":1,"\\u0061":2}','{"😀":1,"\\ud83d\\ude00":2}'.encode(),b'{"x":1,"y":2,"z"}']
for i,raw in enumerate(invalid):run('malformed-'+str(i),raw,'malformed')
for n in (131073,1048577):
 raw=b'['+b'0,'*(n-1)+b'0]'
 def check(a,count,n=n):
  assert count==n+1 and struct.unpack_from('<Q',a,64)[0]==5 and struct.unpack_from('<Q',a,96)[0]==n
  for index in (1,n//2,n):
   row=struct.unpack_from('<9Q',a,64+index*72);assert row[0]==3 and row[1]==0 and row[3:5]==(1+(index-1)*2,1) and row[2]==(index+1 if index<n else (1<<64)-1)
 run('wide-node-count-'+str(n),raw,'wide_graph',False,check)
raw=b'['*600+b'0'+b']'*600
run('depth-600-private-transport',raw,'wide_graph',False,lambda a,count:count==601 or (_ for _ in ()).throw(AssertionError(count)))
# The complete 32-candidate container exceeds both former decoder total byte ceilings.
part=b'{"id":"X","program":{"padding":"'+b'z'*(3<<20)+b'"}}'
raw=b'{"candidates":['+b','.join(part.replace(b'"X"',('"C'+str(i)+'"').encode(),1) for i in range(32))+b']}'
def check_large(a,count):
 assert count==130 and struct.unpack_from('<Q',a,64)[0]==6
 assert a.count(b'z'*(1<<20))==96
run('32-three-mib-program-values',raw,'wide_graph',False,check_large)
# Keys and scopes remain distinct through decoded Unicode equality.
run('escaped-key-equivalence',b'{"\\u00e9":1,"e":2}','small')
run('nested-key-scopes',b'{"a":{"x":1},"b":{"x":2}}','small')
report.update(passed=True,count=len(rows),seed=2026112506,small_existing_decoder_exact=True);save();print('NDU_DYNAMIC_JSON_ALL_PASS',len(rows),counts,flush=True)
