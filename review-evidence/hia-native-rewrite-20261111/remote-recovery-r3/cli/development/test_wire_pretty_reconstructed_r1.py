"""New reconstruction: real images, independent CPython 3.12 oracle."""
from pathlib import Path
from hashlib import sha256
import ctypes as C,struct,json,sys,runpy,random,zlib,traceback,resource
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
from unittest.mock import patch
BASE=Path('/var/tmp/hia9acdfa-native-resume-a3c61136-20261111')
P=BASE/'cli-recovery/workspace/native-hia-cli-next'
R=BASE/'cli-recovery/r6-exact-original'
sys.path.insert(0,str(BASE/'source'));sys.dont_write_bytecode=True
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program_tools import bounded_json_wire
OUT=P/'development/wire-pretty-reconstructed-native-r1'
OUT.mkdir(exist_ok=False);(OUT/'cas').mkdir();pins={}
def read(p):
 p=Path(p);v=p.read_bytes();h=sha256(v).hexdigest()
 if str(p) in pins:assert pins[str(p)]==h
 pins[str(p)]=h;return v
read(R/'development/graph_harness_r3.py')
h=runpy.run_path(str(R/'development/graph_harness_r3.py'))
capture=h['capture'];ERRORS=h['ERRORS']
bundle=json.loads(read(P/'development/cli-wire-reconstructed-compile-r1/bundle.json'))
assert bundle['status']=='PASS_COMPILE_ONLY'
images={}
def image(name,row,source,path):
 s=read(source);v=read(path)
 assert sha256(s).hexdigest()==row['source_sha256'] and sha256(v).hexdigest()==row['image_sha256']
 images[name]=NativeHiaJsonImage(v,expected_sha256=row['image_sha256'])
for role in ('scan','emit'):
 row=bundle['components'][role];image('new-'+role,row,row['source_path'],row['image_path'])
 old=json.loads(read(R/('development/compile-r3/'+role+'.manifest.json')))
 image('old-'+role,old,R/('examples/hia_bootstrap/graph_json_wire_'+role+'.hiaasm'),R/'development/compile-r3'/Path(old['image_path']).name)
row=json.loads(read(P/'development/pretty-reconstructed-compile-r1/cli-pretty.manifest.json'))
image('pretty',row,row['source'],row['image'])
read(__file__);(OUT/'source-before.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
MAG=lambda x:int.from_bytes(x,'little')
BAD=0xfffffffd;GROW=0xfffffffe;CLI=(1<<61)-1;GUARD=b'\xb9'*32
counts={k:0 for k in images};cases=[];ledger=(OUT/'entries.jsonl').open('w')

def cas(v):
 v=bytes(v);h=sha256(v).hexdigest();p=OUT/'cas'/(h+'.zlib')
 if not p.exists():p.write_bytes(zlib.compress(v,6))
 assert zlib.decompress(p.read_bytes())==v
 return {'sha256':h,'bytes':len(v),'path':'cas/'+p.name,'compression':'zlib'}
def call(role,s,r,w,label):
 a=C.create_string_buffer(s+GUARD);b=C.create_string_buffer(r+GUARD);c=C.create_string_buffer(w+GUARD)
 counts[role]+=1
 row={'role':role,'entry':counts[role],'label':label,'source':cas(s),'command':cas(r),'before':cas(w),'state':'ENTER'}
 ledger.write(json.dumps(row,sort_keys=True)+'\n');ledger.flush()
 ret=int(images[role]._entry(C.addressof(a),len(s),C.addressof(b),len(r),C.addressof(c),len(w)))
 assert a.raw[:len(s)+32]==s+GUARD and b.raw[:len(r)+32]==r+GUARD and c.raw[len(w):len(w)+32]==GUARD
 v=c.raw[:len(w)];row.update(state='RETURN',ret=ret,after=cas(v))
 ledger.write(json.dumps(row,sort_keys=True)+'\n');ledger.flush();return ret,v
def cmd(g,maxi,flags):
 return struct.pack('<8Q',MAG(b'HIAGWC01'),struct.unpack_from('<Q',g,8)[0],1,struct.unpack_from('<Q',g,24)[0],maxi,flags,4300,0)
def wire(g,maxi,flags,label,pair=False):
 r=cmd(g,maxi,flags);role='scan';w=bytes(32768);old=w;steps=0
 while True:
  steps+=1;assert steps<100
  ret,v=call('new-'+role,g,r,w,label)
  if pair:
   ret0,v0=call('old-'+role,g,r,old,label)
   assert (ret,v)==(ret0,v0),(label,role,ret,ret0,sha256(v).hexdigest(),sha256(v0).hexdigest())
   old=v0
  w=v;e=struct.unpack_from('<16Q',w)
  assert ret==128 and e[0]==MAG(b'HIAGWE01') and e[2:8]==struct.unpack('<8Q',r)[1:7],(label,ret,e)
  if e[1]==1:
   assert e[10]>len(w);size=max(e[10],len(w)*2);w+=bytes(size-len(w))
   if pair:old+=bytes(size-len(old))
   continue
  if e[1]==2:
   assert role=='scan' and e[13]==2;role='emit';continue
  if e[1]==3:return {'error':'E_HIA_EDIT: '+ERRORS[e[8]],'cause':e[9],'steps':steps}
  assert e[1]==0 and role=='emit' and e[8:10]==(0,0) and e[11]+e[12]<=len(w)
  return {'wire':w[e[11]:e[11]+e[12]],'steps':steps}

def pc(raw,ascii=0):
 return struct.pack('<12Q',MAG(b'HIAJPC01'),1,19,7,len(raw),1,ascii,0,0,0,0,0)
def pretty(raw,ascii,label):
 r=pc(raw,ascii);w=bytes(1024);steps=0
 while True:
  ret,w=call('pretty',raw,r,w,label);steps+=1;assert steps<10
  e=struct.unpack_from('<16Q',w,256);assert e[0]==MAG(b'HIAJPE01') and e[2:4]==(19,7)
  if ret==GROW:
   assert e[1]==1 and e[6]>len(w);w+=bytes(e[6]-len(w));continue
  assert ret==128 and e[1]==0 and e[4]+e[5]<=len(w),(label,ret,e)
  return w[e[4]:e[4]+e[5]]
def forbid(*a,**k):raise AssertionError('host wire fallback disabled')
try:
 values=[None,False,True,0,1,-1,2**64,-2**100,2**511,0.0,-0.0,1.25,5e-324,1.7976931348623157e308,'','x','a\n\t\x00\x7f','\u4e2d\U0001f600',b'bad',object(),'\ud800',float('nan'),float('inf'),[],{},(),[1,True,None],{'z':[1,2],'a':{'b':'x'}},{1:'x','1':'y'},{None:0,True:1},{'a':1,2:3},[{'x':0}]*4]
 cycle=[];cycle.append(cycle);values.append(cycle)
 for i,value in enumerate(values):
  for flags in range(4):
   for maximum in (32,4096):
    label='old-%d-%d-%d'%(i,flags,maximum)
    try:expected={'wire':bounded_json_wire(value,maximum,ensure_ascii=bool(flags&1),sort_keys=bool(flags&2))}
    except Exception as exc:expected={'error':str(exc)}
    graph=capture(value)
    with patch('hepta.hia_program_tools.bounded_json_wire',new=forbid):actual=wire(graph,maximum,flags,label,True)
    if 'wire' in expected:assert actual.get('wire')==expected['wire'],(label,actual,expected)
    else:assert actual.get('error')==expected['error'],(label,actual,expected)
    cases.append({'label':label,'scope':'OLD_FLAGS_FULL_WORKSPACE_EQUAL','steps':actual['steps'],'outcome':cas(expected['wire']) if 'wire' in expected else expected})
 rng=random.Random(0x4a534f4e)
 def tree(depth=0):
  if depth>=3 or rng.randrange(4)==0:return rng.choice([None,True,False,rng.randrange(-10**16,10**16),rng.random(),'x\n\u4e2d\U0001f600'])
  if rng.randrange(2):return [tree(depth+1) for _ in range(rng.randrange(5))]
  return {'k'+str(i):tree(depth+1) for i in rng.sample(range(6),rng.randrange(5))}
 valid=[None,True,False,0,-1,2**512,0.0,-0.0,1.25,5e-324,'','\u4e2d\U0001f600',[],{},[1,2],{'z':1,'a':2}]+[tree() for _ in range(80)]
 for i,value in enumerate(valid):
  label='cli-'+str(i);want=json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()
  actual=wire(capture(value),CLI,6,label);assert actual.get('wire')==want,(label,actual,want)
  for ascii in (0,1):
   got=pretty(want,ascii,label+'-pretty-'+str(ascii));expected=(json.dumps(value,sort_keys=True,ensure_ascii=bool(ascii),indent=2)+'\n').encode('utf-8','surrogatepass');assert got==expected,(label,got,expected)
  cases.append({'label':label,'scope':'CLI_WIRE_AND_TWO_PRETTY_POLICIES','wire':cas(want)})

 for i,value in enumerate([float('nan'),float('inf'),float('-inf'),'\ud800','\udc80','\ud800\udc00','\\u4e2d']):
  raw=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode('utf-8','surrogatepass')
  for ascii in (0,1):
   got=pretty(raw,ascii,'pretty-extra-%d-%d'%(i,ascii));expected=(json.dumps(value,ensure_ascii=bool(ascii),indent=2)+'\n').encode('utf-8','surrogatepass');assert got==expected
   cases.append({'label':'pretty-extra-%d-%d'%(i,ascii),'scope':'PRIVATE_CANONICAL_PRESENTATION','wire':cas(got)})
 for label,value in [('large-nine-mib',{'value':'x'*(9*1024*1024)}),('beyond-worker-node-count',[None]*270000)]:
  g=capture(value);want=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
  actual=wire(g,CLI,6,label);assert actual.get('wire')==want
  got=pretty(want,0,label+'-pretty');expected=(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode();assert got==expected
  old=wire(g,8388608,2,label+'-worker',True);assert 'error' in old
  cases.append({'label':label,'scope':'CLI_QUOTA_SEPARATION','wire':cas(want),'pretty':cas(got),'unchanged_worker_error':old['error']})
 g=capture('x'*65536);r=cmd(g,CLI,6)
 ret,w=call('new-scan',g,r,bytes(32768),'grow-control-scan');assert ret==128 and struct.unpack_from('<Q',w,8)[0]==2
 ret,w=call('new-emit',g,r,w,'grow-control-measure');e=struct.unpack_from('<16Q',w);assert ret==128 and e[1]==1 and e[14]==4
 expanded=w+bytes(e[10]-len(w))
 for label,at,val in [('mode',568,0),('measured',576,1),('outlen',528,1),('outbase',536,0),('level',408,1)]:
  bad=bytearray(expanded);struct.pack_into('<Q',bad,at,val)
  ret,bad=call('new-emit',g,r,bytes(bad),'grow-'+label);assert ret==BAD,(label,ret)
  ret,bad=call('new-scan',g,r,bad,'grow-'+label+'-followup');assert ret==BAD
  cases.append({'label':'grow-'+label,'scope':'PRIVATE_PERMANENT_BAD'})
 for flags in (4,5,7):
  g=capture(0);badcmd=cmd(g,CLI,flags)
  ret,w=call('new-scan',g,badcmd,bytes(32768),'invalid-flag-'+str(flags));assert ret==BAD
  ret,w=call('new-scan',g,cmd(g,CLI,6),w,'invalid-flag-followup');assert ret==BAD
  cases.append({'label':'invalid-flag-'+str(flags),'scope':'PRIVATE_PERMANENT_BAD'})
 g=capture(0);ret,w=call('new-scan',g,cmd(g,8388608,6),bytes(32768),'invalid-cli-maximum');assert ret==BAD
 ret,w=call('new-emit',g,cmd(g,CLI,6),w,'invalid-cli-maximum-followup');assert ret==BAD
 cases.append({'label':'invalid-cli-maximum','scope':'PRIVATE_PERMANENT_BAD'})
 for i,raw in enumerate([b'',b'{',b'01',b'"\xff"',b'{"a":}',b'[1,]',b'true false']):
  ret,w=call('pretty',raw,pc(raw),bytes(2048+len(raw)+1024),'pretty-malformed-'+str(i));assert ret==BAD
  ret,w=call('pretty',b'null',pc(b'null'),w,'pretty-malformed-followup');assert ret==BAD
  cases.append({'label':'pretty-malformed-'+str(i),'scope':'PRIVATE_PERMANENT_BAD'})
 raw=b'"hello"';r=pc(raw);ret,w=call('pretty',raw,r,bytes(1024),'pretty-grow-initial');assert ret==GROW
 size=struct.unpack_from('<Q',w,304)[0];w+=bytes(size-len(w))
 for at in (24,32,40,48,152):
  bad=bytearray(w);struct.pack_into('<Q',bad,at,123)
  ret,bad=call('pretty',raw,r,bytes(bad),'pretty-grow-state-'+str(at));assert ret==BAD
  ret,bad=call('pretty',raw,r,bad,'pretty-grow-state-followup');assert ret==BAD
  cases.append({'label':'pretty-grow-state-'+str(at),'scope':'PRIVATE_PERMANENT_BAD'})

 result={'status':'PASS','scope':'NEW_RECONSTRUCTION_ACTUAL_NOT_OLD_RUN_OR_COLD','cases':len(cases),'entries':counts,'python':sys.version}
 (OUT/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True),flush=True)
except BaseException:
 failure=traceback.format_exc();(OUT/'failure.txt').write_text(failure)
 (OUT/'result.json').write_text(json.dumps({'status':'FAIL','cases_completed':len(cases),'entries':counts,'failure':failure},sort_keys=True,indent=2)+'\n');raise
finally:
 ledger.close();(OUT/'cases-completed.json').write_text(json.dumps(cases,sort_keys=True,indent=2)+'\n')
 after={p:sha256(Path(p).read_bytes()).hexdigest() for p in pins}
 (OUT/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');assert after==pins
