"""Fresh original _structure versus sealed native structure role.

This external qualifier exercises the default CPython conversion policy and
explicitly selected policies separately. The production owner must capture its
actual conversion policy. The original structural/byte/depth budgets are fixed.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes as C,fcntl,json,os,random,resource,struct,sys,time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from hepta.hia_program import _structure
MAX_BYTES=8388608
MAX_NODES=262144
NONE=(1<<64)-1
SEEN=4202496
JSON_PIN='2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144'
ENTRY=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
class Flat:
 def __init__(self,path,pin=None):
  self.path=Path(path);self.raw=self.path.read_bytes();self.sha=sha256(self.raw).hexdigest()
  if pin is not None:assert self.sha==pin
  self.fd=os.memfd_create('background-native-structure',os.MFD_ALLOW_SEALING)
  at=0
  while at<len(self.raw):n=os.write(self.fd,self.raw[at:]);assert n>0;at+=n
  fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,15)
  lib=C.CDLL(None);lib.mmap.argtypes=[C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long];lib.mmap.restype=C.c_void_p
  address=lib.mmap(None,len(self.raw),5,2,self.fd,0);assert address not in (None,C.c_void_p(-1).value)
  self.entry=ENTRY(address)
 def call(self,raw,out,work):
  src=C.create_string_buffer(raw)
  rc=self.entry(src,len(raw),out,len(out),work,len(work))
  assert src.raw==raw+b'\0'
  return rc
class Decoder:
 def __init__(self,path):self.flat=Flat(path,JSON_PIN);self.calls=0
 def decode(self,raw):
  out=C.create_string_buffer(64);work=C.create_string_buffer(128)
  rc=self.flat.call(raw,out,work);assert rc==0,('json sizes',rc)
  magic,nodes,keys,depth,cap,wn,sn,reserved=struct.unpack('<8s7Q',out.raw)
  assert magic==b'HIANJS01' and sn==len(raw) and reserved==0
  out=C.create_string_buffer(cap);work=C.create_string_buffer(wn)
  struct.pack_into('<QQ',work,48,nodes,depth);struct.pack_into('<QQ',work,96,keys,1)
  rc=self.flat.call(raw,out,work);assert rc==0,('json arena',rc,raw[:120])
  self.calls+=2;used=struct.unpack_from('<Q',out,24)[0]
  assert 64<=used<=cap
  return out.raw[:used]
def original(value,limit):
 prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(limit)
 try:
  try:return {'size':_structure(value)}
  except BaseException as e:return {'type':type(e).__name__,'message':str(e)}
 finally:sys.set_int_max_str_digits(prior)
def raw_json(value,pretty=False,ascii=False):
 prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(0)
 try:return json.dumps(value,ensure_ascii=ascii,allow_nan=False,indent=2 if pretty else None,separators=None if pretty else (',',':')).encode()
 finally:sys.set_int_max_str_digits(prior)
def nodes_in_order(value):
 answer=[]
 def visit(x):
  answer.append(x)
  if type(x) is dict:
   for y in x.values():visit(y)
  elif type(x) is list:
   for y in x:visit(y)
 visit(value);return answer
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--json-flat',type=Path,required=True);p.add_argument('--threshold',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 D=a.output;D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 image=Flat(a.directory/'background_optimizer_structure.flat');decoder=Decoder(a.json_flat);threshold=a.threshold.read_bytes()
 assert len(threshold)==10100891 and threshold.isdigit() and threshold[:1]!=b'0'
 build=json.loads((a.directory/'build.json').read_text())
 assert sha256(threshold).hexdigest()==build['threshold']['sha256']
 assert image.sha==build['native_compiles'][0]['sha256']
 rows=[];counts={};report={'passed':False,'whole_background_qualified':False,'scope':'Original _structure semantics for owned JSON trees/subtrees and explicit private Unicode spans. Foreign classes, cycles and public owner capture are separate.','flat_sha256':image.sha,'json_sha256':decoder.flat.sha,'threshold_sha256':sha256(threshold).hexdigest(),'original_source_sha256':sha256((ROOT/'hepta/hia_program.py').read_bytes()).hexdigest(),'default_conversion_limit':sys.get_int_max_str_digits(),'cases':rows,'counts':counts}
 def save():(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 def native(name,raw,arena,root,limit,expected,group):
  count=struct.unpack_from('<Q',arena,8)[0];wn=SEEN+count
  header=struct.pack('<8s15Q',b'HIABST01',root,len(raw),len(arena),len(threshold),limit,*([0]*10))
  frame=header+raw+arena+threshold
  src=C.create_string_buffer(frame);out=C.create_string_buffer(544);work=C.create_string_buffer(wn+32)
  C.memset(out,0xdb,len(out));C.memset(work,0xa5,len(work))
  start=time.monotonic_ns();rc=image.entry(src,len(frame),C.addressof(out)+16,512,C.addressof(work)+16,wn);elapsed=time.monotonic_ns()-start
  actual=None
  try:
   assert rc==0,(name,'private return',rc)
   assert out.raw[:16]+out.raw[-16:]==b'\xdb'*32 and work.raw[:16]+work.raw[-16:]==b'\xa5'*32,(name,'canaries')
   assert src.raw==frame+b'\0',(name,'source changed')
   head=struct.unpack_from('<8s15Q',out,16)
   assert head[0]==b'HIABSR01' and head[1] in (0,1) and head[5]<=384
   if head[1]==0:
    assert head[2]==0 and head[5]==0
    actual={'size':head[4]}
   else:actual=json.loads(out.raw[16+128:16+128+head[5]])
   assert actual==expected,(name,actual,expected,limit)
  except BaseException as e:
   (D/'failure.input').write_bytes(frame);(D/'failure.output').write_bytes(out.raw)
   (D/'failure.json').write_text(json.dumps({'case':name,'error':repr(e),'actual':actual,'expected':expected,'limit':limit,'completed':len(rows)},indent=2)+'\n');raise
  row={'case':name,'group':group,'root':root,'conversion_limit':limit,'source_bytes':len(raw),'source_sha256':sha256(raw).hexdigest(),'arena_bytes':len(arena),'nodes':count,'expected':expected,'native_elapsed_ns':elapsed,'passed':True}
  rows.append(row);counts[group]=counts.get(group,0)+1
  if len(rows)%50==0 or group in ('large','integer_threshold'):
   save();print('BG_STRUCTURE_CASE',len(rows),name,limit,actual,elapsed,flush=True)
  return head
 def run(name,value,limit=4300,group='small',raw=None,subtrees=False):
  raw=raw_json(value,pretty=bool(len(rows)%3==0),ascii=bool(len(rows)%2)) if raw is None else raw
  arena=decoder.decode(raw)
  native(name,raw,arena,0,limit,original(value,limit),group)
  if subtrees:
   values=nodes_in_order(value)
   for root in sorted(set([1,len(values)//2,len(values)-1])):
    if root>0 and root<len(values):native(name+'-subtree-'+str(root),raw,arena,root,limit,original(values[root],limit),'subtree')
 atoms=[None,False,True,0,-1,1,10**80,-10**80,0.0,-0.0,1e-300,1.7976931348623157e308,'','a','é','中','😀','\x00\b\t\n\f\r\\"']
 for i,value in enumerate(atoms):run('atom-'+str(i),value)
 for i in range(256):
  value=chr(i)
  run('codepoint-'+str(i),{'key'+value:[value]},group='unicode')
 for value in [0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]:
  run('unicode-width-'+str(value),chr(value),group='unicode')
 rng=random.Random(0x20261125)
 def value(depth=0):
  if depth>=5 or rng.randrange(3)==0:return rng.choice(atoms)
  if rng.randrange(2):return [value(depth+1) for _ in range(rng.randrange(7))]
  return {str(i)+rng.choice(['x','é','😀','\x00']):value(depth+1) for i in range(rng.randrange(7))}
 for i in range(400):run('random-'+str(i),value(),limit=[4300,0,640][i%3],group='random',subtrees=i<25)
 for depth in [0,1,62,63,64,65,66,100]:
  x=0
  for i in range(depth):x=[x]
  run('depth-'+str(depth),x,group='limits')
 for count in [MAX_NODES-2,MAX_NODES-1,MAX_NODES,MAX_NODES+1]:
  run('queued-node-'+str(count),[None]*count,group='large')
 run('nested-queued-priority',[[None]*(MAX_NODES-2),[]],group='large')
 for ch,n in [('a',MAX_BYTES-2),('a',MAX_BYTES-1),('\0',(MAX_BYTES-2)//6),('\0',(MAX_BYTES-2)//6+1),('😀',(MAX_BYTES-2)//4),('😀',(MAX_BYTES-2)//4+1)]:
  run('encoded-string-'+str(ord(ch))+'-'+str(n),ch*n,group='large')
 run('large-dict-key-exact',{'a'*(MAX_BYTES-6):0},group='large')
 run('large-dict-key-over',{'a'*(MAX_BYTES-5):0},group='large')
 run('raw-whitespace-over-eight-mib',[0],raw=b' '*(MAX_BYTES+1)+b'[0]',group='large')
 for limit in [640,4300,5000,0]:
  for digits in sorted(set([1,639,640,641,4299,4300,4301,4999,5000,5001])):
   for negative in [False,True]:
    v=10**(digits-1)
    if negative:v=-v
    run('integer-'+str(digits)+'-'+str(negative)+'-'+str(limit),v,limit,group='conversion')
 run('negative-zero',0,raw=b'-0',group='conversion')
 run('float-exponent-overflow',float('inf'),raw=b'1e9999999',group='conversion')
 run('right-to-left-conversion-first',['a'*MAX_BYTES,10**5000],group='large')
 run('right-to-left-byte-first',[10**5000,'a'*MAX_BYTES],group='large')
 run('key-before-integer',{'\0'*((MAX_BYTES-2)//6+1):10**5000},group='large')
 # The threshold is mathematical algorithm data, not recorded interpreter output.
 power=1<<33554432
 for delta in [-1,0,1]:
  val=power+delta
  magnitude=threshold if delta==0 else threshold[:-1]+bytes([threshold[-1]+delta])
  # 2^33554432 ends in a middle decimal digit; confirm without decimal conversion.
  assert threshold[-1:]==str(pow(2,33554432,10)).encode() and 48<=magnitude[-1]<=57
  for sign in [1,-1]:
   raw=(b'-' if sign<0 else b'')+magnitude
   for limit in [4300,0]:run('power-threshold-'+str(delta)+'-'+str(sign)+'-'+str(limit),sign*val,limit,group='integer_threshold',raw=raw)
 # Private owned Unicode span controls: fresh parser rightly refuses lone
 # surrogates, while a typed native ingress must preserve _structure's error order.
 for code in [0xd800,0xdbff,0xdc00,0xdfff]:
  x=chr(code);raw=raw_json(x,ascii=True);encoded=x.encode('utf-8','surrogatepass')
  arena=struct.pack('<8Q',5208772604367785521,1,136,136+len(encoded),136+len(encoded),len(raw),1,0)+struct.pack('<9Q',4,NONE,NONE,136,len(encoded),0,0,0,len(raw))+encoded
  native('owned-unpaired-'+str(code),raw,arena,0,4300,original(x,4300),'private_unicode')
 for prefix in [True,False]:
  x=('\ud800'+'a'*(MAX_BYTES-1)) if prefix else ('a'*(MAX_BYTES-1)+'\ud800')
  raw=raw_json(x,ascii=True);encoded=x.encode('utf-8','surrogatepass')
  arena=struct.pack('<8Q',5208772604367785521,1,136,136+len(encoded),136+len(encoded),len(raw),1,0)+struct.pack('<9Q',4,NONE,NONE,136,len(encoded),0,0,0,len(raw))+encoded
  native('lower-bound-before-surrogate-'+str(prefix),raw,arena,0,4300,original(x,4300),'private_unicode')
 # Malformed private frames are not semantic errors and must not publish a header.
 raw=b'[0]';arena=decoder.decode(raw);base=struct.pack('<8s15Q',b'HIABST01',0,len(raw),len(arena),len(threshold),4300,*([0]*10))+raw+arena+threshold
 variants=[('empty',b''),('truncated-header',base[:127]),('extra',base+b'x'),('missing-threshold',base[:-1])]
 for at,val in [(0,0),(8,2),(16,NONE),(24,NONE),(32,0),(32,len(threshold)-1),(40,1),(40,639),(40,2147483648)]+[(x,1) for x in range(48,128,8)]:
  b=bytearray(base);struct.pack_into('<Q',b,at,val);variants.append(('field-'+str(at)+'-'+str(val),bytes(b)))
 for name,wire in variants:
  out=C.create_string_buffer(512);work=C.create_string_buffer(SEEN+2);C.memset(out,0xdb,len(out))
  rc=image.call(wire,out,work);assert rc==0xfffffffd and out.raw==b'\xdb'*512,(name,rc)
  rows.append({'case':'private-'+name,'group':'private_frame','passed':True});counts['private_frame']=counts.get('private_frame',0)+1
 for on,wn in [(511,SEEN+2),(512,SEEN-1),(512,SEEN+1)]:
  out=C.create_string_buffer(on);work=C.create_string_buffer(wn);C.memset(out,0xdb,on)
  rc=image.call(base,out,work);assert rc==0xfffffffd and out.raw==b'\xdb'*on
  rows.append({'case':'short-'+str(on)+'-'+str(wn),'group':'private_frame','passed':True});counts['private_frame']=counts.get('private_frame',0)+1
 report.update(passed=True,count=len(rows),decoder_calls=decoder.calls,conversion_policies=[0,640,4300,5000],all_budgets_unchanged=True,source_threshold_unchanged=a.threshold.read_bytes()==threshold)
 save();print('BG_STRUCTURE_ALL_PASS',len(rows),counts,flush=True)
if __name__=='__main__':main()
