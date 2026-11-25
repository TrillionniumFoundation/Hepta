"""Fresh native owned capture against original JSON value semantics.

The unlimited decimal setting below represents lexical typed capture only.
The real captured conversion policy is applied separately by checked freezing.
Strict Core and proof JSON parsers remain untouched.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes as C,json,math,random,resource,struct,sys,time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.qualify_hia_background_optimizer_structure import Flat,Decoder
from tools.qualify_hia_background_optimizer_freeze import original
NONE=(1<<64)-1
def parse_original(raw):
 prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(0)
 try:return json.loads(raw)
 finally:sys.set_int_max_str_digits(prior)
def encode(value,ascii=False):
 prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(0)
 try:return json.dumps(value,ensure_ascii=ascii,separators=(',',':')).encode('utf-8','surrogatepass')
 finally:sys.set_int_max_str_digits(prior)
def unpack_tree(raw,arena):
 magic,count,base,used,used2,sn,valid,zero=struct.unpack_from('<8Q',arena)
 assert magic==5208772604367785521 and used==used2==len(arena) and sn==len(raw) and valid==1 and zero==0 and base==64+72*count
 values=[None]*count;keys=[None]*count;seen=[False]*count;seen[0]=True
 for i in range(count-1,-1,-1):
  row=struct.unpack_from('<9Q',arena,64+i*72);kind,parent,next_,at,n,key,kn,ra,rn=row
  assert kind<=6 and (i==0 and parent==NONE and next_==NONE or 0<=parent<i) and (next_==NONE or i<next_<count)
  if key:keys[i]=arena[key:key+kn].decode('utf-8','surrogatepass')
  if kind==4:values[i]=arena[at:at+n].decode('utf-8','surrogatepass')
  elif kind<4:
   assert ra==rn==0,('owned scalar unused fields',i,ra,rn)
   values[i]=parse_original(raw[at:at+n])
  else:
   children=[];child=at
   for _ in range(n):
    assert i<child<count and not seen[child];seen[child]=True;children.append(child)
    assert struct.unpack_from('<Q',arena,64+child*72+8)[0]==i
    child=struct.unpack_from('<Q',arena,64+child*72+16)[0]
   assert child==NONE
   if kind==5:values[i]=[values[x] for x in children]
   else:
    pairs=[(keys[x],values[x])for x in children];assert all(type(k)is str for k,v in pairs) and len({k for k,v in pairs})==len(pairs)
    values[i]=dict(pairs)
 assert all(seen)
 return values[0],values
def equal(a,b):
 pending=[(a,b)]
 while pending:
  a,b=pending.pop()
  if type(a)is not type(b):return False
  if type(a)is float:
   if math.isnan(a):
    if not math.isnan(b):return False
   elif struct.pack('<d',a)!=struct.pack('<d',b):return False
  elif type(a)is list:
   if len(a)!=len(b):return False
   pending.extend(zip(a,b))
  elif type(a)is dict:
   if list(a)!=list(b):return False
   pending.extend((a[k],b[k])for k in a)
  elif a!=b:return False
 return True
class Capture:
 def __init__(self,path):self.flat=Flat(path);self.calls=0
 def decode(self,raw):
  out=C.create_string_buffer(64);work=C.create_string_buffer(128)
  rc=self.flat.call(raw,out,work);assert rc==0,('sizes',rc)
  magic,nodes,keys,depth,cap,wn,sn,zero=struct.unpack('<8s7Q',out.raw)
  assert magic==b'HIANJS01'and sn==len(raw)and zero==0
  source=C.create_string_buffer(raw);out=C.create_string_buffer(cap+32);work=C.create_string_buffer(wn+32)
  C.memset(out,0xdb,len(out));C.memset(work,0xa5,len(work))
  struct.pack_into('<QQ',work,16+48,nodes,depth);struct.pack_into('<QQ',work,16+96,keys,1)
  began=time.monotonic_ns();rc=self.flat.entry(source,len(raw),C.addressof(out)+16,cap,C.addressof(work)+16,wn);elapsed=time.monotonic_ns()-began
  assert source.raw==raw+b'\0'
  assert out.raw[:16]+out.raw[-16:]==b'\xdb'*32
  assert work.raw[:16]+work.raw[-16:]==b'\xa5'*32
  self.calls+=2
  if rc:return rc,None,elapsed,{'nodes':nodes,'keys':keys,'depth':depth,'arena_cap':cap,'work_cap':wn}
  used=struct.unpack_from('<Q',out,16+24)[0];assert 64<=used<=cap
  return 0,out.raw[16:16+used],elapsed,{'nodes':nodes,'keys':keys,'depth':depth,'arena_cap':cap,'work_cap':wn}
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--strict-json',type=Path,required=True);p.add_argument('--freezer',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 D=a.output;D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 capture=Capture(a.directory/'background_optimizer_json_capture.flat');strict=Decoder(a.strict_json);freezer=Flat(a.freezer)
 rows=[];counts={};report={'passed':False,'whole_background_qualified':False,'scope':'Native owned-JSON lexical capture; fresh Python JSON accepted-value/type/order comparison, strict old-profile defined-byte parity (only unused scalar +56/+64 words normalized), and actual checked-freeze composition. Original business and decimal-conversion limits are applied by the caller.','flat_sha256':capture.flat.sha,'strict_json_sha256':strict.flat.sha,'freezer_sha256':freezer.sha,'cases':rows,'counts':counts}
 def save():(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 def frozen(raw,arena,value,root=0,limit=4300):
  frame=struct.pack('<8s15Q',b'HIABJF01',0,root,len(raw),len(arena),limit,*([0]*10))+raw+arena
  work=C.create_string_buffer(max(131072,len(arena)+16384));out=C.create_string_buffer(1024)
  rc=freezer.call(frame,out,work);assert rc==0,('freeze check',rc)
  head=struct.unpack_from('<8s15Q',out);expected=original(value,limit)
  assert head[0]==b'HIABJR01'
  if 'bytes'in expected:
   assert head[1]==0 and head[3]==len(expected['bytes'])
   f=bytearray(frame);struct.pack_into('<Q',f,8,1)
   target=C.create_string_buffer(128+head[3]);rc=freezer.call(bytes(f),target,work)
   assert rc==0 and target.raw[128:]==expected['bytes'],('freeze emit',rc)
   return {'json_bytes':len(expected['bytes']),'sha256':sha256(expected['bytes']).hexdigest()}
  actual=json.loads(out.raw[128:128+head[4]])
  assert head[1]==1 and actual=={k:v for k,v in expected.items()if k!='span'},(actual,expected)
  if 'span'in expected:assert [head[6],head[7]]==expected['span']
  return actual
 def run(name,raw,group='normal',parity=False,check=True,subtrees=False):
  expected=parse_original(raw);rc,arena,elapsed,stats=capture.decode(raw)
  try:
   assert rc==0,(name,rc,stats)
   actual,values=unpack_tree(raw,arena);assert equal(actual,expected),(name,'value/order/type')
   parity_unused=0
   if parity:
    expected_arena=bytearray(strict.decode(raw))
    count=struct.unpack_from('<Q',expected_arena,8)[0]
    for index in range(count):
     row=64+72*index
     if struct.unpack_from('<Q',expected_arena,row)[0]<4:
      if expected_arena[row+56:row+72]!=b'\0'*16:parity_unused+=1
      expected_arena[row+56:row+72]=b'\0'*16
    assert arena==bytes(expected_arena),(name,'strict defined arena mismatch')
   result=frozen(raw,arena,expected)if check else None
   if subtrees:
    for index in sorted(set([1,len(values)//2,len(values)-1])):
     if 0<index<len(values):frozen(raw,arena,values[index],index)
  except BaseException as e:
   (D/'failure.input').write_bytes(raw)
   if arena is not None:(D/'failure.arena').write_bytes(arena)
   (D/'failure.json').write_text(json.dumps({'case':name,'error':repr(e),'rc':rc,'stats':stats,'completed':len(rows)},indent=2)+'\n');raise
  rows.append({'case':name,'group':group,'source_bytes':len(raw),'source_sha256':sha256(raw).hexdigest(),'arena_bytes':len(arena),'retained_nodes':struct.unpack_from('<Q',arena,8)[0],'native_elapsed_ns':elapsed,'stats':stats,'freeze':result,'strict_defined_byte_parity':parity,'old_unused_scalar_rows':parity_unused,'passed':True})
  counts[group]=counts.get(group,0)+1
  if len(rows)%100==0 or group=='large':save();print('BG_CAPTURE_CASE',len(rows),name,len(raw),len(arena),elapsed,flush=True)
 atoms=[None,False,True,0,1,-1,10**80,-10**80,0.0,-0.0,1e-300,1.7976931348623157e308,'','a','é','中','😀','\x00\b\t\n\f\r\\"']
 for i,x in enumerate(atoms):run('atom-'+str(i),encode(x,ascii=bool(i%2)),parity=True)
 rng=random.Random(0x20261127)
 def value(depth=0):
  if depth>5 or rng.randrange(4)==0:return rng.choice(atoms)
  if rng.randrange(2):return[value(depth+1)for _ in range(rng.randrange(6))]
  return{str(i)+rng.choice(['x','é','中','😀','\x00']):value(depth+1)for i in range(rng.randrange(6))}
 for i in range(350):run('tree-'+str(i),encode(value(),ascii=bool(i%2)),parity=True,subtrees=i<20)
 for i in range(128):
  bad=''.join(chr(rng.randrange(0xd800,0xe000))for _ in range(rng.randrange(1,6)))
  x={rng.choice(['z','a','中','😀'])+bad:[bad,'界'+bad,'😀'+bad]}
  run('unicode-escaped-'+str(i),encode(x,ascii=True),group='surrogate')
  run('unicode-raw-'+str(i),encode(x,ascii=False),group='surrogate')
 for token in [b'NaN',b'Infinity',b'-Infinity',b'1e99999',b'-1e99999']:
  run('nonfinite-'+token.decode(),b'{"z":'+token+b',"a":0}',group='nonfinite')
 for n in [1,5,32,1000]:
  raw=b'{'+b','.join(b'"x":'+encode(i)for i in range(n))+b'}'
  run('duplicate-'+str(n),raw,group='duplicate')
 explicit=[
  b'{"b":0,"a":1,"b":2,"c":3,"a":4}',
  b'{"x":{"old":1},"x":[0,{"new":2}],"a":3}',
  b'{"a":[1,2],"b":3,"a":{"k":4,"k":5}}',
  b'{"a":NaN,"a":1}',b'{"a":1,"a":NaN}',
  b'{"x":"\\ud800","x":0}',b'{"x":0,"x":"\\ud800"}',
  b'{"\\ud83d\\ude00":0,"\xf0\x9f\x98\x80":1}',
  b'{"\\ud800":0,"\xed\xa0\x80":1}',
  b'{"a":{"x":0,"x":1},"b":{"x":2,"x":3}}',
  b'["\\ud800\\ud800","\\ud800\\udfff","\\udfff\\ud800"]',
  b'{"z":0,"a":0,"z":{"x":1,"x":2},"a":[0,1]}'
 ]
 for i,raw in enumerate(explicit):run('explicit-'+str(i),raw,group='duplicate',subtrees=True)
 for i in range(100):
  pairs=[]
  for j in range(rng.randrange(1,30)):
   key=rng.choice(['x','a','é','中','😀','\ud800'])
   val=rng.choice([None,0,1,[1,2],{'k':3},float('nan'),'\udfff',True])
   pairs.append(encode(key,ascii=bool(j%2))+b':'+encode(val,ascii=bool(j%3)))
  run('duplicate-random-'+str(i),b'{'+b','.join(pairs)+b'}',group='duplicate')
 for n in [4300,4301,100000]:
  run('integer-'+str(n),b'{"x":'+b'9'*n+b'}',group='conversion')
 for depth in [64,65,300,600]:
  raw=b'['*depth+b'null'+b']'*depth
  run('depth-'+str(depth),raw,group='depth',check=depth<600)
 for name,raw in [
  ('million-nodes',b'['+b','.join([b'null']*1048577)+b']'),
  ('duplicate-wide',b'{'+b','.join(b'"x":'+str(i).encode() for i in range(100000))+b'}'),
  ('96MiB-frame',encode(['a'*(3*1024*1024)]*32)),
  ('8MiB-string',encode('x'*(8388608+1))),
  ('empty-after-overwrite',b'{"x":'+encode('x'*(8388608+1))+b',"x":null}')
 ]:run(name,raw,group='large',check=name not in('million-nodes','96MiB-frame'))
 malformed=[b'',b' ',b'[',b'{',b'Na',b'Inf',b'-Inf',b'nan',b'inf',b'+Infinity',b'Infinity.0',b'NaN0',b'-NaN',b'[NaN,]',b'{"a":1,"a":}',b'"\\ud800\\q"',b'"\\ud800\\uZZZZ"',b'"\\u12"',b'"\xc0\x80"',b'"\xf4\x90\x80\x80"',b'01',b'-01',b'1e+',b'[1 2]',b'{"a":1}x']
 for i,raw in enumerate(malformed):
  try:parse_original(raw);raise AssertionError(('malformed accepted by oracle',i))
  except (json.JSONDecodeError,UnicodeDecodeError,ValueError):pass
  rc,arena,elapsed,stats=capture.decode(raw);assert rc!=0,(i,raw)
  rows.append({'case':'malformed-'+str(i),'group':'malformed','status':rc,'passed':True});counts['malformed']=counts.get('malformed',0)+1
 report.update(passed=True,total=len(rows),actual_capture_calls=capture.calls,strict_decoder_calls=strict.calls)
 save();print('BG_CAPTURE_QUALIFIED',len(rows),counts,capture.flat.sha,flush=True)
if __name__=='__main__':main()
