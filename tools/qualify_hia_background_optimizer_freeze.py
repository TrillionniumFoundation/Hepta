"""Compare checked native JSON freezing with fresh CPython conversion."""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes as C,json,math,os,random,resource,struct,sys,time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.qualify_hia_background_optimizer_structure import Flat,Decoder
NONE=(1<<64)-1
def encode(value,ascii=False,pretty=False):
 prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(0)
 try:return json.dumps(value,ensure_ascii=ascii,allow_nan=True,separators=None if pretty else (',',':')).encode('utf-8','surrogatepass')
 finally:sys.set_int_max_str_digits(prior)
def original(value,limit):
 prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(limit)
 try:
  try:
   raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
   return {'bytes':raw}
  except BaseException as e:
   out={'type':type(e).__name__,'message':str(e)}
   if isinstance(e,UnicodeEncodeError):out['span']=[e.start,e.end]
   return out
 finally:sys.set_int_max_str_digits(prior)
def owned_arena(value):
 raw=bytearray();nodes=[]
 def visit(v,parent=NONE,key=None):
  index=len(nodes);row=[0,parent,NONE,0,0,0,0,0,0];nodes.append({'row':row,'key':key,'text':None})
  start=len(raw);kind={type(None):0,bool:2,int:3,float:3,str:4,list:5,dict:6}[type(v)]
  if v is False:kind=1
  row[0]=kind
  if kind in (5,6):
   raw.extend(b'[' if kind==5 else b'{');children=[]
   values=list(enumerate(v)) if kind==5 else list(v.items())
   for k,item in values:
    if children:raw.extend(b',')
    if kind==6:raw.extend(encode(k,ascii=True));raw.extend(b':')
    child=visit(item,index,k if kind==6 else None);children.append(child)
   raw.extend(b']' if kind==5 else b'}')
   row[3]=children[0] if children else NONE;row[4]=len(children)
   for a,b in zip(children,children[1:]):nodes[a]['row'][2]=b
  else:
   raw.extend(encode(v,ascii=True))
   if kind==4:nodes[index]['text']=v.encode('utf-8','surrogatepass')
   else:row[3]=start;row[4]=len(raw)-start
  if kind>=4:row[7]=start;row[8]=len(raw)-start
  return index
 visit(value);first=64+72*len(nodes);data=bytearray()
 for node in nodes:
  row=node['row']
  if node['key'] is not None:
   text=node['key'].encode('utf-8','surrogatepass');row[5]=first+len(data);row[6]=len(text);data.extend(text)
  if node['text'] is not None:
   row[3]=first+len(data);row[4]=len(node['text']);data.extend(node['text'])
 n=first+len(data)
 header=struct.pack('<8Q',5208772604367785521,len(nodes),first,n,n,len(raw),1,0)
 return bytes(raw),header+b''.join(struct.pack('<9Q',*x['row']) for x in nodes)+data
def objects(value):
 out=[]
 def visit(x):
  out.append(x)
  if type(x) is list:
   for v in x:visit(v)
  elif type(x) is dict:
   for v in x.values():visit(v)
 visit(value);return out
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--json-flat',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 D=a.output;D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 flat=Flat(a.directory/'background_optimizer_freeze.flat');decoder=Decoder(a.json_flat)
 rows=[];counts={};report={'passed':False,'whole_background_qualified':False,'scope':'Checked canonical serialization of fresh owned JSON subtrees, original conversion policy, and separately labeled private typed nonfinite/WTF8 arenas. No BG structure budget is introduced here.','flat_sha256':flat.sha,'json_sha256':decoder.flat.sha,'default_conversion_limit':sys.get_int_max_str_digits(),'counts':counts,'cases':rows}
 def save():(D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 def invoke(frame,wn,on):
  source=C.create_string_buffer(frame);out=C.create_string_buffer(on+32);work=C.create_string_buffer(wn+32)
  C.memset(out,0xdb,len(out));C.memset(work,0xa5,len(work))
  began=time.monotonic_ns();rc=flat.entry(source,len(frame),C.addressof(out)+16,on,C.addressof(work)+16,wn);elapsed=time.monotonic_ns()-began
  assert source.raw==frame+b'\0'
  assert out.raw[:16]+out.raw[-16:]==b'\xdb'*32
  assert work.raw[:16]+work.raw[-16:]==b'\xa5'*32
  return rc,out.raw[16:16+on],elapsed
 def native(name,value,raw,arena,root,limit,group):
  expected=original(value,limit);count=struct.unpack_from('<Q',arena,8)[0]
  frame=struct.pack('<8s15Q',b'HIABJF01',0,root,len(raw),len(arena),limit,*([0]*10))+raw+arena
  wn=max(131072,len(arena)+16384);rc,out,elapsed=invoke(frame,wn,1024);actual=None
  try:
   assert rc==0,(name,rc)
   head=struct.unpack_from('<8s15Q',out)
   assert head[0]==b'HIABJR01' and head[1] in (0,1) and head[4]<=896
   if 'bytes' in expected:
    assert head[1]==0 and head[2]==0 and head[3]==len(expected['bytes']) and head[4]==0
    assert head[5]==len(expected['bytes'].decode())
    emitted=bytearray(frame);struct.pack_into('<Q',emitted,8,1)
    rc2,out2,ns=invoke(bytes(emitted),wn,128+head[3]);elapsed+=ns
    assert rc2==0 and out2[128:]==expected['bytes'],(name,'emit',rc2,out2[128:160],expected['bytes'][:32])
    actual={'json_bytes':len(expected['bytes']),'sha256':sha256(expected['bytes']).hexdigest()}
    if len(rows)%31==0:
     badrc,badout,ns=invoke(bytes(emitted),wn,127+head[3]);elapsed+=ns
     assert badrc==0xfffffffe and badout==b'\xdb'*len(badout),(name,'atomic short',badrc)
   else:
    actual=json.loads(out[128:128+head[4]])
    assert head[1]==1 and actual=={k:v for k,v in expected.items() if k!='span'},(name,actual,expected)
    if 'span' in expected:assert [head[6],head[7]]==expected['span']
  except BaseException as e:
   (D/'failure.input').write_bytes(frame);(D/'failure.output').write_bytes(out)
   exp={k:v for k,v in expected.items() if k!='bytes'}
   if 'bytes' in expected:exp={'bytes':len(expected['bytes']),'sha256':sha256(expected['bytes']).hexdigest()}
   (D/'failure.json').write_text(json.dumps({'case':name,'error':repr(e),'expected':exp,'actual':actual,'completed':len(rows)},indent=2)+'\n');raise
  rows.append({'case':name,'group':group,'root':root,'limit':limit,'raw_bytes':len(raw),'raw_sha256':sha256(raw).hexdigest(),'arena_bytes':len(arena),'native_elapsed_ns':elapsed,'result':actual,'passed':True});counts[group]=counts.get(group,0)+1
  if len(rows)%100==0 or group=='large':
   save();print('BG_FREEZE_CASE',len(rows),name,actual,elapsed,flush=True)
 def run(name,value,limit=4300,group='regular',manual=False,subtree=False,raw=None):
  if manual:raw,arena=owned_arena(value)
  else:
   raw=encode(value,ascii=bool(len(rows)%2),pretty=bool(len(rows)%7==0)) if raw is None else raw
   arena=decoder.decode(raw)
  native(name,value,raw,arena,0,limit,group)
  if subtree:
   values=objects(value)
   for root in sorted(set([1,len(values)//2,len(values)-1])):
    if 0<root<len(values):native(name+'-sub-'+str(root),values[root],raw,arena,root,limit,'subtree')
 atoms=[None,False,True,0,1,-1,10**80,-10**80,0.0,-0.0,1e-300,1.7976931348623157e308,'','a','é','中','😀','\x00\b\t\n\f\r\\"']
 for i,x in enumerate(atoms):run('atom-'+str(i),x)
 for i in range(256):run('unicode-'+str(i),{chr(i)+'k':[chr(i)]},group='unicode')
 rng=random.Random(0x20261126)
 for i in range(400):
  bits=rng.getrandbits(64);x=struct.unpack('<d',struct.pack('<Q',bits))[0]
  run('binary64-'+str(i),x,group='binary64',manual=not math.isfinite(x))
 def tree(d=0):
  if d>4 or rng.randrange(4)==0:return rng.choice(atoms)
  if rng.randrange(2):return [tree(d+1) for _ in range(rng.randrange(5))]
  return {str(i)+rng.choice(['x','é','中','😀']):tree(d+1) for i in range(rng.randrange(5))}
 for i in range(180):run('tree-'+str(i),tree(),group='tree',subtree=i<30)
 for limit in [0,640,4300,5000]:
  for digits in [639,640,641,4299,4300,4301,4999,5000,5001,100000]:
   prior=sys.get_int_max_str_digits();sys.set_int_max_str_digits(0)
   try:value=int('9'*digits)
   finally:sys.set_int_max_str_digits(prior)
   for sign in [1,-1]:run('conversion-'+str(limit)+'-'+str(digits)+'-'+str(sign),value*sign,limit,group='conversion')
 big=10**4301
 special=[float('nan'),float('inf'),float('-inf'),'\ud800','\udfff','x\ud800y','界\ud800','😀\ud800\udfff',
  {'z':big,'a':float('inf')},{'z':float('inf'),'a':big},{'a':'\ud800','z':big},{'a':'\ud800','z':float('nan')},
  {'a':big,'z':'\ud800'},{'z':float('-inf'),'a':float('nan')},{'\ud800':'x','z':float('inf')},
  {'x':'\ud800\udfff\udc00'},{'x':'\ud800X\udfff'},{'a':'\ud800','b':'\udfff'}]
 for i,x in enumerate(special):run('typed-errors-'+str(i),x,group='typed-errors',manual=True,subtree=type(x) is dict)
 for i in range(200):
  prefix=rng.choice(['x','é','中','😀','\x01','"','\\'])*rng.randrange(30)
  bad=''.join(chr(rng.randrange(0xd800,0xe000)) for _ in range(rng.randrange(1,8)))
  x={rng.choice(['z','a','中','😀'])+prefix:prefix+bad+rng.choice(['','x','\ud800'])}
  run('typed-surrogate-'+str(i),x,group='typed-unicode',manual=True)
 for token in [b'1e999999',b'-1e999999',b'1e-999999',b'-0',b'-0.0']:
  value=json.loads(token);run('raw-number-'+token.decode(),value,group='raw-number',raw=token)
 run('wide-100001',list(range(100001)),limit=0,group='large')
 run('nodes-over-old-domain',[None]*150000,limit=0,group='large')
 run('string-over-8MiB','x'*(8388608+1),group='large')
 run('utf8-over-8MiB','界'*3000000,group='large')
 run('raw-whitespace-over-8MiB',None,group='large',raw=b' '*8388609+b'null')
 for depth in [63,64,65,128,300]:
  x=0
  for _ in range(depth):x=[x]
  run('deep-'+str(depth),x,group='depth')
 raw,arena=owned_arena({'a':[1,'x']});base=struct.pack('<8s15Q',b'HIABJF01',0,0,len(raw),len(arena),4300,*([0]*10))+raw+arena;wn=max(131072,len(arena)+16384)
 guards=[]
 for at,value in [(0,0),(8,2),(16,99),(24,len(raw)+1),(32,len(arena)-1),(40,1),(40,639),(40,2147483648)]+[(i,1) for i in range(48,128,8)]:
  f=bytearray(base);struct.pack_into('<Q',f,at,value);guards.append(('header-'+str(at)+'-'+str(value),bytes(f),wn,1024,0xfffffffd))
 for cut in [0,1,63,127,len(base)-1]:guards.append(('cut-'+str(cut),base[:cut],wn,1024,0xfffffffd))
 guards += [('work-short',base,131071,1024,0xfffffffd),('out-short',base,wn,127,0xfffffffe)]
 for label,f,workn,outn,expected in guards:
  rc,out,elapsed=invoke(f,workn,outn);assert rc==expected and out==b'\xdb'*outn,(label,rc,expected)
  rows.append({'case':label,'group':'private','passed':True});counts['private']=counts.get('private',0)+1
 report.update(passed=True,total=len(rows),json_native_calls=decoder.calls,max_error_json_bytes=max([len(json.dumps(r['result'],sort_keys=True,separators=(',',':'))) for r in rows if isinstance(r.get('result'),dict) and 'type' in r['result']]or[0]))
 save();print('BG_FREEZE_QUALIFIED',len(rows),counts,flat.sha,flush=True)
if __name__=='__main__':main()
