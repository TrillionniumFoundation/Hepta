"""Actual Q02 native objects in the same shared mutable value graph.
This qualifier needs the actual native packed value image. Python is the
independent semantic oracle and orchestration only.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,os,struct,threading,time,concurrent.futures
MASK=(1<<64)-1;BAD=0xfffffffd;A=(0,0,0)
get=lambda b,p:struct.unpack_from('<Q',b,p)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
def qframe(op,a=A,b=A,c=A,arg0=0,arg1=0,tail=b'',extended=False):
 return struct.pack('<8s15Q',b'HIABVQ02' if extended else b'HIABVQ01',op,0,*a,*b,*c,len(tail),arg0,arg1,0)+tail
class Image:
 def __init__(self,path):
  self.raw=Path(path).read_bytes();self.m=mmap.mmap(-1,len(self.raw),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);self.m.write(self.raw)
  self.v=(C.c_ubyte*len(self.raw)).from_buffer(self.m)
  self.f=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(C.addressof(self.v))
class Context:
 def __init__(self,image,rows):
  self.image=image;self.w=C.create_string_buffer(256);self.rows=rows;self.lock=threading.Lock()
  self.call(0)
 def call(self,op,a=A,b=A,c=A,arg0=0,arg1=0,tail=b'',extended=False,want=0,outn=16384):
  raw=qframe(op,a,b,c,arg0,arg1,tail,extended);s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa5'*(outn+64))
  start=time.monotonic_ns();rc=int(self.image.f(s,len(raw),o,outn,self.w,len(self.w)))
  assert rc==0 and o.raw[:8]==b'HIABVR01',(op,rc,o.raw[:128])
  status=get(o.raw,8);assert status==want,(op,status,want,o.raw[:128])
  assert s.raw==raw+b'\0' and o.raw[outn:outn+64]==b'\xa5'*64
  with self.lock:self.rows.append(dict(op=op,extended=extended,status=status,elapsed_ns=time.monotonic_ns()-start))
  return o.raw[:outn]
 def scalar(self,kind,data=b'',bits=0):
  o=self.call(2,arg0=kind,arg1=bits,tail=data);return tuple(get(o,p)for p in(24,32,40))
 def retain(self,a):
  o=self.call(5,a);return tuple(get(o,p)for p in(24,32,40))
 def drop(self,a):self.call(6,a)
 def kind(self,a):return get(self.call(7,a),16)
 def new(self,env,name,base=A,basekind=0,entry=0):
  o=self.call(25,env,base,name,arg0=basekind,arg1=entry,extended=True);return tuple(get(o,p)for p in(24,32,40))
 def inspect(self,a):
  o=self.call(26,a,extended=True)
  assert get(o,16)==8 and o[8192:8200]==b'HIAVNO01'
  caps=[tuple(get(o,p+i*24)for p in(8224,8232,8240))for i in range(3)]
  return get(o,8200),get(o,8208),caps
 def bytes(self,a):
  o=self.call(19,a,arg1=0);n=get(o,72)
  return self.call(19,a,arg1=n,outn=max(8192+n,8320))[8192:8192+n]
 def export(self,a):
  o=self.call(18,a);cap=tuple(get(o,p)for p in(24,32,40));raw=self.bytes(cap);self.drop(cap);return raw
 def same(self,a,b):return bool(get(self.call(8,a,b),48))
 def emptydict(self):
  o=self.call(4);return tuple(get(o,p)for p in(24,32,40))
 def finish(self):self.call(20)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--image',required=True);ap.add_argument('--output',required=True);args=ap.parse_args()
 dest=Path(args.output);dest.mkdir(parents=True,exist_ok=False);im=Image(args.image);rows=[];groups=[]
 def done(name,**extra):groups.append(dict(name=name,passed=True,**extra))
 # Object/environment/name and base are independent real references.
 c=Context(im,rows);env=c.emptydict();name=c.scalar(4,b'ActualPathLike');obj=c.new(env,name,entry=123456)
 assert c.kind(obj)==8
 for original in (env,name):c.drop(original)
 basekind,entry,caps=c.inspect(obj);assert basekind==0 and entry==123456 and c.kind(caps[0])==6 and c.kind(caps[1])==0 and c.bytes(caps[2])==b'ActualPathLike'
 for cap in caps:c.drop(cap)
 c.call(17,obj,want=2);c.call(19,obj,want=2);c.call(18,obj,want=2)
 c.drop(obj);c.finish();done('actual-environment-and-class-lifetime')
 # Equivalent metadata does not coalesce distinct objects; strings/bytes use
 # their inherited value semantics as keys while preserving exact object type.
 for kind,data in ((4,b'alpha'),(4,'汉字\U0001f642'.encode()),(4,b''),(4,b'\xed\xa0\x80'),(7,b'\0\xff'),(7,b'')):
  c=Context(im,rows);env=c.scalar(0);name=c.scalar(4,b'Subclass');base=c.scalar(kind,data)
  a=c.new(env,name,base,kind,0);b=c.new(env,name,base,kind,123)
  assert c.kind(a)==8 and not c.same(a,b) and not c.same(a,base)
  assert c.bytes(a)==data and get(c.call(17,a),48)==get(c.call(17,base),48)
  d=c.emptydict();v1=c.scalar(2,b'11');v2=c.scalar(2,b'22')
  c.call(10,d,base,v1);c.call(10,d,a,v2)
  assert get(c.call(17,d),48)==1
  o=c.call(9,d,b);picked=tuple(get(o,p)for p in(24,32,40));assert c.same(picked,v2);c.drop(picked)
  row=c.call(23,d,arg1=1);key=tuple(get(row,p)for p in(8208,8216,8224));value=tuple(get(row,p)for p in(8232,8240,8248))
  assert c.same(key,base) and c.same(value,v2)
  c.drop(key);c.drop(value)
  if kind==7:c.call(18,a,want=2)
  elif b'\xed\xa0\x80' in data:c.call(18,a,want=10)
  else:assert json.loads(c.export(a))==data.decode()
  for cap in (d,v1,v2,a,b,base,env,name):c.drop(cap)
  c.finish();done('subclass-%d-%s'%(kind,sha(data)),input_bytes=len(data))
 c=Context(im,rows);env=c.scalar(0);name=c.scalar(4,b'Class')
 a=c.new(env,name);b=c.new(env,name)
 d=c.emptydict();one=c.scalar(2,b'1');two=c.scalar(2,b'2')
 c.call(10,d,a,one);c.call(10,d,b,two);assert get(c.call(17,d),48)==2
 for key,want in((a,one),(b,two)):
  r=c.call(9,d,key);cap=tuple(get(r,p)for p in(24,32,40));assert c.same(cap,want);c.drop(cap)
 for cap in (a,b,d,one,two,env,name):c.drop(cap)
 c.finish();done('opaque-identity-hash-equality')
 # The dictionary owns the native object, and the object owns the dictionary.
 # Dropping the external roots exercises the actual shared cycle collector.
 c=Context(im,rows);env=c.emptydict();name=c.scalar(4,b'Cyclic');key=c.scalar(4,b'self')
 obj=c.new(env,name);c.call(10,env,key,obj)
 for cap in (obj,name,key,env):c.drop(cap)
 c.finish();done('native-object-environment-cycle-collection')
 # Rooted objects survive collection pressure, while unreachable cycles do not.
 c=Context(im,rows);name=c.scalar(4,b'Cycles');keepenv=c.emptydict();keep=c.new(keepenv,name);key=c.scalar(4,b'x')
 for i in range(4200):
  env=c.emptydict();a=c.new(env,name);c.call(10,env,key,a);c.drop(env);c.drop(a)
 kind,entry,caps=c.inspect(keep);assert kind==0 and c.same(caps[0],keepenv)
 for cap in caps:c.drop(cap)
 for cap in (keep,keepenv,name,key):c.drop(cap)
 c.finish();done('actual-collector-4096-trigger',cycles=4200)
 # Three inspect nodes are published atomically. Output-short creates none.
 c=Context(im,rows);env=c.scalar(0);name=c.scalar(4,b'Atomic');obj=c.new(env,name)
 out=c.call(26,obj,extended=True,outn=8319,want=13);assert get(out,72)==8320
 c.drop(obj);c.drop(name);c.drop(env);c.finish();done('inspect-short-no-live-reference')
 # New opaque scalars cannot be manufactured through the old scalar profile.
 c=Context(im,rows)
 c.call(2,arg0=8,want=7);c.call(2,arg0=9,want=7)
 env=c.scalar(0);name=c.scalar(4,b'Controls');obj=c.new(env,name)
 cases=[]
 for op in range(25,29):cases.append(qframe(op,a=obj))
 for op in tuple(range(25))+(32,MASK):cases.append(qframe(op,extended=True))
 for arg in(1,2,3,5,6,8,9,MASK):cases.append(qframe(25,a=env,c=name,arg0=arg,extended=True))
 for raw in cases:
  src=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*8192);before=c.w.raw
  rc=int(im.f(src,len(raw),out,len(out),c.w,len(c.w)))
  assert rc==BAD and c.w.raw==before
 c.call(25,env,env,name,arg0=4,extended=True,want=2)
 c.call(25,env,A,env,extended=True,want=2)
 for badname,expected in ((b'A\0B',8),(b'\xed\xa0\x80',10),(b'\0\xed\xa0\x80',10)):
  badcap=c.scalar(4,badname);c.call(25,env,A,badcap,extended=True,want=expected);c.drop(badcap)
 c.call(26,env,extended=True,want=2)
 stale=c.retain(obj);c.drop(stale);c.call(26,stale,extended=True,want=1)
 c.drop(obj);c.drop(name);c.drop(env);c.finish();done('old-profile-and-private-controls',controls=len(cases)+4)
 # Independent inspect references keep the objects alive through concurrent
 # last external drops. Every temporary object is independently registered.
 c=Context(im,rows);env=c.emptydict();name=c.scalar(4,b'Concurrent');obj=c.new(env,name)
 roots=[c.retain(obj)for _ in range(16)]
 c.drop(obj);c.drop(env);c.drop(name)
 def worker(cap):
  for i in range(128):
   k,e,refs=c.inspect(cap)
   assert k==0 and c.bytes(refs[2])==b'Concurrent'
   for r in refs:c.drop(r)
  c.drop(cap)
 with concurrent.futures.ThreadPoolExecutor(max_workers=16)as ex:list(ex.map(worker,roots))
 c.finish();done('16-thread-independent-inspect-ownership',rounds=2048)
 report=dict(schema='hia.native-value.object-extension.qualification.v1',passed=True,
  scope='actual_native_object_container_ownership_and_base_semantics',
  image=dict(bytes=len(im.raw),sha256=sha(im.raw)),groups=groups,calls=len(rows),rows=rows,
  callable_execution_closed=False,dict_iterator_qualified_separately=True,whole_public_runtime_closed=False)
 (dest/'qualification.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print('NATIVE_VALUE_OBJECT_QUALIFIED',len(groups),len(rows),sha((dest/'qualification.json').read_bytes()),flush=True)
if __name__=='__main__':main()

