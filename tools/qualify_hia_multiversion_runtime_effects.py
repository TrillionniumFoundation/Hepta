"""Actual original runtime versus fixed HIA effects; no supplied effect facts."""
from pathlib import Path
import sys,os,json,struct,ctypes as C,mmap,time,hashlib,threading,concurrent.futures,argparse,copy
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');V=B/'native-multiversion-source';sys.path.insert(0,str(V))
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_runtime_generation import scalar_program,rawdoc
from hepta.hia_multiversion import ScalarMultiversionRuntime,MultiversionRejected
from hepta.hia_program import HIAProgramRejected
get=lambda b,i:struct.unpack_from('<Q',b,i)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
class Runtime:
 def __init__(self,lib,identity,files,parent,rows):
  self.w=C.create_string_buffer(131072);self.f=lib.hia_mv_runtime_effects;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.id=identity.hia_mv_runtime_identity;self.id.argtypes=[C.c_void_p,C.c_uint64]*3;self.id.restype=C.c_uint32
  self.files=files;self.parent=parent;self.rows=rows;self.row_lock=threading.Lock()
 def q(self,op,*,raw=b'',lease=(0,0,0),fn=b'',args=b'',expect=None,maxlive=8,prove=False,expected=(0,0),budget=0,token=0,measurement=b'',handoff=NONE,want=0):
  h=bytearray(256);struct.pack_into('<8sQ',h,0,b'HIAMVEX1',op)
  if op==0:
   struct.pack_into('<6Q',h,16,*[fd for fd,b in self.files],2000,maxlive,int(prove))
   parent=os.fsencode(self.parent);h[128:224]=b''.join(hashlib.sha256(b).digest() for fd,b in self.files)
  else:
   parent=b'';struct.pack_into('<3Q',h,16,*lease);struct.pack_into('<4Q',h,40,*expected,budget,token)
  struct.pack_into('<Q',h,72,handoff)
  struct.pack_into('<6Q',h,80,len(raw),len(parent),len(fn),len(args),len(measurement),int(bool(measurement)))
  src=bytes(h)+raw+parent+fn+args+measurement;s=C.create_string_buffer(src)
  mem=mmap.mmap(-1,40<<20);o=(C.c_char*(40<<20)).from_buffer(mem)
  start=time.monotonic_ns();rc=self.f(s,len(src),o,len(o),self.w,len(self.w));elapsed=time.monotonic_ns()-start
  out=C.string_at(C.addressof(o),1024);value=bytes(o[get(out,120):get(out,120)+get(out,112)]) if get(out,112) else b''
  streams=[]
  for at in (96,104):
   fd=get(out,at)
   if fd!=NONE:
    st=os.fstat(fd);streams.append(dict(bytes=st.st_size,sha256=sha(os.pread(fd,st.st_size,0))));os.close(fd)
  row=dict(op=op,rc=rc,fields=[get(out,i) for i in range(8,144,8)],elapsed_ns=elapsed,value=value.decode('utf-8'),streams=streams)
  with self.row_lock:self.rows.append(row)
  assert s.raw==src+b'\0'
  del o;mem.close()
  if want is not None:assert rc==want,row
  return out,value,rc
 def idq(self,op,selector=0,cap=(0,0,0)):
  req=struct.pack('<8s7Q',b'HIAMVID1',op,selector,*cap,0,0);s=C.create_string_buffer(req);o=C.create_string_buffer(4096)
  rc=self.id(s,len(req),o,len(o),C.addressof(self.w)+32768,32768)
  assert rc==0 and o.raw[:8]==b'HIAMVIDR' and get(o,8)==0,(op,selector,rc,list(struct.unpack('<8Q',o.raw[:64])))
  return o.raw
 def decimal(self,selector=None,cap=None):
  if cap is None:
   o=self.idq(7,selector);cap=tuple(get(o,at) for at in (24,32,40))
  o=self.idq(13,cap=cap);return int(o[1536:1536+get(o,80)])
 def lease(self):
  o,v,rc=self.q(3);return tuple(get(o,at) for at in (64,80,88))
 def call(self,lease,argument):
  o,v,rc=self.q(4,lease=lease,fn=b'calculate',args=json.dumps([argument]).encode());return json.loads(v)
 def closelease(self,lease,drop=True):
  self.q(5,lease=lease)
  if drop:self.q(12,lease=lease)
 def view(self):
  self.q(10)
  gens=[]
  for i in range(64):
   state=get(self.w,8192+512+i*256)
   if state&2:
    ptr=get(self.w,65536+i*16);go=C.string_at(ptr,256);gw=get(go,32);ret=C.string_at(get(go,40),get(go,48));ctrl=C.string_at(gw+(500<<20),2560)
    gens.append(dict(generation=self.decimal(i),program_sha256=ctrl[320:352].hex(),input_sha256=ctrl[288:320].hex(),native_probe_calls=get(ctrl,512+88),baseline=bool(get(self.w,8192+512+i*256+16)),active_leases=int.from_bytes(ret[64:64+get(ret,32)],'little'),retired=bool(get(ret,24)&1)))
  current=get(self.w,8192+48)
  head=get(self.w,32768+28672);count=get(self.w,32768+28680);events=[]
  for i in range(count):
   row=C.string_at(C.addressof(self.w)+32768+16384+((head-count+i)%128)*96,96)
   events.append(dict(event={1:'publish',2:'publish_if_current',3:'rollback',4:'retire'}[get(row,64)],generation=self.decimal(cap=tuple(get(row,a) for a in (0,8,16))),epoch=self.decimal(cap=tuple(get(row,a) for a in (32,40,48)))))
  return dict(closed=bool(get(self.w,8192+24)),current_generation=None if current==NONE else self.decimal(current),selection_epoch=self.decimal(64),generations=sorted(gens,key=lambda x:x['generation']),recent_events=events,attempts=self.decimal(66))
def original_view(r):
 s=r.snapshot();keys=('generation','program_sha256','input_sha256','native_probe_calls','baseline','active_leases','retired')
 return dict(closed=s['closed'],current_generation=s['current_generation'],selection_epoch=s['selection_epoch'],generations=[{k:g[k] for k in keys} for g in s['generations']],recent_events=[{k:e[k] for k in ('event','generation','epoch')} for e in s['recent_events']],attempts=s['cleanup']['attempts'])
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--component',type=Path,required=True);a=p.parse_args();d=a.output;d.mkdir(exist_ok=False)
 paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];lib=C.CDLL(str(a.component));identity=C.CDLL(str(B/'native-multiversion-runtime-identity-v5/identity-component.so'))
 pnative=d/'native';poriginal=d/'original';pnative.mkdir(mode=0o700);poriginal.mkdir(mode=0o700)
 rows=[];views=[];native=Runtime(lib,identity,files,pnative,rows);base=scalar_program(None);equiv=scalar_program('bit.xor');orig=ScalarMultiversionRuntime(base,poriginal)
 def compare(name):
  ov=original_view(orig);nv=native.view();views.append(dict(name=name,original=ov,native=nv));(d/'views.json').write_text(json.dumps(views,indent=2)+'\n');(d/'calls.json').write_text(json.dumps(rows,indent=2)+'\n')
  assert ov==nv,(name,ov,nv)
  print('EFFECTS_PAIR_PASS',name,flush=True)
 native.q(0,raw=rawdoc(base));compare('constructor')
 ol0=orig.lease();nl0=native.lease();assert ol0.call('calculate',[7])==native.call(nl0,7)==7;compare('baseline-lease')
 orig.publish(equiv);native.q(1,raw=rawdoc(equiv));compare('first-publication')
 ol1=orig.lease();nl1=native.lease();compare('new-lease')
 assert ol0.call('calculate',[99])==native.call(nl0,99)==99
 assert ol1.call('calculate',[13])==native.call(nl1,13)==13
 orig.publish(base);native.q(1,raw=rawdoc(base));compare('second-publication-retains-old-lease')
 ol2=orig.lease();nl2=native.lease();compare('newest-lease')
 ol1.close();native.closelease(nl1,drop=False);compare('retired-lease-close')
 native.q(6,lease=nl1);native.q(12,lease=nl1);compare('closed-lease-info-and-drop')
 orig.rollback();native.q(7);compare('rollback')
 orig.rollback();native.q(7);compare('repeated-rollback')
 assert ol2.call('calculate',[55])==native.call(nl2,55)==55
 for label,doc in [('malformed',b'{'),('wrong-behavior',rawdoc(scalar_program(value=1)))]:
  try:orig.publish(doc)
  except (MultiversionRejected,HIAProgramRejected):pass
  else:raise AssertionError(label)
  native.q(1,raw=doc,want=10 if label=='malformed' else 24);compare(label+'-consumes-id-no-selection')
 orig.publish(base);native.q(1,raw=rawdoc(base));compare('publication-after-refusal')
 orig.close();native.q(8);compare('runtime-close-with-live-leases')
 assert ol0.call('calculate',[42])==native.call(nl0,42)==42
 assert ol2.call('calculate',[43])==native.call(nl2,43)==43
 ol0.close();native.closelease(nl0,drop=False);compare('baseline-last-close')
 ol2.close();native.closelease(nl2,drop=False);compare('last-live-lease-close')
 native.q(13,want=5);native.q(6,lease=nl0);native.q(6,lease=nl2)
 native.q(12,lease=nl0);native.q(12,lease=nl2)
 orig.close();native.q(8);compare('repeated-runtime-close')
 native.q(13);assert not list(pnative.iterdir()) and not list(poriginal.iterdir())
 for fd,b in files:os.close(fd)
 result=dict(schema='hepta.hia.multiversion-runtime-effects-actual.v1',whole_native_runtime=False,passed=len(views),failed=0,actual_effect_calls=len(rows),image_bytes=a.component.stat().st_size,image_sha256=sha(a.component.read_bytes()),same_holder=True,actual_original_runtime=True,source_identity='primitive profiles',views=views,calls=rows)
 (d/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('EFFECTS_PAIR_COMPLETE',len(views),len(rows),flush=True)
if __name__=='__main__':main()
