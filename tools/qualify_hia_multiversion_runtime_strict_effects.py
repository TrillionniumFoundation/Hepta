"""Actual original runtime versus fixed HIA effects; no supplied effect facts."""
from pathlib import Path
import sys,os,json,struct,fcntl,ctypes as C,mmap,time,hashlib,threading,concurrent.futures,argparse,copy
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_runtime_generation import scalar_program,rawdoc
from hepta.hia_multiversion import ScalarMultiversionRuntime,MultiversionRejected
from hepta.hia_program import HIAProgramRejected
get=lambda b,i:struct.unpack_from('<Q',b,i)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
libc=C.CDLL(None);libc.free.argtypes=[C.c_void_p];libc.free.restype=None
class Runtime:
 def __init__(self,lib,identity,files,parent,rows):
  self.w=C.create_string_buffer(131072);self.f=lib.hia_mv_runtime_effects;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.id=identity.hia_mv_runtime_identity;self.id.argtypes=[C.c_void_p,C.c_uint64]*3;self.id.restype=C.c_uint32
  self.files=files;self.parent=parent;self.rows=rows;self.row_lock=threading.Lock();self.snapshots=[]
 def q(self,op,*,raw=b'',lease=(0,0,0),fn=b'',args=b'',expect=None,maxlive=8,prove=False,expected=(0,0),budget=0,token=0,measurement=b'',handoff=NONE,want=0):
  h=bytearray(256);struct.pack_into('<8sQ',h,0,b'HIAMVEX5' if op==0 else b'HIAMVEX3',op)
  if op==0:
   struct.pack_into('<6Q',h,16,*[fd for fd,b in self.files],2000,maxlive,int(prove));struct.pack_into('<Q',h,240,sys.get_int_max_str_digits())
   parent=os.fsencode(self.parent);h[128:224]=b''.join(hashlib.sha256(b).digest() for fd,b in self.files)
  else:
   parent=b'';struct.pack_into('<3Q',h,16,*lease);struct.pack_into('<4Q',h,40,*expected,budget,token)
  struct.pack_into('<Q',h,72,handoff)
  struct.pack_into('<6Q',h,80,len(raw),len(parent),len(fn),len(args),len(measurement),int(bool(measurement)))
  src=bytes(h)+raw+parent+fn+args+measurement;s=C.create_string_buffer(src)
  mem=mmap.mmap(-1,40<<20);o=(C.c_char*(40<<20)).from_buffer(mem)
  start=time.monotonic_ns();rc=self.f(s,len(src),o,len(o),self.w,len(self.w));elapsed=time.monotonic_ns()-start
  out=C.string_at(C.addressof(o),1024);value=bytes(o[get(out,120):get(out,120)+get(out,112)]) if get(out,112) else b''
  ptr,n=get(out,144),get(out,152);payload=C.string_at(ptr,n) if ptr else b''
  if ptr:libc.free(ptr)
  if op in (9,10) and rc==0:
   self.snapshot=json.loads(payload);self.snapshots.append(dict(op=op,value=self.snapshot))
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
  value=self.snapshot
  keys=('generation','program_sha256','input_sha256','native_probe_calls','baseline','active_leases','retired')
  return dict(closed=value['closed'],current_generation=value['current_generation'],selection_epoch=value['selection_epoch'],generations=[{k:g[k] for k in keys} for g in value['generations']],recent_events=[{k:e[k] for k in ('event','generation','epoch')} for e in value['recent_events']],attempts=value['cleanup']['attempts'])

def original_view(r):
 s=r.snapshot();r._qualification_snapshot=s;keys=('generation','program_sha256','input_sha256','native_probe_calls','baseline','active_leases','retired')
 return dict(closed=s['closed'],current_generation=s['current_generation'],selection_epoch=s['selection_epoch'],generations=[{k:g[k] for k in keys} for g in s['generations']],recent_events=[{k:e[k] for k in ('event','generation','epoch')} for e in s['recent_events']],attempts=s['cleanup']['attempts'])
def exact_live_evidence(native, original, value, is_native):
 from hepta.native_mapping_identity import verify_loaded_symbols
 syms=C.CDLL(None).dlsym;syms.argtypes=[C.c_void_p,C.c_char_p];syms.restype=C.c_void_p
 native_by_gen={}
 if is_native:
  for slot in range(64):
   ptr=get(native.w,65536+slot*16)
   if not ptr:continue
   go=C.string_at(ptr,256)
   generation=native.decimal(cap=tuple(get(go,at) for at in (80,88,96)))
   native_by_gen[generation]=go
 evidence=[]
 for g in value['generations']:
  path=Path(g['artifact_identity_pin']['path']);data=path.read_bytes();st=path.lstat()
  assert sha(data)==g['artifact_sha256'] and len(data)==g['artifact_bytes']
  assert g['artifact_identity_pin']['inode']==[st.st_dev,st.st_ino]
  if is_native:
   go=native_by_gen[g['generation']];gw=get(go,32);image=C.string_at(gw,2048);fd=get(image,48);library=get(image,56)
   funcs={}
   for signature in g['abi']:
    p=syms(library,signature['function'].encode());assert p
    funcs[signature['function']]=C.CFUNCTYPE(C.c_uint64)(p)
  else:
   state=original._states[g['generation']];fd=state.fd;funcs=state.functions
  assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15
  sealed_data=os.pread(fd,len(data)+1,0);assert sealed_data==data
  actual=verify_loaded_symbols(fd,funcs);reported=dict(g['loaded_mapping']);checker=reported.pop('checker_sha256')
  assert type(checker) is str and len(checker)==64 and all(c in '0123456789abcdef' for c in checker)
  assert reported==actual,(is_native,g['generation'],reported,actual)
  evidence.append(dict(generation=g['generation'],artifact_sha256=sha(data),bytes=len(data),actual_mapping=actual,checker_sha256=checker))
 return evidence

def normalize_snapshot(value, directory):
 # Only inherently run-specific observations are normalized. Actual artifact
 # content/seals/entry mappings are independently rechecked above. All error,
 # lifecycle, count, ordering, cause, status and optional-field shapes remain.
 dynamic_numbers={'observed_ns','attempted_ns','finished_ns','prepare_ns','artifact_bytes','file_bytes','file_offset','device_major','device_minor'}
 def walk(x,key=None):
  if isinstance(x,dict):return {k:walk(v,k) for k,v in x.items()}
  if isinstance(x,list):
   if key in ('inode','actual_inode','recorded_inode','instance'):
    assert len(x)==2 and all(type(v) is int and v>=0 for v in x);return '<actual-inode-pair>'
   return [walk(v) for v in x]
  if key=='inode' and type(x) is int:
   assert x>0;return '<actual-sealed-inode>'
  if key in dynamic_numbers:
   assert type(x) is int and x>=0,(key,x)
   if key.endswith('_ns'):assert x>0 and x<=time.monotonic_ns()
   return '<actual-'+key+'>'
  if key in ('artifact_sha256','checker_sha256'):
   assert type(x) is str and len(x)==64 and all(c in '0123456789abcdef' for c in x);return '<actual-'+key+'>'
  if isinstance(x,str):return x.replace(str(directory),'<owned-runtime>')
  return x
 return walk(value)

def differences(a,b,path=''):
 if type(a) is not type(b):return [(path,'type',a,b)]
 if isinstance(a,dict):
  out=[]
  for k in sorted(set(a)|set(b)):
   if k not in a or k not in b:out.append((path+'/'+k,'field',a.get(k,'<absent>'),b.get(k,'<absent>')))
   else:out.extend(differences(a[k],b[k],path+'/'+k))
  return out
 if isinstance(a,list):
  if len(a)!=len(b):return [(path,'length',len(a),len(b))]
  return [q for i,(x,y) in enumerate(zip(a,b)) for q in differences(x,y,path+'/'+str(i))]
 return [] if a==b else [(path,'value',a,b)]

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--component',type=Path,required=True);[p.add_argument('--'+name,type=Path,required=True) for name in ('normalizer','proof','builder','identity')];a=p.parse_args();d=a.output;d.mkdir(exist_ok=False)
 paths=[a.normalizer,a.proof,a.builder]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];lib=C.CDLL(str(a.component));identity=C.CDLL(str(a.identity))
 pnative=d/'native';poriginal=d/'original';pnative.mkdir(mode=0o700);poriginal.mkdir(mode=0o700)
 rows=[];views=[];full_views=[];native=Runtime(lib,identity,files,pnative,rows);base=scalar_program(None);equiv=scalar_program('bit.xor');orig=ScalarMultiversionRuntime(base,poriginal)
 def compare(name):
  ov=original_view(orig);nv=native.view();views.append(dict(name=name,original=ov,native=nv));(d/'views.json').write_text(json.dumps(views,indent=2)+'\n');(d/'calls.json').write_text(json.dumps(rows,indent=2)+'\n')
  (d/'full-snapshots.json').write_text(json.dumps(native.snapshots,indent=2)+'\n')
  assert ov==nv,(name,ov,nv)
  old_full=orig._qualification_snapshot;new_full=native.snapshot
  old_evidence=exact_live_evidence(native,orig,old_full,False);new_evidence=exact_live_evidence(native,orig,new_full,True)
  native_dir=new_full['cleanup']['directory_identity_pin']['path']
  before=normalize_snapshot(old_full,orig._directory);after=normalize_snapshot(new_full,native_dir)
  diff=differences(before,after)
  full_views.append(dict(name=name,original=old_full,native=new_full,original_actual=old_evidence,native_actual=new_evidence,differences=diff))
  (d/'full-original-pairs.json').write_text(json.dumps(full_views,indent=2)+'\n')
  assert not diff,(name,diff)
  print('EFFECTS_FULL_PAIR_PASS',name,flush=True)
 native.q(0,raw=rawdoc(base));assert get(native.w,424)==sys.get_int_max_str_digits() and get(native.w,432)==1;compare('constructor')
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
 result=dict(schema='hepta.hia.multiversion-runtime-effects-actual.v1',whole_native_runtime=False,full_public_snapshot_capture=True,full_original_snapshot_fields=True,actual_artifact_seals_and_mapping_rechecked=True,passed=len(views),failed=0,actual_effect_calls=len(rows),image_bytes=a.component.stat().st_size,image_sha256=sha(a.component.read_bytes()),same_holder=True,actual_original_runtime=True,source_identity='strict raw profile with captured integer policy',views=views,calls=rows,full_fields=len(full_views))
 (d/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('EFFECTS_PAIR_COMPLETE',len(views),len(rows),flush=True)
if __name__=='__main__':main()
