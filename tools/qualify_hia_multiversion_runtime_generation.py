"""Actual native generation-stage integration; private frame conversion only."""
from pathlib import Path
import ctypes as C, mmap, os, struct, json, hashlib, argparse, time, copy, runpy
from tools.qualify_hia_multiversion_prepare_process import sealed,NONE
from tools.qualify_hia_multiversion_prepare_intake import abi_bytes
from tools.qualify_hia_multiversion_prepare_owner import source_groups
from hepta.hia_multiversion import _admit,_prove,_probe_vectors,MultiversionRejected
from hepta.hia_program import verify_program
ROOT=Path(__file__).resolve().parents[1]
fixture=runpy.run_path(str(ROOT/'tests/test_hia_multiversion.py'))
scalar_program=fixture['scalar_program']
get=lambda x,a:struct.unpack_from('<Q',x,a)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
class Generation:
 def __init__(self,lib):
  self.memory=mmap.mmap(-1,512<<20,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS)
  self.w=(C.c_char*(512<<20)).from_buffer(self.memory)
  self.o=C.create_string_buffer(4096)
  self.f=lib.hia_mv_runtime_generation;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
 def stage(self,raw):
  s=C.create_string_buffer(raw);C.memset(self.o,0xa5,4096);t=time.monotonic_ns()
  rc=self.f(s,len(raw),self.o,len(self.o),self.w,len(self.w))
  elapsed=time.monotonic_ns()-t
  assert s.raw==raw+b'\0'
  out=self.o.raw
  if rc<0xfffffff0:
   assert out[:8]==b'HIAMVGD1' and get(out,8)==rc,(rc,out[:128].hex())
  return rc,out,elapsed
 def operation(self,op):
  return self.stage(struct.pack('<8sQ',b'HIAMVGX1',op)+bytes(240))
 def read(self,at,n):return C.string_at(C.addressof(self.w)+at,n)
 def close_memory(self):
  del self.w;self.memory.close()
def request(raw,base,abi,path,files,*,prove=False,baseline=False):
 h=bytearray(256)
 struct.pack_into('<8s14Q',h,0,b'HIAMVGX1',0,files[0][0],files[1][0],files[2][0],2000,time.monotonic_ns()+120_000_000_000,time.monotonic_ns()+120_000_000_000,int(prove),int(baseline),len(raw),len(base),len(abi),len(path),0)
 h[128:224]=b''.join(hashlib.sha256(b).digest() for fd,b in files)
 return bytes(h)+raw+base+abi+path
def rawdoc(d):return json.dumps(d,separators=(',',':'),ensure_ascii=True).encode()
def main():
 p=argparse.ArgumentParser();p.add_argument('--component',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--normalizer',required=True,type=Path);p.add_argument('--proof',required=True,type=Path);p.add_argument('--builder',required=True,type=Path);p.add_argument('--all-signatures',action='store_true');a=p.parse_args()
 d=a.output;d.mkdir(parents=True,exist_ok=True);lib=C.CDLL(str(a.component));files=[(sealed(p.read_bytes()),p.read_bytes()) for p in (a.normalizer,a.proof,a.builder)];rows=[];began=time.monotonic_ns()
 def close_streams(out):
  for at in (96,104):
   fd=get(out,at)
   if fd!=NONE:os.close(fd)
 def apply(g,name,op,want):
  rc,out,ns=g.operation(op);(d/(name+'.reply')).write_bytes(out)
  assert rc==want,(name,op,rc,[get(out,i) for i in range(8,128,8)])
  close_streams(out);return out,ns
 def cleanup(g,name,path):
  fds=set(os.listdir('/proc/self/fd'));pin=get(g.w,32);sealedfd=get(g.w,48);library=get(g.w,56)
  out,ns=apply(g,name+'-pending',4,8)
  assert get(out,16)==6 and path.exists()
  assert set(os.listdir('/proc/self/fd'))==fds and get(g.w,32)==pin and get(g.w,48)==sealedfd and get(g.w,56)==library
  os.fstat(pin);os.fstat(sealedfd)
  out,n2=apply(g,name+'-registered-release',6,0)
  assert get(out,16)==7 and not path.exists()
  assert get(g.w,48)==NONE and get(g.w,56)==0  # original identity-pin number remains an audit field
  for fd in (pin,sealedfd):
   try:os.fstat(fd)
   except OSError:pass
   else:raise AssertionError(('still live released descriptor',fd))
  # Reusing the same small fd number must not recreate a close obligation.
  held=os.open('/dev/null',os.O_RDONLY)
  try:
   apply(g,name+'-repeat-pending',4,8)
   apply(g,name+'-repeat-release',6,0)
   os.fstat(held)
  finally:os.close(held)
  return ns+n2
 def run(name,document,*,baseline_doc=None,prove=False,expected_stage=4):
  g=Generation(lib);path=d/(name+'.so');raw=rawdoc(document)
  bp=babi=b''
  if baseline_doc is not None:
   original,abis,_=_admit(baseline_doc)
   bp=original.canonical_bytes;babi=abi_bytes(original,abis)
  source,signatures,totality=_admit(raw,prove_total=prove) if expected_stage==4 else (None,None,None)
  prior=set(os.listdir('/proc/self/fd'));req=request(raw,bp,babi,os.fsencode(path),files,prove=prove,baseline=baseline_doc is None)
  rc,out,n0=g.stage(req);assert rc==0,(name,'admission',rc,[get(out,i) for i in range(8,128,8)]);close_streams(out)
  out,n1=apply(g,name+'-profile',1,0)
  assert get(out,16)==2
  if baseline_doc is not None:
   out,n2=apply(g,name+'-proof',2,0 if expected_stage==4 else 3)
   if expected_stage!=4:
    assert not path.exists()
    apply(g,name+'-build-after-unproved',3,9)
    assert set(os.listdir('/proc/self/fd'))==prior
    rows.append(dict(case=name,unproved=True,admission_ns=n0,profile_ns=n1,proof_ns=n2,build_not_started=True));g.close_memory();return
  else:n2=0
  out,n3=apply(g,name+'-native-prepare',3,0)
  assert get(out,16)==4 and get(out,512+40)==1
  expected=sum(len(_probe_vectors(sig)) for sig in signatures)
  assert get(out,512+88)==expected,(name,'probe count',get(out,600),expected)
  data=path.read_bytes();assert sha(data)==out[512+224:512+256].hex()
  assert g.read(448<<20,get(out,72))==source.canonical_bytes
  assert g.read(456<<20,get(out,80))==abi_bytes(source,signatures)
  if prove:
   assert get(out,112)>512 and get(g.w,(336<<20)+8)==0
  if baseline_doc is not None:assert get(out,120)>512
  queries,qn=apply(g,name+'-query',5,0)
  assert queries[512:2560]==out[512:2560]
  t=cleanup(g,name,path)
  assert set(os.listdir('/proc/self/fd'))==prior
  rows.append(dict(case=name,admission_ns=n0,profile_ns=n1,proof_ns=n2,prepare_ns=n3,retirement_ns=t,actual_probe_vectors=expected,artifact_bytes=len(data),artifact_sha256=sha(data),same_holder=True,registered_before_release=True))
  print('NATIVE_GENERATION_PASS',name,expected,flush=True);g.close_memory()
 run('baseline',scalar_program())
 run('equivalent',scalar_program('bit.xor'),baseline_doc=scalar_program())
 run('wrong-behavior',scalar_program(value=1),baseline_doc=scalar_program(),expected_stage=3)
 multi=scalar_program(None)
 extra=copy.deepcopy(multi['functions'][0]);extra['name']='alternate';multi['functions'].append(extra)
 reorder=copy.deepcopy(multi);reorder['functions'].reverse()
 run('reordered-function-indices',reorder,baseline_doc=multi)
 checked=scalar_program('int.div.checked',value=1,typ='u8');checked['functions'][0]['effects']=['trap']
 run('proved-total-baseline',checked,prove=True)
 run('proved-total-candidate',scalar_program(None,typ='u8'),baseline_doc=scalar_program(None,typ='u8'),prove=True)
 for name,raw,want in [('malformed',b'{',1),('empty',b'',1),('wrong-schema',b'{"schema":"wrong"}',1)]:
  g=Generation(lib);path=d/(name+'.so');rc,out,ns=g.stage(request(raw,b'',b'',os.fsencode(path),files,baseline=True))
  assert rc==want,(name,rc);close_streams(out);assert not path.exists()
  rows.append(dict(case=name,status=rc,stage=get(out,16),elapsed_ns=ns));g.close_memory()
 if a.all_signatures:
  for name,core,abi,vectors,signatures in source_groups(True):
   run('all-'+name,json.loads(core))
 for fd,b in files:os.close(fd)
 report=dict(schema='hepta.hia.multiversion-runtime-generation-qualification.v1',whole_native_runtime=False,passed=len(rows),failed=0,elapsed_ns=time.monotonic_ns()-began,image_sha256=sha(a.component.read_bytes()),dependencies=[dict(path=str(p),bytes=len(b),sha256=sha(b)) for p,(fd,b) in zip((a.normalizer,a.proof,a.builder),files)],cases=rows)
 (d/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('GENERATION_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
