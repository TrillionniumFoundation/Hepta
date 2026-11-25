from pathlib import Path
import os,sys,runpy,ctypes as C,struct,json,hashlib,subprocess,argparse
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');V=B/'native-multiversion-source';sys.path.insert(0,str(V))
from tools.qualify_hia_multiversion_values_allocations import INJECTOR
INJECTOR=INJECTOR.replace('unsigned long values_fault_count(', 'void values_fault_next(unsigned long n) { fail_after=n?attempts+n:0; }\nunsigned long values_fault_count(')
q=runpy.run_path(str(B/'qualify-runtime-decimal-view-v2.py'));Runtime=q['DecimalRuntime'];Token=q['Token'];rawdoc=q['rawdoc'];scalar_program=q['scalar_program'];sealed=q['sealed'];get=q['get'];NONE=q['NONE'];sha=q['sha']
def child(D,image):
 lib=C.CDLL(str(image));identity=C.CDLL(str(B/'native-multiversion-runtime-identity-v5/identity-component.so'));future=C.CDLL(str(B/'native-multiversion-future-v2/future-component.so'))
 hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;nxt=hooks.values_fault_next;nxt.argtypes=[C.c_uint64];cnt=hooks.values_fault_count;cnt.argtypes=[C.c_uint64];cnt.restype=C.c_uint64
 ranges=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(image) in x];lo=min(int(a,16) for a,b in ranges);hi=max(int(b,16) for a,b in ranges)
 paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];base=rawdoc(scalar_program(None));cases=[]
 for name,op,ordinal in [('snapshot-control',14,0),('snapshot-malloc',14,1),('decimal-first-retain',2,1),('decimal-second-retain',2,2)]:
  p=D/name;p.mkdir(mode=0o700);rows=[];r=Runtime(lib,identity,files,p,rows);token=Token(future);arm(lo,hi,0);before=set(os.listdir('/proc/self/fd'));r.q(0,raw=base)
  private_head=get(r.w,32768+64+16);nxt(ordinal);externally_freed=0
  if op==14:
   out,payload,rc=r.extended(14,want=None)
   externally_freed+=bool(payload)
   assert rc==(0 if ordinal==0 else 36),(name,rc)
  else:
   out,payload,rc=r.extended(2,b'0',b'0',base,token.address,want=None)
   assert rc!=0 and get(out,24)==0,(name,rc)
   assert get(r.w,8192+48)==0 and get(r.w,32768+64+16)==private_head,(name,'leaked retained identity')
  refusal=rows[-1];nxt(0)
  # The same actual runtime and token stay usable after the failed allocation.
  out,payload,rc=r.extended(14);externally_freed+=1
  assert payload[:8]==b'HIAMVBS1' and payload[256:]==b'00'
  if op==2:
   r.extended(2,b'0',b'0',base,token.address);assert get(token.w,64)==2
  r.q(8);r.q(13);token.q(10);assert not list(p.iterdir()) and set(os.listdir('/proc/self/fd'))==before
  counts=[cnt(i) for i in range(3)];assert counts[1]==counts[2]+externally_freed,(name,counts,externally_freed)
  cases.append(dict(name=name,ordinal=ordinal,actual_counts=counts,owned_results_freed_by_receiver=externally_freed,refusal=refusal,calls=rows));(D/'progress.json').write_text(json.dumps(cases,indent=2)+'\n')
  print('DECIMAL_ALLOCATION_PASS',name,counts,flush=True)
 for fd,b in files:os.close(fd)
 report=dict(schema='hepta.hia.multiversion-runtime-decimal-allocation.v1',whole_native_runtime=False,passed=len(cases),failed=0,image_sha256=sha(image.read_bytes()),cases=cases)
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
def main():
 p=argparse.ArgumentParser();p.add_argument('--child',action='store_true');p.add_argument('--output',type=Path,required=True);p.add_argument('--component',type=Path,required=True);a=p.parse_args()
 if a.child:return child(a.output,a.component)
 D=a.output;D.mkdir(exist_ok=False);src=D/'allocation-injector.c';src.write_text(INJECTOR);so=D/'allocation-injector.so'
 subprocess.run(['/usr/bin/cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror',str(src),'-o',str(so)],check=True,capture_output=True)
 r=subprocess.run([sys.executable,'-u',__file__,'--child','--output',str(D),'--component',str(a.component)],env={**os.environ,'LD_PRELOAD':str(so)},stdout=(D/'child.stdout').open('wb'),stderr=(D/'child.stderr').open('wb'),timeout=90)
 assert r.returncode==0,(r.returncode,(D/'child.stderr').read_text());print('DECIMAL_ALLOCATIONS_QUALIFIED',4,flush=True)
if __name__=='__main__':main()
