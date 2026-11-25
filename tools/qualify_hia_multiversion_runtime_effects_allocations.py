"""Actual allocation faults in the fixed HIA runtime image, with lifetime accounting."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,runpy,subprocess,sys,time
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');V=B/'native-multiversion-source';sys.path.insert(0,str(V))
from tools.qualify_hia_multiversion_values_allocations import INJECTOR
x=runpy.run_path(str(Path(__file__).with_name('qualify_hia_multiversion_runtime_effects.py')))
Runtime=x['Runtime'];scalar_program=x['scalar_program'];rawdoc=x['rawdoc'];sealed=x['sealed'];get=x['get']
INJECTOR=INJECTOR.replace('unsigned long values_fault_count(', 'void values_fault_next(unsigned long n) { fail_after=n?attempts+n:0; }\nunsigned long values_fault_count(')
def child(d,image):
 lib=C.CDLL(str(image));identity=C.CDLL(str(B/'native-multiversion-runtime-identity-v5/identity-component.so'))
 libc=C.CDLL(None);arm=libc.values_fault_arm;arm.argtypes=[C.c_uint64]*3
 nextfail=libc.values_fault_next;nextfail.argtypes=[C.c_uint64]
 count=libc.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
 ranges=[line.split()[0].split('-') for line in Path('/proc/self/maps').read_text().splitlines() if str(image) in line]
 lo=min(int(a,16) for a,b in ranges);hi=max(int(b,16) for a,b in ranges)
 paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];raw=rawdoc(scalar_program(None));cases=[]
 def numbers():return [count(i) for i in range(3)]
 def finish(r,p):
  nextfail(0)
  if get(r.w,0)!=0:r.q(13)
  assert not list(p.iterdir()),list(p.iterdir())
  actual=numbers();assert actual[1]==actual[2],actual
  return actual
 def start(name,failed=0):
  p=d/name;p.mkdir(mode=0o700);rows=[];r=Runtime(lib,identity,files,p,rows)
  arm(lo,hi,failed);before=set(os.listdir('/proc/self/fd'));o,v,rc=r.q(0,raw=raw,want=None)
  return r,p,rows,before,rc
 r,p,rows,before,rc=start('constructor-control');assert rc==0
 ctor_attempts=count(0);tot=finish(r,p);assert set(os.listdir('/proc/self/fd'))==before
 cases.append(dict(name='constructor-control',rc=rc,constructor_attempts=ctor_attempts,counts=tot,calls=rows))
 (d/'progress.json').write_text(json.dumps(cases,indent=2)+'\n')
 print('MALLOC_CTOR_ATTEMPTS',ctor_attempts,flush=True)
 for n in range(1,ctor_attempts+1):
  r,p,rows,before,rc=start('constructor-fault-'+str(n),n)
  failed=dict(name='constructor-fault-'+str(n),failed_ordinal=n,rc=rc,counts_before_cleanup=numbers(),calls=rows)
  cases.append(failed);(d/'progress.json').write_text(json.dumps(cases,indent=2)+'\n')
  assert rc!=0,failed
  failed['counts']=finish(r,p);assert set(os.listdir('/proc/self/fd'))==before
  (d/'progress.json').write_text(json.dumps(cases,indent=2)+'\n')
  print('MALLOC_CTOR_PASS',n,rc,flush=True)
 for growth in (False,True):
  for n in range(1,5 if growth else 4):
   name=('growth' if growth else 'lease')+'-fault-'+str(n);r,p,rows,before,rc=start(name);assert rc==0
   leases=[r.lease() for _ in range(255)] if growth else []
   actual_before=r.view();prior=numbers();nextfail(n)
   o,v,rc=r.q(3,want=None);actual_after=numbers()
   case=dict(name=name,failed_ordinal=n,rc=rc,counts_delta=[a-b for a,b in zip(actual_after,prior)],calls=rows);cases.append(case)
   (d/'progress.json').write_text(json.dumps(cases,indent=2)+'\n')
   assert rc!=0,case
   nextfail(0);assert r.view()==actual_before,(name,actual_before,r.view())
   new=r.lease();assert r.call(new,43)==43;r.closelease(new)
   for lease in leases:r.closelease(lease)
   case['counts']=finish(r,p);assert set(os.listdir('/proc/self/fd'))==before
   print('MALLOC_LEASE_PASS',name,rc,flush=True)
 for fd,b in files:os.close(fd)
 result=dict(schema='hepta.hia.runtime-effects-actual-malloc.v1',whole_native_runtime=False,passed=len(cases),failed=0,constructor_attempts=ctor_attempts,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),cases=cases)
 (d/'qualification.json').write_text(json.dumps(result,indent=2)+'\n')
 print('EFFECTS_MALLOC_PASS',len(cases),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--component',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args()
 if a.child:return child(a.directory,a.component)
 d=a.directory;d.mkdir(exist_ok=False);src=d/'allocation-injector.c';src.write_text(INJECTOR);so=d/'allocation-injector.so'
 subprocess.run(['/usr/bin/cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(so),str(src)],check=True,capture_output=True)
 r=subprocess.run([sys.executable,'-u',__file__,'--directory',str(d),'--component',str(a.component),'--child'],env={**os.environ,'LD_PRELOAD':str(so)},stdout=(d/'allocation.stdout').open('wb'),stderr=(d/'allocation.stderr').open('wb'),timeout=180)
 print('ALLOCATION_CHILD',r.returncode,flush=True);assert r.returncode==0,(d/'allocation.stderr').read_text()
if __name__=='__main__':main()
