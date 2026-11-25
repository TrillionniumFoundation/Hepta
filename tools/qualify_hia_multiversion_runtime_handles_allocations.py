from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,runpy,subprocess,sys
B=Path("/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z");V=B/'native-multiversion-source';sys.path.insert(0,str(V))
from tools.qualify_hia_multiversion_values_allocations import INJECTOR
INJECTOR=INJECTOR.replace('unsigned long values_fault_count(', 'void values_fault_next(unsigned long n) { fail_after=n?attempts+n:0; }\nunsigned long values_fault_count(')
x=runpy.run_path(str(B/'qualify-runtime-handles-smoke-v2.py'));Carrier=x['Carrier'];inner=x['inner'];scalar_program=x['scalar_program'];rawdoc=x['rawdoc'];get=x['get'];sealed=x['sealed']
def child(d,image):
 libc=C.CDLL(None);arm=libc.values_fault_arm;arm.argtypes=[C.c_uint64]*3;nextfail=libc.values_fault_next;nextfail.argtypes=[C.c_uint64];count=libc.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
 preload=C.CDLL(str(image))
 ranges=[line.split()[0].split('-') for line in Path('/proc/self/maps').read_text().splitlines() if str(image) in line];lo=min(int(a,16) for a,b in ranges);hi=max(int(b,16) for a,b in ranges)
 paths=[Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/normalizer-84619bd.bin'),B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125/production-p3/products/hia-build-object-539ce9.bin')]
 files=[(sealed(p.read_bytes()),p.read_bytes()) for p in paths];raw=rawdoc(scalar_program(None));cases=[]
 def numbers():return [count(i) for i in range(3)]
 def start(name,ordinal=0):
  p=d/name;p.mkdir(mode=0o700);rows=[];r=Carrier(image,rows);r.q(0);arm(lo,hi,ordinal);before=set(os.listdir('/proc/self/fd'))
  result=r.q(1,payload=inner(0,files=files,parent=os.fsencode(p),raw=raw),want=None)
  return r,p,rows,before,result
 def finish(name,r,p,rows,before,cap=(0,0,0),**extra):
  nextfail(0)
  if cap[0]:r.q(3,cap)
  if get(r.w,40):r.q(7)
  assert get(r.w,16)==get(r.w,40)==get(r.w,64)==0,[get(r.w,k) for k in (16,40,64)]
  assert not list(p.iterdir()),list(p.iterdir());r.q(5)
  total=numbers();assert total[1]==total[2],(name,total)
  assert set(os.listdir('/proc/self/fd'))==before
  cases.append(dict(name=name,counts=total,calls=rows,**extra));(d/'progress.json').write_text(json.dumps(cases,indent=2)+'\n');print('HANDLES_MALLOC_PASS',name,total,flush=True)
 r,p,rows,before,result=start('constructor-control');assert result['cap'][0]
 ct=count(0);finish('constructor-control',r,p,rows,before,result['cap'],constructor_attempts=ct)
 for n in range(1,ct+1):
  r,p,rows,before,result=start('constructor-fault-'+str(n),n)
  assert not result['cap'][0] and (result['row']['status']!=0 or result['row']['child_status']!=0),result
  finish('constructor-fault-'+str(n),r,p,rows,before,failed_ordinal=n,refusal=result['row'])
 # Clone nodes do not change the original generation's logical lease count.
 for targetkind in ('runtime','lease'):
  name=targetkind+'-clone-fault';r,p,rows,before,result=start(name);cap=result['cap'];lease=r.lease(cap) if targetkind=='lease' else None
  target=lease or cap;prior=numbers();nextfail(1);refused=r.q(2,target,want=4);assert not refused['cap'][0]
  nextfail(0);c=r.q(2,target)['cap'];r.q(3,c)
  if lease:r.call(lease,37);r.q(3,lease)
  finish(name,r,p,rows,before,cap,failed_ordinal=1)
 # Every actual allocation in acquire is injected, including the two wrapper allocations.
 r,p,rows,before,result=start('lease-control');cap=result['cap'];prior=count(0);lease=r.lease(cap);lc=count(0)-prior;r.q(3,lease)
 finish('lease-control',r,p,rows,before,cap,lease_attempts=lc)
 for n in range(1,lc+1):
  name='lease-fault-'+str(n);r,p,rows,before,result=start(name);cap=result['cap'];nextfail(n);refused=r.q(4,cap,inner(3),want=None)
  assert not refused['cap'][0] and (refused['row']['status']!=0 or refused['row']['child_status']!=0),refused
  nextfail(0);lease=r.lease(cap);r.call(lease,43);r.q(3,lease)
  finish(name,r,p,rows,before,cap,failed_ordinal=n,refusal=refused['row'])
 for fd,b in files:os.close(fd)
 report=dict(schema='hepta.hia.runtime-handles-actual-malloc.v1',whole_native_runtime=False,passed=len(cases),failed=0,constructor_attempts=ct,lease_attempts=lc,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),cases=cases)
 (d/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('HANDLES_MALLOC_COMPLETE',len(cases),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--component',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args()
 if a.child:return child(a.directory,a.component)
 d=a.directory;d.mkdir(exist_ok=False);src=d/'allocation-injector.c';src.write_text(INJECTOR);so=d/'allocation-injector.so'
 subprocess.run(['/usr/bin/cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(so),str(src)],check=True,capture_output=True)
 r=subprocess.run([sys.executable,'-u',__file__,'--directory',str(d),'--component',str(a.component),'--child'],env={**os.environ,'LD_PRELOAD':str(so)},stdout=(d/'allocation.stdout').open('wb'),stderr=(d/'allocation.stderr').open('wb'),timeout=180)
 print('ALLOCATION_CHILD',r.returncode,flush=True);assert r.returncode==0,(d/'allocation.stderr').read_text()
if __name__=='__main__':main()
