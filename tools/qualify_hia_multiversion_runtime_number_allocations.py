"""Allocation failures in the actual native decimal transaction call sites."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys
from tools.qualify_hia_multiversion_runtime_numbers import Numbers,cap,get
from tools.qualify_hia_multiversion_values_allocations import INJECTOR
def child(D):
    image=D/'numbers-component.so';probe=Numbers(image);h=C.CDLL(None)
    arm=h.values_fault_arm;arm.argtypes=[C.c_uint64]*3
    count=h.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
    maps=[x.split()[0].split('-') for x in Path('/proc/self/maps').read_text().splitlines() if str(image) in x]
    lo=min(int(a,16) for a,b in maps);hi=max(int(b,16) for a,b in maps)
    rows=[]
    for nth in range(1,8):
        q=Numbers(image);arm(lo,hi,nth);q.call(0,want=4);actual=[count(i) for i in range(3)]
        assert actual==[nth,nth-1,nth-1],(nth,actual)
        assert get(q.w.raw,80)==0 and get(q.w.raw,16)==1
        rows.append({'operation':'initialize','failed_ordinal':nth,'actual_counts':actual,'all_allocated_nodes_and_objects_freed':True})
    for op,attempts in [(1,3),(2,3),(11,1)]:
        for nth in range(1,attempts+1):
            q=Numbers(image);arm(lo,hi,0);q.call(0);before=q.w.raw
            arm(lo,hi,nth);q.call(op,1 if op==1 else 64 if op==11 else 0,want=4);actual=[count(i) for i in range(3)]
            assert actual==[nth,nth-1,nth-1],(op,nth,actual)
            assert q.w.raw==before,(op,nth)
            arm(lo,hi,0)
            if op==1:q.call(1,1);assert q.copy(7,1)==b'1';q.release(5,1)
            elif op==2:q.call(2);q.release(3);assert q.copy(8)==b'1'
            else:c=cap(q.call(11,64));q.call(12,c=c)
            q.call(10)
            rows.append({'operation':op,'failed_ordinal':nth,'actual_counts':actual,'complete_context_unchanged':True,'same_context_retry':True})
    arm(lo,hi,0)
    q=Numbers(image);q.call(0)
    for _ in range(100):
        q.call(1,1);q.release(5,1);q.call(2);q.release(3)
    q.call(10);actual=[count(i) for i in range(3)]
    assert actual[0]==actual[1]==actual[2],actual
    rows.append({'operation':'100-publication-transactions-complete-free','actual_counts':actual})
    print(json.dumps({'passed':len(rows),'failed':0,'cases':rows,'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest()}),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--child',action='store_true');a=p.parse_args();D=a.directory
    if a.child:return child(D)
    src=D/'number-allocation-injector.c';src.write_text(INJECTOR);so=D/'number-allocation-injector.so'
    subprocess.run(['cc','-shared','-fPIC','-O2','-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-o',str(so),str(src)],check=True,capture_output=True)
    r=subprocess.run([sys.executable,'-u','-m','tools.qualify_hia_multiversion_runtime_number_allocations','--directory',str(D),'--child'],env={**os.environ,'LD_PRELOAD':str(so)},capture_output=True,timeout=30)
    (D/'allocation.stdout').write_bytes(r.stdout);(D/'allocation.stderr').write_bytes(r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stderr.decode(errors='replace'),r.stdout[-2000:])
    value=json.loads(r.stdout);report={'schema':'hepta.hia.multiversion-runtime-numbers-allocation.v1','whole_native_runtime':False,'external_qa_injector':True,'injector_source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),**value}
    (D/'allocation-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('RUNTIME_NUMBERS_ALLOCATION_PASS',value['passed'],flush=True)
if __name__=='__main__':main()
