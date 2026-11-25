"""Actual native ownership qualification; Python supplies only independent values."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,random,struct,threading,time
MAGIC=b'HIAMVU01';REPLY=b'HIAMVUR1';U64=(1<<64)-1
get=lambda b,n:struct.unpack_from('<Q',b,n)[0]
class Owner:
    def __init__(self,image):
        self.image=Path(image);self.lib=C.CDLL(str(self.image));self.f=self.lib.hia_mv_values
        self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
        self.w=C.create_string_buffer(256);self.invoke=self.f;self.calls=0;self.count_lock=threading.Lock()
        self.run(0)
    @staticmethod
    def packet(op,a=(0,0,0),b=(0,0,0),raw=b''):
        h=bytearray(128);h[:8]=MAGIC;struct.pack_into('<Q',h,8,op);struct.pack_into('<3Q',h,24,*a);struct.pack_into('<3Q',h,48,*b);struct.pack_into('<Q',h,72,len(raw));return bytes(h)+raw
    def run(self,op,a=(0,0,0),b=(0,0,0),raw=b'',size=512,want=0,wire=None):
        wire=self.packet(op,a,b,raw) if wire is None else wire
        src=C.create_string_buffer(wire);out=C.create_string_buffer(size);C.memset(out,0xa5,size)
        rc=self.invoke(src,len(wire),out,size,self.w,len(self.w));data=out.raw
        with self.count_lock:self.calls+=1
        if want>=0xfffffff0:
            assert rc==want,(op,rc,want);return data
        assert rc==0 and data[:8]==REPLY,(op,rc,data[:128].hex())
        status=get(data,8);assert status==want,(op,status,want,data[:128].hex())
        return data
    def create(self,digits):
        data=self.run(1,raw=digits);return tuple(get(data,n) for n in (16,24,32))
    def clone(self,cap):
        data=self.run(2,cap);return tuple(get(data,n) for n in (16,24,32))
    def copy(self,cap,n):
        d=self.run(8,cap,size=512+n);assert get(d,40)==n;return d[512:512+n]
    def value(self,op,a,b=(0,0,0),want=0):
        d=self.run(op,a,b,want=want)
        return tuple(get(d,n) for n in (16,24,32)),get(d,40),get(d,48)
    def drop(self,cap):self.run(3,cap)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();args.output.mkdir(exist_ok=True,parents=True)
    owner=Owner(args.image);cases=[]
    def record(name,fn):
        start=time.monotonic_ns();fn();cases.append({'name':name,'passed':True,'elapsed_ns':time.monotonic_ns()-start});print('VALUE_OWNER_PASS',name,flush=True)
    def basic():
        a=owner.create(b'18446744073709551615');a2=owner.clone(a);b,n,_=owner.value(4,a)
        assert n==20 and owner.copy(b,n)==b'18446744073709551616'
        assert owner.copy(a,20)==b'18446744073709551615'
        c,n,_=owner.value(5,a,b);assert owner.copy(c,n)==b'36893488147419103231'
        d,n,_=owner.value(6,b,a);assert owner.copy(d,n)==b'1'
        _,_,less=owner.value(7,a,b);_,_,greater=owner.value(7,b,a);_,_,equal=owner.value(7,a,a2);assert (less,greater,equal)==(0,2,1)
        owner.value(6,a,b,want=3);owner.run(9,want=5)
        owner.drop(a);assert owner.copy(a2,20)==b'18446744073709551615';owner.run(8,a,size=532,want=1)
        for cap in (a2,b,c,d):owner.drop(cap)
        assert get(owner.w.raw,16)==0
    record('u64-crossing-immutable-retain-underflow',basic)
    def random_values():
        rng=random.Random(0x4167)
        for i in range(200):
            x=rng.randrange(10**rng.randrange(1,300));y=rng.randrange(10**rng.randrange(1,300))
            ax=str(x).encode();by=str(y).encode();a=owner.create(ax);b=owner.create(by)
            c,n,_=owner.value(5,a,b);assert owner.copy(c,n)==str(x+y).encode();owner.drop(c)
            c,n,_=owner.value(4,a);assert owner.copy(c,n)==str(x+1).encode();owner.drop(c)
            _,_,cmp=owner.value(7,a,b);assert cmp==(0 if x<y else 1 if x==y else 2)
            if x>=y:
                c,n,_=owner.value(6,a,b);assert owner.copy(c,n)==str(x-y).encode();owner.drop(c)
            else:owner.value(6,a,b,want=3)
            assert owner.copy(a,len(ax))==ax and owner.copy(b,len(by))==by
            owner.drop(a);owner.drop(b)
        assert get(owner.w.raw,16)==0
    record('200-fresh-bigint-arithmetic-ownership-pairs',random_values)
    def huge():
        n=1048577;a=owner.create(b'9'*n);keep=owner.clone(a)
        b,bn,_=owner.value(4,a);assert bn==n+1 and owner.copy(b,bn)==b'1'+b'0'*n
        c,cn,_=owner.value(6,b,a);assert cn==1 and owner.copy(c,1)==b'1'
        owner.drop(a);assert owner.copy(keep,n)==b'9'*n
        for cap in (keep,b,c):owner.drop(cap)
        assert get(owner.w.raw,16)==0
    record('1048577-digit-carry-borrow-and-lifetime',huge)
    def invalid():
        for raw in (b'',b'00',b'01',b'-1',b'+1',b'1.0',b'1e2',b' 1',b'1 ',b'\xff',b'1\x00'):
            owner.run(1,raw=raw,want=2);assert get(owner.w.raw,16)==0
        a=owner.create(b'340282366920938463463374607431768211455')
        owner.run(8,(a[0],a[1]^1,a[2]),size=551,want=1)
        owner.run(3,(a[0],a[1],a[2]^1),want=1)
        owner.run(3,(1,2,3),want=1)
        owner.run(8,a,size=512,want=7)
        assert owner.copy(a,39)==b'340282366920938463463374607431768211455'
        foreign=Owner(args.image);foreign.run(8,a,size=551,want=1);foreign.run(9)
        owner.drop(a);owner.run(3,a,want=1)
        for index,value in ((0,0),(8,10),(16,1),(80,1),(120,1)):
            wire=bytearray(owner.packet(9));struct.pack_into('<Q',wire,index,value);owner.run(9,wire=bytes(wire),want=0xfffffffd)
        owner.run(9,wire=owner.packet(9)+b'x',want=0xfffffffd)
    record('format-stale-cross-owner-short-output-guards',invalid)
    def concurrency():
        a=owner.create(b'1' + b'0'*79);errors=[]
        def worker(index):
            try:
                for j in range(40):
                    keep=owner.clone(a)
                    assert owner.copy(keep,80)==b'1'+b'0'*79
                    b,n,_=owner.value(4,keep);assert owner.copy(b,n)==b'1'+b'0'*78+b'1'
                    owner.drop(keep);owner.drop(b)
            except BaseException as exc:errors.append(repr(exc))
        threads=[threading.Thread(target=worker,args=(i,)) for i in range(16)]
        for t in threads:t.start()
        for t in threads:t.join(30);assert not t.is_alive(),'native futex owner failed to settle'
        assert not errors,errors
        assert owner.copy(a,80)==b'1'+b'0'*79;owner.drop(a);assert get(owner.w.raw,16)==0
    record('16-thread-640-retain-arithmetic-release-rounds',concurrency)
    def fork_guard():
        a=owner.create(b'7');pid=os.fork()
        if pid==0:
            try:owner.run(8,a,size=513,want=5);os._exit(0)
            except BaseException:os._exit(71)
        _,status=os.waitpid(pid,0);assert status==0,status;assert owner.copy(a,1)==b'7';owner.drop(a)
    record('fork-context-owner-pid-refusal',fork_guard)
    def close():
        assert get(owner.w.raw,16)==0;owner.run(9);owner.run(9,want=5);owner.run(1,raw=b'1',want=5);owner.run(0,want=5)
    record('closed-context-and-complete-release',close)
    report={'schema':'hepta.hia.multiversion-value-owner.qualification.v1','whole_native_runtime':False,'image':str(args.image),'image_bytes':args.image.stat().st_size,'image_sha256':hashlib.sha256(args.image.read_bytes()).hexdigest(),'passed':len(cases),'failed':0,'actual_native_calls':owner.calls,'cases':cases,'scope':'Actual HIA ownership, libc allocations, kernel futex and fresh Python integer oracle; not the complete runtime.'}
    (args.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('VALUE_OWNER_QUALIFIED',len(cases),owner.calls,flush=True)
if __name__=='__main__':main()
