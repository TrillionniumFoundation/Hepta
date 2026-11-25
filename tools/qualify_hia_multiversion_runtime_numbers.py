"""Actual native decimal transactions. Private seeded state uses actual value-owner nodes."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,sys,threading,concurrent.futures
from tools import generate_hia_multiversion_runtime_numbers_packer as P
CALLS=0;VALUE_CALLS=0
Q=C.c_uint64;F=C.CFUNCTYPE(C.c_uint32,C.c_void_p,Q,C.c_void_p,Q,C.c_void_p,Q)
def get(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def packet(op=0,slot=0,cap=(0,0,0)):return struct.pack('<8s7Q',b'HIAMVNB1',op,slot,*cap,0,0)
def cap(out,at=16):return struct.unpack_from('<3Q',out,at)
class Numbers:
    def __init__(self,image):
        self.path=Path(image);self.lib=C.CDLL(str(image));self.fn=self.lib.hia_mv_runtime_numbers;self.fn.argtypes=[C.c_void_p,Q,C.c_void_p,Q,C.c_void_p,Q];self.fn.restype=C.c_uint32;self.w=C.create_string_buffer(8192)
        address=C.cast(self.fn,C.c_void_p).value;h=P.OUTER_HOLES['values'];relative=struct.unpack('<i',C.string_at(address+h,4))[0];self.inner=F(address+h+4+relative);self.calls=0
    def call(self,op=0,slot=0,c=(0,0,0),extra=0,want=0,raw=None):
        global CALLS
        raw=packet(op,slot,c) if raw is None else raw;s=C.create_string_buffer(raw,max(1,len(raw)));o=C.create_string_buffer(2048+extra);C.memset(o,0xa5,len(o));rc=self.fn(s,len(raw),o,len(o),self.w,len(self.w));self.calls+=1;CALLS+=1
        assert s.raw[:len(raw)]==raw
        if want>=0xfffffff0:assert rc==want,(rc,want);return o.raw
        assert rc==0 and o.raw[:8]==b'HIAMVNR1' and get(o.raw,8)==want,(op,slot,rc,get(o.raw,8),o.raw[:128].hex())
        return o.raw
    def copy(self,op,slot=0,c=(0,0,0),size=1024):
        out=self.call(op,slot,c,size);n=get(out,48);assert n<=size;return out[2048:2048+n]
    def release(self,op,slot=0):
        out=self.call(op,slot);c=cap(out,64)
        if c[0]:self.call(12,c=c)
        return out
    def seed(self,at,digits):
        # Independent setup of a reachable large value state, not a product API.
        # Both the old and new nodes are manipulated by the actual fixed owner.
        def value(op,c=(0,0,0),data=b''):
            global VALUE_CALLS
            raw=bytearray(128+len(data));raw[:8]=b'HIAMVU01';struct.pack_into('<Q',raw,8,op);struct.pack_into('<3Q',raw,24,*c);struct.pack_into('<Q',raw,72,len(data));raw[128:]=data
            s=C.create_string_buffer(bytes(raw));o=C.create_string_buffer(512);rc=self.inner(s,len(raw),o,512,C.byref(self.w,64),256);VALUE_CALLS+=1;assert rc==0 and o.raw[:8]==b'HIAMVUR1' and get(o.raw,8)==0,(op,rc,o.raw[:64].hex());return o.raw[16:48]
        old=cap(self.w.raw,at);new=value(1,data=digits);value(3,c=old);C.memmove(C.addressof(self.w)+at,new,32)
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory;rows=[];image=D/'numbers-component.so';q=Numbers(image)
    q.call(0);assert q.copy(8)==b'0' and q.copy(9)==b'1' and q.copy(7,0)==b'0'
    for n in range(1,258):
        o=q.call(1,1);assert q.copy(7,1)==str(n).encode()
        q.call(1,1,want=5);q.call(12,c=cap(o),want=5);q.release(5,1)
        assert q.copy(9)==str(n+1).encode()
    rows.append({'case':'consecutive-generation-reserve-release','count':257})
    for n in range(1,258):
        q.call(2);q.call(2,want=5);assert q.copy(8)==str(n-1).encode()
        q.release(3);assert q.copy(8)==str(n).encode()
        q.call(2);q.release(4);assert q.copy(8)==str(n).encode()
    rows.append({'case':'epoch-commit-and-rollback-same-owner','count':257})
    for at,copyop in [(320,9),(352,8)]:
        for text in [b'18446744073709551615',b'18446744073709551616',b'340282366920938463463374607431768211455',b'9'*4096,b'9'*1048577]:
            q.seed(at,text)
            assert q.copy(copyop,size=len(text)+1)==text
            if at==320:q.call(1,1);assert q.copy(7,1,size=len(text))==text;q.release(5,1)
            else:q.call(2);q.release(3)
            want=(b'1'+b'0'*len(text)) if set(text)=={57} else str(int(text)+1).encode()
            assert q.copy(copyop,size=len(want))==want
            rows.append({'case':'unbounded-carry','counter':'next' if at==320 else 'epoch','digits':len(text),'input_sha256':hashlib.sha256(text).hexdigest(),'actual_sha256':hashlib.sha256(want).hexdigest()})
    c=cap(q.call(11,64));text=q.copy(13,c=c,size=1048578);q.call(2);q.release(3);assert q.copy(13,c=c,size=len(text))==text
    before=q.w.raw;q.call(10,want=5);assert q.w.raw==before
    q.call(12,c=c);q.call(12,c=c,want=1);q.call(10);q.call(6,want=5)
    rows.append({'case':'independent-node-retention-blocks-destroy-and-stale-refusal'})
    # Fresh concurrent original-size counter, fixed per-thread physical slot.
    q=Numbers(image);q.call(0);observed=[];lock=threading.Lock()
    def run(index):
        local=[]
        for _ in range(50):
            q.call(1,index);local.append(int(q.copy(7,index)));q.release(5,index)
        with lock:observed.extend(local)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:list(pool.map(run,range(1,17)))
    assert sorted(observed)==list(range(1,801));assert q.copy(9)==b'801';q.call(10)
    rows.append({'case':'sixteen-native-caller-threads','reserves':800,'unique':len(set(observed))})
    q=Numbers(image);q.call(0)
    for op in [0,1,2,3,4,5,6,7,8,9,10,11,12,13]:
        for at in [0,48,56]:
            raw=bytearray(packet(op));struct.pack_into('<Q',raw,at,get(raw,at)^1);old=q.w.raw;q.call(raw=bytes(raw),want=0xfffffffd);assert q.w.raw==old
    for op,slot in [(1,64),(5,64),(7,64),(11,66),(2,1),(13,1),(14,0)]:
        old=q.w.raw;q.call(raw=packet(op,slot),want=0xfffffffd);assert q.w.raw==old
    q.call(0,want=5);q.call(3,want=5);q.call(5,0,want=5);q.call(1,0,want=5);q.call(7,1,want=1)
    rows.append({'case':'private-bad-header-reserved-op-slot-and-live-state','count':54})
    pr,pw=os.pipe();pid=os.fork()
    if pid==0:
        os.close(pr)
        try:q.call(6,want=5);os.write(pw,b'PASS');os._exit(0)
        except BaseException:os._exit(1)
    os.close(pw);got=os.read(pr,16);os.close(pr);_,status=os.waitpid(pid,0);assert got==b'PASS' and status==0
    q.call(10);rows.append({'case':'forked-context-refusal'})
    report={'schema':'hepta.hia.multiversion-runtime-number-qualification.v1','whole_native_runtime':False,'passed':len(rows),'failed':0,'actual_parent_calls':CALLS,'actual_large_state_setup_value_calls':VALUE_CALLS,'fork_child_calls':1,'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'cases':rows,'scope':'Actual native immutable values and owner mutex; large-state setup creates real decimal nodes through the same native value owner. This is not a new runtime seeding API.'}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('RUNTIME_NUMBERS_PASS',len(rows),flush=True)
if __name__=='__main__':main()
