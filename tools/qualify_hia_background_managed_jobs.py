"""Actual managed Jobs/canonical Future interoperation on the one native-bound arena."""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,hashlib,json,os,struct,traceback
from tools import qualify_hia_future_native_callbacks as callbacks
ZERO=(0,0,0)
def word(b,p):return struct.unpack_from('<Q',b,p)[0]
def cap(b,p=16):return struct.unpack_from('<3Q',b,p)
def put(b,p,*v):struct.pack_into('<'+'Q'*len(v),b,p,*v)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def frame(op,a=ZERO,offset=0,count=0,data=b'',bind=None):
    r=bytearray(128+len(data));r[:8]=b'HIABJM01';put(r,8,op)
    put(r,24,*a)
    if op==4:put(r,48,offset,count)
    if op==10:put(r,72,len(data));r[128:]=data
    if bind is not None:
        assert op==13
        put(r,24,*bind)
    return bytes(r)
class Jobs:
    def __init__(self,path,fixture,fac):
        self.lib=C.CDLL(str(path));self.entry=self.lib.hia_background_optimizer_jobs_owner
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.ctx=C.create_string_buffer(256);self.calls=[]
        provider=(C.c_char*768).from_address(C.addressof(fixture.bound.owner.context)+1280)
        bind=(word(fixture.public.ctx,64),word(provider,104),word(provider,112),256,
              word(fixture.public.ctx,80),fac[0][0]+256,256)
        self.q(13,bind=bind)
        assert self.ctx.raw[:8]==b'HIABJS02' and word(self.ctx,8)==os.getpid()
    def raw(self,raw):
        src=C.create_string_buffer(raw,len(raw));out=C.create_string_buffer(16384+32)
        C.memset(C.addressof(out)+16384,0xa5,32)
        rc=self.entry(src,len(raw),out,16384,self.ctx,256)
        assert src.raw==raw and out.raw[16384:]==b'\xa5'*32
        return rc,out.raw[:16384]
    def q(self,op,want=0,**kw):
        rc,r=self.raw(frame(op,**kw))
        assert rc==0 and r[:8]==b'HIABJMR1',(op,rc,r[:192].hex())
        assert word(r,8)==want,(op,want,r[:192].hex())
        assert word(r,136)==1 and word(r,176)==1 and word(r,184)==0
        assert all(word(r,p)<=1 for p in(128,144,152,160,168))
        self.calls.append(dict(op=op,status=word(r,8),consumed=word(r,128),
            known=word(r,136),local_pending=word(r,144),queue_pending=word(r,152),
            mapping_pending=word(r,160),unknown=word(r,168)))
        return r
    def drop(self,owned):
        r=self.q(11,a=owned);assert word(r,128)==1
        assert all(word(r,p)==0 for p in(144,152,160,168)),r[:192].hex()
    def close(self):
        r=self.q(12);assert word(r,128)==0 and word(r,144)==0
        assert word(self.ctx,16)==word(self.ctx,40)==0
        self.q(5);assert word(self.ctx,24)==1
def setup(owner,jobs):
    f=callbacks.Fixture(owner);fac=f.public.factory();resource,weak=f.resource(fac)
    strong,pair=f.acquire(resource);j=Jobs(jobs,f,fac)
    return f,fac,resource,weak,strong,pair,j
def finish(f,resource,weak,strong,j):
    j.close();f.v.drop(strong);f.v.drop(resource);f.v.raw(80,a=weak,arg0=1,want=3)
    f.finish()
def read_cell(f,pair):
    raw=bytearray(128);raw[:8]=b'HIABFQ06';put(raw,8,6);put(raw,24,*pair[1])
    entry=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)(word(f.public.ctx,80))
    src=C.create_string_buffer(bytes(raw));out=C.create_string_buffer(16384)
    rc=entry(src,128,out,16384,pair[0][0]+256,256)
    assert rc==0 and out.raw[:8]==b'HIABFR03' and word(out,8)==0
    return word(out,64)
def lifecycle(owner,jobs,out):
    f,fac,resource,weak,strong,pair,j=setup(owner,jobs)
    payload=bytes(range(256))*17+b'actual immutable native job input'
    owned=cap(j.q(10,a=pair[1],data=payload))
    assert all(owned)
    alias=cap(j.q(2,a=owned));assert alias!=owned
    first=j.q(6,a=owned);second=j.q(6,a=alias)
    assert word(first,64)==word(second,64)==read_cell(f,pair)
    assert word(first,72)==word(second,72) and word(first,80)==word(second,80)
    r=j.q(4,a=alias,offset=191,count=4097)
    assert word(r,48)==4097 and r[2048:6145]==payload[191:4288]
    j.q(4,a=alias,offset=len(payload),count=1,want=3)
    j.q(5,want=5);assert word(j.ctx,24)==0
    j.drop(owned);j.q(6,a=owned,want=1)
    r=j.q(6,a=alias);assert word(r,64)==read_cell(f,pair)
    j.drop(alias);stale=j.q(11,a=alias,want=1);assert word(stale,128)==0
    calls=list(j.calls);finish(f,resource,weak,strong,j)
    return dict(case='actual-cell-clone-alias-read-lastdrop',passed=True,calls=calls,
                immutable_input_bytes=len(payload),actual_same_kernel_identity=True)
def completion(owner,jobs,out):
    f,fac,resource,weak,strong,pair,j=setup(owner,jobs)
    owned=cap(j.q(10,a=pair[1],data=b'complete while actual Jobs cap retains the cell'))
    value=f.v.scalar('completed real Future result');f.public.call(22,*pair,value=value,kind=1);f.v.drop(value)
    got=f.v.keep(f.public.call(10,*pair),72);assert f.v.python_value(got)=='completed real Future result';f.v.drop(got)
    assert word(j.q(6,a=owned),64)==read_cell(f,pair)
    j.drop(owned);calls=list(j.calls);finish(f,resource,weak,strong,j)
    return dict(case='job-retains-cell-through-real-Future-completion',passed=True,calls=calls)
def cancellation(owner,jobs,out):
    f,fac,resource,weak,strong,pair,j=setup(owner,jobs)
    owned=cap(j.q(10,a=pair[1],data=b'cancel'))
    r=f.public.call(7,*pair);assert word(r,16)==1
    assert word(j.q(6,a=owned),64)==read_cell(f,pair)
    j.drop(owned);calls=list(j.calls);finish(f,resource,weak,strong,j)
    return dict(case='job-retains-real-cancelled-cell-until-drop',passed=True,calls=calls)
def guards(owner,jobs,out):
    f,fac,resource,weak,strong,pair,j=setup(owner,jobs);rows=[]
    variants=[]
    for op in(0,1,3,9,14,2**64-1):variants.append(('forbidden-op-'+str(op),frame(op)))
    for p in(16,48,56,64,72,80,88,96,104,112,120):
        r=bytearray(frame(2,a=pair[1]));put(r,p,1);variants.append(('reserved-'+str(p),bytes(r)))
    for magic in(b'HIABJO01',b'HIABJO02',b'HIABJO03'):
        r=bytearray(frame(12));r[:8]=magic;variants.append(('old-domain-'+magic.decode(),bytes(r)))
    variants.extend([('short',frame(12)[:-1]),('extra',frame(12)+b'x')])
    for name,raw in variants:
        before=bytes(j.ctx);rc,r=j.raw(raw)
        assert rc==0xfffffffd and bytes(j.ctx)==before,(name,rc,r[:192].hex())
        rows.append(name)
    finish(f,resource,weak,strong,j)
    return dict(case='new-private-domain-malformed-no-state-write',passed=True,controls=rows)
def parallel(owner,jobs,out):
    f,fac,resource,weak,strong,pair,j=setup(owner,jobs)
    kernel=read_cell(f,pair)
    def one(i):
        raw=('native-job-'+str(i)).encode()
        owned=cap(j.q(10,a=pair[1],data=raw));alias=cap(j.q(2,a=owned))
        assert word(j.q(6,a=alias),64)==kernel
        r=j.q(4,a=owned,count=len(raw));assert r[2048:2048+len(raw)]==raw
        j.drop(owned);j.drop(alias);return i
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        assert list(pool.map(one,range(64)))==list(range(64))
    calls=list(j.calls);finish(f,resource,weak,strong,j)
    return dict(case='eight-callers-real-Jobs-registry-and-cell-retirement',passed=True,
                threads=8,jobs=64,calls=calls,production_worker_qualification=False)
CASES=(lifecycle,completion,cancellation,guards,parallel)
def main():
    p=argparse.ArgumentParser();p.add_argument('--owner',type=Path,required=True)
    p.add_argument('--jobs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    report=dict(schema='hia.background-managed-Jobs.component.v1',passed=False,component_qualified=False,
        whole_background_closed=False,trusted_BG_initializer=False,queued_managed_edge=False,
        production_worker_qualified=False,same_arena=True,canonical_Future_pin_held_until_raw_job_retired=True,
        products={'owner':dict(path=str(a.owner),**pin(a.owner.read_bytes())),
                  'jobs':dict(path=str(a.jobs),**pin(a.jobs.read_bytes()))},cases=[])
    try:
        for fn in CASES:
            row=fn(a.owner,a.jobs,a.output);report['cases'].append(row);save(a.output/'report.json',report)
            print('ACTUAL_MANAGED_JOBS_CASE',row['case'],flush=True)
        report['passed']=report['component_qualified']=True
    except BaseException as e:
        report['error']=repr(e);report['traceback']=traceback.format_exc();raise
    finally:save(a.output/'report.json',report)
    print('ACTUAL_MANAGED_JOBS_PASS',len(report['cases']),flush=True)
if __name__=='__main__':main()
