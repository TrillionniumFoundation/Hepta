"""Real fixed resource admission, sealed tool custody and threshold lifetime."""
from pathlib import Path
import argparse,ctypes as C,errno,fcntl,hashlib,json,os,struct,threading
from tools import generate_hia_native_runtime_resources_packer as spec
from tools import generate_hia_native_runtime_resource_catalog as catalog
from tools import qualify_hia_native_fixed_component_loader as legacy
from tools import qualify_hia_generation_lease_owner_tempdir as tq
from tools.qualify_hia_clang_capture_faults import isolated
WORK=8<<20;OUT=131072;BAD=0xfffffffd;NONE=(1<<64)-1
Q=int.from_bytes(b'HIANGRQ1','little');R=int.from_bytes(b'HIANGRR1','little')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def frame(op,cap=(0,0,0)):return struct.pack('<16Q',Q,op,0,*cap,*([0]*10))
def decoded(raw):
    row={k:word(raw,v)for k,v in dict(status=8,state=16,pending=80,known=88,consumed=96,retired=104,detail=112,count=120,source_fd=72,threshold=128,threshold_bytes=136,threshold_fd=144,nonce=152,digits=160).items()}
    row['cap']=tuple(word(raw,i)for i in(24,32,40));row['tool_fds']=tuple(word(raw,i)for i in(48,56,64))
    return row
def native_seccomp(client,rules):
    saved=legacy.spec;legacy.spec=spec
    try:return legacy.native_seccomp(client,rules)
    finally:legacy.spec=saved
class Native:
    def __init__(self,path):
        self.path=Path(path);self.lib=C.CDLL(str(self.path));self.entry=self.lib.hia_native_runtime_resources
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.address=C.cast(self.entry,C.c_void_p).value;self.context=C.create_string_buffer(WORK);self.calls=0
    def raw(self,wire,context=None,output=None):
        src=C.create_string_buffer(wire);out=output if output is not None else C.create_string_buffer(b'\xa5'*OUT,OUT)
        w=self.context if context is None else context
        rc=int(self.entry(src,len(wire),out,OUT,w,WORK));self.calls+=1;assert bytes(src)==wire+b'\0'
        return rc,bytes(out)
    def call(self,op,cap=(0,0,0)):
        rc,raw=self.raw(frame(op,cap));assert rc==0 and word(raw,0)==R,(rc,raw[:192].hex())
        row=decoded(raw);assert all(row[k]in(0,1)for k in('known','consumed','pending','retired')),row
        return row
    def deny(self,op,rules,cap=(0,0,0)):
        return legacy.in_thread(lambda:(native_seccomp(self,rules),self.call(op,cap))[1])
ready=legacy.ready;retired=legacy.retired
def actual_fields(row):
    ready(row);assert row['consumed']==1 and all(row['cap'])and row['nonce']and row['digits']==4300,row
    assert row['threshold_bytes']==10100891 and row['threshold']!=0,row
    assert os.fstat(row['source_fd']).st_mode&0o170000==0o040000
    fds=(*row['tool_fds'],row['threshold_fd'])
    actual=[]
    for entry,fd in zip(catalog.RESOURCES,fds):
        st=os.fstat(fd);assert fd>=3 and st.st_nlink==0 and st.st_size==entry['bytes'],(entry,fd,st)
        assert fcntl.fcntl(fd,1034)==15 and st.st_mode&0o777==(0o500 if entry['id']<4 else 0o400)
        raw=os.pread(fd,st.st_size,0);assert pin(raw)=={k:entry[k]for k in('bytes','sha256')}
        actual.append(pin(raw))
    assert pin(C.string_at(row['threshold'],row['threshold_bytes']))==actual[-1]
    relevant=[l for l in Path('/proc/self/maps').read_text().splitlines()if int(l.split('-')[0],16)==row['threshold']]
    assert len(relevant)==1 and relevant[0].split()[1]=='r--p',relevant
    return actual
def basic(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));b=n.call(2);actual=actual_fields(b)
    assert b['count']==1
    busy=n.call(1);assert busy['status']==6 and busy['state']==2 and busy['count']==1 and busy['consumed']==0,busy
    drop=n.call(3,b['cap']);ready(drop);assert drop['consumed']==1 and drop['count']==0
    stale=n.call(3,b['cap']);assert stale['status']==7 and stale['consumed']==0
    retired(n.call(1));retired(n.call(1));retired(n.call(4));assert tq.fdset()==fds
    return dict(passed=True,four_actual_resource_pins=actual,real_readonly_threshold_mapping=True,busy_close=busy,all_fd_custody_retired=True)
def cap_guards(path,out):
    a=Native(path);b=Native(path);fds=tq.fdset();ready(a.call(0));ready(b.call(0));x=a.call(2);y=b.call(2)
    for cap in((0,0,0),(1,2,3),y['cap'],(x['cap'][0],x['cap'][1]^1,x['cap'][2])):
        r=a.call(3,cap);assert r['status']==7 and r['consumed']==0 and r['count']==1,r
    ready(a.call(3,x['cap']));ready(b.call(3,y['cap']));retired(a.call(1));retired(b.call(1));assert tq.fdset()==fds
    return dict(passed=True,wrong_nonce_foreign_stale_zero_arbitrary_caps=True)
def guards(path,out):
    n=Native(path);fds=tq.fdset();bad=[b'',bytes(127),frame(5),frame(0)+b'x']
    for at in(0,16,24,40,48,72,120):
        r=bytearray(frame(0));struct.pack_into('<Q',r,at,1);bad.append(bytes(r))
    for r in bad:
        before=bytes(n.context);rc,raw=n.raw(r);assert rc==BAD and raw==b'\xa5'*OUT and bytes(n.context)==before,(rc,r.hex())
    ready(n.call(0));before=bytes(n.context);copy=C.create_string_buffer(before)
    rc,raw=n.raw(frame(1),copy);assert rc==BAD and raw==b'\xa5'*OUT and copy.raw[:WORK]==before
    rd,wr=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(rd);rc,raw=n.raw(frame(1));os.write(wr,json.dumps([rc,raw==b'\xa5'*OUT,bytes(n.context)==before]).encode());os._exit(0)
        except BaseException:os._exit(90)
    os.close(wr);answer=json.loads(os.read(rd,4096));os.close(rd);_,status=os.waitpid(pid,0)
    assert status==0 and answer==[BAD,True,True],answer
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,controls=len(bad),real_fork_copy_no_write=True)
def mutated(path,out):
    fds=tq.fdset();rows=[]
    for entry in catalog.RESOURCES:
        n=Native(path);target=Path(path).parent/entry['artifact'];original=target.read_bytes();mode=target.stat().st_mode&0o777
        changed=bytearray(original);changed[-1]^=1
        try:
            target.chmod(0o600);target.write_bytes(changed)
            r=n.call(0);assert r['status']==2 and r['retired']==1 and r['known']==1 and r['pending']==0,r
            retired(n.call(1));rows.append(dict(id=entry['id'],reply=r))
        finally:target.write_bytes(original);target.chmod(mode)
        assert tq.fdset()==fds
    return dict(passed=True,actual_each_asset_hash_mismatch=rows,no_partial_bank_published=True)
def source_lifetime(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));b=n.call(2)
    source=Path(path).parent/'source';moved=source.with_name('source-held')
    source.rename(moved)
    try:
        fd=os.open('examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat',os.O_RDONLY|os.O_CLOEXEC,dir_fd=b['source_fd'])
        try:assert pin(os.read(fd,10100891))=={k:catalog.RESOURCES[3][k]for k in('bytes','sha256')}
        finally:os.close(fd)
        assert pin(C.string_at(b['threshold'],b['threshold_bytes']))['sha256']==catalog.RESOURCES[3]['sha256']
        assert n.call(1)['status']==6
        ready(n.call(3,b['cap']));retired(n.call(1))
    finally:moved.rename(source)
    assert tq.fdset()==fds
    return dict(passed=True,real_source_fd_and_threshold_survive_installation_rename=True)
def concurrent(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));barrier=threading.Barrier(8);errors=[];counts=[]
    def worker():
        try:
            barrier.wait()
            for _ in range(16):
                b=n.call(2);ready(b);assert b['nonce']and b['threshold_bytes']==10100891
                os.fstat(b['tool_fds'][0]);r=n.call(3,b['cap']);ready(r);assert r['consumed']==1
            counts.append(16)
        except BaseException as e:errors.append(repr(e))
    ts=[threading.Thread(target=worker)for _ in range(8)]
    for t in ts:t.start()
    for t in ts:t.join(15)
    assert not any(t.is_alive()for t in ts)and not errors and counts==[16]*8,(errors,counts)
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,threads=8,actual_borrow_drop_pairs=sum(counts))
def allocation_failures(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));rows=[]
    for nr in(9,318):
        r=n.deny(2,[(nr,errno.EIO,None)]);assert r['status']!=0 and r['known']==1 and r['consumed']==0 and r['cap']==(0,0,0)and r['count']==0 and r['pending']==0,r
        rows.append(r);ready(n.call(4));b=n.call(2);ready(n.call(3,b['cap']))
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,actual_mmap_getrandom_no_cap_publication=rows)
def drop_retry(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));b=n.call(2);r=n.deny(3,[(11,errno.EIO,None)],b['cap'])
    assert r['status']==1 and r['known']==1 and r['consumed']==1 and r['pending']==1 and r['count']==0,r
    stale=n.call(3,b['cap']);assert stale['status']==7 and stale['consumed']==0 and stale['pending']==1
    retry=n.call(4);ready(retry);assert retry['consumed']==0
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,actual_munmap_failure=r,actual_retry=retry,no_double_consume=True)
def threshold_retry(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));b=n.call(2);at=b['threshold'];size=b['threshold_bytes'];ready(n.call(3,b['cap']))
    r=n.deny(1,[(11,errno.EIO,None)])
    assert r['known']==1 and r['pending']==1 and r['retired']==0 and word(bytes(n.context),344)==at,r
    assert pin(C.string_at(at,size))['sha256']==catalog.RESOURCES[3]['sha256']
    retired(n.call(4));assert word(bytes(n.context),344)==0 and tq.fdset()==fds
    return dict(passed=True,actual_threshold_munmap_eio_retains_live_mapping=r,actual_retry_retires=True)
def fd_retry(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));r=n.deny(1,[(436,errno.EIO,None)])
    assert r['status']==1 and r['state']==3 and r['known']==1 and r['pending']==1 and r['retired']==0,r
    retired(n.call(4));assert tq.fdset()==fds
    return dict(passed=True,actual_close_range_eio=r,actual_retry=True)
def fallback(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0));r=n.deny(1,[(436,errno.ENOSYS,None)]);retired(r);assert tq.fdset()==fds
    return dict(passed=True,actual_close_fallback=r)
def ambiguous(path,out):
    n=Native(path);ready(n.call(0));r=n.deny(1,[(436,errno.ENOSYS,None),(3,errno.EIO,None)])
    assert r['status']==5 and r['state']==5 and r['known']==0 and r['pending']==1 and r['retired']==0,r
    again=n.call(4);assert again['known']==0 and again['pending']==1 and again['retired']==0
    return dict(passed=True,unknown_close_preserved=r,qa_process_exit_reclaims_quarantined_fd=True)
def initialization_failures(path,out):
    fds=tq.fdset();rows=[]
    for nr in(257,5,9,319,72,17,91,318,11,436):
        n=Native(path);r=n.deny(0,[(nr,errno.EIO,None)])
        assert r['status']!=0 and r['known']==1 and r['consumed']==0,r
        if r['pending']:
            assert r['retired']==0;retired(n.call(4))
        else:assert r['retired']==1
        retired(n.call(1));assert tq.fdset()==fds,(nr,r,tq.fdset(),fds);rows.append(dict(syscall=nr,reply=r))
    return dict(passed=True,actual_initial_failures=rows,all_known_custody_retried_and_retired=True)
def closed_standard_fds(path,out):
    n=Native(path)
    for fd in(0,1,2):
        try:os.close(fd)
        except OSError:pass
    fds=tq.fdset();ready(n.call(0));b=n.call(2);actual_fields(b);assert all(fd>=3 for fd in b['tool_fds'])
    ready(n.call(3,b['cap']));retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,actual_fd_zero_one_two_closed_native_capture_and_retirement=True)
CASES=(('four-assets-and-lifetime',basic),('cap-guards',cap_guards),('wire-fork-copy',guards),('actual-each-hash-mutation',mutated),
 ('source-fd-lifetime',source_lifetime),('8thread-borrow-drop',concurrent),('allocation-failures',allocation_failures),
 ('drop-munmap-retry',drop_retry),('threshold-munmap-retry',threshold_retry),('fd-close-retry',fd_retry),
 ('enosys-close-fallback',fallback),('ambiguous-close',ambiguous),('initial-syscall-failures',initialization_failures),
 ('closed-standard-fds',closed_standard_fds))
def main():
    p=argparse.ArgumentParser();p.add_argument('--resources',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',default='')
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);selected=set(a.cases.split(','))if a.cases else{n for n,_ in CASES}
    assert selected<={n for n,_ in CASES};rows=[]
    for name,fn in CASES:
        if name not in selected:continue
        here=a.output/name;here.mkdir();rows.append(isolated(name,lambda fn=fn,here=here:fn(a.resources,here)))
        (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
    report=dict(passed=True,complete=not a.cases,groups=len(rows),cases=rows,product=pin(a.resources.read_bytes()),
       root_binding_qualified=False,public_constructor_qualified=False,whole_native_runtime_qualified=False)
    (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(dict(passed=True,complete=report['complete'],groups=len(rows))),flush=True)
if __name__=='__main__':main()
