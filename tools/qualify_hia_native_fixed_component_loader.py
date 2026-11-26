"""Actual fixed-catalog native loading, borrow custody, kernel failure and retirement gates."""
from pathlib import Path
import argparse,ctypes as C,errno,hashlib,json,mmap,os,queue,select,struct,threading,time
from tools import generate_hia_native_fixed_component_packer as spec
from tools import qualify_hia_generation_lease_owner_tempdir as tq
from tools import qualify_hia_native_owned_directory_cleanup as rq
from tools import qualify_hia_native_seccomp_notify as notify
from tools.qualify_hia_clang_capture_faults import isolated,seccomp
WORK=25<<20;OUT=131072;BAD=0xfffffffd;NONE=(1<<64)-1
Q=int.from_bytes(b'HIANLCQ1','little');R=int.from_bytes(b'HIANLCR1','little')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def frame(op,ident=0,cap=(0,0,0)):
    words=[Q,op,ident,*cap,*([0]*10)];assert len(words)==16
    return struct.pack('<16Q',*words)
def decoded(raw):
    keys=dict(status=8,state=16,export_count=48,source_fd=56,pending=80,known=88,consumed=96,retired=104,detail=112,count=120)
    d={k:word(raw,v)for k,v in keys.items()};d['cap']=tuple(word(raw,i)for i in(24,32,40))
    d['exports']=tuple(word(raw,128+8*i)for i in range(d['export_count']))
    return d
def native_seccomp(client,rules):
    class F(C.Structure):_fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
    class P(C.Structure):_fields_=[('len',C.c_ushort),('filter',C.POINTER(F))]
    start=client.address;end=start+len(spec.OUTER);assert start>>32==(end-1)>>32
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(6,0,0,0x80000000),
          (0x20,0,0,12),(0x15,0,0,start>>32),(0x20,0,0,8),(0x35,0,0,start&0xffffffff),(0x35,0,0,end&0xffffffff)]
    for nr,err,match in rules:
        if match is None:rows.extend([(0x20,0,0,0),(0x15,0,1,nr),(6,0,0,0x50000|err)])
        else:
            index,value=match
            rows.extend([(0x20,0,0,0),(0x15,0,3,nr),(0x20,0,0,16+8*index),(0x15,0,1,value&0xffffffff),(6,0,0,0x50000|err)])
    end_at=len(rows);rows.append((6,0,0,0x7fff0000))
    rows[4]=(0x15,0,end_at-5,start>>32);rows[6]=(0x35,0,end_at-7,start&0xffffffff);rows[7]=(0x35,end_at-8,0,end&0xffffffff)
    filt=(F*len(rows))(*(F(*x)for x in rows));p=P(len(rows),filt);libc=C.CDLL(None,use_errno=True)
    assert libc.prctl(38,1,0,0,0)==0,C.get_errno()
    assert libc.prctl(22,2,C.byref(p),0,0)==0,C.get_errno()
def in_thread(fn):
    result=[]
    def run():
        try:result.append((True,fn()))
        except BaseException as e:result.append((False,e))
    t=threading.Thread(target=run);t.start();t.join(15);assert not t.is_alive(),'native call did not return'
    assert len(result)==1
    if not result[0][0]:raise result[0][1]
    return result[0][1]
class Native:
    def __init__(self,path):
        self.path=Path(path);self.lib=C.CDLL(str(self.path));self.entry=self.lib.hia_native_fixed_component_loader
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.address=C.cast(self.entry,C.c_void_p).value;self.context=C.create_string_buffer(WORK);self.calls=0
    def raw(self,wire,context=None,output=None):
        src=C.create_string_buffer(wire);out=output if output is not None else C.create_string_buffer(b'\xa5'*OUT,OUT)
        w=self.context if context is None else context
        rc=int(self.entry(src,len(wire),out,OUT,w,WORK));self.calls+=1
        assert bytes(src)==wire+b'\0'
        return rc,bytes(out)
    def call(self,op,ident=0,cap=(0,0,0)):
        rc,raw=self.raw(frame(op,ident,cap));assert rc==0 and word(raw,0)==R,(rc,raw[:128].hex())
        result=decoded(raw)
        assert result['known'] in(0,1)and result['consumed']in(0,1)and result['pending']in(0,1)and result['retired']in(0,1),result
        assert raw[64:80]==bytes(16),raw[:128].hex()
        return result
    def deny(self,op,rules,ident=0,cap=(0,0,0)):
        return in_thread(lambda:(native_seccomp(self,rules),self.call(op,ident,cap))[1])
def ready(row):
    assert row['status']==0 and row['state']==2 and row['known']==1 and row['pending']==0 and row['retired']==0,row
def retired(row):
    assert row['status']==0 and row['state']==4 and row['known']==1 and row['pending']==0 and row['retired']==1 and row['count']==0,row
def maps():
    return tuple(x for x in Path('/proc/self/maps').read_text().splitlines()if'/memfd:iamodule'in x)
def child_call(entry,parent,root,leaf):
    fn=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(entry)
    req=rq.req(0,root,parent,leaf);source=C.create_string_buffer(req);out=C.create_string_buffer(128);work=C.create_string_buffer(4096)
    rc=fn(source,len(req),out,128,work,4096)
    assert rc==0 and word(bytes(out),0)==rq.R,(rc,bytes(out).hex())
    answer=rq.decode(bytes(out));rq.done(answer);return answer
def basic(path,out):
    n=Native(path);fds=tq.fdset();before=maps();ready(n.call(0,1));borrow=n.call(2);ready(borrow)
    assert borrow['consumed']==1 and all(borrow['cap'])and borrow['export_count']==1,borrow
    assert borrow['count']==1 and len(maps())>len(before)
    sourcefd=borrow['source_fd'];assert os.fstat(sourcefd).st_mode&0o170000==0o040000
    f=os.open('native_owned_directory_cleanup.hepta',os.O_RDONLY|os.O_CLOEXEC,dir_fd=sourcefd)
    try:assert os.read(f,64)
    finally:os.close(f)
    t=rq.Tree(out,'real-child');(t.path/'nested').mkdir();(t.path/'nested'/'actual').write_bytes(b'actual native child')
    result=child_call(borrow['exports'][0],t.parentfd,t.rootfd,b'work');assert not t.path.exists();t.close()
    busy=n.call(1);assert busy['status']==6 and busy['state']==2 and busy['count']==1 and busy['consumed']==0,busy
    drop=n.call(3,cap=borrow['cap']);ready(drop);assert drop['consumed']==1 and drop['count']==0,drop
    again=n.call(3,cap=borrow['cap']);assert again['status']==7 and again['consumed']==0,again
    retired(n.call(1));retired(n.call(1));retired(n.call(4))
    assert tq.fdset()==fds and maps()==before
    return dict(passed=True,actual_native_recursive_child=result,busy_close=busy,true_consumed_drop=drop,fd_and_mapping_balance=True)
def cap_guards(path,out):
    a=Native(path);b=Native(path);fds=tq.fdset();ready(a.call(0,1));ready(b.call(0,1))
    x=a.call(2);y=b.call(2)
    for bad in((0,0,0),(1,2,3),y['cap'],(x['cap'][0],x['cap'][1]^1,x['cap'][2])):
        row=a.call(3,cap=bad);assert row['status']==7 and row['consumed']==0 and row['count']==1,row
    ready(a.call(3,cap=x['cap']));ready(b.call(3,cap=y['cap']));retired(a.call(1));retired(b.call(1))
    assert tq.fdset()==fds
    return dict(passed=True,foreign_wrong_nonce_zero_and_arbitrary_caps_refused=True)
def guards(path,out):
    n=Native(path);fds=tq.fdset()
    bad=[b'',bytes(127),frame(0,0),frame(5),frame(2,1),frame(3,1),(frame(0,1)+b'x')]
    for at in(0,48,64,120):
        q=bytearray(frame(0,1));struct.pack_into('<Q',q,at,1);bad.append(bytes(q))
    for q in bad:
        before=bytes(n.context);rc,raw=n.raw(q);assert rc==BAD and raw==b'\xa5'*OUT and bytes(n.context)==before,(rc,q)
    ready(n.call(0,1));snapshot=bytes(n.context);copy=C.create_string_buffer(snapshot)
    rc,raw=n.raw(frame(1),copy);assert rc==BAD and raw==b'\xa5'*OUT and copy.raw[:WORK]==snapshot
    raw=C.create_string_buffer(frame(1));a5=C.create_string_buffer(b'\xa5'*OUT,OUT)
    views=[(None,128,a5,OUT,n.context,WORK),(raw,128,None,OUT,n.context,WORK),(raw,128,a5,OUT-1,n.context,WORK),
           (raw,128,a5,OUT,None,WORK),(raw,128,a5,OUT,n.context,WORK-1),(raw,128,n.context,OUT,n.context,WORK),
           (C.c_void_p((1<<64)-64),128,a5,OUT,n.context,WORK)]
    for args in views:
        a5.raw=b'\xa5'*OUT
        rc=n.entry(*args);assert rc==BAD and bytes(a5)==b'\xa5'*OUT and bytes(n.context)==snapshot,rc
    read,write=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(read);rc,raw=n.raw(frame(1));os.write(write,json.dumps(dict(rc=rc,out_unchanged=raw==b'\xa5'*OUT,context_unchanged=bytes(n.context)==snapshot)).encode());os._exit(0)
        except BaseException:os._exit(90)
    os.close(write);data=json.loads(os.read(read,16384));os.close(read);_,status=os.waitpid(pid,0)
    assert status==0 and data==dict(rc=BAD,out_unchanged=True,context_unchanged=True),data
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,wire_controls=len(bad),span_controls=len(views),copied_and_forked_context_no_write=True)
def missing_and_export(path,out):
    n=Native(path);fds=tq.fdset();before=maps()
    answers=[]
    for ident in(3,4,999):
        x=Native(path);r=x.call(0,ident)
        assert r['status']!=0 and r['known']==1 and r['retired']==1 and r['pending']==0 and r['count']==0,r
        retired(x.call(1));answers.append(r)
    assert tq.fdset()==fds and maps()==before
    return dict(passed=True,actual_missing_file_export_and_catalog=answers,fd_and_mapping_balance=True)
def mutated(path,out):
    n=Native(path);fds=tq.fdset();target=Path(path).parent/'components/mutable.so';original=target.read_bytes();changed=bytearray(original);changed[-1]^=1
    try:
        target.write_bytes(changed);r=n.call(0,2);assert r['status']==2 and r['retired']==1 and r['known']==1 and r['pending']==0,r
        retired(n.call(1))
    finally:target.write_bytes(original)
    assert tq.fdset()==fds
    return dict(passed=True,actual_sha_mismatch_rejected_before_dlopen=True,actual=r)
def source_lifetime(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1));b=n.call(2);source=Path(path).parent/'source/rmtree';renamed=source.with_name('rmtree-moved')
    source.rename(renamed)
    try:
        f=os.open('native_owned_directory_cleanup.hepta',os.O_RDONLY|os.O_CLOEXEC,dir_fd=b['source_fd'])
        try:assert os.read(f,64)
        finally:os.close(f)
        assert n.call(1)['status']==6
        ready(n.call(3,cap=b['cap']));retired(n.call(1))
    finally:renamed.rename(source)
    assert tq.fdset()==fds
    return dict(passed=True,actual_source_directory_fd_survives_rename_until_last_borrow=True)
def concurrent(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1));barrier=threading.Barrier(8);errors=[];totals=[]
    def run():
        try:
            barrier.wait();count=0
            for i in range(16):
                row=n.call(2);ready(row);assert all(row['cap'])and row['export_count']==1
                os.fstat(row['source_fd'])
                drop=n.call(3,cap=row['cap']);ready(drop);assert drop['consumed']==1
                count+=1
            totals.append(count)
        except BaseException as e:errors.append(repr(e))
    threads=[threading.Thread(target=run)for _ in range(8)]
    for t in threads:t.start()
    for t in threads:t.join(15)
    assert not any(t.is_alive()for t in threads)and not errors and totals==[16]*8,(errors,totals)
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,threads=8,real_borrow_drop_pairs=sum(totals),snapshot_facts_observed=True)
def allocation_failures(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1));rows=[]
    for nr in(9,318):
        row=n.deny(2,[(nr,errno.EIO,None)]);assert row['status']!=0 and row['known']==1 and row['consumed']==0 and row['cap']==(0,0,0)and row['count']==0 and row['pending']==0,row
        rows.append(row);ready(n.call(4))
        b=n.call(2);ready(b);ready(n.call(3,cap=b['cap']))
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,actual_mmap_getrandom_failure_no_cap_publication=rows,real_recovery=True)
def drop_retry(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1));b=n.call(2)
    row=n.deny(3,[(11,errno.EIO,None)],cap=b['cap'])
    assert row['status']==1 and row['known']==1 and row['consumed']==1 and row['pending']==1 and row['count']==0,row
    stale=n.call(3,cap=b['cap']);assert stale['status']==7 and stale['consumed']==0 and stale['pending']==1,stale
    recovered=n.call(4);ready(recovered);assert recovered['consumed']==0,recovered
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,actual_munmap_eio=row,actual_other_thread_retry=recovered,no_double_consumption=True)
def fd_retry(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1))
    row=n.deny(1,[(436,errno.EIO,None)])
    assert row['status']==1 and row['state']==3 and row['known']==1 and row['pending']==1 and row['retired']==0,row
    recovered=n.call(4);retired(recovered);assert tq.fdset()==fds
    return dict(passed=True,actual_close_range_eio=row,actual_retry=recovered)
def fallback(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1));row=n.deny(1,[(436,errno.ENOSYS,None)]);retired(row)
    assert tq.fdset()==fds
    return dict(passed=True,actual_close_range_enosys_close_success=row)
def ambiguous(path,out):
    n=Native(path);ready(n.call(0,1))
    row=n.deny(1,[(436,errno.ENOSYS,None),(3,errno.EIO,None)])
    assert row['status']==5 and row['state']==5 and row['known']==0 and row['pending']==1 and row['retired']==0,row
    later=n.call(4);assert later['known']==0 and later['pending']==1 and later['retired']==0,later
    return dict(passed=True,actual_ambiguous_close_quarantined=row,retry_does_not_invent_ack=later,owned_qa_subprocess_exit_reclaims_isolated_leak=True)
def initialization_failures(path,out):
    client=Native(path);fds=tq.fdset();rows=[]
    for nr in(257,5,9,319,72,17):
        n=Native(path);row=n.deny(0,[(nr,errno.EIO,None)],ident=1)
        assert row['status']!=0 and row['known']==1 and row['pending']==0 and row['retired']==1,row
        retired(n.call(1));rows.append(dict(syscall=nr,reply=row))
        assert tq.fdset()==fds,(nr,tq.fdset(),fds)
    return dict(passed=True,actual_initial_syscall_failures=rows)
def postclose_observation_retry(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1))
    row=n.deny(1,[(257,errno.EIO,None)])
    assert row['status']==1 and row['state']==3 and row['known']==1 and row['pending']==1 and row['retired']==0,row
    assert word(bytes(n.context),72)==0 and word(bytes(n.context),296)==1
    retired(n.call(4));assert tq.fdset()==fds
    return dict(passed=True,actual_dlclose_already_consumed_but_maps_open_failed=row,no_second_dlclose=True)
def actual_loader_munmap_failure(path,out):
    n=Native(path);before=maps();ready(n.call(0,1));assert len(maps())>len(before)
    row=in_thread(lambda:(seccomp([(11,errno.EIO,None)]),n.call(1))[1])
    assert row['status']==5 and row['state']==5 and row['known']==0 and row['pending']==1 and row['retired']==0 and row['detail']==712,row
    assert word(bytes(n.context),72)==0 and len(maps())>len(before)
    later=n.call(4);assert later['known']==0 and later['retired']==0 and later['pending']==1,later
    return dict(passed=True,actual_libc_munmap_eio_did_not_become_false_retired_ack=row,actual_owned_image_still_mapped=True,quarantine_retained=True)
def contention(path,out):
    n=Native(path);fds=tq.fdset();ready(n.call(0,1));holder_q=queue.Queue();waiter_q=queue.Queue();answers={};errors=[];events=[];waiter_done=threading.Event()
    def holder():
        listener=None
        try:
            native_seccomp(n,[(202,errno.EIO,(1,129))])
            listener=notify.install(n.address,n.address+len(spec.OUTER),318);holder_q.put(listener)
            answers['holder']=n.call(2)
        except BaseException as e:errors.append(repr(e))
        finally:
            if listener is not None:os.close(listener)
    def waiter():
        listener=None
        try:
            listener=notify.install(n.address,n.address+len(spec.OUTER),202);waiter_q.put(listener)
            answers['waiter']=n.call(2)
        except BaseException as e:errors.append(repr(e))
        finally:waiter_done.set()
    a=threading.Thread(target=holder);a.start();hfd=holder_q.get(timeout=5)
    assert select.select([hfd],[],[],5)[0];held=notify.receive(hfd);assert held.data.nr==318 and word(bytes(n.context),40)==1
    b=threading.Thread(target=waiter);b.start();wfd=waiter_q.get(timeout=5)
    for i in range(2):
        assert select.select([wfd],[],[],5)[0];event=notify.receive(wfd)
        assert event.data.nr==202 and event.data.args[1]==128 and event.data.args[0]==C.addressof(n.context)+40,event.data.nr
        timespec=struct.unpack('<2Q',C.string_at(event.data.args[3],16));assert timespec==(0,10000000),timespec
        assert word(bytes(n.context),40)==1
        events.append(dict(syscall=202,operation=128,timespec=timespec));notify.continue_syscall(wfd,event)
    notify.continue_syscall(hfd,held)
    deadline=time.monotonic()+8
    while not waiter_done.is_set()and time.monotonic()<deadline:
        if not select.select([wfd],[],[],.1)[0]:continue
        if waiter_done.is_set():break
        event=notify.receive(wfd);events.append(dict(syscall=int(event.data.nr),operation=int(event.data.args[1])))
        notify.continue_syscall(wfd,event)
    a.join(5);b.join(5);os.close(wfd);assert not a.is_alive()and not b.is_alive()and not errors,(answers,errors)
    for row in answers.values():ready(row);ready(n.call(3,cap=row['cap']))
    retired(n.call(1));assert tq.fdset()==fds
    return dict(passed=True,actual_getrandom_holds_native_mutex=True,real_timed_futex_waits=events,real_denied_wake_does_not_strand_waiter=True)
CASES=(('basic',basic),('cap-guards',cap_guards),('wire-fork-copy',guards),('missing-export',missing_and_export),
 ('actual-hash-mutation',mutated),('source-fd-lifetime',source_lifetime),('8thread-borrow-drop',concurrent),
 ('allocation-failures',allocation_failures),('drop-munmap-retry',drop_retry),('fd-close-retry',fd_retry),
 ('enosys-close-fallback',fallback),('ambiguous-close',ambiguous),('initial-syscall-failures',initialization_failures),
 ('post-dlclose-observation-retry',postclose_observation_retry),('actual-ld-munmap-failure',actual_loader_munmap_failure),
 ('native-lock-wait-wake-fault',contention))
def main():
    p=argparse.ArgumentParser();p.add_argument('--loader',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',default='')
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False);selected=set(args.cases.split(','))if args.cases else{n for n,_ in CASES}
    assert selected<={n for n,_ in CASES};rows=[]
    for name,fn in CASES:
        if name not in selected:continue
        here=args.output/name;here.mkdir()
        rows.append(isolated(name,lambda fn=fn,here=here:fn(args.loader,here)))
        (args.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
    report=dict(passed=True,complete=not args.cases,groups=len(rows),cases=rows,loader=pin(args.loader.read_bytes()),same_process_real_native_calls=True,
                source_files={str(Path(__file__).relative_to(Path(__file__).resolve().parents[1])):pin(Path(__file__).read_bytes())},
                whole_native_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(dict(passed=True,complete=report['complete'],groups=len(rows))),flush=True)
if __name__=='__main__':main()
