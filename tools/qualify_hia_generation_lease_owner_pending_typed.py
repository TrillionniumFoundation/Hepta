"""Actual deferred typed validation with a real queued resource finalizer.

A kernel notification pauses the fixed Value call while the real lease mutex
is held. Another thread creates a real unlink failure. Finalizer notifications
then prove callbacks run only after that lease mutex has been released.
"""
from pathlib import Path
import argparse,ctypes as C,json,mmap,os,queue,select,struct,threading,time
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools import qualify_hia_native_seccomp_notify as notify
from tools import generate_hia_result_value_resources_packer as value_spec
from tools import generate_hia_generation_lease_owner_packer as spec


def install_two_spans(spans):
    # Linux permits one NEW_LISTENER for a thread. One BPF filter covers the two
    # actual fixed entry spans, so the controller can distinguish their IPs.
    rows=[(0x20,0,0,0),(0x15,0,6*len(spans),39)]
    for start,end in spans:
        assert 0<start<end and start>>32==(end-1)>>32
        rows += [(0x20,0,0,12),(0x15,0,4,start>>32),
                 (0x20,0,0,8),(0x35,0,2,start&0xffffffff),
                 (0x35,1,0,end&0xffffffff),(0x06,0,0,notify.USER_NOTIF)]
    rows.append((0x06,0,0,notify.ALLOW))
    code=(notify.Filter*len(rows))(*(notify.Filter(*r)for r in rows))
    program=notify.Program(len(rows),code)
    assert notify.libc.prctl(38,1,0,0,0)==0,C.get_errno()
    fd=notify.libc.syscall(C.c_long(317),C.c_long(1),C.c_long(8),C.byref(program))
    assert fd>=0,('union NEW_LISTENER',C.get_errno())
    return fd

def run(path,files,parent):
    owner,c,v=resources.setup(path);api=q.Lifecycle(owner)
    before=set(os.listdir('/proc/self/fd'))
    current=parent/'current';pending=parent/'pending';current.mkdir();pending.mkdir()
    runtime=q.old.create(c,files,current);lease=q.old.lease(c,runtime)
    retire=q.old.create(c,files,pending);resource=resources.capture(owner,v,1,retire);c.q(3,retire)
    fn=v.scalar('calculate');scalar=v.scalar(71);args=v.lst([scalar])
    value_entry=q.get(owner.context,40);final_entry=q.get(owner.context,640)
    assert C.string_at(value_entry,200)==value_spec.BRIDGE[:200]
    assert C.string_at(final_entry,200)==spec.FINALIZER_PREFIX[:200]
    carrier_entry=q.get(owner.context,32);hole=spec.HANDLES_HOLES['effects']
    effects_entry=carrier_entry+hole+4+struct.unpack('<i',C.string_at(carrier_entry+hole,4))[0]
    assert C.string_at(effects_entry,96)==spec.EFFECTS_PREFIX[:96]
    endpoints=queue.Queue();errors=queue.Queue();state={}
    def call_worker():
        try:
            q.deny_syscall(87,5)
            frame=bytearray(128);struct.pack_into('<8sQ',frame,0,b'HIAMVHQ1',4)
            struct.pack_into('<3Q',frame,24,*lease);struct.pack_into('<Q',frame,72,256)
            raw=q.envelope(1,bytes(frame)+q.typed_request(fn,args));src=C.create_string_buffer(raw)
            with mmap.mmap(-1,q.OUT)as out:
                state['output']=out
                fd=install_two_spans(((value_entry,value_entry+len(value_spec.BRIDGE)),(final_entry,final_entry+len(spec.FINALIZER_PREFIX))))
                endpoints.put(('call',fd,threading.get_native_id()))
                rc=owner.entry(src,len(raw),q.address(out),q.OUT,owner.context,q.CONTEXT_BYTES)
                assert rc==0 and out[:8]==b'HIAGLOR1'
                assert q.get(out,8)==0 and q.get(out,64)==0
                assert q.get(out,72)==11,'pending cleanup is separately visible without discarding the scalar result'
                head=bytes(out[q.CHILD:q.CHILD+128]);assert head[:8]==b'HIAMVHR1'and q.get(head,8)==0
                at=q.CHILD+q.get(head,56);child=bytes(out[at:at+1024])
                assert child[:8]==b'HIAMVER1'and q.get(child,8)==0
                value=bytes(out[at+q.get(child,120):at+q.get(child,120)+q.get(child,112)])
                assert json.loads(value)==71
                state['result']=71;state['cleanup_status']=11
        except BaseException as exc:
            errors.put(('call',repr(exc)));print('PENDING_TYPED_CALL_ERROR',repr(exc),flush=True)
        finally:state['call_done']=True
    def close_worker():
        try:
            fd=notify.install(effects_entry,effects_entry+len(spec.EFFECTS_PREFIX),202)
            endpoints.put(('close',fd,threading.get_native_id()))
            q.old.ok(api.call(1,lease));state['closed']=True
        except BaseException as exc:
            errors.put(('close',repr(exc)));print('PENDING_TYPED_CLOSE_ERROR',repr(exc),flush=True)
        finally:state['close_done']=True
    call=threading.Thread(target=call_worker,daemon=True);call.start()
    mapping={}
    name,fd,tid=endpoints.get(timeout=30);mapping[name]=(fd,tid)
    callfd,calltid=mapping['call']
    def receive(fd):
        assert select.select([fd],[],[],30)[0],('notification timed out',list(errors.queue))
        return notify.receive(fd)
    events=[]
    for _ in range(2):
        e=receive(callfd);assert e.pid==calltid and e.data.nr==39
        notify.continue_syscall(callfd,e)
    held=receive(callfd);assert held.pid==calltid and held.data.nr==39
    out=state['output'];at=q.CHILD+(1<<20)
    assert q.get(out,at+128)==636
    pointer=q.get(out,at+272);mutex=pointer+88
    assert pointer and C.c_uint32.from_address(mutex).value==1
    for cap in(args,fn,scalar):v.drop(cap)
    # Queue creation occurs after argument retains and before the actual private
    # typed validation; no intervening Value observer can drain that queue.
    pending_results=queue.Queue()
    def fail_retirement():
        try:
            q.deny_syscall(87,5)
            raw=v.raw(29,a=resource,want=11)
            assert tuple(q.get(raw,x)for x in(80,88,96))==(1,1,1)
            v.held.remove(resource);pending_results.put(True)
        except BaseException as exc:pending_results.put(exc)
    worker=threading.Thread(target=fail_retirement);worker.start();worker.join(30)
    assert not worker.is_alive()
    result=pending_results.get_nowait()
    if isinstance(result,BaseException):raise result
    assert q.get(owner.context,688)!=0 and q.get(c.w,40)!=0
    events.append(dict(step='actual-resource-queued-while-typed-lease-mutex-held',lease_mutex=1))
    close=threading.Thread(target=close_worker,daemon=True);close.start()
    name,closefd,closetid=endpoints.get(timeout=30);assert name=='close';mapping[name]=(closefd,closetid)
    for _ in range(16):
        e=receive(closefd);assert e.pid==closetid and e.data.nr==202
        if e.data.args[1]==128:break
        assert e.data.args[1]==129
        notify.continue_syscall(closefd,e)
    else:raise AssertionError('actual close did not wait')
    assert e.data.args[0]==mutex and e.data.args[2]==1
    notify.continue_syscall(closefd,e)
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        kernel=Path('/proc/self/task/'+str(closetid)+'/wchan').read_text().strip()
        if 'futex'in kernel:break
        assert not state.get('close_done')
    else:raise AssertionError('no actual close kernel futex wait')
    assert C.c_uint32.from_address(mutex).value==1
    notify.continue_syscall(callfd,held)
    callbacks=0;deadline=time.monotonic()+60
    while not(state.get('call_done')and state.get('close_done')):
        assert time.monotonic()<deadline,('completion deadline',list(errors.queue))
        fds=[]
        if not state.get('call_done'):fds.append(callfd)
        if not state.get('close_done'):fds.append(closefd)
        for fd in select.select(fds,[],[],0.1)[0]:
            if state.get('call_done'if fd==callfd else 'close_done'):continue
            event=notify.receive(fd)
            if fd==callfd and final_entry<=event.data.ip<final_entry+len(spec.FINALIZER_PREFIX):
                assert event.pid==calltid and event.data.nr==39
                # The close thread can now own this same mutex. Inspecting
                # only its lockword would confuse that with ownership by the
                # typed thread. Its actual outer phase must already be cleanup.
                assert q.get(out,256)in(33,34),'resource callback ran before the carrier call returned'
                # Keep the typed thread at this real finalizer syscall while
                # the other thread completes close. Completion proves the
                # paused typed thread no longer owns the lease mutex.
                closing_deadline=time.monotonic()+30
                while not state.get('close_done'):
                    assert time.monotonic()<closing_deadline,'close could not complete while finalizer was paused'
                    ready=select.select([closefd],[],[],0.1)[0]
                    if ready and not state.get('close_done'):
                        closing=notify.receive(closefd)
                        assert closing.pid==closetid and closing.data.nr==202
                        notify.continue_syscall(closefd,closing)
                    assert errors.empty(),list(errors.queue)
                assert state.get('closed')and C.c_uint32.from_address(mutex).value==0
                callbacks+=1
                events.append(dict(step='fixed-resource-finalizer-after-lease-unlock',lease_mutex=0,ip=event.data.ip))
            elif fd==callfd:assert event.data.nr==39
            else:assert event.data.nr==202
            notify.continue_syscall(fd,event)
        assert errors.empty(),list(errors.queue)
    call.join();close.join()
    for fd in(callfd,closefd):os.close(fd)
    assert callbacks and state['result']==71 and state['closed']
    assert q.get(owner.context,688)!=0 and q.get(c.w,40)!=0
    q.old.ok(api.call(6,lease));c.q(4,runtime,q.old.public_request(8),child=0);c.q(3,runtime)
    assert not v.held
    closed=owner.call(3)
    assert closed['status']==0 and closed['state']==3,resources.clean_row(closed)
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
    assert not list(current.iterdir())and not list(pending.iterdir())
    current.rmdir();pending.rmdir()
    assert set(os.listdir('/proc/self/fd'))==before
    return dict(passed=True,actual_deferred_private_typed_call=True,real_queued_resource=True,
                kernel_wait=kernel,callbacks=callbacks,events=events,scalar_result=71,
                cleanup_pending_reported_separately=True,actual_native_retry_fully_retired=True,
                code_mutexes_results_unmodified=True,fd_set_unchanged=True)

def main():
    ap=argparse.ArgumentParser()
    for name in('owner','normalizer','proof','builder','output'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False);files=[]
    for name in('normalizer','proof','builder'):
        raw=getattr(a,name).read_bytes();files.append((q.old.sealed(raw),raw))
    try:
        report=run(a.owner,files,a.output);(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=True,callbacks=report['callbacks'],kernel_wait=report['kernel_wait'])),flush=True)
    finally:
        for fd,_ in files:os.close(fd)
if __name__=='__main__':main()
