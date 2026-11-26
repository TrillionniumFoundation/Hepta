"""Observe actual typed lease locking through kernel syscall notifications.

The product bytes, mutexes, results and syscall return values are never patched.
Only the test threads receive seccomp filters, and every notification continues
the real syscall. Read-only native output observations identify the same lease
mutex subsequently used by the close thread.
"""
from pathlib import Path
import argparse, ctypes as C, json, mmap, os, queue, select, struct, threading, time
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_native_seccomp_notify as notify
from tools.qualify_hia_result_value_records import Values
from tools import generate_hia_result_value_resources_packer as value_spec
from tools import generate_hia_generation_lease_owner_packer as owner_spec

def run(path,files,parent):
    owner=q.Owner(path);owner.initialize();carrier=q.Carrier(owner);lifecycle=q.Lifecycle(owner)
    values=Values(q.ValueTransport(owner))
    before=set(os.listdir('/proc/self/fd'))
    runtime=q.old.create(carrier,files,parent);lease=q.old.lease(carrier,runtime)
    function=values.scalar('calculate');scalar=values.scalar(71);arguments=values.lst([scalar])
    value_entry=q.get(owner.context,40)
    assert C.string_at(value_entry,200)==value_spec.BRIDGE[:200]
    carrier_entry=q.get(owner.context,32);hole=owner_spec.HANDLES_HOLES['effects']
    displacement=struct.unpack('<i',C.string_at(carrier_entry+hole,4))[0]
    effects_entry=carrier_entry+hole+4+displacement
    assert C.string_at(effects_entry,96)==owner_spec.EFFECTS_PREFIX[:96]
    listeners=queue.Queue();shared={};errors=queue.Queue()
    def typed_worker():
        listener=None
        try:
            frame=bytearray(128);struct.pack_into('<8sQ',frame,0,b'HIAMVHQ1',4)
            struct.pack_into('<3Q',frame,24,*lease);struct.pack_into('<Q',frame,72,256)
            raw=q.envelope(1,bytes(frame)+q.typed_request(function,arguments))
            source=C.create_string_buffer(raw)
            with mmap.mmap(-1,q.OUT) as output:
                shared['output']=output
                listener=notify.install(value_entry,value_entry+len(value_spec.BRIDGE),39)
                listeners.put(('typed',listener,threading.get_native_id()))
                rc=owner.entry(source,len(raw),q.address(output),q.OUT,owner.context,q.CONTEXT_BYTES)
                assert rc==0 and output[:8]==b'HIAGLOR1' and q.get(output,8)==0
                at=q.CHILD;header=bytes(output[at:at+128])
                assert header[:8]==b'HIAMVHR1' and q.get(header,8)==0
                at+=q.get(header,56);child=bytes(output[at:at+1024])
                assert child[:8]==b'HIAMVER1' and q.get(child,8)==0
                value=bytes(output[at+q.get(child,120):at+q.get(child,120)+q.get(child,112)])
                assert json.loads(value)==71
                shared['typed_result']=71
        except BaseException as exc:errors.put(('typed',repr(exc)))
        finally:shared['typed_done']=True
    def close_worker():
        try:
            listener=notify.install(effects_entry,effects_entry+len(owner_spec.EFFECTS_PREFIX),202)
            listeners.put(('close',listener,threading.get_native_id()))
            result=lifecycle.call(1,lease);q.old.ok(result)
            shared['close_result']=result
        except BaseException as exc:errors.put(('close',repr(exc)))
        finally:shared['close_done']=True
    call_thread=threading.Thread(target=typed_worker,daemon=True);call_thread.start()
    label,callfd,calltid=listeners.get(timeout=30);assert label=='typed'
    def receive(fd):
        assert select.select([fd],[],[],30)[0],('notification timeout',fd,list(errors.queue))
        return notify.receive(fd)
    observations=[]
    for index in range(2):
        event=receive(callfd)
        assert event.pid==calltid and event.data.nr==39
        observations.append(dict(step='retain-'+str(index),syscall=event.data.nr,ip=event.data.ip))
        notify.continue_syscall(callfd,event)
    held=receive(callfd)
    assert held.pid==calltid and held.data.nr==39
    output=shared['output']
    effects_at=q.CHILD+(1<<20)
    assert q.get(output,effects_at+128)==636
    lease_pointer=q.get(output,effects_at+272)
    assert lease_pointer,('missing native lease pointer',q.get(output,effects_at+128))
    mutex=lease_pointer+88
    assert C.c_uint32.from_address(mutex).value==1
    assert q.get(values.raw(47),48)==5
    # The real args/function objects remain reachable through the owner's two
    # private retained caps after every caller-owned reference has been dropped.
    for cap in (arguments,function,scalar):values.drop(cap)
    assert q.get(values.raw(47),48)==2
    assert owner.call(3)['status']==2
    close_thread=threading.Thread(target=close_worker,daemon=True);close_thread.start()
    label,closefd,closetid=listeners.get(timeout=30);assert label=='close'
    for _ in range(16):
        waiting=receive(closefd)
        assert waiting.pid==closetid and waiting.data.nr==202
        if waiting.data.args[1]==128:break
        assert waiting.data.args[1]==129,tuple(waiting.data.args)
        observations.append(dict(step='close-prior-unlock-wake',syscall=202,operation=129))
        notify.continue_syscall(closefd,waiting)
    else:raise AssertionError('close did not attempt a mutex wait')
    assert waiting.data.args[0]==mutex and waiting.data.args[2]==1,(tuple(waiting.data.args),mutex)
    assert C.c_uint32.from_address(mutex).value==1
    assert not shared.get('close_done') and not shared.get('typed_done')
    observations.append(dict(step='close-waits-on-exact-held-lease-mutex',
                             syscall=waiting.data.nr,ip=waiting.data.ip,
                             operation=waiting.data.args[1]))
    notify.continue_syscall(closefd,waiting)
    # This is an observed kernel wait, not an elapsed-sleep assumption.
    deadline=time.monotonic()+30;kernel_wait=None
    while time.monotonic()<deadline:
        state=Path('/proc/self/task/'+str(closetid)+'/wchan').read_text().strip()
        if 'futex' in state:
            kernel_wait=state;break
        if shared.get('close_done'):raise AssertionError('close completed while native lease call held the mutex')
    assert kernel_wait,('no actual kernel futex wait',state)
    assert C.c_uint32.from_address(mutex).value==1
    notify.continue_syscall(callfd,held)
    deadline=time.monotonic()+30
    while not (shared.get('typed_done') and shared.get('close_done')):
        assert time.monotonic()<deadline,('workers did not finish',list(errors.queue))
        live=[]
        if not shared.get('typed_done'):live.append(callfd)
        if not shared.get('close_done'):live.append(closefd)
        ready=select.select(live,[],[],0.1)[0]
        for fd in ready:
            if shared.get('typed_done' if fd==callfd else 'close_done'):continue
            event=notify.receive(fd)
            if fd==callfd:assert event.data.nr==39
            else:assert event.data.nr==202
            observations.append(dict(step='completion',thread='typed' if fd==callfd else 'close',
                                     syscall=event.data.nr,ip=event.data.ip))
            notify.continue_syscall(fd,event)
        assert errors.empty(),list(errors.queue)
    call_thread.join();close_thread.join()
    assert errors.empty(),list(errors.queue)
    os.close(callfd);os.close(closefd)
    assert shared['typed_result']==71 and shared['close_result']['status']==0
    assert q.get(values.raw(47),48)==0
    q.old.ok(lifecycle.call(0,lease),4)
    q.old.ok(lifecycle.call(6,lease))
    carrier.q(4,runtime,q.old.public_request(8),child=0);carrier.q(3,runtime)
    assert owner.call(3)['status']==0
    assert set(os.listdir('/proc/self/fd'))==before and not list(parent.iterdir())
    return dict(actual_native_image=True,value_image_sha256=q.sha((path.parent/'hia-generation-lease-values.core.bin').read_bytes()),
                same_lease_mutex_held_during_typed_validation=True,actual_close_kernel_wait=kernel_wait,
                actual_loaded_function_completed=71,caller_cap_drop_during_call_safe=True,
                temporary_references_consumed=True,fd_set_unchanged=True,artifact_parent_empty=True,
                observations=observations,syscalls_faked=False,mutexes_or_code_modified=False)

def main():
    ap=argparse.ArgumentParser()
    for name in ('owner','normalizer','proof','builder','output'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    parent=a.output/'artifacts';parent.mkdir(mode=0o700)
    files=[]
    for name in ('normalizer','proof','builder'):
        raw=getattr(a,name).read_bytes();files.append((q.old.sealed(raw),raw))
    try:
        report=run(a.owner,files,parent)
        (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=True,observations=len(report['observations']),kernel_wait=report['actual_close_kernel_wait'])))
    finally:
        for fd,_ in files:os.close(fd)

if __name__=='__main__':main()
