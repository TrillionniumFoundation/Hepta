"""Actual native carrier finalizer acknowledgement and retained-failure gates."""
from pathlib import Path
import argparse, ctypes as C, json, os, queue, struct, threading
from tools import qualify_hia_generation_lease_owner as q

SIGNATURE=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)

class Finalizer:
    def __init__(self,owner):
        self.owner=owner;self.entry=SIGNATURE(q.get(owner.context,640))
        self.context=C.addressof(owner.context)+768
        assert q.get(owner.context,648)==self.context and q.get(owner.context,656)==256
        self.nonce=q.get(owner.context,664);assert self.nonce
    def call(self,kind,cap,op=0,nonce=None):
        raw=bytearray(128)
        struct.pack_into('<8s6Q',raw,0,b'HIAVRFQ1',op,self.nonce if nonce is None else nonce,kind,*cap)
        source=C.create_string_buffer(bytes(raw));output=C.create_string_buffer(128)
        rc=self.entry(source,128,output,128,self.context,256)
        assert rc==0 and output.raw[:8]==b'HIAVRFR1',(rc,output.raw.hex())
        result=dict(status=q.get(output,8),known=q.get(output,16),consumed=q.get(output,24),
                    pending=q.get(output,32),carrier_status=q.get(output,40),
                    carrier_child=q.get(output,48),carrier_retained=q.get(output,56),
                    carrier_final=q.get(output,64))
        assert output.raw[72:]==bytes(56)
        assert all(result[key] in (0,1) for key in ('known','consumed','pending'))
        return result

def consumed(row,pending=0):
    assert (row['known'],row['consumed'],row['pending'])==(1,1,pending),row
    assert row['status']==(11 if pending else 0),row

def run(path,files,parent):
    rows=[]
    for runtime_first in (False,True):
        target=parent/('runtime-first'if runtime_first else'lease-first');target.mkdir(mode=0o700)
        owner=q.Owner(path);owner.initialize();carrier=q.Carrier(owner);finalizer=Finalizer(owner)
        before=set(os.listdir('/proc/self/fd'))
        runtime=q.old.create(carrier,files,target);lease=q.old.lease(carrier,runtime)
        alias=carrier.q(2,lease)['cap']
        wrong=finalizer.call(1,lease)
        assert wrong['known']==1 and wrong['consumed']==0 and wrong['carrier_status']==3
        carrier.q(6,lease)
        wrong=finalizer.call(2,lease,nonce=finalizer.nonce^1)
        assert wrong['known']==wrong['consumed']==0
        carrier.call(lease,37)
        consumed(finalizer.call(2,alias))
        stale=finalizer.call(2,alias)
        assert stale['known']==1 and stale['consumed']==0 and stale['carrier_status']==1
        if runtime_first:
            consumed(finalizer.call(1,runtime))
            carrier.call(lease,39)
            consumed(finalizer.call(2,lease))
        else:
            consumed(finalizer.call(2,lease))
            another=q.old.lease(carrier,runtime);carrier.call(another,41)
            consumed(finalizer.call(2,another));consumed(finalizer.call(1,runtime))
        assert all(q.get(carrier.w,at)==0 for at in (16,40,64))
        assert owner.call(3)['status']==0
        assert set(os.listdir('/proc/self/fd'))==before and not list(target.iterdir())
        rows.append(dict(case='runtime-first'if runtime_first else'lease-first',
                         actual_capability_unlink_acknowledged=True,alias_independent=True,
                         wrong_kind_did_not_consume=True,wrong_binding_nonce_refused=True,
                         last_lease_retires_actual_runtime=True,registry_and_fds_empty=True))
    # A filter on this one thread refuses real artifact unlink syscalls. Once it
    # returns and exits, an unfiltered thread retries the registered holder;
    # there is no second DROP of the already-consumed capability.
    target=parent/'pending-retirement';target.mkdir(mode=0o700)
    owner=q.Owner(path);owner.initialize();carrier=q.Carrier(owner);finalizer=Finalizer(owner)
    before=set(os.listdir('/proc/self/fd'));runtime=q.old.create(carrier,files,target)
    results=queue.Queue()
    def retire_with_kernel_refusal():
        try:
            q.deny_syscall(87,5)
            results.put(finalizer.call(1,runtime))
        except BaseException as exc:results.put(exc)
    worker=threading.Thread(target=retire_with_kernel_refusal);worker.start();worker.join(30)
    assert not worker.is_alive()
    failed=results.get_nowait()
    if isinstance(failed,BaseException):raise failed
    consumed(failed,1)
    assert failed['carrier_retained']==1 and q.get(carrier.w,40)!=0
    stale=finalizer.call(1,runtime)
    assert stale['known']==1 and stale['consumed']==0 and stale['carrier_status']==1
    retried=[]
    for _ in range(16):
        row=finalizer.call(1,runtime,op=1);retried.append(row)
        assert row['known']==row['consumed']==1,row
        if row['pending']==0:
            consumed(row);break
    else:raise AssertionError(('real retirement did not drain',retried))
    assert all(q.get(carrier.w,at)==0 for at in (16,40,64))
    assert owner.call(3)['status']==0
    assert set(os.listdir('/proc/self/fd'))==before and not list(target.iterdir())
    rows.append(dict(case='actual-kernel-unlink-refusal-and-retry',first=failed,retries=retried,
                     capability_consumed_once=True,actual_retained_holder_retired=True,
                     registry_and_fds_empty=True))
    return dict(actual_native_finalizer=True,source_bound_callback=True,
                supplied_callback_in_request=False,classes_and_value_gc_binding_pending=True,cases=rows)

def main():
    ap=argparse.ArgumentParser()
    for name in ('owner','normalizer','proof','builder','output'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    files=[]
    for name in ('normalizer','proof','builder'):
        raw=getattr(a,name).read_bytes();files.append((q.old.sealed(raw),raw))
    try:
        report=run(a.owner,files,a.output)
        (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=True,cases=len(report['cases']))))
    finally:
        for fd,_ in files:os.close(fd)
if __name__=='__main__':main()
