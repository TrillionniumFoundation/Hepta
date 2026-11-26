"""Actual managed edges and per-entry deferred release in the one Value arena.

A fixed native enclosing owner supplies real Runtime/Lease carriers and its
finalizer. The oracle calls that captured entry; it never edits binding slots,
object headers, capability nodes, lock words, or cleanup receipts.
"""
from pathlib import Path
import argparse, concurrent.futures, ctypes as C, hashlib, json, os, platform
import queue, struct, sys, threading

ZERO=(0,0,0)
BAD=0xfffffffd

def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def triple(raw,at=24):return struct.unpack_from('<3Q',raw,at)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def frame(op,a=ZERO,b=ZERO,c=ZERO,arg0=0,arg1=0,tail=b'',deferred=False):
    magic=b'HIABVQ01' if op<=24 else b'HIABVQ02' if op<=31 else b'HIABVQ03' if op<=39 else b'HIABVQ04' if op<=47 else b'HIABVQ05'
    if deferred:magic=b'HIABVQ06'
    return struct.pack('<8s15Q',magic,op,0,*a,*b,*c,len(tail),arg0,arg1,0)+tail

class Captured:
    def __init__(self,owner):
        self.owner=owner
        assert word(owner.context,48)==C.addressof(owner.context)+512
        assert word(owner.context,56)==256
        signature=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
        self.entry=signature(word(owner.context,40))
        self.context=(C.c_char*256).from_buffer(owner.context,512)
        self.calls=0

    def call(self,raw,on=16384):
        source=C.create_string_buffer(raw)
        output=C.create_string_buffer(b'\xa5'*(on+64))
        rc=self.entry(source,len(raw),output,on,self.context,256)
        self.calls+=1
        assert source.raw==raw+b'\0'
        assert output.raw[on:]==b'\xa5'*64+b'\0'
        return rc,output.raw[:on]

    def raw(self,op,want=0,**kw):
        rc,out=self.call(frame(op,**kw))
        expected=b'HIABVR02' if op in(29,30,31,77,78,79,92,93) else b'HIABVR01'
        assert rc==0 and out[:8]==expected,(op,rc,out[:128].hex())
        assert word(out,8)==want,(op,word(out,8),want,out[:128].hex())
        return out

    def managed_count(self):
        arena=word(self.context,16)
        return C.c_uint64.from_address(arena+1072).value if arena else 0

def release_facts(reply,pending=0,consumed=1):
    assert tuple(word(reply,at)for at in(80,88,96))==(pending,1,consumed),reply[:128].hex()

def deferred_facts(reply,pending=0,consumed=1):
    release_facts(reply,pending,consumed)
    assert tuple(word(reply,at)for at in(104,112,120))==(0,pending,1),reply[:128].hex()

def private_drop(p,v,cap,pending=0):
    reply=p.raw(78,a=cap);deferred_facts(reply,pending)
    v.held.remove(cap)

def base_setup(path,files,parent):
    owner,c,v=resources.setup(path)
    before=set(os.listdir('/proc/self/fd'))
    raw=q.old.create(c,files,parent)
    runtime=resources.capture(owner,v,1,raw)
    return owner,c,v,Captured(owner),before,raw,runtime

def adoption_case(path,files,parent):
    owner,c,v,p,before,raw,runtime=base_setup(path,files,parent)
    rawlease=q.old.lease(c,raw);lease=resources.capture(owner,v,2,rawlease,runtime)
    child=v.scalar('an actual managed child')
    assert p.managed_count()==0
    for _ in range(2):
        release_facts(p.raw(77,a=runtime,b=child))
        assert p.managed_count()==1
    release_facts(p.raw(77,a=lease,b=child,want=6),consumed=0)
    release_facts(p.raw(79,a=lease,b=child,want=6),consumed=0)
    assert v.python(child)=='an actual managed child'
    alias=v.keep(p.raw(91,a=child));deferred_facts(p.raw(78,a=alias))
    v.held.remove(alias)
    release_facts(p.raw(79,a=runtime,b=child))
    assert p.managed_count()==0
    release_facts(p.raw(79,a=runtime,b=child,want=6),consumed=0)
    release_facts(p.raw(77,a=runtime,b=runtime,want=2),consumed=0)
    release_facts(p.raw(77,a=child,b=runtime,want=2),consumed=0)
    release_facts(p.raw(77,a=runtime,b=(1,1,1),want=1),consumed=0)
    release_facts(p.raw(77,a=runtime,b=child))
    private_drop(p,v,child)
    assert p.managed_count()==0
    p.raw(7,a=child,want=1,deferred=True)
    c.q(3,rawlease);c.q(3,raw)
    v.drop(lease);v.drop(runtime)
    return dict(case='native-managed-edge-adopt-restore-consume',
                real_native_resources=True,idempotent_adoption=True,actual_child_edges=True,
                wrong_owner_and_stale_cap_refused=True,
                **resources.finish(owner,c,v,parent,before))

def weak_case(path,files,parent):
    owner,c,v,p,before,raw,runtime=base_setup(path,files,parent)
    weak_reply=p.raw(80,a=runtime)
    weak=triple(weak_reply)
    assert word(weak_reply,16)==8 and word(weak_reply,48)==1
    alias=v.keep(p.raw(80,a=weak,arg0=1))
    assert v.same(alias,runtime)
    p.raw(80,a=(weak[0],weak[1]^1,weak[2]),arg0=1,want=3)
    p.raw(80,a=(weak[0]+128,weak[1],weak[2]),arg0=1,want=3)
    c.q(3,raw);v.drop(runtime)
    alias2=v.keep(p.raw(80,a=weak,arg0=1));assert v.same(alias,alias2)
    v.drop(alias);v.drop(alias2)
    p.raw(80,a=weak,arg0=1,want=3)
    return dict(case='native-weak-resource-identity-and-real-promotions',
                actual_random_tags=True,live_identity_preserved=True,dead_identity_not_revived=True,
                **resources.finish(owner,c,v,parent,before))

def query_case(path,files,parent):
    owner,c,v,p,before,raw,runtime=base_setup(path,files,parent)
    text=v.scalar('x'*64000+'\ud800')
    key=v.scalar('item');value=v.scalar(123);mapping=v.dictionary([])
    cls=v.cls('ActualDeferredClass',[],namespace=v.dictionary([('answer',123)]))
    obj=v.instance(cls)
    name=v.scalar('answer')
    rows=[]
    def run(op,**kw):
        result=p.raw(op,deferred=True,**kw);rows.append(op);return result
    assert word(run(7,a=text),16)==4
    assert word(run(8,a=text,b=text),48)==1
    length=64001
    assert word(run(17,a=text),48)==length
    data='x'*64000+'\ud800';encoded=data.encode('utf-8','surrogatepass')
    rc,out=p.call(frame(19,a=text,arg1=len(encoded),deferred=True),on=8192+len(encoded)+64)
    assert rc==0 and word(out,8)==0 and out[8192:8192+len(encoded)]==encoded
    rows.append(19)
    created=v.keep(run(2,arg0=4,tail=encoded));assert v.python(created)==data
    empty=v.keep(run(4));run(10,a=empty,b=key,c=value)
    fetched=v.keep(run(9,a=empty,b=key));assert v.python(fetched)==123
    token=triple(run(21));assert token[0]
    deferred_facts(p.raw(92,a=token))
    v.keep(run(32,arg0=6))
    actual_type=v.keep(run(36,a=obj));assert v.same(actual_type,cls)
    assert word(run(37,a=obj,b=cls),48)==1
    cname=v.keep(run(38,a=cls));assert v.python(cname)=='ActualDeferredClass'
    attr=v.keep(run(39,a=obj,b=name));assert v.python(attr)==123
    inherited=run(26,a=obj)
    for i in range(3):v.keep(inherited,8224+i*24)
    stored=run(49,a=runtime,arg0=1)
    assert word(stored,16)==1 and triple(stored)!=ZERO
    q.old.release_detached(c.q(4,triple(stored),q.old.public_request(10),child=0))
    # The private profile only changes the single call's release phase.
    assert word(p.context,120)==0 and word(p.context,160)==0
    for cap in list(v.held):
        if cap!=runtime:private_drop(p,v,cap)
    c.q(3,raw);v.drop(runtime)
    return dict(case='native-variable-payload-query-profile-preserves-all-original-operations',
                tested_operations=sorted(rows),payload_bytes=len(encoded),
                per_entry_only=True,immutable_request_and_output_guards=True,
                **resources.finish(owner,c,v,parent,before))

def pending_case(path,files,parent):
    owner,c,v,p,before,raw,runtime=base_setup(path,files,parent)
    text=v.scalar('pending cleanup remains owned')
    key=v.scalar('key');value=v.scalar(17);dictionary=v.dictionary([])
    klass=v.builtin(6);weak=triple(p.raw(80,a=runtime))
    c.q(3,raw);result=queue.Queue()
    def denied():
        try:
            q.deny_syscall(87,5)
            reply=v.raw(29,a=runtime,want=11)
            release_facts(reply,pending=1);v.held.remove(runtime)
            result.put(dict(status=word(reply,8),pending=1,known=1,consumed=1))
        except BaseException as exc:result.put(exc)
    worker=threading.Thread(target=denied);worker.start();worker.join(60)
    assert not worker.is_alive()
    failed=result.get_nowait()
    if isinstance(failed,BaseException):raise failed
    assert word(p.context,176)!=0 and list(parent.iterdir())
    initial_queue=word(p.context,176)
    checks=[]
    def unchanged():
        assert word(p.context,176)==initial_queue
        assert list(parent.iterdir())
    def run(op,**kw):
        out=p.raw(op,deferred=True,**kw);unchanged();checks.append(op);return out
    assert word(run(7,a=text),16)==4
    assert word(run(8,a=text,b=text),48)==1
    assert word(run(17,a=text),48)==len(b'pending cleanup remains owned')
    assert run(19,a=text,arg1=29)[8192:8221]==b'pending cleanup remains owned'
    new=v.keep(run(2,arg0=4,tail=b'new'))
    empty=v.keep(run(4));run(10,a=empty,b=key,c=value)
    v.keep(run(9,a=empty,b=key))
    typ=v.keep(run(36,a=text));assert word(run(37,a=text,b=klass),48)==1
    v.keep(run(38,a=typ))
    v.keep(run(32,arg0=6))
    token=triple(run(21))
    out=p.raw(92,a=token);deferred_facts(out,pending=1);unchanged()
    out=p.raw(93);deferred_facts(out,pending=1,consumed=0);unchanged()
    out=p.raw(91,a=text);deferred_facts(out,pending=1)
    assert word(out,16)==4 and word(out,48)==len(b'pending cleanup remains owned')
    alias=v.keep(out);unchanged()
    p.raw(80,a=weak,arg0=1,want=6);unchanged()
    for cap in list(v.held):private_drop(p,v,cap,pending=1);unchanged()
    assert not v.held
    # Exactly one ordinary, outside-lock drain retries the actual native unlink.
    p.raw(56)
    assert word(p.context,176)==0 and not list(parent.iterdir())
    p.raw(80,a=weak,arg0=1,want=3)
    return dict(case='real-unlink-eio-pending-is-not-drained-by-private-queries-or-token-release',
                initial_failure=failed,tested_operations=checks,
                real_consumed_token_does_not_self_wait=True,retain_cap_delivered_with_pending=True,
                explicit_outside_lock_native_drain=True,
                **resources.finish(owner,c,v,parent,before))

def concurrency_case(path,files,parent):
    owner,c,v,p,before,raw,runtime=base_setup(path,files,parent)
    child=v.scalar('thread-owned managed value')
    release_facts(p.raw(77,a=runtime,b=child))
    gate=threading.Barrier(8)
    def work(index):
        gate.wait(timeout=20)
        for _ in range(48):
            out=p.raw(91,a=child);deferred_facts(out)
            cap=triple(out)
            assert word(p.raw(7,a=cap,deferred=True),16)==4
            deferred_facts(p.raw(78,a=cap))
        return 48
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        calls=sum(pool.map(work,range(8)))
    assert calls==384 and p.managed_count()==1
    private_drop(p,v,child)
    c.q(3,raw);v.drop(runtime)
    return dict(case='actual-eight-thread-managed-retain-drop-contention',threads=8,roundtrips=calls,
                **resources.finish(owner,c,v,parent,before))

def unpublished_failure_case(path,files,parent):
    owner,c,v,p,before,raw,runtime=base_setup(path,files,parent)
    child=v.scalar('original survives refused publication')
    weak=triple(p.raw(80,a=runtime))
    counts=word(p.raw(47),48)
    result=queue.Queue()
    def denied():
        try:
            q.deny_syscall(318,5)
            token=p.raw(21,want=11)
            assert triple(token)==ZERO and token[16:128]==bytes(112)
            retained=p.raw(91,a=child,want=11)
            deferred_facts(retained,consumed=0)
            assert triple(retained)==ZERO
            promoted=p.raw(80,a=weak,arg0=1,want=11)
            assert triple(promoted)==ZERO
            result.put(dict(actual_getrandom_eio=True,ordinary_token_not_published=True,
                            retained_known_unconsumed=True,weak_promotion_not_published=True))
        except BaseException as exc:result.put(exc)
    worker=threading.Thread(target=denied);worker.start();worker.join(60)
    assert not worker.is_alive()
    failure=result.get_nowait()
    if isinstance(failure,BaseException):raise failure
    assert word(p.raw(47),48)==counts
    assert v.python(child)=='original survives refused publication'
    token=triple(p.raw(21));deferred_facts(p.raw(92,a=token))
    retained=v.keep(p.raw(91,a=child));private_drop(p,v,retained)
    private_drop(p,v,child);c.q(3,raw);v.drop(runtime)
    return dict(case='actual-kernel-refusal-before-capability-publication',
                **failure,**resources.finish(owner,c,v,parent,before))

def controls_case(path,files,parent):
    owner,c,v,p,before,raw,runtime=base_setup(path,files,parent)
    child=v.scalar('ordinary');token=triple(p.raw(21,deferred=True))
    p.raw(78,a=token,want=1);p.raw(92,a=child,want=1)
    p.raw(91,a=token,want=1)
    controls=[]
    for op in (0,1,3,5,6,11,12,20,22,23,25,27,29,30,31,33,34,35,40,45,48,50,52,56,61,70,77,78,79,80,91,92,93):
        controls.append(frame(op,deferred=True))
    for op in (77,78,79,80,91,92,93):
        for at in (16,96,112,120):
            invalid=bytearray(frame(op))
            struct.pack_into('<Q',invalid,at,1);controls.append(bytes(invalid))
    for wire in controls:
        prior=p.context.raw
        rc,out=p.call(wire)
        expected=bytearray(b'\xa5'*len(out));struct.pack_into('<Q',expected,128,0)
        assert rc==BAD and out==expected,(wire[:128].hex(),rc,out[:128].hex())
        assert p.context.raw==prior
    deferred_facts(p.raw(92,a=token))
    private_drop(p,v,child);c.q(3,raw);v.drop(runtime)
    return dict(case='private-deferred-wire-and-real-token-type-controls',
                controls=len(controls),no_mutation_on_invalid_frames=True,
                **resources.finish(owner,c,v,parent,before))

def main():
    ap=argparse.ArgumentParser()
    for name in('root','owner','value','normalizer','proof','builder','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    args=ap.parse_args();assert platform.python_version()=='3.14.4'
    args.output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(args.root))
    global q,resources
    from tools import qualify_hia_generation_lease_owner as q
    from tools import qualify_hia_generation_lease_owner_resources as resources
    source=Path(__file__).read_bytes()
    files=[];rows=[]
    try:
        for name in('normalizer','proof','builder'):
            raw=getattr(args,name).read_bytes();files.append((q.old.sealed(raw),raw))
        cases=[('adopt',adoption_case),('weak',weak_case),('queries',query_case),
               ('pending',pending_case),('concurrent',concurrency_case),
               ('publication-faults',unpublished_failure_case),('controls',controls_case)]
        for name,fn in cases:
            parent=args.output/name;parent.mkdir(mode=0o700)
            row=fn(args.owner,files,parent);rows.append(row)
            (args.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
            print('MANAGED_VALUE_CASE',name,flush=True)
        assert Path(__file__).read_bytes()==source
        report=dict(schema='hia.native-value-managed-edges.component.v1',passed=True,
                    owner=pin(args.owner.read_bytes()),value=pin(args.value.read_bytes()),
                    qualifier=pin(source),cases=rows,
                    actual_native_managed_edges=True,per_entry_deferred_release=True,
                    future_resource_cycles_qualified=False,native_callable_qualified=False,
                    whole_public_runtime_qualified=False)
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=True,groups=len(rows))),flush=True)
    finally:
        for fd,_ in files:os.close(fd)

if __name__=='__main__':main()
