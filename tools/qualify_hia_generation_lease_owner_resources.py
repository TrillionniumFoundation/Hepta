"""Real carrier resources shared by the enclosing owner and native Future.

Only existing public/native capability operations create, retain and release
objects. The oracle neither writes arena nodes nor substitutes a finalizer.
"""
from pathlib import Path
import argparse, concurrent.futures, ctypes as C, hashlib, json, mmap, os, queue, struct, threading
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_result_value_resources import Values, frame
from tools.qualify_hia_future_retirement import Public, facts
from tools.qualify_hia_multiversion_components import Image
from tools.qualify_hia_future_value_kinds import PUBLIC, identity

ZERO=(0,0,0)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def clean_row(row):return {k:v for k,v in row.items()if k!='result'}

def setup(path):
    owner=q.Owner(path);owner.initialize()
    assert q.get(owner.context,680)==6
    return owner,q.Carrier(owner),Values(q.ValueTransport(owner))

def capture(owner,v,kind,carrier,env=ZERO,want=0):
    request=b'HIAGLOB1'+struct.pack('<7Q',kind,*carrier,*env)
    row=owner.call(7,request)
    assert row['status']==want,clean_row(row)
    if want:return row
    assert row['kind']==4 and row['child_rc']==0
    reply=row['result']
    assert reply[:8]==b'HIABVR01'and q.get(reply,8)==0
    assert tuple(q.get(reply,x)for x in(80,88,96))==(0,1,1)
    return v.keep(reply)

def finish(owner,carrier,v,parent,before):
    assert not v.held,v.held
    assert q.get(v.raw(47),48)==0
    result=owner.call(3)
    assert result['status']==0 and result['state']==3,clean_row(result)
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
    assert all(q.get(carrier.w,at)==0 for at in(16,40,64))
    assert not list(parent.iterdir()),list(parent.iterdir())
    assert set(os.listdir('/proc/self/fd'))==before
    return dict(registry_empty=True,arena_and_scratch_retired=True,artifact_parent_empty=True,fd_set_unchanged=True)

def resource_case(path,files,parent,runtime_first):
    owner,c,v=setup(path);before=set(os.listdir('/proc/self/fd'))
    raw_runtime=q.old.create(c,files,parent);raw_lease=q.old.lease(c,raw_runtime)
    runtime=capture(owner,v,1,raw_runtime)
    lease=capture(owner,v,2,raw_lease,runtime)
    runtime_type=v.builtin(20);lease_type=v.builtin(31)
    assert v.isinst(runtime,runtime_type)and v.isinst(lease,lease_type)
    assert not v.isinst(runtime,lease_type)and not v.isinst(lease,runtime_type)
    rt=v.keep(v.raw(36,a=runtime));lt=v.keep(v.raw(36,a=lease))
    assert v.same(rt,runtime_type)and v.same(lt,lease_type)
    kind,parts=v.inherited_parts(lease)
    assert v.same(parts[0],runtime)
    for cap in [runtime_type,lease_type,rt,lt]+parts:v.drop(cap)
    c.q(3,raw_lease);c.q(3,raw_runtime)
    assert owner.call(3)['status']==2
    if runtime_first:
        original=identity(v,runtime);v.drop(runtime)
        _,parts=v.inherited_parts(lease)
        assert identity(v,parts[0])==original
        for item in parts:v.drop(item)
        v.drop(lease)
    else:
        v.drop(lease)
        assert q.get(v.raw(7,a=runtime),16)==8
        v.drop(runtime)
    result=finish(owner,c,v,parent,before)
    return dict(case='runtime-value-first'if runtime_first else'lease-value-first',
                actual_canonical_classes=(20,31),lease_holds_actual_runtime_value=True,
                independent_carrier_and_value_capabilities=True,**result)

def binding_cases(path,files,parent):
    owner,c,v=setup(path);before=set(os.listdir('/proc/self/fd'))
    first=parent/'first';other=parent/'other';first.mkdir();other.mkdir()
    r1=q.old.create(c,files,first);l1=q.old.lease(c,r1)
    r2=q.old.create(c,files,other)
    a=capture(owner,v,1,r1);b=capture(owner,v,1,r2);none=v.scalar(None)
    counts=tuple(q.get(c.w,at)for at in(16,40,64))
    invalid=[]
    for label,kind,raw,env in (
        ('lease-cannot-bind-different-real-runtime',2,l1,b),
        ('lease-requires-resource-not-none',2,l1,none),
        ('runtime-kind-cannot-wrap-lease',1,l1,ZERO),
        ('lease-kind-cannot-wrap-runtime',2,r1,a),
        ('forged-carrier',1,(1,1,1),ZERO),
        ('value-domain-not-native-carrier-domain',1,a,ZERO)):
        capture(owner,v,kind,raw,env,want=1)
        assert tuple(q.get(c.w,at)for at in(16,40,64))==counts,label
        assert q.get(owner.context,1024)==0,label
        invalid.append(label)
    source=q.envelope(7,b'HIAGLOB1'+struct.pack('<7Q',1,*r1,*ZERO))
    readfd,writefd=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(readfd);row=owner.call(7,source[64:]);os.write(writefd,json.dumps(clean_row(row)).encode());os._exit(0)
        except BaseException:os._exit(73)
    os.close(writefd);raw=os.read(readfd,4096);os.close(readfd)
    _,status=os.waitpid(pid,0)
    assert os.waitstatus_to_exitcode(status)==0
    fork=json.loads(raw);assert fork['status']==3
    # Private custody and Info identities cannot be supplied through public Value transport.
    controls=[]
    with mmap.mmap(-1,q.OUT)as output:
        for op in(48,49,52,53,54,55,56,58,59,60,61):
            wire=bytearray(frame(51));struct.pack_into('<Q',wire,8,op)
            data=q.envelope(4,bytes(wire));src=C.create_string_buffer(data)
            output[:128]=b'\xa5'*128;ctx=bytes(owner.context)
            rc=owner.entry(src,len(data),q.address(output),q.OUT,owner.context,q.CONTEXT_BYTES)
            assert rc==q.BAD and output[:128]==b'\xa5'*128 and bytes(owner.context)==ctx,op
            controls.append(op)
    c.q(3,l1);c.q(3,r1);c.q(3,r2)
    for cap in list(v.held):v.drop(cap)
    assert not list(first.iterdir())and not list(other.iterdir())
    first.rmdir();other.rmdir()
    return dict(case='actual-parent-and-private-authority-validation',refusals=invalid,
                private_operations_refused=controls,fork=fork,**finish(owner,c,v,parent,before))

def concurrent_last_refs(path,files,parent):
    owner,c,v=setup(path);before=set(os.listdir('/proc/self/fd'))
    raw_runtime=q.old.create(c,files,parent);raw_lease=q.old.lease(c,raw_runtime)
    runtime=capture(owner,v,1,raw_runtime);lease=capture(owner,v,2,raw_lease,runtime)
    aliases=[v.keep(v.raw(5,a=lease))for _ in range(8)]
    c.q(3,raw_lease);c.q(3,raw_runtime);v.drop(runtime);v.drop(lease)
    start=threading.Barrier(len(aliases))
    def drop(cap):
        start.wait(timeout=20)
        return v.raw(29,a=cap)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        replies=list(pool.map(drop,aliases))
    for cap,reply in zip(aliases,replies):
        assert tuple(q.get(reply,at)for at in(80,88,96))==(0,1,1)
        v.held.remove(cap)
    return dict(case='real-eight-thread-last-value-reference-contention',threads=8,
                consumed_exactly_once=True,**finish(owner,c,v,parent,before))

def pending_case(path,files,parent,lease_pending=False):
    owner,c,v=setup(path);before=set(os.listdir('/proc/self/fd'))
    raw_runtime=q.old.create(c,files,parent)
    runtime=capture(owner,v,1,raw_runtime)
    target=runtime
    if lease_pending:
        raw_lease=q.old.lease(c,raw_runtime)
        target=capture(owner,v,2,raw_lease,runtime)
        c.q(4,raw_runtime,q.old.public_request(8),child=0)
        c.q(3,raw_lease)
        v.drop(runtime)
    c.q(3,raw_runtime)
    result=queue.Queue()
    def blocked_cleanup():
        try:
            q.deny_syscall(87,5)
            reply=v.raw(29,a=target,want=11)
            assert tuple(q.get(reply,at)for at in(80,88,96))==(1,1,1),reply[:128].hex()
            v.held.remove(target)
            # Repeating actual cleanup under the same real kernel denial must
            # preserve the queue and never claim the enclosing context closed.
            refused=owner.call(3)
            assert refused['status']==5 and refused['state']==1,clean_row(refused)
            assert q.get(owner.context,688)!=0 and q.get(c.w,40)!=0
            result.put(dict(drop_status=q.get(reply,8),known=1,consumed=1,pending=1,
                            refused=clean_row(refused)))
        except BaseException as exc:result.put(exc)
    thread=threading.Thread(target=blocked_cleanup);thread.start();thread.join(60)
    assert not thread.is_alive()
    failed=result.get_nowait()
    if isinstance(failed,BaseException):raise failed
    assert not v.held
    # One public native destroy enters Value56 -> real finalizer retry -> fence
    # -> registry retirement -> anchor ACK. There is no host polling loop.
    closed=owner.call(3)
    assert closed['status']==0 and closed['state']==3,clean_row(closed)
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
    assert not list(parent.iterdir())and set(os.listdir('/proc/self/fd'))==before
    return dict(case='lease-resource-pending-native-retry'if lease_pending else'runtime-resource-pending-native-retry',
                actual_unlink_eio=True,initial=failed,owner_native_retry_closed=True,
                consumed_once=True,queue_and_carrier_custody_preserved=True,registry_and_fds_empty=True)

def build_future(compiler,value_path,out):
    from tools.generate_hia_background_optimizer_future_public_cleanup_packer import reference_flat
    names=PUBLIC+('background_optimizer_future_public_cleanup',
                  'background_optimizer_future_public_observers_notify',
                  'background_optimizer_future_public_observers_notify_packer',
                  'background_optimizer_future_public_cleanup_packer',
                  'background_optimizer_future_public_truth',
                  'background_optimizer_future_public_truth_packer')
    captured={name:(q.ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()for name in names}
    flats={};rows=[]
    for name,raw in captured.items():
        flat=q.old.compiler_run(compiler,raw,name);flats[name]=flat
        (out/(name+'.flat')).write_bytes(flat)
        rows.append(dict(path='examples/hia_bootstrap/'+name+'.hepta',source=pin(raw),flat=pin(flat),double_compile=True))
    notify_body=flats['background_optimizer_future_public_observers_notify']
    notify_wire=b'HIABFNPK'+struct.pack('<3Q',len(notify_body),0,0)+notify_body
    notify_image=Image(out/'background_optimizer_future_public_observers_notify_packer.flat')
    src=C.create_string_buffer(notify_wire);ob=C.create_string_buffer(16<<20);work=C.create_string_buffer(16<<20)
    rc=notify_image.entry(src,len(notify_wire),ob,len(ob),work,len(work))
    assert rc==0 and 0<q.get(work,0)<len(ob)
    notify=ob.raw[:q.get(work,0)]
    value=value_path.read_bytes()
    from tools.generate_hia_background_optimizer_future_public_truth_packer import reference_flat as cleanup_reference
    cleanup_parts=[flats['background_optimizer_future_public_cleanup'],flats['background_optimizer_future_public_truth']]
    cleanup_wire=b'HIABFTPK'+struct.pack('<3Q',2,*map(len,cleanup_parts))+b''.join(cleanup_parts)
    cleanup=q.old.run_packer(flats['background_optimizer_future_public_truth_packer'],cleanup_wire)
    assert cleanup==cleanup_reference(cleanup_parts) and len(cleanup)<=4194304
    (out/'future-cleanup-truth.flat').write_bytes(cleanup)
    pieces=[flats[name]for name in PUBLIC]+[value,notify,cleanup]
    wire=b'HIABFPP3'+struct.pack('<11Q',9,*map(len,pieces),1)+b''.join(pieces)
    native=q.old.run_packer(flats['background_optimizer_future_public_cleanup_packer'],wire)
    assert native==reference_flat(pieces)
    path=out/'hia-future-owner-resource-coupled.core.bin';path.write_bytes(native)
    assert all((q.ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()==raw for name,raw in captured.items())
    record=dict(modules=rows,value_pin=pin(value),future_pin=pin(native),native_pack=True,
                independent_reference_comparison=True,same_value_implementation=True,
                public_cleanup_capsule=dict(protocol='HIABFTPK',roles=['cleanup','truth'],
                    packer='background_optimizer_future_public_truth_packer',product=pin(cleanup),
                    native_pack=True,independent_byte_comparison=True))
    (out/'future-build.json').write_text(json.dumps(record,indent=2)+'\n')
    return path,record

def future_case(path,future_path,files,parent,lease_first):
    owner,c,v=setup(path);before=set(os.listdir('/proc/self/fd'))
    raw_runtime=q.old.create(c,files,parent);raw_lease=q.old.lease(c,raw_runtime)
    runtime=capture(owner,v,1,raw_runtime);lease=capture(owner,v,2,raw_lease,runtime)
    original_runtime=identity(v,runtime);original_lease=identity(v,lease)
    token=struct.unpack_from('<3Q',v.raw(21),24)
    p=Public(v,Image(future_path));factory=p.factory()
    runtime_future=p.make(factory);lease_future=p.make(factory)
    p.call(22,*runtime_future,value=runtime,kind=1)
    p.call(22,*lease_future,value=lease,kind=1)
    c.q(3,raw_lease);c.q(3,raw_runtime);v.drop(runtime);v.drop(lease)
    assert owner.call(3)['status']==2
    from_runtime=v.keep(p.call(10,*runtime_future),72)
    from_lease=v.keep(p.call(10,*lease_future),72)
    assert identity(v,from_runtime)==original_runtime and identity(v,from_lease)==original_lease
    _,parts=v.inherited_parts(from_lease)
    assert identity(v,parts[0])==original_runtime
    for cap in parts+[from_runtime,from_lease]:v.drop(cap)
    ordered=(lease_future,runtime_future)if lease_first else(runtime_future,lease_future)
    facts(p.typed(26,*ordered[0]),1)
    survivor=v.keep(p.call(10,*ordered[1]),72)
    expected=original_runtime if lease_first else original_lease
    assert identity(v,survivor)==expected
    v.drop(survivor);facts(p.typed(26,*ordered[1]),1)
    facts(p.typed(27,*factory),1);facts(p.typed(29),1)
    assert q.get(p.ctx,200)==q.get(p.ctx,224)==0
    assert owner.call(3)['status']==2,'actual external Value context token must still block destroy'
    v.raw(22,a=token)
    result=finish(owner,c,v,parent,before)
    return dict(case='future-lease-first'if lease_first else'future-runtime-first',
                single_actual_value_arena=True,actual_value_context_token=True,
                identical_runtime_and_lease_objects=True,final_drop_retired_native_carriers=True,**result)

def main():
    ap=argparse.ArgumentParser()
    for name in('owner','compiler','value','normalizer','proof','builder','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--skip-future',action='store_true')
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    owner_build=json.loads((a.owner.parent/'build.json').read_bytes())
    assert pin(a.owner.read_bytes())==owner_build['build']['products']['hia-generation-lease-owner.so']
    assert pin(a.value.read_bytes())==owner_build['build']['products']['hia-generation-lease-values.core.bin']
    files=[];rows=[]
    for name in('normalizer','proof','builder'):
        raw=getattr(a,name).read_bytes();files.append((q.old.sealed(raw),raw))
    try:
        cases=[('lease-first',lambda p:resource_case(a.owner,files,p,False)),
               ('runtime-first',lambda p:resource_case(a.owner,files,p,True)),
               ('binding',lambda p:binding_cases(a.owner,files,p)),
               ('concurrent',lambda p:concurrent_last_refs(a.owner,files,p)),
               ('pending-runtime',lambda p:pending_case(a.owner,files,p,False)),
               ('pending-lease',lambda p:pending_case(a.owner,files,p,True))]
        for name,fn in cases:
            p=a.output/name;p.mkdir(mode=0o700);row=fn(p);rows.append(row)
            (a.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
            print('OWNER_RESOURCE_CASE',name,flush=True)
        future_build=None
        if not a.skip_future:
            build=a.output/'future-build';build.mkdir()
            future_path,future_build=build_future(a.compiler,a.value,build)
            for name,lease_first in(('future-runtime-first',False),('future-lease-first',True)):
                p=a.output/name;p.mkdir(mode=0o700);row=future_case(a.owner,future_path,files,p,lease_first);rows.append(row)
                (a.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
                print('OWNER_RESOURCE_CASE',name,flush=True)
        report=dict(schema='hepta.hia.generation-lease-resource-coupling.v1',passed=True,
                    owner=pin(a.owner.read_bytes()),value=pin(a.value.read_bytes()),cases=rows,
                    future_build=future_build,resource_finalizer_integration_qualified=True,
                    shared_future_arena_qualified=future_build is not None,
                    whole_public_runtime_qualified=False,constructor_qualified=False,
                    generation_info_qualified=False,pending_typed_lock_qualified=False)
        (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=True,cases=len(rows),whole_public_runtime_qualified=False)),flush=True)
    finally:
        for fd,_ in files:os.close(fd)
if __name__=='__main__':main()
