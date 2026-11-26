"""Trusted native provider capture, refusal, retry and owner retirement gates."""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,errno,json,os,queue,struct,threading
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools import qualify_hia_generation_lease_owner_provider as prior
from tools import generate_hia_generation_lease_owner_bound_packer as spec
from tools import generate_hia_generation_lease_owner_provider_packer as provider_spec
from tools import generate_hia_multiversion_background_payload_packer as payload_spec

def clean(row):return {k:v for k,v in row.items()if k!='result'}
def pin(path):return resources.pin(Path(path).read_bytes())
def fixed_target(entry,hole):
    return entry+hole+4+struct.unpack('<i',C.string_at(entry+hole,4))[0]

class Provider(prior.Provider):
    def __init__(self,owner):
        self.owner=owner;self.context=(C.c_char*768).from_buffer(owner.context,1280)
        base=C.addressof(owner.context);entry=C.cast(owner.entry,C.c_void_p).value
        actual=fixed_target(entry,spec.OWNER_HOLES['provider_address'])
        assert actual==q.get(self.context,56)
        assert fixed_target(entry,spec.OWNER_HOLES['provider_call'])==actual
        assert q.get(self.context,0)==int.from_bytes(b'HIAGPCX1','little')
        assert q.get(self.context,8)==os.getpid() and q.get(self.context,16)==1
        expected={40:base,48:base+1280,56:actual,64:base+256,72:256,
                  80:q.get(owner.context,40),88:base+512,96:256,
                  104:actual+provider_spec.PAYLOAD_OFFSET,112:base+1792,120:256,
                  128:q.get(owner.context,664)}
        assert all(q.get(self.context,k)==v for k,v in expected.items())
        carrier=q.get(owner.context,32)
        effects=fixed_target(carrier,q.spec.HANDLES_HOLES['effects'])
        for name,target in [('handles',carrier),('effects',effects),('values',q.get(owner.context,40))]:
            assert fixed_target(actual,provider_spec.OUTER_HOLES[name])==target
        self.entry=prior.ENTRY(actual)
        self.rows=[];self.row_lock=threading.Lock()

def deny_fixed_syscall(start,end,number,error):
    assert start<end and start>>32==(end-1)>>32
    class Filter(C.Structure):_fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
    class Program(C.Structure):_fields_=[('length',C.c_ushort),('filters',C.POINTER(Filter))]
    rows=[(0x20,0,0,0),(0x15,0,6,number),(0x20,0,0,12),(0x15,0,4,start>>32),
          (0x20,0,0,8),(0x35,0,2,start&0xffffffff),(0x35,1,0,end&0xffffffff),
          (0x06,0,0,0x00050000|error),(0x06,0,0,0x7fff0000)]
    filters=(Filter*len(rows))(*(Filter(*r)for r in rows));program=Program(len(rows),filters)
    libc=C.CDLL(None,use_errno=True)
    assert libc.prctl(38,1,0,0,0)==0,C.get_errno()
    assert libc.prctl(22,2,C.byref(program),0,0)==0,C.get_errno()

def thread_result(fn):
    results=queue.Queue()
    def work():
        try:results.put((True,fn()))
        except BaseException as error:results.put((False,error))
    thread=threading.Thread(target=work);thread.start();thread.join(90)
    assert not thread.is_alive(),'native operation remained blocked'
    ok,result=results.get_nowait()
    if not ok:raise result
    return result

def behavior(path,token_object,files,out):
    owner,c,v=resources.setup(path);provider=Provider(owner)
    before=set(os.listdir('/proc/self/fd'));parent=out/'runtime';parent.mkdir(mode=0o700)
    checks=[]
    def mark(name,**fields):
        checks.append(dict(name=name,**fields))
        (out/'calls.json').write_text(json.dumps(provider.rows,indent=2)+'\n')
        (out/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
        print('BOUND_PROVIDER_GATE',name,flush=True)
    mark('actual-owner-initializes-fixed-provider-and-shared-payload',same_code=True,same_arena=True,host_prefix_writes=False)
    guards=prior.private_controls(provider);mark('private-frames-spans-copy-and-fork',controls=guards)
    provider.call(prior.control(1));provider.q(3,(1,1,1),want=3)
    provider.call(prior.control(2))
    raw_runtime=q.old.create(c,files,parent);runtime=resources.capture(owner,v,1,raw_runtime)
    raw_lease=q.old.lease(c,raw_runtime);lease=resources.capture(owner,v,2,raw_lease,runtime)
    cls=v.builtin(20);assert v.isinst(runtime,cls);v.drop(cls)
    mark('actual-source-built-runtime-and-real-class')
    captured=provider.q(3,runtime,family=b'HIAMVBQ2');cap=captured['cap']
    assert cap[0] and cap!=raw_runtime and tuple(q.get(captured['header'],x)for x in(72,80,88))==(1,0,0)
    for bad in(lease,raw_runtime,(1,1,1)):provider.q(3,bad,family=b'HIAMVBQ2',want=3)
    plain=v.scalar(None);provider.q(3,plain,family=b'HIAMVBQ2',want=3);v.drop(plain)
    old=provider.q(3,raw_runtime,family=b'HIAMVBQ1');assert old['header'][72:]==bytes(56)
    provider.q(4,old['cap'],family=b'HIAMVBQ1')
    mark('true-runtime-capture-and-old-carrier-domain')
    snap=provider.q(1,cap);assert snap['payload'][:8]==b'HIAMVBS1' and snap['payload'][256:]==b'00'
    start=threading.Barrier(8)
    def alias(_):
        start.wait(timeout=20);copy=provider.q(3,runtime,family=b'HIAMVBQ2');provider.drop(copy['cap'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:list(pool.map(alias,range(8)))
    assert q.get(provider.context,32)==0
    mark('eight-thread-fixed-capture-drop-and-real-snapshot',threads=8)
    imports={n:C.cast(getattr(prior.libc,n),C.c_void_p).value for n in('malloc','free')}
    image=prior.ObjectImage(token_object,imports);token=prior.Token(image)
    published=provider.q(2,cap,token=token.address,gen=b'0',epoch=b'0',raw=q.old.rawdoc(q.old.scalar_program('bit.xor')))
    doc=json.loads(published['payload']);assert q.get(published['header'],64)==1 and doc['generation']['generation']==1
    stale=provider.q(2,cap,want=1,token=token.address,gen=b'0',epoch=b'0',raw=q.old.rawdoc(q.old.scalar_program(None)))
    assert json.loads(stale['payload'])=={'type':'MultiversionRejected','message':'E_HIA_MULTIVERSION: stale generation or selection epoch'}
    cancelled=prior.Token(image);cancelled.q(1)
    no=provider.q(2,cap,want=1,token=cancelled.address,gen=b'1',epoch=b'1',raw=q.old.rawdoc(q.old.scalar_program(None)))
    assert json.loads(no['payload'])=={'type':'MultiversionRejected','message':'E_HIA_MULTIVERSION: publication cancelled before selection'}
    latest=provider.q(1,cap);assert latest['payload'][256:]==b'11'
    mark('actual-publication-stale-and-cancellation')
    c.q(3,raw_lease);c.q(3,raw_runtime);v.drop(lease);v.drop(runtime);assert not v.held
    refused=owner.call(3);assert refused['status']==2 and refused['state']==1,clean(refused)
    assert q.get(provider.context,16)==1 and q.get(owner.context,672)==0
    for result in(snap,published,stale,no,latest):
        assert C.string_at(result['pointer'],len(result['payload']))==result['payload']
        provider.drop_payload(result)
    mark('actual-owner-refuses-live-payload-and-rolls-value-fence-back')
    refused=owner.call(3);assert refused['status']==2 and refused['state']==1,clean(refused)
    assert q.get(provider.context,16)==1 and q.get(owner.context,672)==0
    still=provider.q(1,cap);assert still['payload'][256:]==b'11';provider.drop_payload(still)
    mark('actual-registry-busy-rolls-provider-and-value-fences-back')
    provider.drop(cap);provider.q(4,cap,want=3);assert not list(parent.iterdir())
    provider.call(prior.control(4));provider.q(6);token.q(10);cancelled.q(10)
    closed=owner.call(3);assert closed['status']==0 and closed['state']==3,clean(closed)
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
    assert set(os.listdir('/proc/self/fd'))==before
    mark('owner-retires-actual-provider-payload-value-and-carrier',fd_set_unchanged=True)
    return dict(checks=checks,calls=provider.rows,trusted_enclosing_bootstrap_qualified=True)

def initialization_failure(path,out):
    owner=q.Owner(path);entry=C.cast(owner.entry,C.c_void_p).value
    provider=fixed_target(entry,spec.OWNER_HOLES['provider_address'])
    start=provider+provider_spec.PAYLOAD_OFFSET;end=start+len(payload_spec.BRIDGE)
    before=set(os.listdir('/proc/self/fd'))
    def fail():
        deny_fixed_syscall(start,end,39,errno.EACCES)
        failed=owner.call(0)
        assert failed['status']==5 and failed['state']==11,clean(failed)
        assert q.get(owner.context,1296)==0 and q.get(owner.context,1792)==0
        assert q.get(owner.context,528)!=0 and q.get(owner.context,800)!=0
        assert q.get(owner.context,848)==1
        return clean(failed)
    failed=thread_result(fail)
    owner.initialize();Provider(owner)
    assert owner.call(3)['status']==0
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
    assert set(os.listdir('/proc/self/fd'))==before
    return dict(case='provider-init-actual-getpid-eacces-retains-and-retries',failure=failed,
                actual_kernel_refusal=True,recovered_after_filtered_thread_exit=True)

def commit_failure(path,out):
    owner=q.Owner(path);owner.initialize();provider=Provider(owner)
    start=q.get(provider.context,104);end=start+len(payload_spec.BRIDGE)
    before=set(os.listdir('/proc/self/fd'));arena=q.get(owner.context,528)
    def fail():
        deny_fixed_syscall(start,end,39,errno.EACCES);rows=[]
        for _ in range(2):
            row=owner.call(3);assert row['status']==5 and row['state']==14,clean(row)
            assert q.get(provider.context,16)==5
            assert q.get(owner.context,528)==arena and q.get(owner.context,848)==1
            assert q.get(owner.context,672)==1
            rows.append(clean(row))
        return rows
    failures=thread_result(fail)
    closed=owner.call(3);assert closed['status']==0 and closed['state']==3
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
    assert set(os.listdir('/proc/self/fd'))==before
    return dict(case='provider-commit-actual-getpid-eacces-retries-before-anchor-release',
                failures=failures,actual_kernel_refusal=True,anchor_not_consumed_early=True,
                recovered_after_filtered_thread_exit=True)

def pending_cleanup(path,files,out):
    owner,c,v=resources.setup(path);provider=Provider(owner)
    before=set(os.listdir('/proc/self/fd'));parent=out/'runtime';parent.mkdir(mode=0o700)
    raw=q.old.create(c,files,parent);runtime=resources.capture(owner,v,1,raw)
    cap=provider.q(3,runtime,family=b'HIAMVBQ2')['cap'];c.q(3,raw);v.drop(runtime)
    assert not v.held
    def fail():
        q.deny_syscall(87,errno.EIO)
        result=provider.q(4,cap,want=3)
        assert tuple(q.get(result['header'],x)for x in(72,80,88))==(1,1,1),result['row']
        assert q.get(provider.context,32)!=0
        refused=owner.call(3);assert refused['status']==5 and refused['state']==1,clean(refused)
        assert q.get(provider.context,32)!=0 and q.get(owner.context,672)==0
        return dict(drop=result['row'],owner=clean(refused))
    facts=thread_result(fail)
    closed=owner.call(3);assert closed['status']==0 and closed['state']==3,clean(closed)
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128) and not list(parent.iterdir())
    assert set(os.listdir('/proc/self/fd'))==before
    return dict(case='actual-consumed-carrier-pending-retried-by-owner',failure=facts,
                no_second_drop=True,pending_registry_retained=True,actual_kernel_unlink_eio=True,
                exact_native_cleanup_and_final_retirement=True)

def main():
    parser=argparse.ArgumentParser()
    for name in('owner','token-object','normalizer','proof','builder','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    manifest=json.loads((args.owner.parent/'build.json').read_bytes())
    assert pin(args.owner)==manifest['build']['products']['hia-generation-lease-owner.so']
    token_build=json.loads((args.token_object.parent/'build.json').read_bytes())
    assert pin(args.token_object)==token_build['products']['token']
    files=[]
    for name in('normalizer','proof','builder'):
        raw=getattr(args,name).read_bytes();files.append((q.old.sealed(raw),raw))
    rows={}
    try:
        for name,fn in [('behavior',lambda p:behavior(args.owner,args.token_object.read_bytes(),files,p)),
                        ('init-failure',lambda p:initialization_failure(args.owner,p)),
                        ('commit-failure',lambda p:commit_failure(args.owner,p)),
                        ('pending-cleanup',lambda p:pending_cleanup(args.owner,files,p))]:
            out=args.output/name;out.mkdir();row=fn(out);rows[name]=row
            (args.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n')
            print('BOUND_OWNER_CASE',name,flush=True)
        report=dict(schema='hepta.hia.generation-lease-bound-owner.qualification.v1',
                    passed=True,owner=pin(args.owner),value=manifest['build']['products']['hia-generation-lease-values.core.bin'],
                    cases=rows,trusted_enclosing_provider_initialized=True,same_actual_value_and_carrier=True,
                    native_pending_custody_and_retry=True,raw_owner_workspace_bytes=2048,
                    no_host_context_prefix_writes=True,no_python_callbacks=True,
                    public_constructor_qualified=False,whole_public_runtime_qualified=False)
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=True,cases=len(rows),provider_groups=len(rows['behavior']['checks']))),flush=True)
    finally:
        for fd,_ in files:os.close(fd)
if __name__=='__main__':main()
