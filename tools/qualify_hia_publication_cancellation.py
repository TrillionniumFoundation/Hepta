"""External qualification of the actual closed native cancellation owner.

This program is a development oracle and fault injector, never product glue.
The product is four compiled HIA policies, a fixed mechanical prefix, and the
HIA packer. No test result is supplied as a product success/proof input.
"""
from pathlib import Path
import argparse, ast, concurrent.futures, copy, ctypes, hashlib, json, mmap
import os, struct, subprocess, sys, threading, time

ROOT=Path(__file__).resolve().parents[1]
OUT=(96<<20)+16384
BAD=0xfffffffd
FN=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_size_t,
    ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t)
ROLE_NAMES=('publication_cancellation_public','multiversion_runtime_handles',
    'publication_cancellation_effects','multiversion_future')
Q=int.from_bytes(b'HIAPCQ01','little')
R=int.from_bytes(b'HIAPCR01','little')
SOURCE_REVISION='ecd688626409d1adcf4e04a7a535c1b2c45a13ce'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def address(view):
    return ctypes.addressof(ctypes.c_char.from_buffer(view))

class Image:
    def __init__(self,raw):
        self.raw=raw
        self.mapping=mmap.mmap(-1,len(raw),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
        self.mapping[:]=raw
        self.entry=FN(address(self.mapping))
    def at(self,offset):
        return FN(address(self.mapping)+offset)

class Owner:
    def __init__(self,image):
        self.image=image
        self.context=mmap.mmap(-1,256)
        self.calls=0
        self.call_lock=threading.Lock()
    def call(self,op,cap=(0,0,0),output=None):
        raw=struct.pack('<8Q',Q,op,*cap,0,0,0)
        source=ctypes.create_string_buffer(raw)
        own=output is None
        if own:
            output=mmap.mmap(-1,OUT)
        rc=self.image.entry(source,len(raw),address(output),OUT,address(self.context),256)
        words=struct.unpack_from('<16Q',output)
        assert rc==0,(op,rc,words[:12])
        assert words[0]==R,(op,words[:12])
        assert words[7]<=256
        error=output[128:128+words[7]].decode()
        result={'op':op,'status':words[1],'kind':words[2],'cap':list(words[3:6]),
            'value':words[6],'error':json.loads(error) if error else None,
            'child_status':words[8],'pid':words[9],
            'retained':words[10],'finalizer_status':words[11]}
        with self.call_lock:
            self.calls+=1
        if own:
            output.close()
        return result
    def close_mapping(self):
        self.context.close()

def ok(record,status=0):
    assert record['status']==status,record
    return record

def owned(image):
    owner=Owner(image)
    ok(owner.call(0))
    cap=ok(owner.call(1))['cap']
    return owner,cap

def kernel(image,workspace,op,arg=0,flag=0):
    # QA-only internal role call. Workspace is derived from an actually
    # registered owner, never accepted by the public source ABI.
    source=ctypes.create_string_buffer(struct.pack('<8Q',
        int.from_bytes(b'HIAMVFQ1','little'),op,arg,flag,0,0,0,0))
    with mmap.mmap(-1,512) as output:
        rc=image.at(947)(source,64,address(output),512,workspace,131072)
        words=struct.unpack_from('<9Q',output)
        return {'rc':rc,'status':words[1],'value':words[2],'token':words[4]}

def kernel_workspace(cap):
    # External white-box observer: the actual registry node owns an object;
    # no product input or response grants this internal pointer.
    return struct.unpack('<Q',ctypes.string_at(cap[0]+8,8))[0]+256

def original_cancellation():
    path=ROOT/'hepta/hia_multiversion.py'
    if not path.exists():
        path=ROOT/'reference/hepta/hia_multiversion.py'
    raw=path.read_bytes()
    tree=ast.parse(raw)
    nodes=[n for n in tree.body if getattr(n,'name',None) in
        ('MultiversionRejected','_reject','PublicationCancellation')]
    assert len(nodes)==3
    namespace={'threading':threading}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),namespace)
    return namespace['PublicationCancellation'],{'path':'hepta/hia_multiversion.py',
        'bytes':len(raw),'sha256':sha(raw),'source_revision':SOURCE_REVISION,
        'scope':'unchanged exact class, rejection exception and helper extracted by AST'}

def compile_roles(compiler,directory):
    directory.mkdir(parents=True,exist_ok=True)
    result=[]
    for name in (*ROLE_NAMES,'publication_cancellation_packer'):
        raw=(ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes()
        pair=[]
        for _ in range(2):
            run=subprocess.run([str(compiler),'compile'],input=raw,capture_output=True,timeout=30)
            assert run.returncode==0,(name,run.returncode,run.stderr.decode())
            pair.append(run.stdout)
        assert pair[0]==pair[1],name
        (directory/(name+'.flat')).write_bytes(pair[0])
        result.append({'role':name,'source_bytes':len(raw),'source_sha256':sha(raw),
            'image_bytes':len(pair[0]),'image_sha256':sha(pair[0]),'two_builds_identical':True})
    return result

def pack_image(directory):
    from tools.generate_hia_publication_cancellation_packer import reference_image,BRIDGE,HOLES
    # The readable mechanical prefix is independently assembled only for QA.
    assembler=directory/'prefix.o'
    binary=directory/'prefix.bin'
    subprocess.run(['as','--64',str(ROOT/'tools/hia_publication_cancellation_bridge.S'),
        '-o',str(assembler)],check=True,capture_output=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(assembler),str(binary)],
        check=True,capture_output=True)
    assert binary.read_bytes()==BRIDGE
    reloc=subprocess.run(['readelf','-r',str(assembler)],check=True,capture_output=True,text=True)
    assert 'There are no relocations in this file.' in reloc.stdout
    bodies=[(directory/(name+'.flat')).read_bytes() for name in ROLE_NAMES]
    raw=struct.pack('<8Q',int.from_bytes(b'HIAPCPK1','little'),4,*map(len,bodies),0,0)+b''.join(bodies)
    expected=reference_image(bodies)
    packer=Image((directory/'publication_cancellation_packer.flat').read_bytes())
    def invoke(frame,capacity=None):
        source=ctypes.create_string_buffer(frame)
        with mmap.mmap(-1,len(expected)+64) as output,mmap.mmap(-1,1<<20) as work:
            output[:]=b'\xa5'*len(output)
            capacity=len(expected) if capacity is None else capacity
            n=packer.entry(source,len(frame),address(output),capacity,address(work),len(work))
            return n,bytes(output)
    n,out=invoke(raw)
    assert n==len(expected) and out[:n]==expected and out[n:]==b'\xa5'*64
    (directory/'publication_cancellation.flat').write_bytes(out[:n])
    rejected=[]
    for length in (0,1,8,63,len(raw)-1):
        rejected.append(('truncated-'+str(length),raw[:length],None))
    rejected.append(('trailing',raw+b'\0',None))
    for offset,value in [(0,0),(8,0),(8,3),(8,5),(48,1),(56,1)]:
        changed=bytearray(raw);struct.pack_into('<Q',changed,offset,value)
        rejected.append((f'header-{offset}-{value}',bytes(changed),None))
    for offset in (16,24,32,40):
        for value in (0,4194305,(1<<64)-1):
            changed=bytearray(raw);struct.pack_into('<Q',changed,offset,value)
            rejected.append((f'role-{offset}-{value}',bytes(changed),None))
    rejected.append(('output-short',raw,len(expected)-1))
    for label,frame,capacity in rejected:
        rc,body=invoke(frame,capacity)
        assert rc==BAD and body==b'\xa5'*len(body),(label,rc)
    return Image(expected),{'image_bytes':len(expected),'image_sha256':sha(expected),
        'prefix_bytes':len(BRIDGE),'prefix_sha256':sha(BRIDGE),
        'readable_prefix_exact':True,'dynamic_imports':[],
        'native_packer_equals_independent_reference':True,
        'native_pack_negative_guards':len(rejected),'call_holes':HOLES}

def basic_and_original(image):
    Original,oracle=original_cancellation()
    original=Original();owner,cap=owned(image);records=[]
    sequence=[5,6,7,8,4,5,6,4,5,6,7,8]
    names={4:'cancel',5:'cancelled',6:'committed',7:'__copy__',8:'__deepcopy__'}
    for op in sequence:
        record=owner.call(op,cap)
        try:
            expected=getattr(original,names[op])({}) if op==8 else getattr(original,names[op])()
            ok(record);assert record['kind']==1 and bool(record['value']) is expected,record
        except ValueError as exc:
            ok(record,4)
            assert record['error']=={'class':type(exc).__name__,'message':str(exc)},record
        records.append(record)
    ok(owner.call(9),3)
    cap2=ok(owner.call(2,cap))['cap'];assert cap2!=cap
    ok(owner.call(3,cap));ok(owner.call(5,cap),1)
    assert ok(owner.call(5,cap2))['value']==1
    ok(owner.call(3,cap2));ok(owner.call(3,cap2),1)
    ok(owner.call(10));ok(owner.call(9));ok(owner.call(0),3)
    result={'original_pairs':len(sequence),'actual_calls':owner.calls,
        'comparisons':records,'original_source':oracle}
    owner.close_mapping()
    return result

def capabilities_and_guards(image):
    owner,cap=owned(image);other,foreign=owned(image)
    cases=[(1,1,1),((1<<64)-1,0,0),(cap[0],cap[1]^1,cap[2]),
        (cap[0],cap[1],cap[2]^1),tuple(foreign),(0,0,0)]
    for candidate in cases:
        for op in (2,3,4,5,6,7,8):
            ok(owner.call(op,candidate),1)
    source=ctypes.create_string_buffer(struct.pack('<8Q',Q,5,*cap,0,0,0))
    frame=bytes(source)[:64]
    with mmap.mmap(-1,OUT+64) as output:
        output[:1024]=b'\xa5'*1024;output[OUT:]=b'\x5a'*64
        initial_context=bytes(owner.context)
        base=[ctypes.addressof(source),64,address(output),OUT,address(owner.context),256]
        invalid=[]
        for index,value in ((0,0),(2,0),(4,0),(1,0),(1,63),(1,65),
            (3,OUT-1),(5,255),(0,(1<<64)-32),(2,(1<<64)-32),
            (4,(1<<64)-128),(4,address(owner.context)+1)):
            args=list(base);args[index]=value;invalid.append(args)
        for left,right in ((0,2),(0,4),(2,4),(4,2)):
            args=list(base);args[left]=args[right];invalid.append(args)
        for args in invalid:
            assert image.entry(*args)==BAD,args
            assert output[:1024]==b'\xa5'*1024 and output[OUT:]==b'\x5a'*64
            assert bytes(owner.context)==initial_context
        malformed=[]
        for offset,value in ((0,0),(8,11),(8,(1<<64)-1),(40,1),(48,1),(56,1)):
            raw=bytearray(frame);struct.pack_into('<Q',raw,offset,value);malformed.append(raw)
        for op in (0,1,9,10):
            raw=bytearray(frame);struct.pack_into('<Q',raw,8,op);malformed.append(raw)
        for raw in malformed:
            source2=ctypes.create_string_buffer(bytes(raw))
            assert image.entry(source2,64,address(output),OUT,address(owner.context),256)==BAD
            assert output[:128]==b'\xa5'*128 and output[OUT:]==b'\x5a'*64
            assert bytes(owner.context)==initial_context
        valid=owner.call(5,cap,output)
        assert valid['status']==0 and output[OUT:]==b'\x5a'*64
    ok(owner.call(3,cap));ok(owner.call(9))
    ok(other.call(3,foreign));ok(other.call(9))
    result={'forged_or_foreign_capability_calls':len(cases)*7,
        'invalid_view_guards':len(invalid),'malformed_frame_guards':len(malformed),
        'no_writes_for_invalid_views':True,'outer_canary_preserved':True,
        'actual_calls':owner.calls+other.calls}
    owner.close_mapping();other.close_mapping()
    return result

def concurrency(image):
    owner,cap=owned(image);refs=[cap]+[ok(owner.call(2,cap))['cap'] for _ in range(15)]
    gate=threading.Barrier(16)
    def worker(ref):
        gate.wait()
        with mmap.mmap(-1,OUT) as output:
            for _ in range(40):
                assert ok(owner.call(4,ref,output))['value']==1
                assert ok(owner.call(5,ref,output))['value']==1
                assert ok(owner.call(6,ref,output))['value']==0
            ok(owner.call(3,ref,output))
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(worker,refs))
    ok(owner.call(9));total=owner.calls;owner.close_mapping()
    # Exactly one simultaneous drop consumes an independent reference.
    owner,cap=owned(image);gate=threading.Barrier(16)
    def drop(_):
        gate.wait();return owner.call(3,cap)['status']
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results=list(pool.map(drop,range(16)))
    assert results.count(0)==1 and results.count(1)==15,results
    ok(owner.call(9));total+=owner.calls;owner.close_mapping()
    # Public observation may win the pin or lose to final drop, never use freed memory.
    outcomes={0:0,1:0}
    for _ in range(80):
        owner,cap=owned(image);gate=threading.Barrier(2)
        def observe():
            gate.wait();return owner.call(5,cap)
        def release():
            gate.wait();return owner.call(3,cap)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            observer=pool.submit(observe);dropper=pool.submit(release)
            seen=observer.result();ok(dropper.result())
        assert seen['status'] in (0,1),seen
        outcomes[seen['status']]+=1
        ok(owner.call(9));total+=owner.calls;owner.close_mapping()
    return {'retained_reference_threads':16,'calls_per_thread':121,
        'same_reference_drop_successes':1,'same_reference_drop_rejections':15,
        'last_reference_pin_races':80,'pin_race_outcomes':outcomes,'actual_public_calls':total}

def real_kernel_commit_and_retirement(image):
    # The actual old HIA kernel is invoked as an internal QA role. This does not
    # claim MV selection/pointer-swap integration or expose a public commit op.
    owner,cap=owned(image);workspace=kernel_workspace(cap)
    committed=kernel(image,workspace,7)
    assert committed=={'rc':0,'status':0,'value':1,'token':2},committed
    assert ok(owner.call(4,cap))['value']==0
    assert ok(owner.call(5,cap))['value']==0
    assert ok(owner.call(6,cap))['value']==1
    ok(owner.call(3,cap));ok(owner.call(9));total=owner.calls;owner.close_mapping()
    outcomes={'cancelled':0,'committed':0}
    for _ in range(80):
        owner,cap=owned(image);workspace=kernel_workspace(cap);gate=threading.Barrier(2)
        def cancel():
            gate.wait();return owner.call(4,cap)
        def commit():
            gate.wait();return kernel(image,workspace,7)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            cancelled=pool.submit(cancel);committed=pool.submit(commit)
            ca=ok(cancelled.result());co=committed.result()
        assert co['rc']==co['status']==0
        assert ca['value']+co['value']==1,(ca,co)
        state='cancelled' if ca['value'] else 'committed';outcomes[state]+=1
        assert ok(owner.call(5,cap))['value']==ca['value']
        assert ok(owner.call(6,cap))['value']==co['value']
        ok(owner.call(3,cap));ok(owner.call(9));total+=owner.calls;owner.close_mapping()
    # Real pending kernel waiter makes kernel destruction refuse; no simulated
    # finalizer reply or ownership bit is injected. Failed owner stays retained.
    owner,cap=owned(image);workspace=kernel_workspace(cap);wait_result=[]
    waiter=threading.Thread(target=lambda:wait_result.append(kernel(image,workspace,6,250_000_000)))
    waiter.start()
    deadline=time.monotonic()+2
    while struct.unpack('<Q',ctypes.string_at(workspace+72,8))[0]==0:
        assert time.monotonic()<deadline
        time.sleep(.001)
    failure=ok(owner.call(3,cap),5)
    assert failure['retained']==1 and failure['finalizer_status']==3,failure
    ok(owner.call(9),3)
    waiter.join(2);assert not waiter.is_alive() and wait_result[0]['status']==2,wait_result
    retry=ok(owner.call(10));assert retry['retained']==0,retry
    ok(owner.call(9));total+=owner.calls;owner.close_mapping()
    return {'actual_internal_kernel_commit':True,'cancel_commit_races':80,
        'race_outcomes':outcomes,'real_waiter_finalizer_failure':failure,
        'failed_cleanup_retry':retry,'actual_public_calls':total,
        'scope':'internal kernel QA only; MV pointer-swap composition is not claimed'}

def fork_refusal(image):
    owner,cap=owned(image)
    readfd,writefd=os.pipe()
    pid=os.fork()
    if pid==0:
        os.close(readfd)
        try:
            result=owner.call(5,cap)
            os.write(writefd,json.dumps(result).encode())
            os._exit(0)
        except BaseException:
            os._exit(70)
    os.close(writefd)
    result=json.loads(os.read(readfd,4096));os.close(readfd)
    child,code=os.waitpid(pid,0)
    assert os.WIFEXITED(code) and os.WEXITSTATUS(code)==0
    assert result['status']==3,result
    assert ok(owner.call(5,cap))['value']==0
    ok(owner.call(3,cap));ok(owner.call(9));owner.close_mapping()
    return {'child_status':result['status'],'parent_survives':True,'actual_calls':6}

class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint32)]
class Program(ctypes.Structure):
    _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]

def deny_syscall(number,length=None):
    # seccomp is installed only in an isolated QA child. Product bytes stay exact.
    if length is None:
        rules=[(0x20,0,0,0),(0x15,0,1,number),(0x06,0,0,0x50000|12),(0x06,0,0,0x7fff0000)]
    else:
        rules=[(0x20,0,0,0),(0x15,0,3,number),(0x20,0,0,24),
            (0x15,0,1,length),(0x06,0,0,0x50000|12),(0x06,0,0,0x7fff0000)]
    array=(Filter*len(rules))(*(Filter(*r) for r in rules))
    program=Program(len(rules),array);libc=ctypes.CDLL(None,use_errno=True)
    assert libc.prctl(38,1,0,0,0)==0
    assert libc.prctl(22,2,ctypes.byref(program),0,0)==0

def fault_child(directory,scenario):
    image=Image((directory/'publication_cancellation.flat').read_bytes())
    owner=Owner(image);ok(owner.call(0));cap=None
    if scenario=='retain-node':
        cap=ok(owner.call(1))['cap']
    if scenario in ('construct-object','construct-node','retain-node'):
        deny_syscall(9,131360 if scenario=='construct-object' else 128)
    elif scenario=='nonce':
        deny_syscall(318)
    else:
        raise AssertionError(scenario)
    result=owner.call(2 if cap else 1,cap or (0,0,0))
    ok(result,5 if scenario=='nonce' else 2)
    assert result['cap']==[0,0,0] and result['retained']==0,result
    if cap:
        assert ok(owner.call(4,cap))['value']==1
        ok(owner.call(3,cap))
    ok(owner.call(10));ok(owner.call(9));owner.close_mapping()
    return {'scenario':scenario,'result':result,'context_destroyed':True,'actual_calls':owner.calls}

def faults(directory):
    results=[]
    for scenario in ('construct-object','construct-node','retain-node','nonce'):
        run=subprocess.run([sys.executable,__file__,'--output',str(directory),'--fault-child',scenario],
            capture_output=True,text=True,timeout=20)
        assert run.returncode==0,(scenario,run.returncode,run.stdout,run.stderr)
        results.append(json.loads(run.stdout))
    return results

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--compiler',type=Path,default=Path('/dev/shm/hia-20261126-tools/hia-source-build'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--fault-child')
    args=parser.parse_args()
    if args.fault_child:
        print(json.dumps(fault_child(args.output,args.fault_child)))
        return
    start=time.monotonic()
    roles=compile_roles(args.compiler,args.output)
    image,packing=pack_image(args.output)
    report={'schema':'hepta.hia.publication-cancellation-native.v1',
        'whole_native_runtime':False,'final_aggregate_claimed':False,
        'source_revision':SOURCE_REVISION,'compiler_sha256':sha(args.compiler.read_bytes()),
        'build':roles,'packing':packing}
    for name,call in [('original_and_lifecycle',lambda:basic_and_original(image)),
        ('capabilities_and_guards',lambda:capabilities_and_guards(image)),
        ('concurrency',lambda:concurrency(image)),
        ('kernel_and_retirement',lambda:real_kernel_commit_and_retirement(image)),
        ('fork',lambda:fork_refusal(image)),('fault_injection',lambda:faults(args.output))]:
        report[name]=call()
        print(json.dumps({'gate':name,'passed':True}),flush=True)
    report['seconds']=time.monotonic()-start
    report['qualified']=True
    path=args.output/'qualification.json'
    path.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'qualification':str(path),'image':packing,'seconds':report['seconds']}),flush=True)

if __name__=='__main__':
    main()
