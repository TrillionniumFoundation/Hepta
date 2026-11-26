"""Native worker private profile, physical join and post-join cleanup gates."""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,os,struct,subprocess,time
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_generation_lease_owner_provider import ObjectImage,libc,pin,get
from tools.qualify_hia_multiversion_background_queue import Queue,Owner

ROOT=Path(__file__).resolve().parents[1]
PARTS={
 'values':('multiversion_values','unsigned_decimal_values'),
 'future':('multiversion_future',),
 'queue':('multiversion_background_queue',),
 'worker':('multiversion_background_worker',),
 'business':('background_optimizer_business_worker','background_optimizer_business_worker_failure'),
 'cleanup':('background_optimizer_business_cleanup',)}
MOD={key:parts[0]for key,parts in PARTS.items()}
COMPILER='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
def put(b,at,*x):struct.pack_into('<'+'Q'*len(x),b,at,*x)
def address(f):return C.cast(f,C.c_void_p).value
def save(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+chr(10))
def build(compiler,out):
    assert pin(compiler.read_bytes())==dict(bytes=813129,sha256=COMPILER)
    names=list(dict.fromkeys([x for name,parts in PARTS.items()for x in(*parts,MOD[name]+'_packer')]
          +['multiversion_runtime_linker','multiversion_background_worker_linker']))
    flats={};modules=[];sources={}
    for name in names:
        path=ROOT/'examples/hia_bootstrap'/(name+'.hepta');raw=path.read_bytes();sources[name]=raw
        pair=[]
        for _ in range(2):
            result=subprocess.run([str(compiler),'compile'],input=raw,capture_output=True,timeout=30)
            assert result.returncode==0 and not result.stderr,(name,result.stderr)
            pair.append(result.stdout)
        assert pair[0]==pair[1];flats[name]=pair[0];(out/(name+'.flat')).write_bytes(pair[0])
        modules.append(dict(source_path=str(path.relative_to(ROOT)),source=pin(raw),flat=pin(pair[0]),double_compile_identical=True))
        print('WORKER_PRIVATE_NATIVE_COMPILE',name,len(pair[0]),flush=True)
    products={}
    for name,parts in PARTS.items():
        mod=MOD[name];spec=importlib.import_module('tools.generate_hia_'+mod+'_packer')
        blobs=[flats[x]for x in parts]
        wire=struct.pack('<'+'Q'*(len(blobs)+2),spec.MAGIC,len(blobs),*map(len,blobs))+b''.join(blobs)
        raw=q.old.run_packer(flats[mod+'_packer'],wire)
        assert raw==spec.reference_object(blobs)
        (out/(name+'.o')).write_bytes(raw);row=dict(object=pin(raw),independent_native_pack_comparison=True)
        if name not in('business','cleanup'):
            linker='multiversion_background_worker_linker'if name=='worker'else'multiversion_runtime_linker'
            image=q.old.run_packer(flats[linker],raw)
            assert image[:6]==b'\x7fELF\x02\x01'and struct.unpack_from('<H',image,16)[0]==3
            (out/(name+'.so')).write_bytes(image);row['image']=pin(image);row['native_linker']=linker
        products[name]=row;print('WORKER_PRIVATE_NATIVE_PACK',name,len(raw),flush=True)
    assert all((ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()==raw for name,raw in sources.items())
    result=dict(compiler=pin(compiler.read_bytes()),modules=modules,products=products)
    save(out/'build.json',result);return result

def behavior(build_dir,out):
    values=Owner(build_dir/'values.so');future=C.CDLL(str(build_dir/'future.so'))
    queue=Queue(build_dir/'queue.so',values,future,8)
    lib=C.CDLL(str(build_dir/'worker.so'));entry=lib.hia_mv_background_worker
    entry.argtypes=[C.c_void_p,C.c_uint64]*3;entry.restype=C.c_uint32
    imports={name:address(getattr(libc,name))for name in('malloc','free')}
    business=ObjectImage((build_dir/'business.o').read_bytes(),imports)
    cleanup=ObjectImage((build_dir/'cleanup.o').read_bytes(),imports)
    work=C.create_string_buffer(512);bw=C.create_string_buffer(1064960);bw[:8]=b'HIABWBC1'
    put(bw,136,address(queue.f),C.addressof(queue.w),4096);put(bw,456,os.getpid())
    cw=C.create_string_buffer(256);cw[:8]=b'HIABGCC1'
    put(cw,8,address(business.entry),C.addressof(bw),len(bw),address(entry),C.addressof(work),512,os.getpid())
    calls=[];cases=[]
    def request(op,fields=None,magic=b'HIABGW03'):
        raw=bytearray(128);raw[:8]=magic;put(raw,8,op)
        for at,value in(fields or {}).items():put(raw,at,value)
        return bytes(raw)
    def run(op,fields=None,want=0,context=work,magic=b'HIABGW03'):
        raw=request(op,fields,magic);s=C.create_string_buffer(raw);o=C.create_string_buffer(8192)
        rc=entry(s,128,o,8192,context,512)
        assert rc==0 and o.raw[:8]==b'HIABGWO1'and get(o,8)==want,(op,rc,o.raw[:128].hex())
        calls.append(dict(op=op,status=get(o,8),state=get(o,24),tid=get(o,32),join_pending=get(o,48)))
        return o.raw
    def clean(want,state):
        raw=struct.pack('<8s15Q',b'HIABGCQ1',*([0]*15));s=C.create_string_buffer(raw);o=C.create_string_buffer(32768)
        rc=cleanup.entry(s,128,o,32768,cw,256)
        assert rc==0 and o.raw[:8]==b'HIABGCR1'and get(o,8)==want and get(o,24)==state,(rc,o.raw[:128].hex())
    def mark(name,**kw):
        cases.append(dict(case=name,passed=True,**kw));save(out/'cases.json',cases);print('WORKER_PRIVATE_GATE',name,flush=True)
    fields={16:address(queue.f),24:C.addressof(queue.w),32:4096,40:address(business.entry),48:C.addressof(bw),56:len(bw)}
    run(0,fields)
    assert get(work,112)==get(work,120)==1 and get(work,160)==C.addressof(work) and get(work,168)==address(entry)
    clean(6,0);mark('fresh-private-worker-captures-actual-entry-and-context')
    clone=C.create_string_buffer(work.raw,512)
    for magic in(b'HIABGW03',b'HIABGW01'):run(3,want=65,context=clone,magic=magic)
    child=os.fork()
    if child==0:
        try:run(3,want=65);os._exit(0)
        except BaseException:os._exit(1)
    pid,status=os.waitpid(child,0);assert pid==child and status==0
    mark('actual-context-copy-and-fork-refused')
    controls=[]
    for name,at,value in [('bad-magic',0,0),('bad-op',8,6),('reserved',64,1)]:
        raw=bytearray(request(3));put(raw,at,value);s=C.create_string_buffer(bytes(raw));o=C.create_string_buffer(b'\xa5'*8192,8192)
        before=work.raw;assert entry(s,128,o,8192,work,512)==q.BAD and o.raw[:128]==b'\xa5'*128 and work.raw==before
        controls.append(name)
    mark('private-request-domain-controls',controls=controls)
    queue.run(4)
    run(1)
    until=time.monotonic()+5
    while True:
        observed=run(3)
        if get(observed,24)==3:break
        assert time.monotonic()<until,'actual native worker did not exit'
        time.sleep(.001)
    assert get(observed,32)>1 and get(observed,32)!=os.getpid()
    clean(6,3)
    mark('actual-thread-exit-does-not-authorize-post-join-cleanup',actual_worker_tid=get(observed,32),handler_invoked=False)
    joined=run(2);assert get(joined,24)==4 and get(joined,48)==0 and get(joined,40)==0
    clean(0,4)
    assert get(bw,488)==get(bw,496)==get(bw,464)==0
    mark('actual-pthread-join-authorizes-native-business-cleanup')
    run(2);run(5);queue.destroy();values.run(9)
    mark('repeated-join-and-final-native-registry-destruction')
    return cases,calls

def main():
    p=argparse.ArgumentParser()
    for name in('compiler','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--reuse-build',action='store_true');a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=a.reuse_build);bd=a.output/'build';bd.mkdir(exist_ok=a.reuse_build)
    built=json.loads((bd/'build.json').read_bytes())if a.reuse_build else build(a.compiler,bd)
    for row in built['modules']:assert pin((ROOT/row['source_path']).read_bytes())==row['source']
    args=['/usr/bin/python3','-m','tools.qualify_hia_multiversion_background_worker',
        '--image',str(bd/'worker.so'),'--queue',str(bd/'queue.so'),'--values',str(bd/'values.so'),
        '--future',str(bd/'future.so'),'--output',str(a.output/'original-worker')]
    result=subprocess.run(args,capture_output=True,text=True,timeout=400)
    (a.output/'original-worker.log').write_text(result.stdout+result.stderr)
    print(result.stdout,flush=True);assert result.returncode==0,result.stderr
    cases,calls=behavior(bd,a.output)
    report=dict(schema='hepta.hia.background-worker-private-qualification.v1',component_qualified=True,
        whole_public_background_closed=False,build=built,cases=cases,calls=calls,
        original_worker_assertions_unchanged=True,original_worker_timeout_seconds=400,
        original_worker_report=json.loads((a.output/'original-worker/qualification.json').read_bytes()),
        native_private_handler_called=False,private_scope='actual worker self binding, physical pthread join and post-join cleanup admission',
        platform_imports=['pthread_create','pthread_join','malloc','free'])
    save(a.output/'report.json',report);print('WORKER_PRIVATE_PASS',len(cases),flush=True)
if __name__=='__main__':main()
