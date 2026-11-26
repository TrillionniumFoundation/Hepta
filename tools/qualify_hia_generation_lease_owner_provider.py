"""Exercise the actual provider against one retained native owner/Value arena.

The loader performs ordinary fixed ELF relocations directly to native entries.
There are no host callbacks for provider, carrier, effects, payload or Value.
The fixture's private prefix capture is a component seam; the final enclosing
owner initializer and public BackgroundOptimizer are qualified separately.
"""
from pathlib import Path
import argparse,concurrent.futures,ctypes as C,hashlib,json,mmap,os,struct,subprocess,threading,time
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_generation_lease_owner_resources as resources
from tools import generate_hia_generation_lease_owner_provider_packer as spec
from tools import generate_hia_multiversion_future_packer as token_spec
from tools.qualify_hia_multiversion_components import Image

ROOT=Path(__file__).resolve().parents[1]
NAMES=('generation_lease_owner_provider','multiversion_background_payload',
       'generation_lease_owner_provider_packer','multiversion_future','multiversion_future_packer')
ZERO=(0,0,0)
NONE=(1<<64)-1
ENTRY=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
libc=C.CDLL(None)
def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def get(data,at):return struct.unpack_from('<Q',data,at)[0]
def address(obj):return C.addressof(obj)
def request(op,cap=ZERO,*,family=b'HIAMVBQ3',reply=ZERO,token=0,gen=b'',epoch=b'',raw=b'',measurement=b'',budget=20_000_000_000):
    data=bytearray(128);struct.pack_into('<8sQ3Q',data,0,family,op,*cap)
    if op==5:struct.pack_into('<3Q',data,40,*reply)
    if op==2:
        struct.pack_into('<2Q',data,40,token,512)
        struct.pack_into('<7Q',data,56,len(gen),len(epoch),len(raw),len(measurement),budget,NONE,int(bool(measurement)))
        return bytes(data)+gen+epoch+raw+measurement
    return bytes(data)
def control(op):return struct.pack('<8sQ',b'HIAGPCQ1',op)+bytes(112)
def build(compiler,out):
    captured={name:(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()for name in NAMES}
    flats={};rows=[]
    for name,source in captured.items():
        blobs=[]
        for _ in range(2):
            result=subprocess.run([str(compiler),'compile'],input=source,capture_output=True,timeout=30)
            assert result.returncode==0,(name,result.stderr.decode(errors='replace'))
            blobs.append(result.stdout)
        assert blobs[0]==blobs[1]
        flat=blobs[0];flats[name]=flat;(out/(name+'.flat')).write_bytes(flat)
        rows.append(dict(source_path='examples/hia_bootstrap/'+name+'.hepta',source=pin(source),flat=pin(flat),double_compile_identical=True))
    products={}
    for name,packer,parts,magic,reference in (
        ('provider','generation_lease_owner_provider_packer',[flats[x]for x in NAMES[:2]],spec.MAGIC,spec.reference_object),
        ('token','multiversion_future_packer',[flats['multiversion_future']],token_spec.MAGIC,token_spec.reference_object)):
        wire=struct.pack('<'+str(len(parts)+2)+'Q',magic,len(parts),*map(len,parts))+b''.join(parts)
        actual=q.old.run_packer(flats[packer],wire)
        assert actual==reference(parts)
        (out/(name+'.o')).write_bytes(actual);products[name]=pin(actual)
    stem=out/'independent-provider-bridge'
    subprocess.run(['as','--64',str(ROOT/'tools/hia_generation_lease_owner_provider_bridge.S'),'-o',str(stem)+'.o'],capture_output=True,check=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(stem)+'.o',str(stem)+'.bin'],capture_output=True,check=True)
    assert Path(str(stem)+'.bin').read_bytes()==spec.OUTER
    relocs=[]
    for line in subprocess.check_output(['readelf','-rW',str(stem)+'.o'],text=True).splitlines():
        fields=line.split()
        if len(fields)>=7 and fields[2]=='R_X86_64_PLT32':
            assert fields[-2:]==['-','4'];relocs.append((int(fields[0],16),fields[4]))
    assert tuple(relocs)==spec.OUTER_RELOCATIONS
    controls=[]
    source_frame=struct.pack('<4Q',spec.MAGIC,2,*map(len,[flats[x]for x in NAMES[:2]]))+b''.join(flats[x]for x in NAMES[:2])
    image=Image(out/'generation_lease_owner_provider_packer.flat')
    changes=[('short-header',source_frame[:31]),('truncated',source_frame[:-1]),('trailing',source_frame+b'x')]
    for label,at,value in [('magic',0,0),('count-low',8,1),('count-high',8,3),('empty-provider',16,0),('oversize-provider',16,4194305),('empty-payload',24,0)]:
        raw=bytearray(source_frame);struct.pack_into('<Q',raw,at,value);changes.append((label,bytes(raw)))
    for name,raw in changes:
        source=C.create_string_buffer(raw);output=C.create_string_buffer(4<<20);workspace=C.create_string_buffer(1024)
        C.memset(output,165,128)
        rc=image.entry(source,len(raw),output,len(output),workspace,len(workspace))
        assert rc==0xffffffff and output.raw[:128]==b'\xa5'*128,(name,rc)
        controls.append(name)
    assert all((ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()==raw for name,raw in captured.items())
    result=dict(modules=rows,products=products,native_packs=2,independent_native_object_comparisons=True,
                mechanical_bridge_source=pin((ROOT/'tools/hia_generation_lease_owner_provider_bridge.S').read_bytes()),packer_controls=controls)
    (out/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

class ObjectImage:
    def __init__(self,raw,imports):
        assert raw[:6]==b'\x7fELF\x02\x01'
        sh=get(raw,40)
        sections=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+64*i)for i in range(7)]
        text=raw[sections[1][4]:sections[1][4]+sections[1][5]]
        # Native rel32 role calls stay adjacent to the one actual owner image.
        # Distant platform allocator symbols use ordinary native PLT jump slots.
        self.extent=(len(text)+4096+4095)&~4095
        near=imports.get('hia_owner_carrier',next(iter(imports.values())))
        libc.mmap.argtypes=[C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long];libc.mmap.restype=C.c_void_p
        self.base=0
        for distance in range(16<<20,1<<30,16<<20):
            for direction in(1,-1):
                hint=(near+direction*distance)&~4095
                if hint<=0:continue
                mapped=libc.mmap(C.c_void_p(hint),self.extent,3,0x100022,-1,0)
                if mapped==hint:self.base=mapped;break
                if mapped not in(None,NONE):
                    libc.munmap(C.c_void_p(mapped),C.c_size_t(self.extent))
            if self.base:break
        assert self.base,'no free rel32 component mapping adjacent to native owner'
        C.memmove(self.base,text,len(text))
        jump_at=(len(text)+15)&~15
        strings=raw[sections[4][4]:sections[4][4]+sections[4][5]]
        symbols=raw[sections[3][4]:sections[3][4]+sections[3][5]]
        self.bindings=[]
        for at in range(sections[2][4],sections[2][4]+sections[2][5],24):
            offset,info,addend=struct.unpack_from('<QQq',raw,at);assert info&0xffffffff==4 and addend==-4
            no=struct.unpack_from('<I',symbols,24*(info>>32))[0];name=strings[no:strings.index(0,no)].decode()
            target=imports[name];relative=target-(self.base+offset+4)
            if not -(1<<31)<=relative<(1<<31):
                assert name in('malloc','free'),'owner roles must resolve to their exact actual entry'
                jump=b'\xff\x25\x00\x00\x00\x00'+struct.pack('<Q',target)
                C.memmove(self.base+jump_at,jump,len(jump))
                relative=jump_at-offset-4;jump_at+=16
            C.memmove(self.base+offset,struct.pack('<i',relative),4)
            self.bindings.append(name)
        assert libc.mprotect(C.c_void_p(self.base),C.c_size_t(self.extent),mmap.PROT_READ|mmap.PROT_EXEC)==0
        self.entry=ENTRY(self.base)

class Provider:
    def __init__(self,owner,obj):
        self.owner=owner;self.context=(C.c_char*768).from_buffer(owner.context,1280)
        carrier=get(owner.context,32);value=get(owner.context,40)
        hole=q.spec.HANDLES_HOLES['effects'];effects=carrier+hole+4+struct.unpack('<i',C.string_at(carrier+hole,4))[0]
        imports={name:C.cast(getattr(libc,name),C.c_void_p).value for name in ('malloc','free')}
        imports.update(hia_owner_carrier=carrier,hia_owner_effects=effects,hia_owner_values=value)
        self.image=ObjectImage(obj,imports);self.entry=self.image.entry
        # Component fixture binds the exact enclosing context. The production
        # enclosing native initializer is a separate, explicitly pending gate.
        assert bytes(self.context)==bytes(768)
        parent=C.addressof(owner.context);own=C.addressof(self.context)
        prefix=[int.from_bytes(b'HIAGPCX1','little'),os.getpid(),0,0,0,parent,own,self.image.base,parent+256,256,value,parent+512,256,self.image.base+spec.PAYLOAD_OFFSET,own+512,256,get(owner.context,664)]
        for i,value in enumerate(prefix):struct.pack_into('<Q',self.context,8*i,value)
        self.rows=[];self.row_lock=threading.Lock()
        self.call(control(0))
    def call(self,raw,want=0):
        src=C.create_string_buffer(raw);output=C.create_string_buffer(128)
        before=time.monotonic_ns();rc=self.entry(src,len(raw),output,128,self.context,768)
        assert rc==0,(rc,raw[:16].hex(),output.raw.hex())
        result=output.raw;typed=raw[:8]!=b'HIAMVBQ1'
        assert result[:8]==(b'HIAMVBO2'if typed else b'HIAMVBO1')
        status=get(result,8);cap=struct.unpack_from('<3Q',result,40);pointer=get(result,24);size=get(result,32)
        assert bool(pointer)==bool(size)and(not pointer or cap[0])
        payload=C.string_at(pointer,size)if pointer else b''
        assert src.raw==raw+b'\0'
        row=dict(op=get(raw,8),family=raw[:8].decode(),status=status,kind=get(result,16),cap_present=bool(cap[0]),
                 payload=pin(payload),committed=get(result,64),known=get(result,72),consumed=get(result,80),pending=get(result,88),
                 elapsed_ns=time.monotonic_ns()-before)
        with self.row_lock:self.rows.append(row)
        if want is not None:assert status==want,row
        return dict(cap=cap,payload=payload,pointer=pointer,header=result,row=row)
    def q(self,op,cap=ZERO,**kw):
        want=kw.pop('want',0);return self.call(request(op,cap,**kw),want)
    def drop(self,cap):
        result=self.q(4,cap);assert tuple(get(result['header'],x)for x in(72,80,88))==(1,1,0);return result
    def drop_payload(self,result):
        dropped=self.q(5,reply=result['cap'])
        assert tuple(get(dropped['header'],x)for x in(72,80,88))==(1,1,0)
    def close(self):
        self.call(control(1));self.call(control(3))
        assert get(self.context,16)==3 and get(self.context,32)==get(self.context,528)==0 and get(self.context,536)==1

class Token:
    def __init__(self,image):
        self.image=image;self.context=C.create_string_buffer(512);self.q(0)
    @property
    def address(self):return C.addressof(self.context)
    def q(self,op):
        raw=struct.pack('<8s7Q',b'HIAMVFQ1',op,0,0,0,0,0,0);src=C.create_string_buffer(raw);out=C.create_string_buffer(512)
        rc=self.image.entry(src,len(raw),out,len(out),self.context,512)
        assert rc==0,(op,rc,out.raw[:128].hex())
        return out.raw

def private_controls(provider):
    controls=[]
    raw=control(4)
    changes=[]
    for name,at,value in [('magic',0,0),('operation',8,5),('reserved',16,1)]:
        packet=bytearray(raw);struct.pack_into('<Q',packet,at,value);changes.append((name,bytes(packet)))
    changes += [('short',raw[:127]),('trailing',raw+b'x'),('wrong-capture-op',request(1,family=b'HIAMVBQ2'))]
    original=bytes(provider.context)
    for name,packet in changes:
        source=C.create_string_buffer(packet);output=C.create_string_buffer(128);C.memset(output,165,128)
        rc=provider.entry(source,len(packet),output,128,provider.context,768)
        assert rc==q.BAD and output.raw==b'\xa5'*128 and bytes(provider.context)==original,(name,rc)
        controls.append(name)
    source=C.create_string_buffer(raw);output=C.create_string_buffer(128)
    base=[C.addressof(source),len(raw),C.addressof(output),128,C.addressof(provider.context),768]
    for index,value in[(0,0),(2,0),(4,0),(5,767),(5,769),(4,C.addressof(provider.context)+1),(0,NONE-31),(4,NONE-31)]:
        arguments=list(base);arguments[index]=value;C.memset(output,165,128)
        assert provider.entry(*arguments)==q.BAD and output.raw==b'\xa5'*128 and bytes(provider.context)==original
        controls.append('native-span-'+str(index)+'-'+str(value))
    clone=C.create_string_buffer(original,768);C.memset(output,165,128)
    assert provider.entry(source,len(raw),output,128,clone,768)==0
    assert output.raw[:8]==b'HIAMVBO2'and get(output,8)==3
    assert bytes(provider.context)==original and clone.raw==original
    controls.append('actual-context-copy-refused')
    readfd,writefd=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(readfd);out=C.create_string_buffer(128)
            rc=provider.entry(source,len(raw),out,128,provider.context,768)
            os.write(writefd,struct.pack('<I',rc)+out.raw);os._exit(0)
        except BaseException:os._exit(73)
    os.close(writefd);reply=os.read(readfd,132);os.close(readfd);_,status=os.waitpid(pid,0)
    assert os.waitstatus_to_exitcode(status)==0 and len(reply)==132 and get(reply[4:],8)==3
    assert struct.unpack_from('<I',reply)[0]==0 and bytes(provider.context)==original
    controls.append('actual-fork-refused')
    return controls

def behavior(owner_path,provider_object,token_object,files,out):
    owner,c,v=resources.setup(owner_path);provider=Provider(owner,provider_object)
    before=set(os.listdir('/proc/self/fd'));parent=out/'runtime';parent.mkdir(mode=0o700)
    checks=[]
    def mark(name,**fields):
        row=dict(name=name,**fields);checks.append(row)
        (out/'calls.json').write_text(json.dumps(provider.rows,indent=2)+'\n')
        (out/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
        print('PROVIDER_OWNER_GATE',name,flush=True)
    guards=private_controls(provider)
    mark('native-private-frames-spans-copy-and-fork',controls=guards)
    provider.call(control(1))
    provider.q(3,(1,1,1),want=3)
    provider.call(control(2));assert get(provider.context,16)==1
    mark('actual-prepare-fence-and-rollback')
    raw_runtime=q.old.create(c,files,parent)
    runtime=resources.capture(owner,v,1,raw_runtime)
    raw_lease=q.old.lease(c,raw_runtime)
    lease=resources.capture(owner,v,2,raw_lease,runtime)
    original_type=v.builtin(20);assert v.isinst(runtime,original_type);v.drop(original_type)
    mark('actual-source-built-runtime-and-resource-class')
    captured=provider.q(3,runtime,family=b'HIAMVBQ2')
    cap=captured['cap'];assert cap[0] and cap!=raw_runtime
    assert tuple(get(captured['header'],x)for x in(72,80,88))==(1,0,0)
    mark('real-value-private-capture-same-carrier-registry')
    for candidate in(lease,raw_runtime,(1,1,1)):
        provider.q(3,candidate,family=b'HIAMVBQ2',want=3)
    plain=v.scalar(None);provider.q(3,plain,family=b'HIAMVBQ2',want=3);v.drop(plain)
    assert get(provider.context,32)==0
    mark('wrong-resource-and-capability-domains-refused')
    original=provider.q(3,raw_runtime,family=b'HIAMVBQ1')
    assert original['cap'][0]and original['header'][72:]==bytes(56)
    provider.q(4,original['cap'],family=b'HIAMVBQ1')
    mark('original-carrier-wire-preserved')
    snap=provider.q(1,cap);data=snap['payload']
    assert data[:8]==b'HIAMVBS1'and get(data,16)==6 and get(data,24)==get(data,32)==1 and data[256:]==b'00'
    assert get(snap['header'],80)==0
    mark('actual-lock-consistent-snapshot')
    start=threading.Barrier(8)
    def alias(_):
        start.wait(timeout=20);result=provider.q(3,runtime,family=b'HIAMVBQ2');provider.drop(result['cap']);return result['row']
    with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
        rows=list(pool.map(alias,range(8)))
    assert len(rows)==8 and get(provider.context,32)==0
    mark('eight-thread-actual-capture-and-retirement',threads=8)
    native_imports={name:C.cast(getattr(libc,name),C.c_void_p).value for name in('malloc','free')}
    token_image=ObjectImage(token_object,native_imports);token=Token(token_image)
    published=provider.q(2,cap,token=token.address,gen=b'0',epoch=b'0',raw=q.old.rawdoc(q.old.scalar_program('bit.xor')))
    doc=json.loads(published['payload'])
    assert get(published['header'],64)==1 and get(token.context,64)==2
    assert doc['generation']['generation']==1 and doc['selection_epoch']==1,doc
    mark('actual-native-conditional-publication',result=doc)
    stale=provider.q(2,cap,want=1,token=token.address,gen=b'0',epoch=b'0',raw=q.old.rawdoc(q.old.scalar_program(None)))
    assert json.loads(stale['payload'])=={'type':'MultiversionRejected','message':'E_HIA_MULTIVERSION: stale generation or selection epoch'}
    cancelled=Token(token_image);cancelled.q(1)
    no=provider.q(2,cap,want=1,token=cancelled.address,gen=b'1',epoch=b'1',raw=q.old.rawdoc(q.old.scalar_program(None)))
    assert json.loads(no['payload'])=={'type':'MultiversionRejected','message':'E_HIA_MULTIVERSION: publication cancelled before selection'}
    latest=provider.q(1,cap);assert latest['payload'][256:]==b'11'
    mark('original-stale-and-real-cancellation-order')
    provider.call(control(1),want=3);assert get(provider.context,16)==1
    for result in(snap,published,stale,no,latest):
        assert C.string_at(result['pointer'],len(result['payload']))==result['payload']
        provider.drop_payload(result)
    mark('immutable-payload-custody-blocks-prepare')
    c.q(3,raw_lease);c.q(3,raw_runtime);v.drop(lease);v.drop(runtime)
    assert not v.held
    provider.call(control(1))
    refused=owner.call(3)
    assert refused['status']!=0 and refused['state']==1,{k:x for k,x in refused.items()if k!='result'}
    provider.call(control(2));assert get(provider.context,16)==1
    still_live=provider.q(1,cap);assert still_live['payload'][256:]==b'11';provider.drop_payload(still_live)
    mark('actual-registry-busy-owner-refusal-and-provider-rollback')
    provider.drop(cap)
    provider.q(4,cap,want=3)
    assert not list(parent.iterdir())
    assert get(provider.context,32)==get(provider.context,528)==0
    provider.call(control(4))
    provider.q(6)
    token.q(10);cancelled.q(10)
    provider.close()
    closed=owner.call(3);assert closed['status']==0 and closed['state']==3
    assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
    assert set(os.listdir('/proc/self/fd'))==before
    mark('actual-last-carrier-and-provider-arena-final-retirement',fds_unchanged=True,parent_empty=True)
    return checks,provider.rows

def main():
    ap=argparse.ArgumentParser()
    for key in('compiler','owner','normalizer','proof','builder','output'):ap.add_argument('--'+key,type=Path,required=True)
    ap.add_argument('--reuse-build',action='store_true');a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=a.reuse_build)
    build_dir=a.output/'build';build_dir.mkdir(exist_ok=a.reuse_build)
    built=json.loads((build_dir/'build.json').read_bytes())if a.reuse_build else build(a.compiler,build_dir)
    for row in built['modules']:
        assert pin((ROOT/row['source_path']).read_bytes())==row['source'],'stale reused provider source'
    for name in('provider','token'):
        assert pin((build_dir/(name+'.o')).read_bytes())==built['products'][name]
    owner_build=json.loads((a.owner.parent/'build.json').read_bytes())
    assert pin(a.owner.read_bytes())==owner_build['build']['products']['hia-generation-lease-owner.so']
    files=[]
    try:
        for key in('normalizer','proof','builder'):
            raw=getattr(a,key).read_bytes();files.append((q.old.sealed(raw),raw))
        checks,calls=behavior(a.owner,(build_dir/'provider.o').read_bytes(),(build_dir/'token.o').read_bytes(),files,a.output)
        report=dict(schema='hepta.hia.generation-lease-owner-provider-qualification.v1',
                    component_qualified=True,passed=len(checks),failed=0,owner=pin(a.owner.read_bytes()),
                    value=owner_build['build']['products']['hia-generation-lease-values.core.bin'],
                    compiler=pin(a.compiler.read_bytes()),build=built,checks=checks,calls=calls,
                    same_actual_value_arena=True,no_python_role_callbacks=True,
                    trusted_enclosing_bootstrap_qualified=False,whole_public_background_closed=False,
                    platform_allocator_imports=['malloc','free'])
        (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(passed=len(checks),failed=0,actual_calls=len(calls),whole_public_background_closed=False)),flush=True)
    finally:
        for fd,_ in files:os.close(fd)
if __name__=='__main__':main()
