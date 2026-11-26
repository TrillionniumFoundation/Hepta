"""Exercise the single source-bound native lease/Value owner.

This development oracle compiles every retained HIA role twice and invokes the
actual native packers/linker. Python only drives wires and independently checks
results. It never supplies a callback or constructs the product's child context.
"""
from pathlib import Path
import argparse, concurrent.futures, ctypes as C, hashlib, json, mmap, os
import struct, subprocess, threading, time
from tools import qualify_hia_generation_lease_public_lifecycle as old
from tools.qualify_hia_publication_cancellation import Image, address
from tools.qualify_hia_result_value_dict_iterator import Values, wire as value_wire
from tools import generate_hia_generation_lease_owner_packer as spec

ROOT=Path(__file__).resolve().parents[1]
BOOT='examples/hia_bootstrap/'
OUT=(96<<20)+32768
CONTEXT_BYTES=2048
CHILD=16384
BAD=0xfffffffd
NONE=(1<<64)-1
get=old.get
sha=old.sha
VALUE_ROLES=('result_value_owner','result_value_core','result_value_import',
 'result_value_export','background_optimizer_json_capture','agent_binary64_format',
 'result_value_binary64','result_value_dict_iterator','result_value_classes',
 'native_class_mro','result_value_records','result_value_resources')
PRODUCTS=('hia-generation-lease-owner.so','hia-generation-lease-lifecycle.core.bin',
          'hia-generation-lease-values.core.bin')


def envelope(op,payload=b''):
    return struct.pack('<8Q',int.from_bytes(b'HIAGLOQ1','little'),op,len(payload),0,0,0,0,0)+payload


class Owner:
    def __init__(self,path):
        self.lib=C.CDLL(str(path));self.entry=self.lib.hia_generation_lease_owner
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.context=C.create_string_buffer(CONTEXT_BYTES)
        self.calls=0;self.lock=threading.Lock()

    def call(self,op,payload=b'',consume=None):
        raw=envelope(op,payload);source=C.create_string_buffer(raw)
        with mmap.mmap(-1,OUT) as output:
            rc=self.entry(source,len(raw),address(output),OUT,self.context,CONTEXT_BYTES)
            assert source.raw==raw+b'\0'
            head=bytes(output[:128])
            assert rc==0 and head[:8]==b'HIAGLOR1',(op,rc,head.hex())
            status=get(head,8);kind=get(head,16);at=get(head,24)
            assert kind in (0,1,2,4)
            assert at==(CHILD if kind else 0)
            result=consume(output,at) if kind and consume is not None else bytes(output[at:at+16384]) if kind else b''
            row=dict(op=op,status=status,kind=kind,child_rc=get(head,40),
                     state=get(head,48),active=get(head,56),result=result,
                     cleanup_status=get(head,72),cleanup_caps=[struct.unpack_from('<3Q',head,80+i*24) for i in range(get(head,64))])
        with self.lock:self.calls+=1
        return row

    def initialize(self):
        row=self.call(0);assert row['status']==0,row
        assert get(self.context,0)==int.from_bytes(b'HIAGLOW1','little')
        assert get(self.context,8)==os.getpid()
        assert get(self.context,16)==C.addressof(self.context)
        assert get(self.context,24)==C.cast(self.entry,C.c_void_p).value
        assert get(self.context,32)==get(self.context,136)
        assert get(self.context,40)!=0 and get(self.context,48)==C.addressof(self.context)+512
        assert get(self.context,56)==256 and get(self.context,72)==0 and get(self.context,80)==1
        assert get(self.context,144)==C.addressof(self.context)+256
        assert get(self.context,152)==256 and get(self.context,160)==os.getpid()
        assert get(self.context,528)!=0
        assert get(self.context,640) and get(self.context,648)==C.addressof(self.context)+768
        assert get(self.context,656)==256 and get(self.context,664)==get(self.context,832)
        assert get(self.context,800)!=0 and get(self.context,808)==96<<20
        assert get(self.context,840)==get(self.context,848)==1
        again=self.call(0);assert again['status']==0 and again['kind']==0
        return row


class Carrier:
    def __init__(self,owner):
        self.owner=owner;self.rows=[];self.lock=threading.Lock()
        self.w=(C.c_char*256).from_buffer(owner.context,256)

    def q(self,op,cap=(0,0,0),payload=b'',want=0,child=None):
        assert op not in (0,5),'the enclosing native owner controls registry lifetime'
        frame=bytearray(128)
        struct.pack_into('<8sQ',frame,0,b'HIAMVHQ1',op)
        struct.pack_into('<3Q',frame,24,*cap)
        struct.pack_into('<Q',frame,72,len(payload))
        def consume(mem,base):
            head=bytes(mem[base:base+128]);assert head[:8]==b'HIAMVHR1',head.hex()
            status=get(head,8);cp=get(head,56)
            ch=bytes(mem[base+cp:base+cp+1024]) if cp else b''
            value=bytes(mem[base+cp+get(ch,120):base+cp+get(ch,120)+get(ch,112)]) if ch and get(ch,112) else b''
            snap=bytes(mem[base+cp+get(ch,128):base+cp+get(ch,128)+get(ch,136)]) if ch and get(ch,136) else b''
            streams=[]
            if ch:
                assert ch[:8]==b'HIAMVER1'
                for at in (96,104):
                    fd=get(ch,at)
                    if fd!=NONE:
                        n=os.fstat(fd).st_size
                        streams.append(dict(bytes=n,sha256=sha(os.pread(fd,n,0))))
                        os.close(fd)
            outcap=tuple(get(head,i) for i in (24,32,40))
            row=dict(op=op,rc=0,status=status,child_status=get(head,48),kind=get(head,16),
                     result=bool(outcap[0]),retained=get(head,72),finalizer=get(head,80),streams=streams)
            return dict(cap=outcap,header=head,child=ch,value=value,snapshot=snap,row=row)
        outer=self.owner.call(1,bytes(frame)+payload,consume)
        assert outer['status']==0 and outer['child_rc']==0,{k:v for k,v in outer.items() if k!='result'}
        result=outer['result'];row=result['row']
        with self.lock:self.rows.append(row)
        if want is not None:assert row['status']==want,row
        if child is not None:assert row['child_status']==child,row
        return result

    def call(self,cap,arg,want=0):
        result=self.q(4,cap,old.inner(4,fn=b'calculate',args=json.dumps([arg]).encode()),child=want)
        if want==0:assert json.loads(result['value'])==arg,result
        return result


class Lifecycle:
    def __init__(self,owner):
        self.owner=owner;self.calls=0;self.lock=threading.Lock()

    def call(self,op,cap,output=None):
        payload=struct.pack('<8Q',old.Q,op,*cap,0,0,0)
        outer=self.owner.call(2,payload)
        if outer['status']!=0:
            assert outer['status'] in (1,3,4),outer
            result=dict(op=op,status=outer['status'],kind=0,cap=[0,0,0],
                        error_code=0,error=None,child_status=0,retained=0,finalizer=0,
                        enclosing_refusal=True)
        else:
            assert outer['kind']==2 and outer['child_rc']==0
            raw=outer['result'];words=struct.unpack_from('<16Q',raw)
            assert words[0]==old.R and words[7]<=256
            result=dict(op=op,status=words[1],kind=words[2],cap=list(words[3:6]),
                        error_code=words[6],error=json.loads(raw[128:128+words[7]]) if words[7] else None,
                        child_status=words[8],retained=words[10],finalizer=words[11])
        with self.lock:self.calls+=1
        return result


class ValueTransport:
    def __init__(self,owner):
        self.owner=owner;self.calls=0
        self.context=(C.c_char*256).from_buffer(owner.context,512)
    def call(self,request,on=16384):
        row=self.owner.call(4,request,lambda mem,at:bytes(mem[at:at+on]))
        assert row['status']==0 and row['kind']==4,row
        self.calls+=1
        return row['child_rc'],row['result']
    def finish(self):
        request=bytearray(value_wire(47));request[:8]=b'HIABVQ04'
        rc,out=self.call(bytes(request))
        assert rc==0 and out[:8]==b'HIABVR01' and get(out,8)==0 and get(out,48)==0


def compile_all(compiler,out):
    names={Path(row['path']).stem for row in spec.CARRIER_SOURCES}
    names.update(VALUE_ROLES)
    names.update(('generation_lease_owner','generation_lease_owner_packer',
                  'generation_lease_public_lifecycle','generation_lease_public_lifecycle_packer',
                  'multiversion_runtime_linker','result_value_resources_packer','generation_lease_typed_policy','generation_lease_owner_finalizer'))
    captured={name:(ROOT/BOOT/(name+'.hepta')).read_bytes() for name in sorted(names)}
    assert all((ROOT/BOOT/(name+'.hepta')).read_bytes()==raw for name,raw in captured.items()),'source changed during native capture'
    flats={};rows=[]
    for name,raw in captured.items():
        path=BOOT+name+'.hepta'
        flat=old.compiler_run(compiler,raw,name);flats[name]=flat
        (out/(name+'.flat')).write_bytes(flat)
        rows.append(dict(path=path,source_bytes=len(raw),source_sha256=sha(raw),
                         flat_bytes=len(flat),flat_sha256=sha(flat),two_builds_identical=True))
    return flats,rows


def bridge_identity(out):
    records=[]
    expected={'':(spec.OWNER,spec.OWNER_RELOCATIONS),
              '_handles':(spec.HANDLES_PREFIX,spec.HANDLES_RELOCATIONS),
              '_effects':(spec.EFFECTS_PREFIX,spec.EFFECTS_RELOCATIONS),
              '_finalizer':(spec.FINALIZER_PREFIX,())}
    for suffix,(body,relocs) in expected.items():
        source=ROOT/('tools/hia_generation_lease_owner'+suffix+'_bridge.S')
        stem=out/('independent'+suffix)
        subprocess.run(['as','--64',str(source),'-o',str(stem)+'.o'],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','--only-section=.text',str(stem)+'.o',str(stem)+'.bin'],check=True,capture_output=True)
        assert Path(str(stem)+'.bin').read_bytes()==body
        rows=subprocess.check_output(['readelf','-rW',str(stem)+'.o'],text=True)
        actual=[]
        for line in rows.splitlines():
            parts=line.split()
            if len(parts)>=7 and parts[2]=='R_X86_64_PLT32':
                assert parts[-2:] == ['-','4']
                actual.append((int(parts[0],16),parts[4]))
        assert tuple(actual)==tuple(relocs),(suffix,actual,relocs)
        records.append(dict(path=str(source.relative_to(ROOT)),sha256=sha(source.read_bytes()),
                            prefix_bytes=len(body),prefix_sha256=sha(body),relocations=actual))
    return records


def build_images(flats,out):
    from tools import generate_hia_result_value_resources_packer as values
    parts=[flats[name] for name in VALUE_ROLES]
    wire=struct.pack('<15Q',int.from_bytes(b'HIABVP05','little'),12,*map(len,parts),1)+b''.join(parts)
    value=old.run_packer(flats['result_value_resources_packer'],wire)
    assert value==values.reference_flat(parts)
    (out/PRODUCTS[2]).write_bytes(value)
    body=[flats['generation_lease_owner'],flats['generation_lease_public_lifecycle'],value,
          flats['generation_lease_typed_policy'],flats['generation_lease_owner_finalizer']]
    body.extend(flats[Path(row['path']).stem] for row in spec.CARRIER_SOURCES)
    frame=struct.pack('<'+str(2+len(body))+'Q',spec.MAGIC,len(body),*map(len,body))+b''.join(body)
    obj=old.run_packer(flats['generation_lease_owner_packer'],frame)
    assert obj==spec.reference_object(body)
    linked=old.run_packer(flats['multiversion_runtime_linker'],obj)
    (out/'generation-lease-owner.o').write_bytes(obj)
    (out/PRODUCTS[0]).write_bytes(linked)
    lifecycle,facet=old.lifecycle_image(flats,out)
    (out/PRODUCTS[1]).write_bytes((out/'generation-lease-lifecycle.flat').read_bytes())
    packer=Image(flats['generation_lease_owner_packer']);refusals=[]
    changes=[]
    for name,offset,replacement in [('magic',0,0),('role-count-low',8,len(body)-1),
                                    ('role-count-high',8,len(body)+1),
                                    ('empty-role',16,0),('oversize-role',16,4194305)]:
        changed=bytearray(frame);struct.pack_into('<Q',changed,offset,replacement);changes.append((name,bytes(changed)))
    changes += [('short-header',frame[:15]),('truncated-role',frame[:-1]),('trailing-byte',frame+b'x')]
    for name,raw in changes:
        src=C.create_string_buffer(raw)
        with mmap.mmap(-1,32<<20) as output,mmap.mmap(-1,1<<20) as workspace:
            output[:128]=b'\xa5'*128
            rc=packer.entry(src,len(raw),address(output),len(output),address(workspace),len(workspace))
            assert rc==0xffffffff and output[:128]==b'\xa5'*128,(name,rc)
            refusals.append(name)
    src=C.create_string_buffer(frame)
    with mmap.mmap(-1,len(obj)) as output,mmap.mmap(-1,1<<20) as workspace:
        output[:128]=b'\xa5'*128
        rc=packer.entry(src,len(frame),address(output),len(obj)-1,address(workspace),len(workspace))
        assert rc==0xfffffffe and output[:128]==b'\xa5'*128
        refusals.append('short-output')
    records={name:dict(bytes=(out/name).stat().st_size,sha256=sha((out/name).read_bytes())) for name in PRODUCTS}
    return out/PRODUCTS[0],dict(products=records,roles=54,carrier_roles=49,value_roles=12,
                              native_pack=True,native_link=True,object_bytes=len(obj),
                              object_sha256=sha(obj),packer_refusals=refusals,lifecycle=facet)


def guards(owner,carrier,api,runtime,cap,path):
    badcaps=[(0,0,0),(1,1,1),(NONE,0,0),(cap[0],cap[1]^1,cap[2]),
             (cap[0],cap[1],cap[2]^1),runtime]
    for candidate in badcaps:
        for op in range(7):old.ok(api.call(op,candidate),1)
    other=Owner(path);other.initialize();foreign=Lifecycle(other)
    for op in range(7):old.ok(foreign.call(op,cap),1)
    assert other.call(3)['status']==0
    payload=struct.pack('<8Q',old.Q,0,*cap,0,0,0);raw=envelope(2,payload)
    source=C.create_string_buffer(raw)
    with mmap.mmap(-1,OUT+64) as output:
        output[:1024]=b'\xa5'*1024;output[OUT:]=b'\x5a'*64
        context=bytes(owner.context)
        base=[C.addressof(source),len(raw),address(output),OUT,C.addressof(owner.context),CONTEXT_BYTES]
        invalid=[]
        for index,value in ((0,0),(2,0),(4,0),(1,0),(1,63),(3,OUT-1),(5,CONTEXT_BYTES-1),(5,CONTEXT_BYTES+1),
                            (0,NONE-31),(2,NONE-31),(4,NONE-63),(4,C.addressof(owner.context)+1)):
            args=list(base);args[index]=value;invalid.append(args)
        for left,right in ((0,2),(0,4),(2,4),(4,2)):
            args=list(base);args[left]=args[right];invalid.append(args)
        for args in invalid:
            assert owner.entry(*args)==BAD,args
            assert output[:1024]==b'\xa5'*1024 and output[OUT:]==b'\x5a'*64
            assert bytes(owner.context)==context
        malformed=[]
        for offset,value in ((0,0),(8,5),(16,63),(24,1),(32,1),(40,1),(48,1),(56,1)):
            change=bytearray(raw);struct.pack_into('<Q',change,offset,value);malformed.append(bytes(change))
        for op in (0,5):
            request=bytearray(128);struct.pack_into('<8sQ',request,0,b'HIAMVHQ1',op)
            malformed.append(envelope(1,bytes(request)))
        for op in (0,20,30,31):malformed.append(envelope(4,value_wire(op)))
        for change in malformed:
            src=C.create_string_buffer(change)
            assert owner.entry(src,len(change),address(output),OUT,owner.context,CONTEXT_BYTES)==BAD
            assert output[:128]==b'\xa5'*128 and output[OUT:]==b'\x5a'*64
            assert bytes(owner.context)==context
        copied=C.create_string_buffer(context)
        assert owner.entry(source,len(raw),address(output),OUT,copied,CONTEXT_BYTES)==0
        assert output[:8]==b'HIAGLOR1' and get(output,8)==1 and bytes(copied)[:CONTEXT_BYTES]==context
        protected=[]
        for slot in (24,32,40,48,56,136,144,152,160,640,648,656,664,680,768,784,792,800,808,816,824,832,840,848,856,864):
            before=get(owner.context,slot);struct.pack_into('<Q',owner.context,slot,before^1)
            result=owner.call(2,payload);assert result['status']==1,(slot,{k:v for k,v in result.items() if k!='result'})
            struct.pack_into('<Q',owner.context,slot,before);protected.append(slot)
        assert bytes(owner.context)==context
    fork=old.fork_refusal(api,cap)
    return dict(forged_and_wrong_kind=42,foreign_context=7,invalid_views=len(invalid),
                malformed_frames=len(malformed),copied_context_refused=True,
                captured_pointer_tampering_refused=protected,no_writes_on_invalid_views=True,fork=fork)


def lifecycle_case(path,files,parent,runtime_first=False):
    owner=Owner(path);owner.initialize();carrier=Carrier(owner);api=Lifecycle(owner)
    values=Values(ValueTransport(owner));before=set(os.listdir('/proc/self/fd'))
    runtime=old.create(carrier,files,parent);cap=old.lease(carrier,runtime)
    anchor=tuple(get(owner.context,512+i) for i in (16,40,80,88,96))
    probe=owner.call(3);assert probe['status']==2 and probe['state']==1 and probe['kind']==1
    assert tuple(get(owner.context,512+i) for i in (16,40,80,88,96))==anchor
    live_value=values.scalar('owned value survives lease and runtime')
    old.ok(api.call(0,live_value),1)
    carrier.q(6,live_value,want=1)
    result={}
    if runtime_first:
        carrier.q(4,runtime,old.public_request(8),child=0);carrier.q(3,runtime)
        assert owner.call(3)['status']==2
        old.ok(api.call(0,cap));carrier.call(cap,43)
        old.ok(api.call(1,cap));old.ok(api.call(6,cap))
        result['native_call_after_runtime_close']=43
    else:
        result['guards']=guards(owner,carrier,api,runtime,cap,path)
        retained=old.ok(api.call(5,cap))['cap'];assert retained!=list(cap)
        carrier.call(cap,17)
        result['original']=old.compare_original(api,cap)
        assert old.ok(api.call(0,retained),4)['error_code']==1
        old.release_detached(carrier.q(4,cap,old.public_request(6),child=0))
        old.ok(api.call(6,cap));old.ok(api.call(0,cap),1);old.ok(api.call(6,retained))
        result['races']=old.races(api,carrier,runtime)
        old.release_detached(carrier.q(4,runtime,old.public_request(10),child=0))
        carrier.q(4,runtime,old.public_request(8),child=0)
        old.release_detached(carrier.q(4,runtime,old.public_request(9),child=0));carrier.q(3,runtime)
    assert get(carrier.w,16)==get(carrier.w,40)==get(carrier.w,64)==0
    row=owner.call(3);assert row['status']==2 and row['state']==1
    assert values.python(live_value)=='owned value survives lease and runtime'
    values.drop(live_value);values.engine.finish()
    closed=owner.call(3);assert closed['status']==0 and closed['state']==3
    assert bytes(owner.context)[128:]==bytes(CONTEXT_BYTES-128)
    assert owner.call(3)['status']==0
    assert owner.call(2,struct.pack('<8Q',old.Q,0,*cap,0,0,0))['status']==4
    assert not list(parent.iterdir()) and set(os.listdir('/proc/self/fd'))==before
    result.update(owner_calls=owner.calls,lifecycle_calls=api.calls,carrier_calls=len(carrier.rows),
                  value_cap_outlives_runtime_and_lease=True,live_values_block_owner_destroy=True,
                  live_registry_blocks_destroy_without_consuming_value_anchor=True,
                  actual_value_retirement_acknowledged=True,registry_counts_zero=True,
                  fd_set_unchanged=True,artifact_parent_empty=True,rows=carrier.rows)
    return result


def active_destroy(path,files,parent):
    owner=Owner(path);owner.initialize();carrier=Carrier(owner)
    before=set(os.listdir('/proc/self/fd'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(old.create,carrier,files,parent)
        deadline=time.monotonic()+15
        while not get(owner.context,72) and not future.done() and time.monotonic()<deadline:
            time.sleep(0.0001)
        assert get(owner.context,72)>0,'real constructor must still be active'
        refused=owner.call(3);assert refused['status']==2 and refused['kind']==0,refused
        runtime=future.result(timeout=60)
    carrier.q(4,runtime,old.public_request(8),child=0)
    old.release_detached(carrier.q(4,runtime,old.public_request(9),child=0))
    carrier.q(3,runtime);assert owner.call(3)['status']==0
    assert not list(parent.iterdir()) and set(os.listdir('/proc/self/fd'))==before
    return dict(actual_inflight_constructor_blocks_destroy=True,subsequent_destroy_succeeds=True,
                fd_set_unchanged=True,artifact_parent_empty=True)



def typed_request(function,arguments):
    raw=bytearray(256);raw[:8]=b'HIAMVTC1'
    struct.pack_into('<6Q',raw,40,*function,*arguments)
    return bytes(raw)


def typed_calls(path,files,parent):
    """Actual fixed Value role -> lease-held scalar ABI -> real loaded function."""
    import types
    from tools.qualify_hia_result_value_resources import Values as Records
    from tools.qualify_hia_result_value_records import TYPES
    from hepta.hia_program import scalar_value_valid, integer_range
    owner=Owner(path);owner.initialize();carrier=Carrier(owner);api=Lifecycle(owner)
    values=Records(ValueTransport(owner))
    before=set(os.listdir('/proc/self/fd'))
    program=old.scalar_program(None);program['functions']=[]
    signatures=[]
    for typ in TYPES:
        function=old.scalar_program(None,typ=typ)['functions'][0]
        function['name']='identity_'+typ
        program['functions'].append(function)
        signatures.append(types.SimpleNamespace(function=function['name'],parameters=(typ,),result=typ))
    runtime=carrier.q(1,payload=old.public_request(0,files=files,parent=os.fsencode(parent),
                    raw=old.rawdoc(program)),child=0)['cap']
    cap=old.lease(carrier,runtime)
    ns=dict(threading=threading,scalar_value_valid=scalar_value_valid)
    source=old.extract('hepta/hia_multiversion.py',{'GenerationLease','MultiversionRejected','_reject'},ns)
    class Runtime:
        releases=0
        def _release(self,*unused):self.releases+=1
    original_runtime=Runtime()
    generation=types.SimpleNamespace(_retention=None,info=types.SimpleNamespace(abi=signatures),
                                    functions={item.function:lambda x:x for item in signatures})
    original=ns['GenerationLease'](original_runtime,generation,0)
    error_status={'unknown function in this generation':(33,20),
                  'native arguments must be an exact scalar list or tuple':(33,21),
                  'native arguments differ from the exact scalar ABI':(33,22),
                  'generation lease is closed':(32,0)}
    rows=[]
    def compare(function,arguments,function_cap,arguments_cap,label):
        live=get(values.raw(47),48)
        try:
            expected=original.call(function,arguments)
        except ns['MultiversionRejected'] as exc:
            expected_error=str(exc)
        else:expected_error=None
        result=carrier.q(4,cap,typed_request(function_cap,arguments_cap))
        child=result['child'];assert child
        if expected_error is None:
            assert get(child,8)==0 and get(child,16)==0 and get(child,72)==0,result['row']
            actual=json.loads(result['value'])
            assert type(actual) is type(expected) and actual==expected,(label,actual,expected)
            row=dict(case=label,success=True,result=actual)
        else:
            assert expected_error.startswith('E_HIA_MULTIVERSION: ')
            status,native=error_status[expected_error.removeprefix('E_HIA_MULTIVERSION: ')]
            assert get(child,8)!=0 and get(child,16)==status and get(child,72)==native,(label,child[:128].hex(),expected_error)
            assert not result['value']
            row=dict(case=label,success=False,error=expected_error,coordinator_error=status,native_error=native)
        assert get(values.raw(47),48)==live,'owner must drop both temporary argument caps'
        rows.append(row)
    for typ in TYPES:
        if typ=='bool':scalars=[False,True,0,1,-1,None,0.0,'true',b'true']
        else:
            lo,hi=integer_range(typ)
            scalars=[lo-1,lo,lo+1,-1,0,1,hi-1,hi,hi+1,True,False,1.0,None,'1',b'1']
        name='identity_'+typ;function=values.scalar(name)
        for i,item in enumerate(scalars):
            value=values.scalar(item)
            for tuple_mode in (False,True):
                arguments=values.tuple([value]) if tuple_mode else values.lst([value])
                compare(name,(item,) if tuple_mode else [item],function,arguments,
                        typ+'-'+str(i)+('-tuple' if tuple_mode else '-list'))
                values.drop(arguments)
            values.drop(value)
        values.drop(function)
    valid_name='identity_u64';valid=values.scalar(valid_name);bad=values.scalar(None)
    unknown=values.scalar('missing')
    compare('missing',None,unknown,bad,'unknown-function-before-arguments')
    for item in (None,False,42,2.0,b'identity_u64'):
        fn=values.scalar(item);compare(item,None,fn,bad,'non-exact-function-'+type(item).__name__);values.drop(fn)
    for item in (None,False,42,2.0,b'args','args',{}):
        args=values.dictionary([]) if type(item) is dict else values.scalar(item)
        compare(valid_name,item,valid,args,'non-exact-arguments-'+type(item).__name__);values.drop(args)
    for seq in ([],[1,2]):
        items=[values.scalar(x) for x in seq];args=values.lst(items)
        compare(valid_name,seq,valid,args,'arity-'+str(len(seq)))
        for value in [args]+items:values.drop(value)
    # Actual native class identity rejects subclasses, even when their names match.
    class StringAlias(str):pass
    class ListAlias(list):pass
    str_builtin=values.builtin(6);str_cls=values.cls('StringAlias',[str_builtin])
    str_instance=values.instance(str_cls,valid)
    compare(StringAlias(valid_name),None,str_instance,bad,'string-subclass-not-exact')
    list_builtin=values.builtin(8);list_cls=values.cls('ListAlias',[list_builtin])
    one=values.scalar(1);list_base=values.lst([one]);list_instance=values.inherited(list_cls,list_base)
    compare(valid_name,ListAlias([1]),valid,list_instance,'list-subclass-not-exact')
    # The private transport stays private and every failed envelope releases its retained args.
    controls=[]
    for offset in (8,16,24,32,88,120,128,248):
        raw=bytearray(typed_request(valid,list_base));struct.pack_into('<Q',raw,offset,1)
        live=get(values.raw(47),48)
        result=carrier.q(4,cap,bytes(raw),want=3)
        assert get(values.raw(47),48)==live
        controls.append(offset)
    carrier.q(4,runtime,typed_request(valid,list_base),want=3)
    # Close has priority over unknown function, invalid arguments and ABI failures.
    old.ok(api.call(1,cap));original.close()
    for name,args,fc,ac,label in (
        ('missing',None,unknown,bad,'closed-before-unknown-and-bad-arguments'),
        (valid_name,None,valid,bad,'closed-before-bad-arguments'),
        (valid_name,[1],valid,list_base,'closed-before-valid-call'),
        (StringAlias(valid_name),None,str_instance,bad,'closed-before-subclass')):
        compare(name,args,fc,ac,label)
    assert original_runtime.releases==1
    old.ok(api.call(6,cap))
    carrier.q(4,runtime,old.public_request(8),child=0);carrier.q(3,runtime)
    for item in list(values.held):values.drop(item)
    values.engine.finish()
    assert owner.call(3)['status']==0
    assert not list(parent.iterdir()) and set(os.listdir('/proc/self/fd'))==before
    return dict(original_source=source,actual_fixed_value_role=True,actual_loaded_scalar_functions=True,
                comparisons=len(rows),cases=rows,private_reserved_controls=controls,
                temporary_argument_caps_released=True,fd_set_unchanged=True,
                artifact_parent_empty=True,lock_notification_proof_pending=True)


def tool_bank_custody(path,files):
    import fcntl
    owner=Owner(path);owner.initialize()
    before=set(os.listdir('/proc/self/fd'))
    # All inputs are real sealed files. The second request FD is genuinely invalid;
    # the first successful duplicate must be closed during rollback.
    bad=struct.pack('<4Q',int.from_bytes(b'HIAGLTB1','little'),files[0][0],2147483646,files[2][0])
    failed=owner.call(6,bad)
    assert failed['status']==5 and failed['state']==1
    assert all(get(owner.context,i)==0 for i in (88,96,104,112,120))
    assert set(os.listdir('/proc/self/fd'))==before
    inputs=[os.dup(fd) for fd,_ in files]
    payload=struct.pack('<4Q',int.from_bytes(b'HIAGLTB1','little'),*inputs)
    captured=owner.call(6,payload);assert captured['status']==0 and captured['state']==1
    owned=[get(owner.context,i) for i in (88,96,104)]
    assert len(set(owned+inputs))==6 and get(owner.context,112)==1
    for fd in inputs:os.close(fd)
    for fd,(_,raw) in zip(owned,files):
        assert os.fstat(fd).st_size==len(raw)
        assert sha(os.pread(fd,len(raw),0))==sha(raw)
        assert fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
        assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)&15==15
    assert owner.call(6,payload)['status']==2
    assert owner.call(3)['status']==0
    for fd in owned:
        try:os.fstat(fd)
        except OSError as exc:assert exc.errno==9
        else:raise AssertionError(('owned descriptor survived acknowledged close',fd))
    assert set(os.listdir('/proc/self/fd'))==before
    return dict(actual_fcntl_duplicates=True,caller_descriptors_independent=True,
                sealed_tool_bytes_preserved=True,duplicate_configuration_refused=True,
                partial_capture_rolled_back=True,all_owned_descriptors_closed=True,
                fd_set_unchanged=True,source_authority_binding_pending=True)


def deny_syscall(number,error):
    """Real child-only kernel rejection; no fabricated native feedback."""
    class Filter(C.Structure):
        _fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
    class Program(C.Structure):
        _fields_=[('length',C.c_ushort),('filters',C.POINTER(Filter))]
    rules=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,number),
                     Filter(0x06,0,0,0x00050000|error),Filter(0x06,0,0,0x7fff0000))
    program=Program(4,rules)
    libc=C.CDLL(None,use_errno=True)
    assert libc.prctl(38,1,0,0,0)==0,C.get_errno()
    assert libc.prctl(22,2,C.byref(program),0,0)==0,C.get_errno()


def os_failure_retention(path,out):
    records=[]
    for label,number,error in (('init-getrandom',318,5),('init-mmap',9,12),('retire-munmap',11,5)):
        report_path=out/(label+'.json')
        pid=os.fork()
        if pid==0:
            try:
                owner=Owner(path)
                output=mmap.mmap(-1,OUT)
                init=C.create_string_buffer(envelope(0));destroy=C.create_string_buffer(envelope(3))
                def invoke(source):
                    rc=owner.entry(source,64,address(output),OUT,owner.context,CONTEXT_BYTES)
                    assert rc==0 and output[:8]==b'HIAGLOR1'
                    return get(output,8),get(output,48)
                if label=='retire-munmap':
                    assert invoke(init)==(0,1)
                    arena=get(owner.context,528);extent=get(owner.context,552)
                    assert arena and extent
                    deny_syscall(number,error)
                    assert invoke(destroy)==(5,6)
                    assert get(owner.context,592)==1
                    assert get(owner.context,600)==arena and get(owner.context,608)==extent
                    assert get(owner.context,616)!=0
                    assert get(owner.context,528)==arena and get(owner.context,552)==extent
                    assert invoke(destroy)==(5,6)
                    assert get(owner.context,528)==arena and get(owner.context,552)==extent
                    row=dict(case=label,actual_kernel_refusal=True,anchor_consumed_once=True,
                             actual_mapping_retained=True,retry_still_refused=True,
                             owner_not_reported_destroyed=True)
                else:
                    deny_syscall(number,error)
                    assert invoke(init)==(5,4)
                    assert get(owner.context,528)==0
                    assert invoke(destroy)==(0,3)
                    assert bytes(owner.context)[128:]==bytes(CONTEXT_BYTES-128)
                    row=dict(case=label,actual_kernel_refusal=True,failed_init_owner_retired=True,
                             no_value_mapping_owned=True)
                report_path.write_text(json.dumps(row)+'\n');os._exit(0)
            except BaseException as exc:
                report_path.write_text(json.dumps(dict(case=label,error=repr(exc)))+'\n');os._exit(73)
        _,status=os.waitpid(pid,0)
        assert os.waitstatus_to_exitcode(status)==0,(label,status,report_path.read_text())
        records.append(json.loads(report_path.read_text()))
    return records


def main():
    ap=argparse.ArgumentParser()
    for name in ('compiler','normalizer','proof','builder','output'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    assert sha(a.compiler.read_bytes())==old.COMPILER_SHA
    flats,rows=compile_all(a.compiler,a.output)
    bridges=bridge_identity(a.output)
    path,build=build_images(flats,a.output)
    files=[];executables=[]
    for name in ('normalizer','proof','builder'):
        raw=getattr(a,name).read_bytes();files.append((old.sealed(raw),raw))
        executables.append(dict(role=name,bytes=len(raw),sha256=sha(raw)))
    try:
        reports={}
        for name,first in (('lease-first',False),('runtime-first',True)):
            parent=a.output/(name+'-artifacts');parent.mkdir(mode=0o700)
            reports[name]=lifecycle_case(path,files,parent,first)
        parent=a.output/'active-artifacts';parent.mkdir(mode=0o700)
        reports['active_destroy']=active_destroy(path,files,parent)
        reports['os_failure_retention']=os_failure_retention(path,a.output)
        reports['tool_bank_custody']=tool_bank_custody(path,files)
        parent=a.output/'typed-artifacts';parent.mkdir(mode=0o700)
        reports['typed_calls']=typed_calls(path,files,parent)
        report=dict(schema='hepta.hia.generation-lease-owner.qualification.v1',passed=True,failed=0,
                    compiler_sha256=old.COMPILER_SHA,compile=rows,bridges=bridges,build=build,
                    executables=executables,cases=reports,source_bound_enclosing_owner=True,
                    supplied_callback_or_child_context=False,typed_call_basic_qualified=True,typed_call_qualified=False,
                    generation_info_qualified=False,whole_native_runtime=False,
                    final_aggregate_claimed=False,production_activated=False)
        (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        print('GENERATION_LEASE_OWNER_PASS',build['products'][PRODUCTS[0]]['sha256'],flush=True)
    finally:
        for fd,_ in files:os.close(fd)


if __name__=='__main__':
    main()
