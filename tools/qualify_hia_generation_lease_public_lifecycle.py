"""Rebuild and exercise the native public GenerationLease lifecycle.

This is an external development oracle. Product calls contain only operations
and registered capabilities. Captured entries and contexts stand for the
enclosing source-bound owner; this facet does not claim that enclosing API.
"""
from pathlib import Path
import argparse, ast, concurrent.futures, copy, ctypes as C, fcntl, hashlib
import json, mmap, os, struct, subprocess, threading, time, types
from tools.qualify_hia_publication_cancellation import Image, address

ROOT=Path(__file__).resolve().parents[1]
COMPILER_SHA='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
BASE='ecd688626409d1adcf4e04a7a535c1b2c45a13ce'
ROLES=[
  {
    "role": "handles",
    "path": "examples/hia_bootstrap/multiversion_runtime_handles.hepta"
  },
  {
    "role": "effects",
    "path": "examples/hia_bootstrap/multiversion_runtime_effects.hepta"
  },
  {
    "role": "state",
    "path": "examples/hia_bootstrap/multiversion_runtime_state.hepta"
  },
  {
    "role": "retention",
    "path": "examples/hia_bootstrap/generation_retention.hepta"
  },
  {
    "role": "call",
    "path": "examples/hia_bootstrap/multiversion_call.hepta"
  },
  {
    "role": "typed",
    "path": "examples/hia_bootstrap/multiversion_measurement_typed.hepta"
  },
  {
    "role": "information",
    "path": "examples/hia_bootstrap/multiversion_runtime_information.hepta"
  },
  {
    "role": "information_capture",
    "path": "examples/hia_bootstrap/multiversion_runtime_information_capture.hepta"
  },
  {
    "role": "gen_generation",
    "path": "examples/hia_bootstrap/multiversion_runtime_generation.hepta"
  },
  {
    "role": "gen_intake_prepare",
    "path": "examples/hia_bootstrap/multiversion_prepare_intake.hepta"
  },
  {
    "role": "gen_intake_process",
    "path": "examples/hia_bootstrap/multiversion_prepare_process.hepta"
  },
  {
    "role": "gen_intake_intake",
    "path": "examples/hia_bootstrap/multiversion_intake.hepta"
  },
  {
    "role": "gen_intake_admission",
    "path": "examples/hia_bootstrap/core_admission.hepta"
  },
  {
    "role": "gen_intake_canonical",
    "path": "examples/hia_bootstrap/json_canonical.hepta"
  },
  {
    "role": "gen_intake_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "gen_intake_profile",
    "path": "examples/hia_bootstrap/multiversion_profile.hepta"
  },
  {
    "role": "gen_intake_scalar",
    "path": "examples/hia_bootstrap/scalar_profile.hepta"
  },
  {
    "role": "gen_intake_abi",
    "path": "examples/hia_bootstrap/multiversion_abi.hepta"
  },
  {
    "role": "gen_proof_prepare",
    "path": "examples/hia_bootstrap/multiversion_prepare_proof.hepta"
  },
  {
    "role": "gen_proof_process",
    "path": "examples/hia_bootstrap/multiversion_prepare_process.hepta"
  },
  {
    "role": "gen_proof_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "gen_proof_json",
    "path": "examples/hia_bootstrap/native_public_proof_json.hepta"
  },
  {
    "role": "gen_proof_receipt",
    "path": "examples/hia_bootstrap/native_public_proof_receipt.hepta"
  },
  {
    "role": "gen_prepare_owner",
    "path": "examples/hia_bootstrap/multiversion_prepare_owner.hepta"
  },
  {
    "role": "gen_prepare_capture",
    "path": "examples/hia_bootstrap/multiversion_prepare_capture.hepta"
  },
  {
    "role": "gen_prepare_process",
    "path": "examples/hia_bootstrap/multiversion_prepare_process.hepta"
  },
  {
    "role": "gen_prepare_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "gen_prepare_json",
    "path": "examples/hia_bootstrap/native_public_proof_json.hepta"
  },
  {
    "role": "gen_prepare_image",
    "path": "examples/hia_bootstrap/multiversion_prepare_image.hepta"
  },
  {
    "role": "gen_prepare_sha",
    "path": "examples/hia_bootstrap/sha256_stream.hepta"
  },
  {
    "role": "gen_prepare_elf",
    "path": "examples/hia_bootstrap/safe_core_elf_inventory.hepta"
  },
  {
    "role": "gen_prepare_mapping",
    "path": "examples/hia_bootstrap/native_mapping.hepta"
  },
  {
    "role": "gen_prepare_probe",
    "path": "examples/hia_bootstrap/multiversion_probe_owner.hepta"
  },
  {
    "role": "gen_prepare_vectors",
    "path": "examples/hia_bootstrap/multiversion_probes.hepta"
  },
  {
    "role": "gen_prepare_projector",
    "path": "examples/hia_bootstrap/evaluate_reference_wire.hepta"
  },
  {
    "role": "gen_prepare_vm",
    "path": "examples/hia_bootstrap/scalar_reference.hepta"
  },
  {
    "role": "gen_prepare_retire",
    "path": "examples/hia_bootstrap/multiversion_retirement.hepta"
  },
  {
    "role": "gen_prepare_retirement_state",
    "path": "examples/hia_bootstrap/retirement_state.hepta"
  },
  {
    "role": "identity_identity",
    "path": "examples/hia_bootstrap/multiversion_runtime_identity.hepta"
  },
  {
    "role": "identity_numbers",
    "path": "examples/hia_bootstrap/multiversion_runtime_numbers.hepta"
  },
  {
    "role": "identity_values_owner",
    "path": "examples/hia_bootstrap/multiversion_values.hepta"
  },
  {
    "role": "identity_unsigned",
    "path": "examples/hia_bootstrap/unsigned_decimal_values.hepta"
  },
  {
    "role": "future",
    "path": "examples/hia_bootstrap/multiversion_future.hepta"
  },
  {
    "role": "measurement_owner",
    "path": "examples/hia_bootstrap/multiversion_measurement_owner.hepta"
  },
  {
    "role": "measurement_measurement",
    "path": "examples/hia_bootstrap/publication_measurement.hepta"
  },
  {
    "role": "measurement_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "snapshot",
    "path": "examples/hia_bootstrap/multiversion_runtime_snapshot.hepta"
  },
  {
    "role": "snapshot_capture",
    "path": "examples/hia_bootstrap/multiversion_runtime_snapshot_capture.hepta"
  },
  {
    "role": "snapshot_number",
    "path": "examples/hia_bootstrap/multiversion_runtime_snapshot_number.hepta"
  }
]
PUBLIC={'handles':'multiversion_runtime_public_handles','effects':'multiversion_runtime_public_effects',
        'state':'multiversion_runtime_public_state'}
OUT=(96<<20)+16384
BAD=0xfffffffd
NONE=(1<<64)-1
SCHEMA='hepta.hia.program.v1'
Q=int.from_bytes(b'HIAGLQ01','little')
R=int.from_bytes(b'HIAGLR01','little')
get=lambda b,i:struct.unpack_from('<Q',b,i)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
rawdoc=lambda d:json.dumps(d,separators=(',',':'),ensure_ascii=True).encode()
if not hasattr(fcntl,'F_ADD_SEALS'):
    fcntl.F_ADD_SEALS=1033

def source_file(path):
    found=ROOT/path
    return found if found.exists() else ROOT/'reference'/path

def extract(path,names,namespace):
    p=source_file(path);raw=p.read_bytes();tree=ast.parse(raw)
    nodes=[n for n in tree.body if getattr(n,'name',None) in names]
    assert len(nodes)==len(names),(path,names)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(p),'exec'),namespace)
    return {'path':path,'source_sha256':sha(raw),'source_bytes':len(raw),'source_revision':BASE}

extract('tools/qualify_hia_multiversion_runtime_handles.py',{'Carrier','inner'},globals())
extract('tools/qualify_hia_multiversion_prepare_process.py',{'sealed'},globals())
extract('tests/test_hia_multiversion.py',{'scalar_program'},globals())

def public_request(op,**kwargs):
    raw=bytearray(inner(op,**kwargs));raw[:8]=b'HIAMVEX3';return bytes(raw)

def compiler_run(compiler,raw,label):
    runs=[subprocess.run([str(compiler),'compile'],input=raw,capture_output=True,timeout=30)
          for _ in range(2)]
    assert all(r.returncode==0 for r in runs),(label,[(r.returncode,r.stderr) for r in runs])
    assert runs[0].stdout==runs[1].stdout,label
    return runs[0].stdout

def compile_all(compiler,out):
    names=[Path(r['path']).stem for r in ROLES]+list(PUBLIC.values())+[
        'multiversion_runtime_handles_packer','multiversion_runtime_linker',
        'generation_lease_public_lifecycle','generation_lease_public_lifecycle_packer']
    results=[];flats={}
    for name in dict.fromkeys(names):
        path='examples/hia_bootstrap/'+name+'.hepta';raw=(ROOT/path).read_bytes()
        flat=compiler_run(compiler,raw,name);flats[name]=flat
        (out/(name+'.flat')).write_bytes(flat)
        results.append({'path':path,'source_bytes':len(raw),'source_sha256':sha(raw),
            'flat_bytes':len(flat),'flat_sha256':sha(flat),'two_builds_identical':True})
    return flats,results

def run_packer(flat,raw,capacity=32<<20):
    image=Image(flat);source=C.create_string_buffer(raw)
    with mmap.mmap(-1,capacity) as output,mmap.mmap(-1,1<<20) as workspace:
        n=image.entry(source,len(raw),address(output),len(output),address(workspace),len(workspace))
        assert 0<n<len(output),(n,len(output))
        return bytes(output[:n])

def carrier_image(flats,out,public=True,capture=None):
    rows=[];bodies=[]
    for role in ROLES:
        name=PUBLIC.get(role['role'],Path(role['path']).stem) if public else Path(role['path']).stem
        raw=capture if capture is not None and role['role']=='snapshot_capture' else flats[name]
        rows.append({'role':role['role'],'path':'examples/hia_bootstrap/'+name+'.hepta',
                     'flat_bytes':len(raw),'flat_sha256':sha(raw)})
        bodies.append(raw)
    frame=struct.pack('<'+str(2+len(bodies))+'Q',int.from_bytes(b'HIAMVHK2','little'),
                      len(bodies),*map(len,bodies))+b''.join(bodies)
    obj=run_packer(flats['multiversion_runtime_handles_packer'],frame)
    image=run_packer(flats['multiversion_runtime_linker'],obj)
    name='public-carrier' if public else 'baseline-carrier'
    path=out/(name+'.so');path.write_bytes(image)
    (out/(name+'.o')).write_bytes(obj)
    return path,{'roles':rows,'image_bytes':len(image),'image_sha256':sha(image),
                 'object_bytes':len(obj),'object_sha256':sha(obj),
                 'native_pack':True,'native_link':True,'host_library':'libc.so.6'}

def lifecycle_image(flats,out):
    from tools.generate_hia_generation_lease_public_lifecycle_packer import BRIDGE,HOLES,reference_image
    subprocess.run(['as','--64',str(ROOT/'tools/hia_generation_lease_public_lifecycle_bridge.S'),
                    '-o',str(out/'prefix.o')],check=True,capture_output=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(out/'prefix.o'),
                    str(out/'prefix.bin')],check=True,capture_output=True)
    assert (out/'prefix.bin').read_bytes()==BRIDGE
    reloc=subprocess.run(['readelf','-r',str(out/'prefix.o')],check=True,capture_output=True,text=True)
    assert 'There are no relocations in this file.' in reloc.stdout
    policy=flats['generation_lease_public_lifecycle'];expected=reference_image([policy])
    frame=struct.pack('<8Q',int.from_bytes(b'HIAGLPK1','little'),1,len(policy),0,0,0,0,0)+policy
    packer=Image(flats['generation_lease_public_lifecycle_packer'])
    def invoke(raw,capacity=None):
        source=C.create_string_buffer(raw)
        with mmap.mmap(-1,len(expected)+64) as output,mmap.mmap(-1,4096) as workspace:
            output[:]=b'\xa5'*len(output)
            rc=packer.entry(source,len(raw),address(output),len(expected) if capacity is None else capacity,
                            address(workspace),len(workspace))
            return rc,bytes(output)
    rc,body=invoke(frame);assert rc==len(expected) and body[:rc]==expected and body[rc:]==b'\xa5'*64
    negatives=[('truncated-'+str(n),frame[:n],None) for n in (0,1,8,63,len(frame)-1)]
    negatives.append(('trailing',frame+b'\0',None))
    for offset,value in ((0,0),(8,0),(8,2),(16,0),(16,4194305),(16,NONE),
                         (24,1),(32,1),(40,1),(48,1),(56,1)):
        bad=bytearray(frame);struct.pack_into('<Q',bad,offset,value)
        negatives.append((str((offset,value)),bytes(bad),None))
    negatives.append(('short-output',frame,len(expected)-1))
    for label,raw,capacity in negatives:
        result,data=invoke(raw,capacity)
        assert result==BAD and data==b'\xa5'*len(data),(label,result)
    (out/'generation-lease-lifecycle.flat').write_bytes(expected)
    return Image(expected),{'image_bytes':len(expected),'image_sha256':sha(expected),
        'prefix_bytes':len(BRIDGE),'prefix_sha256':sha(BRIDGE),'call_holes':HOLES,
        'native_packer_matches_reference':True,'readable_prefix_exact':True,
        'dynamic_imports':[],'rejected_pack_frames':len(negatives)}

class Lifecycle:
    def __init__(self,image,carrier):
        self.image=image;self.carrier=carrier;self.context=C.create_string_buffer(128)
        self.calls=0;self.lock=threading.Lock()
        struct.pack_into('<5Q',self.context,0,int.from_bytes(b'HIAGLC01','little'),
            C.cast(carrier.f,C.c_void_p).value,C.addressof(carrier.w),256,os.getpid())
    def call(self,op,cap,output=None):
        raw=struct.pack('<8Q',Q,op,*cap,0,0,0);source=C.create_string_buffer(raw)
        own=output is None
        if own:output=mmap.mmap(-1,OUT)
        rc=self.image.entry(source,64,address(output),OUT,self.context,128)
        assert source.raw==raw+b'\0'
        assert rc==0,(op,rc)
        words=struct.unpack_from('<16Q',output);assert words[0]==R and words[7]<=256
        result={'op':op,'status':words[1],'kind':words[2],'cap':list(words[3:6]),
            'error_code':words[6],'error':json.loads(output[128:128+words[7]]) if words[7] else None,
            'child_status':words[8],'retained':words[10],'finalizer':words[11]}
        with self.lock:self.calls+=1
        if own:output.close()
        return result

def ok(record,status=0):
    assert record['status']==status,record
    return record

def create(carrier,files,parent):
    return carrier.q(1,payload=public_request(0,files=files,parent=os.fsencode(parent),
                     raw=rawdoc(scalar_program(None))),child=0)['cap']

def lease(carrier,runtime):
    return carrier.q(4,runtime,public_request(3),child=0)['cap']

def detached(result):
    child=result['child'];pointer=get(child,144);length=get(child,152)
    assert pointer and length
    return pointer,length,C.string_at(pointer,length)

def free(pointer):
    fn=C.CDLL(None).free;fn.argtypes=[C.c_void_p];fn(pointer)

def release_detached(result):
    if result['child'] and get(result['child'],144):
        pointer,length,raw=detached(result);free(pointer);return raw
    return b''

def compare_original(api,cap):
    ns={'threading':threading}
    oracle=extract('hepta/hia_multiversion.py',{'GenerationLease','MultiversionRejected','_reject'},ns)
    class Runtime:
        releases=0
        def _release(self,*unused):self.releases+=1
    runtime=Runtime();generation=types.SimpleNamespace(_retention=None,info=object())
    original=ns['GenerationLease'](runtime,generation,0)
    operations=[(0,'__enter__'),(3,'__copy__'),(4,'__deepcopy__'),(1,'close'),
                (0,'__enter__'),(1,'close'),(2,'__exit__'),(3,'__copy__'),(4,'__deepcopy__'),(0,'__enter__')]
    rows=[]
    for op,name in operations:
        result=api.call(op,cap)
        try:
            fn=getattr(original,name)
            expected=fn({}) if op==4 else fn()
            ok(result)
            if op==0:assert expected is original and result['kind']==1 and result['cap']==list(cap)
            else:assert expected is None and result['kind']==0
        except ValueError as exc:
            ok(result,4);assert result['error']=={'class':type(exc).__name__,'message':str(exc)},result
        rows.append(result)
    assert runtime.releases==1
    return {'source':oracle,'scope':'exact original class reference-retention branch; native lifetime separately exercised',
            'comparisons':rows,'pairs':len(rows),'reference_release_count':runtime.releases}

def guards(api,carrier,runtime,cap,image):
    other=Carrier(carrier.lib._name,[]);other.q(0);foreign_api=Lifecycle(image,other)
    cases=[(0,0,0),(1,1,1),(NONE,0,0),(cap[0],cap[1]^1,cap[2]),
           (cap[0],cap[1],cap[2]^1),runtime]
    for candidate in cases:
        for op in range(7):ok(api.call(op,candidate),1)
    for op in range(7):ok(foreign_api.call(op,cap),1)
    other.q(5)
    raw=struct.pack('<8Q',Q,0,*cap,0,0,0);source=C.create_string_buffer(raw)
    with mmap.mmap(-1,OUT+64) as output:
        output[:1024]=b'\xa5'*1024;output[OUT:]=b'\x5a'*64
        original_context=bytes(api.context);original_carrier=bytes(carrier.w)
        base=[C.addressof(source),64,address(output),OUT,C.addressof(api.context),128]
        invalid=[]
        for index,value in ((0,0),(2,0),(4,0),(1,0),(1,63),(1,65),(3,OUT-1),(5,127),
                            (0,NONE-31),(2,NONE-31),(4,NONE-63),(4,C.addressof(api.context)+1)):
            args=list(base);args[index]=value;invalid.append(args)
        for left,right in ((0,2),(0,4),(2,4),(4,2)):
            args=list(base);args[left]=args[right];invalid.append(args)
        for args in invalid:
            assert image.entry(*args)==BAD,args
            assert output[:1024]==b'\xa5'*1024 and output[OUT:]==b'\x5a'*64
            assert bytes(api.context)==original_context and bytes(carrier.w)==original_carrier
        malformed=[]
        for offset,value in ((0,0),(8,7),(8,NONE),(40,1),(48,1),(56,1)):
            change=bytearray(raw);struct.pack_into('<Q',change,offset,value);malformed.append(change)
        for change in malformed:
            changed=C.create_string_buffer(bytes(change))
            assert image.entry(changed,64,address(output),OUT,api.context,128)==BAD
            assert output[:128]==b'\xa5'*128 and output[OUT:]==b'\x5a'*64
            assert bytes(api.context)==original_context and bytes(carrier.w)==original_carrier
        ok(api.call(0,cap,output))
        assert output[OUT:]==b'\x5a'*64
    # New private protocol only admits a registered lease with an exactly empty tail.
    private=[]
    for offset in (8,16,24,32,40,80,120,128,248):
        frame=bytearray(256);frame[:8]=b'HIAMVLA1';struct.pack_into('<Q',frame,offset,1)
        carrier.q(4,cap,bytes(frame),want=3,child=0);private.append(offset)
    frame=bytearray(256);frame[:8]=b'HIAMVLA1'
    carrier.q(4,runtime,bytes(frame),want=3,child=0)
    return {'forged_and_wrong_kind_calls':len(cases)*7,'foreign_context_calls':7,
            'invalid_views':len(invalid),'malformed_frames':len(malformed),
            'private_reserved_field_refusals':private,'private_runtime_kind_refused':True,
            'no_writes_on_invalid_views':True,'outer_canary_preserved':True}

def fork_refusal(api,cap):
    pid=os.fork()
    if pid==0:
        try:ok(api.call(0,cap),3);os._exit(0)
        except BaseException:os._exit(71)
    _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==0,status
    ok(api.call(0,cap))
    return {'child_lifecycle_refusal':True,'parent_remains_usable':True}

def races(api,carrier,runtime):
    cap=lease(carrier,runtime);refs=[cap]+[ok(api.call(5,cap))['cap'] for _ in range(7)]
    gate=threading.Barrier(8)
    def work(index):
        gate.wait();outcomes={0:0,4:0}
        with mmap.mmap(-1,OUT) as output:
            for i in range(24):
                if index==0 and i==2:ok(api.call(1,refs[index],output))
                row=api.call(0,refs[index],output)
                assert row['status'] in outcomes,row
                if row['status']==4:assert row['error_code']==1
                outcomes[row['status']]+=1
            ok(api.call(2,refs[index],output));ok(api.call(6,refs[index],output))
        return outcomes
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:threads=list(pool.map(work,range(8)))
    cap=lease(carrier,runtime);gate=threading.Barrier(12)
    def drop(_):gate.wait();return api.call(6,cap)['status']
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:status=list(pool.map(drop,range(12)))
    assert status.count(0)==1 and status.count(1)==11,status
    observed={0:0,1:0}
    for _ in range(48):
        cap=lease(carrier,runtime);gate=threading.Barrier(2)
        def enter():gate.wait();return api.call(0,cap)
        def release():gate.wait();return api.call(6,cap)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            seen=pool.submit(enter);released=pool.submit(release);a=seen.result();ok(released.result())
        assert a['status'] in observed,a;observed[a['status']]+=1
    return {'retained_ref_threads':8,'require_open_calls':192,'outcomes_per_thread':threads,
            'same_cap_drop_successes':1,'same_cap_drop_refusals':11,'last_drop_pin_races':48,
            'last_drop_pin_outcomes':observed}

def capture_rejection_controls(flat):
    # Private continuation negative tests only. No supplied status is used to
    # grant public success, construction, or proof.
    image=Image(flat);source=C.create_string_buffer(256);records=[]
    cases=[
        ('legacy-u64-query',1403,NONE-1,1330,0,0),
        ('query-success-without-size-negotiation',1403,0,1330,0,0),
        ('zero-required',1403,0xfffffffe,0,0,0),
        ('query-recorded-error',1403,0xfffffffe,1330,0,1),
        ('legacy-success-is-length',1405,1330,1330,1330,0),
        ('success-capacity-changed',1405,0,1331,1330,0),
        ('success-recorded-error',1405,0,1330,1330,1)]
    for label,phase,feedback,required,allocated,error in cases:
        with mmap.mmap(-1,40<<20) as output,mmap.mmap(-1,131072) as work:
            for offset,value in ((128,phase),(136,feedback),(32768,1),(98304,1),
                                 (98392,allocated),(16777216,required),(16777216+48,error)):
                struct.pack_into('<Q',output,offset,value)
            rc=image.entry(source,256,address(output),len(output),address(work),len(work))
            assert rc==10 and get(output,128)==1600 and get(output,98328)==9,(label,rc)
            assert get(output,27184)==0 and get(output,27192)==0
            assert get(work,104448)==0 and get(work,104456)==0
            records.append({'name':label,'next':'cleanup-owned-capture','error':9,
                            'snapshot_or_history_published':False})
    return records

def old_capture(compiler,out):
    # Reconstitute the two stale call-site conditions from the exact fixed
    # authoring source. This diagnostic artifact is not a product role.
    from tools import generate_hia_multiversion_runtime_snapshot_capture as g
    src=g.source_program()
    current='if get(o,136)!=4294967294 or get(o,16777216)==0 or get(o,16777216+48)!=0:'
    old='if get(o,136)!=18446744073709551615-1 or get(o,16777216)==0:'
    assert src.count(current)==1;src=src.replace(current,old)
    current='if get(o,136)!=0 or get(o,16777216)!=get(o,98392) or get(o,16777216+48)!=0:'
    old='if get(o,136)!=get(o,98392):'
    assert src.count(current)==1;src=src.replace(current,old)
    raw=g.render_assembly(g.document(src,'multiversion_runtime_snapshot_capture')).encode()
    assert sha(raw)=='5f2158592b4d5338e4b2b0144031587ec0f1a00346b6a153b54699c679f0b4cf',sha(raw)
    flat=compiler_run(compiler,raw,'baseline-capture')
    (out/'baseline-capture.flat').write_bytes(flat)
    return flat,{'source_sha256':sha(raw),'flat_sha256':sha(flat),'exact_ecd_source_reconstructed':True}

def baseline_failure(path,files,parent,output):
    # Failure retains its true native owner; run in an isolated process so the
    # diagnostic cannot leak that intentionally retained object into the suite.
    pid=os.fork()
    if pid==0:
        try:
            rows=[];carrier=Carrier(path,rows);carrier.q(0);runtime=create(carrier,files,parent)
            cap=lease(carrier,runtime);carrier.q(4,cap,public_request(5),child=0)
            release_detached(carrier.q(4,cap,public_request(6),child=0));carrier.q(3,cap)
            close=carrier.q(4,runtime,public_request(8),child=35)
            assert get(close['child'],72)==9
            retry=carrier.q(4,runtime,public_request(9),child=35)
            dropped=carrier.q(3,runtime,want=9)
            assert dropped['row']['retained']==1 and dropped['row']['finalizer']==5
            carrier.q(5,want=5)
            report={'reproduced':True,'close_status':35,'native_error':9,
                    'retry_status':35,'runtime_owner_retained':True,'finalizer_status':5,
                    'registry_not_destroyed':True,'artifact_parent_empty':not list(parent.iterdir()),
                    'process_isolation_releases_test_resources':True,'rows':rows}
            output.write_text(json.dumps(report,indent=2)+'\n');os._exit(0)
        except BaseException as exc:
            output.write_text(json.dumps({'error':repr(exc)})+'\n');os._exit(72)
    _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==0,(status,output.read_text())
    return json.loads(output.read_text())

def actual_lifecycle(path,image,files,parent):
    rows=[];carrier=Carrier(path,rows);carrier.q(0);api=Lifecycle(image,carrier)
    fd_before=set(os.listdir('/proc/self/fd'))
    runtime=create(carrier,files,parent);cap=lease(carrier,runtime)
    guard_report=guards(api,carrier,runtime,cap,image);fork_report=fork_refusal(api,cap)
    retained=ok(api.call(5,cap))['cap'];assert retained!=list(cap)
    carrier.call(cap,17)
    comparison=compare_original(api,cap)
    assert ok(api.call(0,retained),4)['error_code']==1
    info=carrier.q(4,cap,public_request(6),child=0);pointer,n,raw=detached(info)
    assert raw[:8]==b'HIAMVIR2';parsed=json.loads(raw[32:]);assert parsed
    legacy=bytearray(public_request(6));struct.pack_into('<Q',legacy,120,1)
    carrier.q(4,cap,bytes(legacy),want=3,child=0)
    ok(api.call(6,cap));ok(api.call(0,cap),1);ok(api.call(6,retained))
    racing=races(api,carrier,runtime)
    before=carrier.q(4,runtime,public_request(10),child=0);sp,sn,sraw=detached(before);snapshot=json.loads(sraw)
    assert snapshot['closed'] is False
    carrier.q(4,runtime,public_request(8),child=0)
    closed=release_detached(carrier.q(4,runtime,public_request(10),child=0))
    assert json.loads(closed)['closed'] is True
    release_detached(carrier.q(4,runtime,public_request(9),child=0))
    carrier.q(3,runtime);carrier.q(5)
    assert get(carrier.w,16)==get(carrier.w,40)==get(carrier.w,64)==0
    assert not list(parent.iterdir())
    assert C.string_at(pointer,n)==raw and C.string_at(sp,sn)==sraw
    free(pointer);free(sp)
    assert set(os.listdir('/proc/self/fd'))==fd_before
    return {'original':comparison,'guards':guard_report,'fork':fork_report,'races':racing,
            'old_ex3_nonzero_info_flag_refused':True,'closed_info_still_available':True,
            'detached_info_and_snapshot_survive_finalizer':True,
            'fd_set_unchanged':True,'artifact_parent_empty':True,'registry_counts_zero':True,
            'actual_public_calls':api.calls,'actual_carrier_calls':len(rows),'rows':rows}

def runtime_last_reference(path,image,files,parent):
    rows=[];carrier=Carrier(path,rows);carrier.q(0);api=Lifecycle(image,carrier)
    before=set(os.listdir('/proc/self/fd'))
    runtime=create(carrier,files,parent);cap=lease(carrier,runtime)
    carrier.q(4,runtime,public_request(8),child=0);carrier.q(3,runtime)
    carrier.q(5,want=5);ok(api.call(0,cap));carrier.call(cap,43)
    ok(api.call(1,cap));ok(api.call(6,cap));carrier.q(5)
    assert get(carrier.w,16)==get(carrier.w,40)==get(carrier.w,64)==0
    assert not list(parent.iterdir()) and set(os.listdir('/proc/self/fd'))==before
    return {'closed_runtime_retained_by_lease':True,'native_call_after_runtime_close':43,
            'last_lease_drop_runs_both_finalizers':True,'registry_counts_zero':True,
            'fd_set_unchanged':True,'artifact_parent_empty':True,'rows':rows}

def main():
    ap=argparse.ArgumentParser()
    for name in ('compiler','normalizer','proof','builder','output'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    assert sha(a.compiler.read_bytes())==COMPILER_SHA
    flats,compile_rows=compile_all(a.compiler,a.output)
    image,product=lifecycle_image(flats,a.output)
    carrier,build=carrier_image(flats,a.output)
    old,old_record=old_capture(a.compiler,a.output)
    baseline,baseline_build=carrier_image(flats,a.output,False,old)
    files=[];executables=[]
    for name in ('normalizer','proof','builder'):
        path=getattr(a,name);raw=path.read_bytes();files.append((sealed(raw),raw))
        executables.append({'role':name,'bytes':len(raw),'sha256':sha(raw)})
    try:
        parents=[]
        for name in ('baseline','lifecycle','last-reference'):
            p=a.output/(name+'-artifacts');p.mkdir(mode=0o700);parents.append(p)
        old_failure=baseline_failure(baseline,files,parents[0],a.output/'baseline-failure.json')
        controls=capture_rejection_controls(flats['multiversion_runtime_snapshot_capture'])
        real=actual_lifecycle(carrier,image,files,parents[1])
        finalizer=runtime_last_reference(carrier,image,files,parents[2])
        report={'schema':'hepta.hia.generation-lease-public-lifecycle.v1',
            'source_base':BASE,'compiler_sha256':COMPILER_SHA,'passed':True,'failed':0,
            'whole_native_runtime':False,'whole_public_api_equivalence':False,
            'final_aggregate_claimed':False,'compile':compile_rows,'public_product':product,
            'public_carrier':build,'executables':executables,
            'snapshot_abi_fix':{'baseline_build':baseline_build,'baseline_capture':old_record,
                'actual_baseline_failure':old_failure,'private_negative_controls':controls},
            'lifecycle':real,'last_reference':finalizer,
            'scope':{'actual_native_normalize_prove_build_seal_load_probe_call':True,
                'public_lifecycle_native_policy':True,'source_bound_enclosing_constructor':False,
                'generation_info_typed_owner':False,'typed_call_method':False,
                'complete_scalar_multiversion_runtime_public_owner':False}}
        (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        print('GENERATION_LEASE_PUBLIC_LIFECYCLE_PASS',real['actual_public_calls'],
              real['actual_carrier_calls'],product['image_sha256'],build['image_sha256'],flush=True)
    finally:
        for fd,_ in files:os.close(fd)

if __name__=='__main__':main()
