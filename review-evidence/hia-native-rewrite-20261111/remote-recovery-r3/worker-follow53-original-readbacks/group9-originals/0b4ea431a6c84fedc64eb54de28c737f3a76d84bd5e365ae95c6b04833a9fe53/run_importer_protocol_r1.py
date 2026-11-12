"""Actual-image protocol controls; no injected fixed-executor syscall faults.

The source leases below are private test fixtures issued by actual packet JSON.
They are not presented as arbitrary external authenticated program evidence.
"""
from hashlib import sha256
import gzip
import json
from pathlib import Path
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[1];OLD=ROOT.parent/'native-composite-driver-reconstructed';BASE=ROOT.parent/'Hepta-v66-restored'
sys.path[:0]=[str(ROOT),str(OLD/'development'),str(OLD),str(BASE)]
from publication_mechanical_executor import PublicBundle,Buffer
from mechanical_executor import actual_source_lease,C
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_instruction_policy_native import transport
from hepta.hia_core_admission_native import NativeCoreAdmission

dest=ROOT/'development/protocol-r1';dest.mkdir(parents=True,exist_ok=False)
bundle_path=ROOT/'development/build-r2/bundle.json';bundle_raw=bundle_path.read_bytes();bundle=json.loads(bundle_raw)
old=PublicBundle(OLD/'development/publication-bundle-r2/bundle.json')
pins=dict(old.pins);pins[bundle_path]=bundle_raw;pins[Path(__file__)]=Path(__file__).read_bytes()
images={};rows=[];native_calls={};start=time.monotonic_ns();summary={'status':'INCOMPLETE','scope':'PRIVATE_ACTUAL_IMAGE_PROTOCOL_CONTROLS','fixed_executor_fault_injection':False,'public_external_lease_authentication':False}

def pin(path):
    path=Path(path).resolve();raw=path.read_bytes()
    if path in pins:assert pins[path]==raw
    pins[path]=raw;return raw

for role,name in [(28,'projection'),(29,'compare'),(46,'import_driver')]:
    row=bundle['components'][str(role)];expected=ROOT/'examples/hia_bootstrap'/f'legacy_composite_{name}.hiaasm'
    assert row['role']==role and Path(row['expected_source_path']).resolve()==expected.resolve()
    src=pin(row['source_path']);current=pin(expected);raw=pin(row['image_path']);receipt=json.loads(pin(row['receipt_path']))
    assert src==current and len(src)==row['source_bytes'] and sha256(src).hexdigest()==row['source_sha256']
    assert len(raw)==row['image_bytes'] and sha256(raw).hexdigest()==row['image_sha256']
    assert receipt['input_sha256']==row['source_sha256'] and receipt['produced_sha256']==row['image_sha256']
    assert receipt['artifact_sha256']==row['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
for p,raw in pins.items():assert p.read_bytes()==raw
for role in (28,29,46):
    row=bundle['components'][str(role)];images[role]=NativeHiaJsonImage(pins[Path(row['image_path']).resolve()],row['image_sha256'])
(dest/'source-before.json').write_text(json.dumps({str(p):{'bytes':len(raw),'sha256':sha256(raw).hexdigest()} for p,raw in pins.items()},indent=2,sort_keys=True)+'\n')

def call(role,s,o,w,*,worksize=None,outsize=None):
    before=s.read(0,s.size);right=o.read(0,o.size) if o.readonly else None
    result=int(images[role]._entry(s.address,s.size,o.address,o.size if outsize is None else outsize,
        w.address,w.size if worksize is None else worksize))
    native_calls[role]=native_calls.get(role,0)+1
    for buf in (s,o,w):buf.check()
    assert s.read(0,s.size)==before
    if right is not None:assert o.read(0,o.size)==right
    return result

def record(name,role,result,output,work=b'',**kw):
    folder=dest/name;folder.mkdir()
    (folder/'output.bin').write_bytes(output)
    if work:(folder/'work.bin.gz').write_bytes(gzip.compress(work,compresslevel=1,mtime=0))
    row={'case':name,'role':role,'return':result,'output_sha256':sha256(output).hexdigest(),**kw,'status':'PASS'}
    rows.append(row);(folder/'result.json').write_text(json.dumps(row,indent=2,sort_keys=True)+'\n')

doc=json.loads((ROOT/'development/smoke-r1/stored/input.json').read_bytes())
packet=transport(doc);lease,issue=actual_source_lease(old,packet)
(dest/'source.lease').write_bytes(lease);(dest/'source-issuance.json').write_text(json.dumps(issue,indent=2)+'\n')
error=None
try:
    for name,value in [('valid',doc),('non-object',None),('wrong-schema',{**doc,'schema':False}),
                       ('keys-first',{**doc,'schema':False,'proof':True}),('missing-types',{k:v for k,v in doc.items() if k!='types'})]:
        p=transport(value);source,issued=actual_source_lease(old,p)
        for capacity in (64,66+len(p)):
            s=Buffer(len(source),source,True);o=Buffer(capacity);w=Buffer(64)
            try:
                result=call(28,s,o,w)
                if name=='valid':
                    if capacity==64:assert result==0xfffffffe
                    else:
                        expected=transport({**doc,'schema':'hepta.hia.composite.v1'})
                        assert result==64+len(expected) and o.read(64,len(expected))==expected
                        actual_source_lease(old,o.read(64,len(expected)))
                else:
                    assert result==64
                    reason=struct.unpack('<8Q',o.read(0,64))[1]
                    assert reason==(2 if name=='wrong-schema' else 1)
                record('projection-'+name+'-'+str(capacity),28,result,o.read(0,min(capacity,64 if result>capacity else result)))
            finally:s.close();o.close();w.close()
    for name,offset,value in [('source-magic',0,0),('source-total',40,len(lease)-1),('source-reserved',48,1),('packet-root-length',72,len(packet))]:
        bad=bytearray(lease);struct.pack_into('<Q',bad,offset,value)
        s=Buffer(len(bad),bad,True);o=Buffer(len(packet)+66);w=Buffer(64)
        try:
            result=call(28,s,o,w);assert result==0xfffffffd
            record(name,28,result,o.read(0,64))
        finally:s.close();o.close();w.close()
    accepted=json.loads((ROOT/'development/smoke-r1/stored/expected.json').read_bytes())
    target=accepted['core'];legacy={**target,'schema':'hepta.hia.program.v1'}
    wire=lambda x:json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    assert sha256(wire(legacy)).hexdigest()==accepted['report']['source_primitive_sha256']
    for name,right,expected in [('equal',target,0),('module-change',{**target,'module':'different'},1),
                                ('module-same-length',{**target,'module':'z'*len(target['module'])},1)]:
        a=wire(legacy);b=wire(right)
        assert NativeCoreAdmission.status(old.images[27],a)==0 and NativeCoreAdmission.status(old.images[27],b)==0
        s=Buffer(len(a),a,True);r=Buffer(len(b),b,True);w=Buffer(64)
        try:
            result=call(29,s,r,w);assert result==64
            event=struct.unpack('<8Q',w.read(0,64));assert event[1:4]==(expected,len(a),len(b))
            record('compare-'+name,29,result,w.read(0,64),both_complete_core_admissions_passed=True)
        finally:s.close();r.close();w.close()
    init=struct.pack('<8Q',int.from_bytes(b'HIALII01','little'),72,0,len(lease),0,0,0,0)
    valid_ack=struct.pack('<8Q',C['ACK_MAGIC'],72,1,14,0,0,64,0)+lease[:64]

    def state():
        w=Buffer(1<<20)
        for slot,size in [(0,1),(1,len(lease)),(2,1<<20)]:w.write(C['CAPS']+slot*8,struct.pack('<Q',size))
        return w

    for name,index,value in [('magic',0,0),('zero-lease',1,0),('max-lease',1,(1<<64)-1),('legacy-flag',2,1),
                              ('source-extent',3,len(lease)-1),('reserved',4,1)]:
        words=list(struct.unpack('<8Q',init));words[index]=value
        s=Buffer(64,struct.pack('<8Q',*words),True);o=Buffer(128);w=state()
        try:
            result=call(46,s,o,w);assert result==0xfffffffd
            good=Buffer(64,init,True)
            try:assert call(46,good,o,w)==0xfffffffd
            finally:good.close()
            record('init-'+name,46,result,o.read(0,128),w.read(0,w.size),permanent_refusal=True)
        finally:s.close();o.close();w.close()
    for name,index,value in [('magic',0,0),('lease',1,73),('sequence',2,2),('opcode',3,1),
                             ('status',4,1),('view-return',5,1),('observed-size',6,63),('reserved',7,1)]:
        s=Buffer(64,init,True);o=Buffer(128);w=state()
        try:
            assert call(46,s,o,w)==128
            event=struct.unpack('<16Q',o.read(0,128));assert event[1:4]==(14,72,1)
            bad=bytearray(valid_ack);struct.pack_into('<Q',bad,index*8,value)
            ack=Buffer(len(bad),bad,True);good=Buffer(len(valid_ack),valid_ack,True)
            try:
                result=call(46,ack,o,w);assert result==0xfffffffd
                assert call(46,good,o,w)==0xfffffffd
                record('ack-'+name,46,result,o.read(0,128),w.read(0,w.size),permanent_refusal=True)
            finally:ack.close();good.close()
        finally:s.close();o.close();w.close()
    s=Buffer(64,init,True);o=Buffer(128);w=state();ack=Buffer(len(valid_ack),valid_ack,True)
    try:
        assert call(46,s,o,w)==128
        assert call(46,ack,o,w)==128
        next_event=struct.unpack('<16Q',o.read(0,128));assert next_event[1:4]==(2,72,2)
        result=call(46,ack,o,w);assert result==0xfffffffd
        record('ack-replay',46,result,o.read(0,128),w.read(0,w.size),permanent_refusal=True)
    finally:s.close();o.close();w.close();ack.close()
    s=Buffer(64,init,True);o=Buffer(128);w=state()
    try:
        before=w.read(0,w.size);result=call(46,s,o,w,worksize=(1<<20)-1)
        assert result==0xfffffffd and w.read(0,w.size)==before
        # This is raw ABI misuse. The fixed executor must discard the lease;
        # a kernel cannot poison memory it was not authorized to receive.
        record('short-workspace',46,result,o.read(0,128),raw_abi_only=True,permanent_native_poison_claimed=False)
    finally:s.close();o.close();w.close()
    summary['status']='PASS'
except BaseException as exc:
    error=exc;summary.update(status='FAIL',error_class=type(exc).__name__,error=str(exc));raise
finally:
    for image in images.values():image._mapping.close()
    old.close();assert all(p.read_bytes()==raw for p,raw in pins.items())
    summary.update(cases=len(rows),results=rows,actual_entries=native_calls,all_source_image_pins_unchanged=True,wall_ns=time.monotonic_ns()-start)
    (dest/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='results'},sort_keys=True),flush=True)
