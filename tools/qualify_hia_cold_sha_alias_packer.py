"""Native constructor boundaries for the cold SHA mechanical alias flat."""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,struct
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.generate_hia_cold_sha_alias import template

GUARD=bytes.fromhex('91d34a68')*4
MAX=1<<20

def qualify(packer_path,old_path,fast_path,expected_path,output):
    output.mkdir(exist_ok=False,parents=True)
    raw=packer_path.read_bytes();im=NativeHiaJsonImage(raw,sha256(raw).hexdigest())
    prefix,old_hole,fast_hole=template();rows=[]
    def wire(old,fast):return b'HIASHA01'+struct.pack('<2Q',len(old),len(fast))+old+fast
    def want(old,fast):
        value=bytearray(prefix+old+fast)
        struct.pack_into('<I',value,old_hole,len(prefix)-old_hole-4)
        struct.pack_into('<I',value,fast_hole,len(prefix)+len(old)-fast_hole-4)
        return bytes(value)
    def call(name,value,expected=None,*,capacity=None,reported=None):
        capacity=capacity if capacity is not None else len(expected) if expected is not None else 512
        s=ctypes.create_string_buffer(GUARD+value+GUARD,len(value)+32)
        o=ctypes.create_string_buffer(GUARD+b'\xa5'*capacity+GUARD,capacity+32)
        w=ctypes.create_string_buffer(GUARD+b'\x5a'*64+GUARD,96)
        result=im._entry(ctypes.byref(s,16),len(value) if reported is None else reported,ctypes.byref(o,16),capacity,ctypes.byref(w,16),64)
        assert s.raw==GUARD+value+GUARD,(name,'source modified')
        assert o.raw[:16]==GUARD and o.raw[-16:]==GUARD,(name,'output bounds')
        assert w.raw==GUARD+b'\x5a'*64+GUARD,(name,'workspace modified')
        after=o.raw[16:-16]
        if expected is None:
            assert result==0xffffffff and after==b'\xa5'*capacity,(name,result)
        elif capacity<len(expected):
            assert result==0xfffffffe and after==b'\xa5'*capacity,(name,result)
        else:
            assert result==len(expected) and after[:result]==expected and after[result:]==b'\xa5'*(capacity-result),(name,result)
        rows.append({'case':name,'passed':True,'result':result,'source_bytes':len(value),'output_capacity':capacity,'source_sha256':sha256(value).hexdigest(),'output_sha256':sha256(after).hexdigest()})
    old=old_path.read_bytes();fast=fast_path.read_bytes();packet=wire(old,fast);expected=want(old,fast)
    assert expected==expected_path.read_bytes()
    call('actual-composite',packet,expected)
    call('actual-composite-larger-output',packet,expected,capacity=len(expected)+31)
    for size in (0,1,len(prefix)-1,len(expected)-1):call('short-output-'+str(size),packet,expected,capacity=size)
    for n in range(24):call('short-frame-'+str(n),packet[:n])
    for at in range(8):
        b=bytearray(packet);b[at]^=1;call('magic-'+str(at),bytes(b))
    for at in (8,16):
        for value in (0,MAX+1,(1<<64)-1):
            b=bytearray(packet);struct.pack_into('<Q',b,at,value);call('length-'+str((at,value)),bytes(b))
    call('extra-tail',packet+b'x');call('missing-tail',packet[:-1])
    call('view-shorter-than-physical',packet,reported=23)
    for a,b in ((b'A',b'B'),(bytes(MAX),b'x'),(b'x',bytes(MAX)),(bytes(MAX),bytes(MAX))):
        call('extent-'+str((len(a),len(b))),wire(a,b),want(a,b))
    report={'schema':'hepta.hia.cold-sha-alias-packer-qualification.v1','passed':True,'count':len(rows),'cases':rows,'image_sha256':sha256(raw).hexdigest(),'composite_sha256':sha256(expected).hexdigest(),'source_unchanged':True,'rejection_atomic':True}
    (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='cases'}))

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('packer','old','fast','expected','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();qualify(a.packer,a.old,a.fast,a.expected,a.output)
