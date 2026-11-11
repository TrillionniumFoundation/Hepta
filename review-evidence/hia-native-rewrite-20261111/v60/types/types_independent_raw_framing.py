"""Two actual private-ABI framing controls using the retained r3 image."""
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import time

BASE=Path('/workspace/scratch/623459b0e1bc')
sys.path.insert(0,str(BASE/'Hepta-native-types'))
from hepta.hia_composite_types_native import NativeCompositeTypes, OUTPUT_BYTES, SESSION_BYTES, MAGIC

folder=BASE/'types-native-development'
manifest=json.loads((folder/'manifest-r3.json').read_bytes())
receipt=json.loads((folder/'types-framing.receipt.json').read_bytes())
raw=(folder/manifest['image_path']).read_bytes()
compiled=(folder/'types-framing.input.bin').read_bytes()
assert sha256(raw).hexdigest()==manifest['image_sha256']==receipt['produced_sha256']
assert sha256(compiled).hexdigest()==manifest['source_sha256']==receipt['input_sha256']
assert manifest['compiler_sha256']==receipt['image_sha256']
image=NativeCompositeTypes(raw,manifest['image_sha256'])
out=ctypes.create_string_buffer(OUTPUT_BYTES+32)
state=ctypes.create_string_buffer(SESSION_BYTES+32)
out_ptr=ctypes.addressof(out)+16
state_ptr=ctypes.addressof(state)+16
canaries=[]
for base,size in [(ctypes.addressof(out),OUTPUT_BYTES),(ctypes.addressof(state),SESSION_BYTES)]:
    for address in [base,base+16+size]:
        ctypes.memmove(address,b'\xa5'*16,16)
        canaries.append(address)
body=b'{"op":"init","definitions":[],"recursive_chain":false,"partial_records":false}'
limit=(8<<20)+128
wire=body+b' '*(limit-len(body))
source=ctypes.create_string_buffer(wire)
started=time.monotonic()
extent=image._entry(source,len(wire),out_ptr,OUTPUT_BYTES,state_ptr,SESSION_BYTES)
header=struct.unpack('<8Q',ctypes.string_at(out_ptr,64)) if 64<=extent<=OUTPUT_BYTES else None
payload=json.loads(ctypes.string_at(out_ptr+64,header[3])) if header else None
exact_pass=bool(header and header[0]==MAGIC and header[1:3]==(0,0)
    and 64+header[3]==extent and header[4:]==(0,0,0,0)
    and len(payload['types'])==16)
first_header=ctypes.string_at(out_ptr,64)
oversized=ctypes.create_string_buffer(wire+b' ')
refused=image._entry(oversized,len(wire)+1,out_ptr,OUTPUT_BYTES,state_ptr,SESSION_BYTES)
plus_one_pass=refused==4294967280 and ctypes.string_at(out_ptr,64)==first_header
canaries_pass=all(ctypes.string_at(p,16)==b'\xa5'*16 for p in canaries)
result={
    'schema':'hepta.hia.composite-types-independent-private-framing.v1',
    'status':'DEVELOPMENT_PRIVATE_ABI_CONTROLS_PASS' if exact_pass and plus_one_pass and canaries_pass else 'FAIL',
    'source_sha256':manifest['source_sha256'],'image_sha256':manifest['image_sha256'],
    'compiler_sha256':manifest['compiler_sha256'],
    'receipt_sha256':sha256((folder/'types-framing.receipt.json').read_bytes()).hexdigest(),
    'exact_private_cap':{'input_bytes':len(wire),'input_sha256':sha256(wire).hexdigest(),
        'returned_extent':extent,'header':header,'decoded_primitive_descriptors':len(payload['types']) if payload else None,
        'passed':exact_pass},
    'private_cap_plus_one':{'input_bytes':len(wire)+1,'returned_status':refused,
        'output_header_unchanged':ctypes.string_at(out_ptr,64)==first_header,'passed':plus_one_pass},
    'four_outer_buffer_canaries_intact':canaries_pass,'elapsed_seconds':time.monotonic()-started,
    'public_core_limits_changed':False,'public_core_admission_tested_by_this_script':False,
    'scope':'Private raw ABI framing only. Ordinary Core boundary tests are separate owner evidence.',
    'new_compilation':False,'cold_qualified':False,'whole_native_delivery_qualified':False,
}
p=BASE/'types-independent-raw-framing-r3.json'
p.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({'path':str(p),'sha256':sha256(p.read_bytes()).hexdigest(),'status':result['status'],
    'exact_pass':exact_pass,'plus_one_pass':plus_one_pass,'outer_canaries_pass':canaries_pass,
    'elapsed_seconds':result['elapsed_seconds']}))
