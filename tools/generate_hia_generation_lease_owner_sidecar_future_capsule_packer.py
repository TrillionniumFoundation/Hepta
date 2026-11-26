"""Native sidecar, code, tempdir and Future-provider capsule.

All Value/Future targets are unresolved fixed imports for the final HIA linker.
The registry is a fixed internal target. No request can choose an entry.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_future_resource_owner_packer as provider
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAGSCP2','little')
ROLES=('sidecar','code','tempdir','future_provider','future_registry')
OUTER=bytes.fromhex('535541544155415641574881ecc88001004881f9800000000f82150300004981f9000800000f850f0300004881fe800000000f85020300004885ff0f84f90200004885d20f84f00200004d85c00f84e702000049f7c0070000000f85da0200004889f84801f00f82ce0200004989d24901ca0f82c20200004d89c34d01cb0f82b60200004839d076094939fa0f87a80200004c39c076094939fb0f879a0200004d39c276094939d30f878c0200004989fc4989f7488954242048894c24284c8dac24c0000000bd008001004d89c64c89cb49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f840c02000083f80a74dc83f8010f846201000083f8020f84a501000083f8030f84ab01000083f8080f84aa01000083f80f0f84a800000083f80c0f82f201000083f8110f87e90100008944246031c9498b44cd004883f8030f87cf010000498b54cd08480314c4488954cc6883c10383f90972db488b7c2468498b7510488b942480000000498b4d284c8b8424980000004d8b4d408b44246083f80c743783f80d741483f810741983f811741ee8b1010000e94e010000e897010000e944010000e800000000e93a010000e8a3010000e930010000e800000000e9260100004d89b500020000488d050000000049898508020000488d050000000049898510020000488d054a01000049898518020000488d054c01000049898520020000488d050000000049898528020000488d05c0fdffff49898530020000488d050000000049898538020000488d05290100004863151e0100004801d049898540020000488d05000000004989854802000031c0e9900000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc3049c1ea02ffc183f90672e0488b7c2430488b742438488b5424404c8b5424484c8b4424504c8b4c2458498b45000f05eb4431c0b901000000f0410fb14e40eb3531c041874640eb2d498b45004883f803774b498b7508480334c4498b45104883f8037739498b7d1848033cc4498b4d20fcf3a431c049898588000000e9d5fdffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c4c8800100415f415e415d415c5d5bc30f1f400066662e0f1f840000000000e90000000090662e0f1f840000000000e90000000090662e0f1f840000000000e900000000')
OUTER_HOLES=dict(core=(502,),values=(483,516),finalizer=(558,),future=(463,586))
CODE_EXPORT=864
TEMPDIR_EXPORT=880
PROVIDER_STUB=896
raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16))
FUTURE_PROVIDER_EXPORT=len(raw)
raw.extend(provider.BRIDGE)
for hole,target in ((897,FUTURE_PROVIDER_EXPORT),(624,FUTURE_PROVIDER_EXPORT+provider.REGISTRY_OFFSET)):
    struct.pack_into('<i',raw,hole,target-hole-4)
BRIDGE=bytes(raw)
HOLES=dict(sidecar=262,code=865,tempdir=881,
           future_provider=FUTURE_PROVIDER_EXPORT+provider.HOLES['owner'],
           future_registry=FUTURE_PROVIDER_EXPORT+provider.HOLES['registry'])
OUTER_HOLES['future']+= (FUTURE_PROVIDER_EXPORT+provider.OUTER_HOLES['future'],)
OUTER_HOLES['values']+= (FUTURE_PROVIDER_EXPORT+provider.OUTER_HOLES['values'],)
RELOCATIONS=tuple((FUTURE_PROVIDER_EXPORT+off,name) for off,name in provider.RELOCATIONS
                  if name not in ('hia_resource_future','hia_resource_values'))
assert all(BRIDGE[h:h+4]==bytes(4) for hs in OUTER_HOLES.values() for h in hs)
assert all(BRIDGE[h:h+4]==bytes(4) for h,_ in RELOCATIONS)
def reference_flat(flats):
    if len(flats)!=len(ROLES) or any(not f or len(f)>4194304 for f in flats):
        raise ValueError('five actual bounded native products required')
    raw=bytearray(BRIDGE)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));at=len(raw)
        struct.pack_into('<i',raw,HOLES[role],at-HOLES[role]-4)
        raw.extend(flat)
    if len(raw)>4194304:raise ValueError('original four MiB capsule bound')
    return bytes(raw)
def source_program():
    calls,emitters=common.emitters('bridge',BRIDGE)
    n=len(ROLES);head=16+8*n
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<128:
        return 4294967294
    if length(s)<{head} or uint(s,0,8)!={MAGIC} or uint(s,8,8)!={n}:
        return 4294967295
    total={head}
    at=({len(BRIDGE)}+15)&18446744073709551600
    count=0
    while count<{n}:
        amount=uint(s,16+count*8,8)
        if amount==0 or amount>4194304:
            return 4294967295
        write(w,count*8,amount,8)
        write(w,64+count*8,at,8)
        at=at+amount
        if count!={n-1}:
            at=(at+15)&18446744073709551600
        total=total+amount
        count=count+1
    if total!=length(s) or at>4194304:
        return 4294967295
    if length(o)<at:
        return 4294967294
    size=at
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for fn in calls:source+=f'    {fn}(o,0)\n'
    for index,role in enumerate(ROLES):
        hole=HOLES[role]
        source+=f'    write(o,{hole},get(w,{64+index*8})-{hole+4},4)\n'
    source+=f'''    at={head}
    i=0
    while i<{n}:
        copy(s,o,at,get(w,64+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return size

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
'''
    return source+'\n\n'+emitters+common.HELPERS
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar_future_capsule_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_future_capsule_packer.hepta'
    path.write_text(render_assembly(doc));print(path.name,path.stat().st_size,flush=True)
if __name__=='__main__':main()
