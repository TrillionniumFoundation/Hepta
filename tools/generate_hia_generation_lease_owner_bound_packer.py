"""Native HIAGLOP2: 54-role owner plus one actual provider/payload capsule.

HIAGLOP1 remains unchanged. The new native linker patches the capsule's three
fixed owner imports to this product's one carrier/effects/Value code and rebases
its allocator relocations; request data never supplies a callback address.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_packer as original
from tools import generate_hia_generation_lease_owner_provider_packer as provider
ROOT=Path(__file__).resolve().parents[1]
common=original.common
ORIGINAL_FIXED_PARTS=original.fixed_parts
OWNER=bytes.fromhex("535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4d85e40f84710400004d85ed0f84680400004d85f60f845f0400004983ff400f82550400004981ff400000040f87480400004881fd008000060f823b0400004881fb000800000f852e04000041f6c6070f85240400004c89e04c01f80f82180400004c89ea4801ea0f820c0400004c89f14801d90f82000400004c39e876094c39e20f87f20300004c39f076094c39e10f87e40300004c39f276094c39e90f87d603000049c78500010000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84b103000083f80a74dc83f8010f843b01000083f8020f843e01000083f8030f844901000083f8040f844d01000083f80c0f849801000083f80d0f84ea01000083f80e0f840e02000083f80f0f842703000083f8100f84be00000083f8110f84d200000083f812744983f813746c83f8140f848800000083f8150f841502000083f8160f843602000083f8170f845c02000083f8180f847202000083f8190f849902000083f81a0f84a0020000e9ff02000031ffbe00000006ba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05e9cb020000498b8538030000498dbc0640030000be080000004829c631d2b83e0100000f05e9a6020000498bbe20030000498bb628030000b80b0000000f05e98c020000498bbd28030000be06040000ba03000000b8480000000f05e96f020000498bbd280300004889fe31d2b8b40100000f05e957020000b8270000000f05e94b02000031c0b901000000f0410fb14e40f390e93702000031c04187464031c0e92a0200004d89b500020000488d058efdffff49898508020000488d050000000049898510020000488d050000000049898518020000488d050000000049898520020000488d05000000004989852802000031c0e9d6010000498d7c2440498b7424104983bd30020000007424498dbd00100000be800000004983bd3002000002750e498dbd00110000498bb538020000498d9500400000b9000000064d8d860001000041b900010000e800000000e97b010000498d7c2440be40000000498d9500400000b9004000064d8d868000000041b980000000e800000000e94e010000498d7c2440498b7424104983bd3002000000740c498dbd00100000be80000000498d9500400000b9000000064d8d860002000041b900010000e909010000498dbd00100000be98000000498d9500400000b9000000064d8d860002000041b900010000e9df000000498dbd00100000be80000000498d9500200000b9800000004d8d860003000041b900010000e800000000e9b7000000498bb550040000498dbd80800000498b8d58040000fcf3a431c0e998000000498dbd00800000498bb5580400004881c680000000498d9500400000b9004000004d8d860002000041b900010000eb61498bbd50040000e80000000031c0eb58498dbd00100000be80000000498d9500400000b9800000004d8d860005000041b900030000e800000000eb2c498dbd00100000be80000000498d9500200000b9002000004d8d860002000041b900010000e800000000eb0049898580010000e935fcffffb8fdffffff4883c408415f415e415d415c5d5bc36690")
OWNER_HOLES={"policy":226,"carrier_address":636,"values_address":650,"finalizer_address":664,"provider_address":678,"carrier_call":778,"lifecycle_call":823,"finalizer_call":974,"provider_call":1116,"values_call":1160}
OWNER_RELOCATIONS=[[1070,"free"]] 
OWNER_RELOCATIONS=tuple(tuple(row)for row in OWNER_RELOCATIONS)
EXPORT_SIZE=len(OWNER)
ROLES=original.ROLES+('provider_capsule',)
MAGIC=int.from_bytes(b'HIAGLOP2','little')
IMPORTS=original.IMPORTS
CARRIER_SOURCES=original.CARRIER_SOURCES
HANDLES_PREFIX=original.HANDLES_PREFIX
HANDLES_RELOCATIONS=original.HANDLES_RELOCATIONS
EFFECTS_PREFIX=original.EFFECTS_PREFIX
EFFECTS_RELOCATIONS=original.EFFECTS_RELOCATIONS
FINALIZER_PREFIX=original.FINALIZER_PREFIX
def patched(function,changes):
    old={k:getattr(original,k)for k in changes}
    try:
        for k,v in changes.items():setattr(original,k,v)
        return function()
    finally:
        for k,v in old.items():setattr(original,k,v)
BRIDGE,HOLES,RELOCATIONS,SIZE_HOLE=patched(original.bridges,dict(OWNER=OWNER,OWNER_HOLES=OWNER_HOLES,OWNER_RELOCATIONS=OWNER_RELOCATIONS))
HOLES['provider_capsule']=[OWNER_HOLES['provider_address'],OWNER_HOLES['provider_call']]
CARRIER_OFFSET=OWNER_HOLES['carrier_address']+4+struct.unpack_from('<i',BRIDGE,OWNER_HOLES['carrier_address'])[0]
EFFECTS_OFFSET=CARRIER_OFFSET+((len(HANDLES_PREFIX)+15)&~15)
DYNAMIC_RELOCATIONS=tuple(('provider_capsule',off,symbol)for off,symbol in provider.RELOCATIONS if symbol in IMPORTS)
CAPSULE_IMPORTS=(('handles','carrier'),('effects','effects'),('values','values'))
PROVIDER_INDEX=ROLES.index('provider_capsule')
VALUE_INDEX=ROLES.index('values')
def fixed_parts():
    relocs=RELOCATIONS+tuple((off,symbol)for _,off,symbol in DYNAMIC_RELOCATIONS)
    return patched(ORIGINAL_FIXED_PARTS,dict(BRIDGE=BRIDGE,RELOCATIONS=relocs,EXPORT_SIZE=EXPORT_SIZE,IMPORTS=IMPORTS))
def reference_object(flats):
    if len(flats)!=len(ROLES) or any(not f or len(f)>4194304 for f in flats):raise ValueError('all 55 bounded native roles required')
    capsule=flats[PROVIDER_INDEX]
    if len(capsule)<len(provider.BRIDGE):raise ValueError('complete native provider capsule required')
    for off,_ in provider.RELOCATIONS:
        if struct.unpack_from('<I',capsule,off)[0]!=0:raise ValueError('capsule must be unresolved at its fixed external holes')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);positions={}
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));positions[role]=len(raw)
        for hole in HOLES[role]:struct.pack_into('<i',raw,64+hole,len(raw)-64-hole-4)
        raw.extend(flat)
    struct.pack_into('<I',raw,64+SIZE_HOLE,len(flats[ROLES.index('gen_prepare_mapping')]))
    targets=dict(carrier=64+CARRIER_OFFSET,effects=64+EFFECTS_OFFSET,values=positions['values'])
    for name,target in CAPSULE_IMPORTS:
        hole=positions['provider_capsule']+provider.OUTER_HOLES[name]
        struct.pack_into('<i',raw,hole,targets[target]-hole-4)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original sixteen MiB text bound')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in(relas,symbols,strings,common.SECTIONS):offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    for i,(_,off,_)in enumerate(DYNAMIC_RELOCATIONS):
        struct.pack_into('<Q',raw,offsets[0]+(len(RELOCATIONS)+i)*24,positions['provider_capsule']-64+off)
    return bytes(raw)
def source_program():
    source=patched(original.source_program,dict(BRIDGE=BRIDGE,HOLES=HOLES,SIZE_HOLE=SIZE_HOLE,ROLES=ROLES,MAGIC=MAGIC,fixed_parts=fixed_parts))
    token='    layout(w)\n'
    assert source.count(token)==1
    guard=f'''    capsule_input=length(s)-uint(s,{16+8*PROVIDER_INDEX},8)
    if uint(s,{16+8*PROVIDER_INDEX},8)<{len(provider.BRIDGE)}:
        return 4294967295
'''
    for off,_ in provider.RELOCATIONS:
        guard+=f'    if uint(s,capsule_input+{off},4)!=0:\n        return 4294967295\n'
    source=source.replace(token,guard+token)
    patch=f'    capsule=get(w,{512+8*PROVIDER_INDEX})\n'
    targets=dict(carrier=str(64+CARRIER_OFFSET),effects=str(64+EFFECTS_OFFSET),values=f'get(w,{512+8*VALUE_INDEX})')
    for name,target in CAPSULE_IMPORTS:
        hole=provider.OUTER_HOLES[name]
        patch+=f'    write(o,capsule+{hole},{targets[target]}-capsule-{hole+4},4)\n'
    for i,(_,off,_)in enumerate(DYNAMIC_RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{(len(RELOCATIONS)+i)*24},capsule-64+{off},8)\n'
    token='    return get(w,1088)\n'
    assert source.count(token)==1
    return source.replace(token,patch+token)
def main():
    doc=document(source_program(),'generation_lease_owner_bound_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_bound_packer.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(ROLES),flush=True)
if __name__=='__main__':main()
