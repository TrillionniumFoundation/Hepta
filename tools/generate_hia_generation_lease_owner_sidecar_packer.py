"""HIAGLOP3: one sole Value owner plus its native trusted sidecar capsule.

The old 54/55-role protocols remain separate. This profile statically binds the
sidecar's one Value import to the enclosing Value body and replaces the common
finalizer with the source-bound callable-aware variant. Its production support
mask remains the core's 1/2 mask until the full callable driver is qualified.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_packer as original
from tools import generate_hia_generation_lease_owner_bound_packer as bound
from tools import generate_hia_generation_lease_owner_provider_packer as provider
from tools import generate_hia_generation_lease_owner_sidecar_capsule_packer as sidecar
from tools import generate_hia_generation_lease_owner_tempdir_packer as tempdir
ROOT=Path(__file__).resolve().parents[1]
common=original.common
FINALIZER_PREFIX=bytes.fromhex('535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4d85e40f84800200004d85ed0f84770200004d85f60f846e0200004981ff800000000f85610200004881fd800000000f82540200004881fb000100000f854702000041f6c6070f853d0200004c89e04c01f80f82310200004c89ea4801ea0f82250200004c89f14801d90f82190200004c39e876094c39e20f870b0200004c39f076094c39e10f87fd0100004c39f276094c39e90f87ef01000049c74560000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84cd01000083f801743d83f802744483f803745183f8040f849900000083f805744e83f806746c83f80c0f849c00000083f80d0f844a01000083f80e0f84cd000000e986010000b8270000000f05e97101000031c0b901000000f0410fb14e08e95f01000031c041874608e954010000498d7e08be80000000ba010000004531d24531c04531c9b8ca0000000f05e931010000498d7e08be81000000baffffff7f4531d24531c04531c9b8ca0000000f05e90e0100004d897550488d05000000004989455831c0e9f8000000498dbe80000000be80000000498b5620498b4e284d8b463041b900010000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424e9b5000000498d8600ffffff49898680000000488b90c000000049899688000000488b90c800000049899690000000488b90d000000049899698000000488b90d8000000498996a0000000488b9098000000498996b0000000488b90a8000000498996b8000000488d0500000000498986a800000031c0eb41498dbe80000000be80000000498b5620b9800000004d8b46c841b900010000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424eb0049894568e919feffffb8fdffffff4883c408415f415e415d415c5d5bc3')
FINALIZER_HOLES=dict(policy=213,carrier_address=409,carrier_call=455,code_address=592,code_call=639)
OWNER=bound.OWNER
OWNER_HOLES=bound.OWNER_HOLES
OWNER_RELOCATIONS=bound.OWNER_RELOCATIONS
EXPORT_SIZE=bound.EXPORT_SIZE
ROLES=bound.ROLES+('sidecar_capsule',)
MAGIC=int.from_bytes(b'HIAGLOP3','little')
IMPORTS=bound.IMPORTS
CARRIER_SOURCES=bound.CARRIER_SOURCES
BRIDGE,HOLES,RELOCATIONS,SIZE_HOLE=bound.patched(original.bridges,dict(
 OWNER=OWNER,OWNER_HOLES=OWNER_HOLES,OWNER_RELOCATIONS=OWNER_RELOCATIONS,
 FINALIZER_PREFIX=FINALIZER_PREFIX,FINALIZER_HOLES=FINALIZER_HOLES))
HOLES['provider_capsule']=[OWNER_HOLES['provider_address'],OWNER_HOLES['provider_call']]
HOLES['sidecar_capsule']=[]
CARRIER_OFFSET=OWNER_HOLES['carrier_address']+4+struct.unpack_from('<i',BRIDGE,OWNER_HOLES['carrier_address'])[0]
EFFECTS_OFFSET=CARRIER_OFFSET+((len(bound.HANDLES_PREFIX)+15)&~15)
FINALIZER_OFFSET=OWNER_HOLES['finalizer_address']+4+struct.unpack_from('<i',BRIDGE,OWNER_HOLES['finalizer_address'])[0]
PROVIDER_INDEX=ROLES.index('provider_capsule')
SIDECAR_INDEX=ROLES.index('sidecar_capsule')
VALUE_INDEX=ROLES.index('values')
DYNAMIC_RELOCATIONS=bound.DYNAMIC_RELOCATIONS
def fixed_parts():
    names=('hia_generation_lease_owner','hia_generation_lease_owner_sidecar',*IMPORTS)
    strings=bytearray(b'\0');positions={}
    for name in names:positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),
      struct.pack('<IBBHQQ',positions[names[0]],18,0,1,0,EXPORT_SIZE),
      struct.pack('<IBBHQQ',positions[names[1]],18,0,1,0,len(sidecar.BRIDGE))]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols)
    rels=RELOCATIONS+tuple((off,name)for _,off,name in DYNAMIC_RELOCATIONS)+tuple(tempdir.RELOCATIONS)
    relas=b''.join(struct.pack('<QQq',off,((4+IMPORTS.index(name))<<32)|4,-4)for off,name in rels)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
      ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
      ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
      ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)

def sidecar_tempdir_offset(flat):
    if len(flat)<len(sidecar.BRIDGE):raise ValueError('complete sidecar capsule required')
    for holes in sidecar.OUTER_HOLES.values():
        for off in holes:
            if struct.unpack_from('<I',flat,off)[0]!=0:raise ValueError('fixed sidecar owner imports must remain unresolved')
    at=sidecar.HOLES['tempdir']+4+struct.unpack_from('<i',flat,sidecar.HOLES['tempdir'])[0]
    if at<len(sidecar.BRIDGE)or at+len(tempdir.BRIDGE)>len(flat):raise ValueError('bounded actual tempdir body required')
    for off,_ in tempdir.RELOCATIONS:
        if struct.unpack_from('<I',flat,at+off)[0]!=0:raise ValueError('fixed tempdir libc import must remain unresolved')
    return at

def reference_object(flats):
    if len(flats)!=56 or any(not f or len(f)>4194304 for f in flats):raise ValueError('all 56 actual bounded roles required')
    pro=flats[PROVIDER_INDEX];side=flats[SIDECAR_INDEX]
    if len(pro)<len(provider.BRIDGE):raise ValueError('complete provider capsule required')
    for off,_ in provider.RELOCATIONS:
        if struct.unpack_from('<I',pro,off)[0]!=0:raise ValueError('provider fixed imports must remain unresolved')
    temp_at=sidecar_tempdir_offset(side)
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);positions={}
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));positions[role]=len(raw)
        for hole in HOLES[role]:struct.pack_into('<i',raw,64+hole,len(raw)-64-hole-4)
        raw.extend(flat)
    struct.pack_into('<I',raw,64+SIZE_HOLE,len(flats[ROLES.index('gen_prepare_mapping')]))
    targets=dict(carrier=64+CARRIER_OFFSET,effects=64+EFFECTS_OFFSET,values=positions['values'])
    for name,target in bound.CAPSULE_IMPORTS:
        hole=positions['provider_capsule']+provider.OUTER_HOLES[name]
        struct.pack_into('<i',raw,hole,targets[target]-hole-4)
    targets=dict(core=64,values=positions['values'],finalizer=64+FINALIZER_OFFSET)
    for name,holes in sidecar.OUTER_HOLES.items():
        for off in holes:
            hole=positions['sidecar_capsule']+off
            struct.pack_into('<i',raw,hole,targets[name]-hole-4)
    for name in ('code_address','code_call'):
        hole=64+FINALIZER_OFFSET+FINALIZER_HOLES[name]
        struct.pack_into('<i',raw,hole,positions['sidecar_capsule']+sidecar.CODE_EXPORT-hole-4)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original sixteen MiB text bound')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in(relas,symbols,strings,common.SECTIONS):offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    struct.pack_into('<Q',raw,offsets[1]+80,positions['sidecar_capsule']-64)
    for i,(_,off,_)in enumerate(DYNAMIC_RELOCATIONS):
        struct.pack_into('<Q',raw,offsets[0]+(len(RELOCATIONS)+i)*24,positions['provider_capsule']-64+off)
    for i,(off,_)in enumerate(tempdir.RELOCATIONS):
        struct.pack_into('<Q',raw,offsets[0]+(len(RELOCATIONS)+len(DYNAMIC_RELOCATIONS)+i)*24,positions['sidecar_capsule']-64+temp_at+off)
    return bytes(raw)

def source_program():
    source=bound.patched(original.source_program,dict(BRIDGE=BRIDGE,HOLES=HOLES,SIZE_HOLE=SIZE_HOLE,ROLES=ROLES,MAGIC=MAGIC,fixed_parts=fixed_parts))
    po=16+8*PROVIDER_INDEX;so=16+8*SIDECAR_INDEX
    guard=f'''    side_input=length(s)-uint(s,{so},8)
    pro_input=side_input-uint(s,{po},8)
    if uint(s,{po},8)<{len(provider.BRIDGE)} or uint(s,{so},8)<{len(sidecar.BRIDGE)}:
        return 4294967295
'''
    for off,_ in provider.RELOCATIONS:guard+=f'    if uint(s,pro_input+{off},4)!=0:\n        return 4294967295\n'
    for holes in sidecar.OUTER_HOLES.values():
        for off in holes:guard+=f'    if uint(s,side_input+{off},4)!=0:\n        return 4294967295\n'
    h=sidecar.HOLES['tempdir']
    guard+=f'''    temp_at=uint(s,side_input+{h},4)+{h+4}
    if temp_at<{len(sidecar.BRIDGE)} or temp_at+{len(tempdir.BRIDGE)}>uint(s,{so},8):
        return 4294967295
    write(w,1104,temp_at,8)
'''
    for off,_ in tempdir.RELOCATIONS:guard+=f'    if uint(s,side_input+temp_at+{off},4)!=0:\n        return 4294967295\n'
    token='    layout(w)\n';assert source.count(token)==1;source=source.replace(token,guard+token)
    patch=f'    pro=get(w,{512+8*PROVIDER_INDEX})\n    side=get(w,{512+8*SIDECAR_INDEX})\n'
    targets=dict(carrier=str(64+CARRIER_OFFSET),effects=str(64+EFFECTS_OFFSET),values=f'get(w,{512+8*VALUE_INDEX})')
    for name,target in bound.CAPSULE_IMPORTS:
        off=provider.OUTER_HOLES[name];patch+=f'    write(o,pro+{off},{targets[target]}-pro-{off+4},4)\n'
    targets=dict(core='64',values=f'get(w,{512+8*VALUE_INDEX})',finalizer=str(64+FINALIZER_OFFSET))
    for name,holes in sidecar.OUTER_HOLES.items():
        for off in holes:patch+=f'    write(o,side+{off},{targets[name]}-side-{off+4},4)\n'
    for name in ('code_address','code_call'):
        off=64+FINALIZER_OFFSET+FINALIZER_HOLES[name]
        patch+=f'    write(o,{off},side+{sidecar.CODE_EXPORT}-{off+4},4)\n'
    patch+='    write(o,get(w,1048)+80,side-64,8)\n'
    for i,(_,off,_)in enumerate(DYNAMIC_RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{(len(RELOCATIONS)+i)*24},pro-64+{off},8)\n'
    for i,(off,_)in enumerate(tempdir.RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{(len(RELOCATIONS)+len(DYNAMIC_RELOCATIONS)+i)*24},side-64+get(w,1104)+{off},8)\n'
    token='    return get(w,1088)\n';assert source.count(token)==1
    return source.replace(token,patch+token)
def main():
    doc=document(source_program(),'generation_lease_owner_sidecar_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_sidecar_packer.hepta'
    path.write_text(render_assembly(doc));print(path.name,path.stat().st_size,len(ROLES),flush=True)
if __name__=='__main__':main()
