"""Static Runtime/callable/managed Future fusion with one Value implementation.

The native 56-role Runtime/code sidecar and eight non-Value Future roles share
the same fixed Value entry. Byte-identical position-independent role bodies
share immutable code while their own captured contexts remain distinct. Both legacy packer protocols remain separate and
unchanged. No caller-provided function pointer or symbol lookup grants custody.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from types import SimpleNamespace
from tools import generate_hia_generation_lease_owner_sidecar_packer as old_owner
from tools import generate_hia_generation_lease_owner_sidecar_future_capsule_packer as sidecar
owner=SimpleNamespace(**{k:v for k,v in vars(old_owner).items() if not k.startswith('__')})
owner.sidecar=sidecar
owner.FINALIZER_PREFIX=bytes.fromhex('535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4d85e40f844d0300004d85ed0f84440300004d85f60f843b0300004981ff800000000f852e0300004881fd800000000f82210300004881fb000100000f851403000041f6c6070f850a0300004c89e04c01f80f82fe0200004c89ea4801ea0f82f20200004c89f14801d90f82e60200004c39e876094c39e20f87d80200004c39f076094c39e10f87ca0200004c39f276094c39e90f87bc02000049c74560000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f849a02000083f801744f83f802745683f803746383f8040f84ab00000083f805746083f806747e83f80c0f84ae00000083f80d0f845f01000083f80e0f84df00000083f80f0f849101000083f8100f84fc010000e941020000b8270000000f05e92c02000031c0b901000000f0410fb14e08e91a02000031c041874608e90f020000498d7e08be80000000ba010000004531d24531c04531c9b8ca0000000f05e9ec010000498d7e08be81000000baffffff7f4531d24531c04531c9b8ca0000000f05e9c90100004d897550488d05000000004989455831c0e9b3010000498dbe80000000be80000000498b5620498b4e284d8b463041b900010000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424e970010000498d8600ffffff49898680000000488b90c000000049899688000000488b90c800000049899690000000488b90d000000049899698000000488b90d8000000498996a0000000488b9098000000498996b0000000488b90a8000000498996b8000000488d0500000000498986a800000031c0e9f9000000498dbe80000000be80000000498b5620b9800000004d8b46c841b900010000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424e9b5000000498d8600ffffff49898680000000488b90e000000049899688000000488b90e800000049899690000000488b90f000000049899698000000488b90f8000000498996a0000000488b9098000000498996b0000000488b90a8000000498996b8000000488d0500000000498986a800000031c0eb41498dbe80000000be80000000498b5620b9800000004d8b46e841b900020000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424eb0049894568e94cfdffffb8fdffffff4883c408415f415e415d415c5d5bc3')
owner.FINALIZER_HOLES=dict(policy=213,carrier_address=427,carrier_call=473,
                          code_address=610,code_call=660,future_address=797,future_call=844)
owner.BRIDGE,owner.HOLES,owner.RELOCATIONS,owner.SIZE_HOLE=owner.bound.patched(
 owner.original.bridges,dict(OWNER=owner.OWNER,OWNER_HOLES=owner.OWNER_HOLES,
 OWNER_RELOCATIONS=owner.OWNER_RELOCATIONS,FINALIZER_PREFIX=owner.FINALIZER_PREFIX,
 FINALIZER_HOLES=owner.FINALIZER_HOLES))
owner.HOLES['provider_capsule']=[owner.OWNER_HOLES['provider_address'],owner.OWNER_HOLES['provider_call']]
owner.HOLES['sidecar_capsule']=[]
owner.CARRIER_OFFSET=owner.OWNER_HOLES['carrier_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['carrier_address'])[0]
owner.EFFECTS_OFFSET=owner.CARRIER_OFFSET+((len(owner.bound.HANDLES_PREFIX)+15)&~15)
owner.FINALIZER_OFFSET=owner.OWNER_HOLES['finalizer_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['finalizer_address'])[0]
def sidecar_tempdir_offset(flat):
    if len(flat)<len(sidecar.BRIDGE):raise ValueError('complete Future sidecar capsule required')
    for holes in sidecar.OUTER_HOLES.values():
        for off in holes:
            if struct.unpack_from('<I',flat,off)[0]!=0:raise ValueError('fixed Future sidecar imports must be unresolved')
    for off,_ in sidecar.RELOCATIONS:
        if struct.unpack_from('<I',flat,off)[0]!=0:raise ValueError('fixed Future provider libc import must be unresolved')
    at=sidecar.HOLES['tempdir']+4+struct.unpack_from('<i',flat,sidecar.HOLES['tempdir'])[0]
    if at<len(sidecar.BRIDGE)or at+len(owner.tempdir.BRIDGE)>len(flat):raise ValueError('bounded actual tempdir body required')
    for off,_ in owner.tempdir.RELOCATIONS:
        if struct.unpack_from('<I',flat,at+off)[0]!=0:raise ValueError('fixed tempdir libc import must be unresolved')
    return at
owner.sidecar_tempdir_offset=sidecar_tempdir_offset
from tools import generate_hia_background_optimizer_future_public_cleanup_packer as future
ROOT=Path(__file__).resolve().parents[1]
FUTURE_ROLES=tuple(role for role in future.ROLES if role!='value')
ROLES=owner.ROLES+tuple('future_public_'+role for role in FUTURE_ROLES)
MAGIC=int.from_bytes(b'HIAGFUP4','little')
IMPORTS=owner.IMPORTS
EXPORT_SIZE=owner.EXPORT_SIZE
SIZE_HOLE=owner.SIZE_HOLE
STATIC_RELOCATIONS=owner.RELOCATIONS
DYNAMIC_RELOCATIONS=owner.DYNAMIC_RELOCATIONS
RELOCATIONS=STATIC_RELOCATIONS+tuple((off,name)for _,off,name in DYNAMIC_RELOCATIONS)+tuple(sidecar.RELOCATIONS)+tuple(owner.tempdir.RELOCATIONS)
raw=bytearray(owner.BRIDGE)
raw.extend(bytes((-len(raw))%16))
FUTURE_AT=len(raw)
raw.extend(future.BRIDGE)
BRIDGE=bytes(raw)
HOLES={role:list(holes)for role,holes in owner.HOLES.items()}
for role in FUTURE_ROLES:HOLES['future_public_'+role]=[]
for role,hole in future.FIXUPS:
    selected='values' if role=='value' else 'future_public_'+role
    HOLES[selected].append(FUTURE_AT+hole)
assert len(ROLES)==64 and len(set(ROLES))==len(ROLES)
assert all(HOLES[role]for role in ROLES if role!='sidecar_capsule')
assert ROLES.count('values')==1 and 'future_public_value'not in ROLES
assert all(BRIDGE[h:h+4]==bytes(4)for holes in HOLES.values()for h in holes)

def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_generation_lease_owner','hia_background_optimizer_future_public','hia_generation_lease_owner_sidecar',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_generation_lease_owner'],18,0,1,0,EXPORT_SIZE),struct.pack('<IBBHQQ',positions['hia_background_optimizer_future_public'],18,0,1,FUTURE_AT,len(future.BRIDGE)),struct.pack('<IBBHQQ',positions['hia_generation_lease_owner_sidecar'],18,0,1,0,len(owner.sidecar.BRIDGE))]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((5+IMPORTS.index(name))<<32)|4,-4) for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def reference_object(flats):
    if len(flats)!=len(ROLES) or any(not f or len(f)>4194304 for f in flats):raise ValueError('all fixed actual roles required')
    capsule=flats[ROLES.index('provider_capsule')]
    if len(capsule)<len(owner.provider.BRIDGE):raise ValueError('complete actual provider capsule required')
    for off,_ in owner.provider.RELOCATIONS:
        if struct.unpack_from('<I',capsule,off)[0]!=0:raise ValueError('unresolved fixed provider holes required')
    side=flats[ROLES.index('sidecar_capsule')]
    temp_at=owner.sidecar_tempdir_offset(side)
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);seen={};positions={}
    for role,flat in zip(ROLES,flats):
        if flat in seen:at=seen[flat]
        else:
            raw.extend(bytes((-len(raw))%16));at=len(raw)
            seen[flat]=at;raw.extend(flat)
        positions[role]=at
        for h in HOLES[role]:struct.pack_into('<i',raw,64+h,at-64-h-4)
    struct.pack_into('<I',raw,64+SIZE_HOLE,len(flats[ROLES.index('gen_prepare_mapping')]))
    targets=dict(carrier=64+owner.CARRIER_OFFSET,effects=64+owner.EFFECTS_OFFSET,values=positions['values'])
    for name,target in owner.bound.CAPSULE_IMPORTS:
        hole=positions['provider_capsule']+owner.provider.OUTER_HOLES[name]
        struct.pack_into('<i',raw,hole,targets[target]-hole-4)
    targets=dict(core=64,values=positions['values'],finalizer=64+owner.FINALIZER_OFFSET,future=64+FUTURE_AT)
    for name,holes in owner.sidecar.OUTER_HOLES.items():
        for off in holes:
            hole=positions['sidecar_capsule']+off
            struct.pack_into('<i',raw,hole,targets[name]-hole-4)
    for name in ('code_address','code_call'):
        hole=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        struct.pack_into('<i',raw,hole,positions['sidecar_capsule']+owner.sidecar.CODE_EXPORT-hole-4)
    for name in ('future_address','future_call'):
        hole=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        struct.pack_into('<i',raw,hole,positions['sidecar_capsule']+sidecar.FUTURE_PROVIDER_EXPORT-hole-4)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original sixteen MiB text bound')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in (relas,symbols,strings,common.SECTIONS):offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    for i,(_,off,_)in enumerate(DYNAMIC_RELOCATIONS):
        struct.pack_into('<Q',raw,offsets[0]+(len(STATIC_RELOCATIONS)+i)*24,positions['provider_capsule']-64+off)
    struct.pack_into('<Q',raw,offsets[1]+104,positions['sidecar_capsule']-64)
    for i,(off,_)in enumerate(owner.tempdir.RELOCATIONS):
        struct.pack_into('<Q',raw,offsets[0]+(len(STATIC_RELOCATIONS)+len(DYNAMIC_RELOCATIONS)+len(sidecar.RELOCATIONS)+i)*24,positions['sidecar_capsule']-64+temp_at+off)
    for i,(off,_)in enumerate(sidecar.RELOCATIONS):
        struct.pack_into('<Q',raw,offsets[0]+(len(STATIC_RELOCATIONS)+len(DYNAMIC_RELOCATIONS)+i)*24,positions['sidecar_capsule']-64+off)
    return bytes(raw)
def source_program():
    prefix,relas,symbols,strings,sections=fixed_parts();tail=relas+symbols+strings+common.SECTIONS
    n=len(ROLES);head=16+8*n;functions=[];calls={}
    assert n<=64
    for name,raw in [('prefix',prefix),('tail',tail),('sections',sections)]:
        calls[name],src=common.emitters(name,raw);functions.append(src)
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<2048:
        return 4294967294
    if length(s)<{head} or uint(s,0,8)!={MAGIC} or uint(s,8,8)!={n}:
        return 4294967295
    count=0
    total={head}
    while count<{n}:
        size=uint(s,16+count*8,8)
        if size==0 or size>4194304:
            return 4294967295
        write(w,count*8,size,8)
        write(w,1536+count*8,total,8)
        total=total+size
        count=count+1
    if total!=length(s):
        return 4294967295
    layout(s,w)
    if get(w,1024)-64>16777216:
        return 4294967295
    size=get(w,1088)
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    pi=ROLES.index('provider_capsule')
    guard=f'''    capsule_input=get(w,{1536+8*pi})
    if get(w,{8*pi})<{len(owner.provider.BRIDGE)}:
        return 4294967295
'''
    for off,_ in owner.provider.RELOCATIONS:
        guard+=f'    if uint(s,capsule_input+{off},4)!=0:\n        return 4294967295\n'
    si=ROLES.index('sidecar_capsule')
    guard+=f'''    side_input=get(w,{1536+8*si})
    if get(w,{8*si})<{len(owner.sidecar.BRIDGE)}:
        return 4294967295
'''
    for holes in owner.sidecar.OUTER_HOLES.values():
        for off in holes:guard+=f'    if uint(s,side_input+{off},4)!=0:\n        return 4294967295\n'
    for off,_ in sidecar.RELOCATIONS:
        guard+=f'    if uint(s,side_input+{off},4)!=0:\n        return 4294967295\n'
    h=owner.sidecar.HOLES['tempdir']
    guard+=f'''    temp_at=uint(s,side_input+{h},4)+{h+4}
    if temp_at<{len(owner.sidecar.BRIDGE)} or temp_at+{len(owner.tempdir.BRIDGE)}>get(w,{8*si}):
        return 4294967295
    write(w,1104,temp_at,8)
'''
    for off,_ in owner.tempdir.RELOCATIONS:guard+=f'    if uint(s,side_input+temp_at+{off},4)!=0:\n        return 4294967295\n'
    assert source.count('    layout(s,w)\n')==1
    source=source.replace('    layout(s,w)\n',guard+'    layout(s,w)\n')
    for name,start in [('prefix','0'),('tail','get(w,1040)'),('sections','get(w,1080)')]:
        for fn in calls[name]:source+=f'    {fn}(o,{start})\n'
    source+='''    sections=get(w,1080)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,1024)-64,8)
    write(o,sections+152,get(w,1040),8)
    write(o,sections+216,get(w,1048),8)
    write(o,sections+280,get(w,1056),8)
    write(o,sections+344,get(w,1064),8)
    write(o,sections+408,get(w,1072),8)
'''
    for i,name in enumerate(ROLES):
        for h in HOLES[name]:source+=f'    write(o,{64+h},get(w,{512+8*i})-{64+h+4},4)\n'
    source+=f'    write(o,{64+SIZE_HOLE},get(w,{8*ROLES.index("gen_prepare_mapping")}),4)\n'
    source+=f'''    at={head}
    i=0
    while i<{n}:
        copy(s,o,at,get(w,512+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,1088)

def same_flat(s:readbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(s,a+i)!=byte(s,b+i):
            return False
        i=i+1
    return True

def layout(s:readbuf,w:mutbuf) -> u64:
    at={len(prefix)}
    i=0
    while i<{n}:
        found=0
        j=0
        while j<i and found==0:
            if get(w,j*8)==get(w,i*8):
                if same_flat(s,get(w,1536+j*8),get(w,1536+i*8),get(w,i*8)):
                    write(w,512+i*8,get(w,512+j*8),8)
                    found=1
            j=j+1
        if found==0:
            at=(at+15)&18446744073709551600
            write(w,512+i*8,at,8)
            at=at+get(w,i*8)
        i=i+1
    write(w,1024,at,8)
    at=(at+7)&18446744073709551608
    write(w,1040,at,8)
    at=at+{len(relas)}
    write(w,1048,at,8)
    at=at+{len(symbols)}
    write(w,1056,at,8)
    at=at+{len(strings)}
    write(w,1064,at,8)
    at=at+{len(common.SECTIONS)}
    write(w,1072,at,8)
    at=(at+7)&18446744073709551608
    write(w,1080,at,8)
    write(w,1088,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
'''
    patch=f'    capsule=get(w,{512+8*pi})\n'
    targets=dict(carrier=str(64+owner.CARRIER_OFFSET),effects=str(64+owner.EFFECTS_OFFSET),values=f'get(w,{512+8*ROLES.index("values")})')
    for name,target in owner.bound.CAPSULE_IMPORTS:
        hole=owner.provider.OUTER_HOLES[name]
        patch+=f'    write(o,capsule+{hole},{targets[target]}-capsule-{hole+4},4)\n'
    for i,(_,off,_)in enumerate(DYNAMIC_RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{(len(STATIC_RELOCATIONS)+i)*24},capsule-64+{off},8)\n'
    patch+=f'    side=get(w,{512+8*si})\n'
    targets=dict(core='64',values=f'get(w,{512+8*ROLES.index("values")})',finalizer=str(64+owner.FINALIZER_OFFSET),future=str(64+FUTURE_AT))
    for name,holes in owner.sidecar.OUTER_HOLES.items():
        for off in holes:patch+=f'    write(o,side+{off},{targets[name]}-side-{off+4},4)\n'
    for name in ('code_address','code_call'):
        off=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        patch+=f'    write(o,{off},side+{owner.sidecar.CODE_EXPORT}-{off+4},4)\n'
    for name in ('future_address','future_call'):
        off=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        patch+=f'    write(o,{off},side+{sidecar.FUTURE_PROVIDER_EXPORT}-{off+4},4)\n'
    patch+='    write(o,get(w,1048)+104,side-64,8)\n'
    for i,(off,_)in enumerate(owner.tempdir.RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{(len(STATIC_RELOCATIONS)+len(DYNAMIC_RELOCATIONS)+len(sidecar.RELOCATIONS)+i)*24},side-64+get(w,1104)+{off},8)\n'
    for i,(off,_)in enumerate(sidecar.RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{(len(STATIC_RELOCATIONS)+len(DYNAMIC_RELOCATIONS)+i)*24},side-64+{off},8)\n'
    assert source.count('    return get(w,1088)\n')==1
    source=source.replace('    return get(w,1088)\n',patch+'    return get(w,1088)\n')
    return source+'\n\n'+'\n\n'.join(functions)+common.HELPERS
def main():
    doc=document(source_program(),'generation_future_managed_fusion_packer')
    path=ROOT/'examples/hia_bootstrap/generation_future_managed_fusion_packer.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(ROLES),flush=True)

if __name__=='__main__':
    main()
