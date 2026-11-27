"""Fixed global + BackgroundOptimizer root with one physical Value image.

The prior 44/45-role products retain their protocol and import boundaries.
This new profile binds the native global resource owner, installed BG loader,
and kind-six finalizer statically; no request supplies a code address.
"""
from pathlib import Path
from types import SimpleNamespace
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_background_component_fusion_packer as base
from tools import generate_hia_generation_runtime_global_capsule_packer as global_capsule
from tools import generate_hia_generation_background_bind_capsule_packer as bg_capsule
ROOT=Path(__file__).resolve().parents[1]
owner=SimpleNamespace(**{k:v for k,v in vars(base.owner).items()if not k.startswith('__')})
owner.FINALIZER_PREFIX=bytes.fromhex('535541544155415641574883ec184989fc4989f74989d54889cd4d89c64c89cb4d85e40f84cd0400004d85ed0f84c40400004d85f60f84bb0400004981ff800000000f85ae0400004881fd800000000f82a10400004881fb000100000f859404000041f6c6070f858a0400004c89e04c01f80f827e0400004c89ea4801ea0f82720400004c89f14801d90f82660400004c39e876094c39e20f87580400004c39f076094c39e10f874a0400004c39f276094c39e90f873c04000049c74560000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f841a04000083f801746583f802746c83f803747983f8040f84c100000083f805747683f8060f849000000083f80c0f84c000000083f80d0f847101000083f80e0f84f100000083f80f0f84a301000083f8100f841102000083f8110f844c02000083f8120f8445030000e9ab030000b8270000000f05e99603000031c0b901000000f0410fb14e08e98403000031c041874608e979030000498d7e08be80000000ba010000004531d24531c04531c9b8ca0000000f05e956030000498d7e08be81000000baffffff7f4531d24531c04531c9b8ca0000000f05e9330300004d897550488d05000000004989455831c0e91d030000498dbe80000000be80000000498b5620498b4e284d8b463041b900010000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424e9da020000498d8600ffffff49898680000000488b90c000000049899688000000488b90c800000049899690000000488b90d000000049899698000000488b90d8000000498996a0000000488b9098000000498996b0000000488b90a8000000498996b8000000488d0500000000498986a800000031c0e963020000498dbe80000000be80000000498b5620b9800000004d8b46c841b900010000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424e91f020000498d8600ffffff49898680000000488b90e000000049899688000000488b90e800000049899690000000488b90f000000049899698000000488b90f8000000498996a0000000488b9098000000498996b0000000488b90a8000000498996b8000000488d0500000000498986a800000031c0e9a8010000498dbe80000000be80000000498b5620b9800000004d8b46e841b900020000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424e964010000498d8600ffffff49898680000000498b5668498996900000004889542410498b567049899698000000498b5678498996a0000000488b9098000000498996b0000000488b90a8000000498996b80000004d8d9e00fdffff4d8b93400400004981bb48040000000080000f85840000004d85d2747f4981c2000270007276488d050000000049898688000000498986a8000000498b4218498986f8000000498b02498986c0000000498b4230498986c8000000498b4210498986d0000000498b4208498986d8000000498b4220498986e0000000498b82d8000000498986e8000000498b82e8000000498986f000000031c0eb7149c786880000000000000031c0eb62498db680000000498b7e204881c700003000b980000000fcf3a4498b7e204881c700003000be80000000498b5620b9000030004d8d8600fdffff41b900080000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b0424eb0049894568e9ccfbffffb8fdffffff4883c418415f415e415d415c5d5bc3')
owner.FINALIZER_HOLES={'policy': 213, 'carrier_address': 449, 'carrier_call': 495, 'code_address': 632, 'code_call': 682, 'future_address': 819, 'future_call': 869, 'background_address': 1033, 'background_call': 1228}
owner.BRIDGE,owner.HOLES,owner.RELOCATIONS,owner.SIZE_HOLE=owner.bound.patched(
 owner.original.bridges,dict(OWNER=owner.OWNER,OWNER_HOLES=owner.OWNER_HOLES,
 OWNER_RELOCATIONS=owner.OWNER_RELOCATIONS,FINALIZER_PREFIX=owner.FINALIZER_PREFIX,
 FINALIZER_HOLES=owner.FINALIZER_HOLES,
 CARRIER_BRIDGE=base.small.CARRIER_BRIDGE,CARRIER_HOLES=base.small.CARRIER_HOLES,
 CARRIER_RELOCATIONS=base.small.CARRIER_RELOCATIONS,CARRIER_SIZE_HOLE=base.small.CARRIER_SIZE_HOLE))
owner.HOLES['provider_capsule']=[owner.OWNER_HOLES['provider_address'],owner.OWNER_HOLES['provider_call']]
owner.HOLES['sidecar_capsule']=[]
owner.CARRIER_OFFSET=owner.OWNER_HOLES['carrier_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['carrier_address'])[0]
owner.EFFECTS_OFFSET=owner.CARRIER_OFFSET+((len(base.small.legacy.HANDLES_PREFIX)+15)&~15)
owner.FINALIZER_OFFSET=owner.OWNER_HOLES['finalizer_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['finalizer_address'])[0]
ROLES=base.ROLES+('global_capsule','background_bind_capsule')
MAGIC=int.from_bytes(b'HIAGBFP2','little')
IMPORTS=base.IMPORTS
EXPORT_SIZE=owner.EXPORT_SIZE
SIZE_HOLE=owner.SIZE_HOLE
STATIC_RELOCATIONS=owner.RELOCATIONS
DYNAMIC_RELOCATIONS=owner.DYNAMIC_RELOCATIONS
BASE_RELOCATIONS=STATIC_RELOCATIONS+tuple((off,name)for _,off,name in DYNAMIC_RELOCATIONS)+tuple(base.sidecar.RELOCATIONS)+tuple(owner.tempdir.RELOCATIONS)
RELOCATIONS=BASE_RELOCATIONS+global_capsule.DYNAMIC_RELOCATIONS+bg_capsule.DYNAMIC_RELOCATIONS
raw=bytearray(owner.BRIDGE);raw.extend(bytes((-len(raw))%16));FUTURE_AT=len(raw);raw.extend(base.future.BRIDGE);BRIDGE=bytes(raw)
HOLES={role:list(v)for role,v in owner.HOLES.items()}
for role in base.FUTURE_ROLES:HOLES['future_public_'+role]=[]
for role,hole in base.future.FIXUPS:
    HOLES['values'if role=='value'else'future_public_'+role].append(FUTURE_AT+hole)
HOLES['global_capsule']=[];HOLES['background_bind_capsule']=[]
assert len(ROLES)==46 and ROLES.count('values')==1 and len(set(ROLES))==46
assert all(BRIDGE[h:h+4]==bytes(4)for holes in HOLES.values()for h in holes)
assert all(name in IMPORTS for _,name in RELOCATIONS)
CAPSULES=(('global_capsule',global_capsule),('background_bind_capsule',bg_capsule))
def fixed_parts():
    common=base.common;strings=bytearray(b'\0');positions={}
    exports=(('hia_generation_lease_owner',0,EXPORT_SIZE),
      ('hia_background_optimizer_future_public',FUTURE_AT,len(base.future.BRIDGE)),
      ('hia_generation_lease_owner_sidecar',0,len(owner.sidecar.BRIDGE)),
      ('hia_generation_runtime_global',0,len(global_capsule.OUTER)),
      ('hia_generation_background_bind',0,len(bg_capsule.OUTER)))
    for name in (*(x[0]for x in exports),*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],18,0,1,at,size)for name,at,size in exports)
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((7+IMPORTS.index(name))<<32)|4,-4)for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
       ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
       ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
       ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def call(fn,*args):
    names=('owner','ROLES','MAGIC','IMPORTS','EXPORT_SIZE','SIZE_HOLE','STATIC_RELOCATIONS',
           'DYNAMIC_RELOCATIONS','RELOCATIONS','FUTURE_AT','BRIDGE','HOLES','fixed_parts')
    values={name:globals()[name]for name in names};saved={name:getattr(base,name)for name in names}
    try:
        for name,value in values.items():setattr(base,name,value)
        return fn(*args)
    finally:
        for name,value in saved.items():setattr(base,name,value)
# Reuse the existing complete stable-file mechanical entry. The fixed_stable
# logical role is its HIA policy, and is not itself the six-word operation.
_rh=global_capsule.resources.OUTER_HOLES['stable']
GLOBAL_STABLE_ENTRY=(global_capsule.RESOURCE_AT+_rh+4+
    struct.unpack_from('<i',global_capsule.resources.BRIDGE,_rh)[0])
assert global_capsule.BRIDGE[GLOBAL_STABLE_ENTRY:GLOBAL_STABLE_ENTRY+len(global_capsule.resources.stable.BRIDGE)]==global_capsule.resources.stable.BRIDGE

def targets(role,position):
    if role=='global_capsule':
        return dict(owner=64,values=position['values'],stable=position['fixed_stable'],sha=position['gen_prepare_sha'])
    stable_entry=position['global_capsule']
    stable_entry=(f'({stable_entry}+{GLOBAL_STABLE_ENTRY})'if isinstance(stable_entry,str)
                  else stable_entry+GLOBAL_STABLE_ENTRY)
    return dict(owner=64,values=position['values'],global_entry=position['global_capsule'],sidecar_entry=position['sidecar_capsule'],
      finalizer=64+owner.FINALIZER_OFFSET,loader_policy=position['fixed_loader'],
      stable=stable_entry,sha=position['gen_prepare_sha'],mapping=position['gen_prepare_mapping'])

# Immutable byte emission with exact overlapping back references.
MINIMUM_COPY=16
def fixed_bridge_source(raw):
    buckets={};commands=[];literal=bytearray();literal_at=0;at=0
    def flush():
        nonlocal literal
        for i in range(0,len(literal),8):
            chunk=literal[i:i+8]
            commands.append(f'    write(o,at+{literal_at+i},{int.from_bytes(chunk,"little")},{len(chunk)})')
        literal=bytearray()
    while at<len(raw):
        best=0;prior=0
        if at+8<=len(raw):
            for old in reversed(buckets.get(raw[at:at+8],())[-96:]):
                n=8
                while at+n<len(raw)and raw[old+n]==raw[at+n]:n+=1
                if n>best:best=n;prior=old
        if best>=MINIMUM_COPY:
            flush()
            commands.append(f'    background_root_bridge_copy(o,at+{at},at+{prior},{best})')
            step=best
        else:
            if not literal:literal_at=at
            literal.append(raw[at]);step=1
        for pos in range(at,at+step):
            if pos+8<=len(raw):buckets.setdefault(raw[pos:pos+8],[]).append(pos)
        at+=step
    flush();calls=[];functions=[]
    for i in range(0,len(commands),120):
        name='background_root_bridge_bytes_'+str(i//120)
        calls.append(name)
        functions.append('def '+name+'(o:mutbuf,at:u64) -> u32:\n'+'\n'.join(commands[i:i+120])+'\n    return 0\n')
    functions.append('''def background_root_bridge_copy(o:mutbuf,to:u64,source:u64,n:u64) -> u32:
    i=0
    while i<n:
        store(o,to+i,byte(o,source+i))
        i=i+1
    return 0
''')
    return calls,'\n'.join(functions)

def source_program():
    old=base.common.emitters
    def emit(name,raw):return fixed_bridge_source(raw)if name=='prefix'else old(name,raw)
    try:
        base.common.emitters=emit;source=call(base._source_program)
    finally:base.common.emitters=old
    guard=''
    for role,capsule in CAPSULES:
        index=ROLES.index(role);guard+=f'    extra_input=get(w,{1536+8*index})\n'
        guard+=f'    if get(w,{8*index})<{len(capsule.BRIDGE)}:\n        return 4294967295\n'
        for off in sorted({x for hs in capsule.FIXED_HOLES.values()for x in hs}|{x for x,_ in capsule.DYNAMIC_RELOCATIONS}):
            guard+=f'    if uint(s,extra_input+{off},4)!=0:\n        return 4294967295\n'
    assert source.count('    layout(s,w)\n')==1
    source=source.replace('    layout(s,w)\n',guard+'    layout(s,w)\n')
    import re
    pattern=r'(?:    if uint\(s,[^\n]+\)!=0:\n        return 4294967295\n){2,}'
    def combine(match):
        expressions=re.findall(r'    if (uint\(s,[^\n]+\))!=0:',match.group())
        return '    unresolved='+'|'.join(expressions)+'\n    if unresolved!=0:\n        return 4294967295\n'
    source=re.sub(pattern,combine,source)
    position={role:f'get(w,{512+8*i})'for i,role in enumerate(ROLES)}
    patch='';relocation_index=len(BASE_RELOCATIONS)
    for j,(role,capsule)in enumerate(CAPSULES):
        at=position[role];patch+=f'    extra_at={at}\n'
        for name,holes in capsule.FIXED_HOLES.items():
            target=targets(role,position)[name]
            for off in holes:patch+=f'    write(o,extra_at+{off},{target}-extra_at-{off+4},4)\n'
        for off,_ in capsule.DYNAMIC_RELOCATIONS:
            patch+=f'    write(o,get(w,1040)+{24*relocation_index},extra_at-64+{off},8)\n'
            relocation_index+=1
        patch+=f'    write(o,get(w,1048)+{128+24*j},extra_at-64,8)\n'
    for name in ('background_address','background_call'):
        off=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        patch+=f'    write(o,{off},{position["background_bind_capsule"]}-{off+4},4)\n'
    assert source.count('    return get(w,1088)\n')==1
    return source.replace('    return get(w,1088)\n',patch+'    return get(w,1088)\n')
def reference_object(parts):
    if len(parts)!=len(ROLES):raise ValueError('46 actual fixed native roles required')
    for role,capsule in CAPSULES:
        data=parts[ROLES.index(role)]
        if len(data)<len(capsule.BRIDGE):raise ValueError('complete fixed capsule required')
        for off in {x for hs in capsule.FIXED_HOLES.values()for x in hs}|{x for x,_ in capsule.DYNAMIC_RELOCATIONS}:
            if data[off:off+4]!=bytes(4):raise ValueError('unresolved fixed holes required')
    raw=bytearray(call(base.reference_object,parts));at=64+len(BRIDGE);seen={};positions={}
    for role,part in zip(ROLES,parts):
        if part in seen:position=seen[part]
        else:
            at=(at+15)&~15;position=at;seen[part]=at;at+=len(part)
        positions[role]=position
    sh=struct.unpack_from('<Q',raw,40)[0];rela=struct.unpack_from('<Q',raw,sh+64*2+24)[0];symtab=struct.unpack_from('<Q',raw,sh+64*3+24)[0]
    relocation_index=len(BASE_RELOCATIONS)
    for j,(role,capsule)in enumerate(CAPSULES):
        at=positions[role]
        for name,holes in capsule.FIXED_HOLES.items():
            target=targets(role,positions)[name]
            for off in holes:struct.pack_into('<i',raw,at+off,target-at-off-4)
        for off,_ in capsule.DYNAMIC_RELOCATIONS:
            struct.pack_into('<Q',raw,rela+24*relocation_index,at-64+off);relocation_index+=1
        struct.pack_into('<Q',raw,symtab+128+24*j,at-64)
    for name in ('background_address','background_call'):
        off=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        struct.pack_into('<i',raw,off,positions['background_bind_capsule']-off-4)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_background_native_fusion_packer')
    p=ROOT/'examples/hia_bootstrap/generation_background_native_fusion_packer.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(ROLES),len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
