"""Runtime terminal installed-resource custody, with the typed VFY frontend.

All old root profiles remain unchanged. The actual last native Runtime holder
retires the resource ledger before its native carrier object may be freed.
"""
from pathlib import Path
from types import SimpleNamespace
import struct,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_future_component_fusion_packer as small
from tools import generate_hia_generation_runtime_global_capsule_packer as global_capsule
from tools import generate_hia_generation_runtime_verified_frontend_capsule_packer as frontend
from tools import generate_hia_generation_runtime_borrow_packer as borrow
ROOT=Path(__file__).resolve().parents[1]
base=small.base
HANDLES_PREFIX=bytes.fromhex('535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000000060f82f10100004881fb000100000f82e401000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84a801000083f80a74dc83f8010f84cb00000083f8020f840e01000083f8030f841a01000083f8040f842001000083f8060f842001000083f8070f842201000083f8080f842601000083f80d745f83f80c0f855601000031c9498b44cd004883f8030f8740010000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d404d8d9e00010000e800000000e9ef000000498dbd00009002be80000000498d9500001000b9000004004d8d8600ffffff41b900080000e80000000089c0e9be0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb72498b55004c01f2418b4508418b4d10f00fb10aeb5d498b55004c01f2418b45088702eb4e498b45004c01e8eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f803772f498b7508480334c4498b45104883f803771d498b7d1848033cc4498b4d20fcf3a431c049898578010000e93efeffffb8fdffffff4881c498000000415f415e415d415c5d5bc3')
HANDLES_HOLES=dict(handles=114,effects=285,runtime_borrow=332)
HANDLES_RELOCATIONS=((469,'malloc'),(480,'free'))
def carrier_bridges():
    changes=dict(HANDLES_PREFIX=HANDLES_PREFIX,HANDLES_HOLES=HANDLES_HOLES,HANDLES_RELOCATIONS=HANDLES_RELOCATIONS)
    old={k:getattr(small.legacy,k)for k in changes}
    try:
        for k,v in changes.items():setattr(small.legacy,k,v)
        raw,holes,relocations,size_hole=small.carrier_bridges()
    finally:
        for k,v in old.items():setattr(small.legacy,k,v)
    holes['runtime_borrow']=[HANDLES_HOLES['runtime_borrow']]
    return raw,holes,relocations,size_hole
CARRIER_BRIDGE,CARRIER_HOLES,CARRIER_RELOCATIONS,CARRIER_SIZE_HOLE=carrier_bridges()
owner=SimpleNamespace(**vars(small.owner))
owner.BRIDGE,owner.HOLES,owner.RELOCATIONS,owner.SIZE_HOLE=owner.bound.patched(
    owner.original.bridges,dict(OWNER=owner.OWNER,OWNER_HOLES=owner.OWNER_HOLES,
      OWNER_RELOCATIONS=owner.OWNER_RELOCATIONS,FINALIZER_PREFIX=owner.FINALIZER_PREFIX,
      FINALIZER_HOLES=owner.FINALIZER_HOLES,CARRIER_BRIDGE=CARRIER_BRIDGE,
      CARRIER_HOLES=CARRIER_HOLES,CARRIER_RELOCATIONS=CARRIER_RELOCATIONS,CARRIER_SIZE_HOLE=CARRIER_SIZE_HOLE))
owner.HOLES['provider_capsule']=[owner.OWNER_HOLES['provider_address'],owner.OWNER_HOLES['provider_call']]
owner.HOLES['sidecar_capsule']=[]
owner.CARRIER_OFFSET=owner.OWNER_HOLES['carrier_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['carrier_address'])[0]
owner.EFFECTS_OFFSET=owner.CARRIER_OFFSET+((len(HANDLES_PREFIX)+15)&~15)
owner.FINALIZER_OFFSET=owner.OWNER_HOLES['finalizer_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['finalizer_address'])[0]
owner.ROLES=small.owner.ROLES+('runtime_borrow',)
FUTURE_ROLES=small.FUTURE_ROLES
ROLES=small.ROLES+('global_capsule','frontend_capsule','runtime_borrow')
MAGIC=int.from_bytes(b'HIAGFUP9','little')
IMPORTS=small.IMPORTS;EXPORT_SIZE=small.EXPORT_SIZE;SIZE_HOLE=owner.SIZE_HOLE
STATIC_RELOCATIONS=tuple(sorted(owner.RELOCATIONS))
DYNAMIC_RELOCATIONS=owner.DYNAMIC_RELOCATIONS
BASE_RELOCATIONS=STATIC_RELOCATIONS+tuple((off,name)for _,off,name in DYNAMIC_RELOCATIONS)+tuple(base.sidecar.RELOCATIONS)+tuple(owner.tempdir.RELOCATIONS)
RELOCATIONS=BASE_RELOCATIONS+global_capsule.DYNAMIC_RELOCATIONS+frontend.DYNAMIC_RELOCATIONS
raw=bytearray(owner.BRIDGE);raw.extend(bytes((-len(raw))%16));FUTURE_AT=len(raw);raw.extend(base.future.BRIDGE)
BRIDGE=bytes(raw)
HOLES={k:list(v)for k,v in owner.HOLES.items()}
for role in FUTURE_ROLES:HOLES['future_public_'+role]=[]
for role,hole in base.future.FIXUPS:
    selected='values'if role=='value'else'future_public_'+role
    HOLES[selected].append(FUTURE_AT+hole)
HOLES['global_capsule']=[];HOLES['frontend_capsule']=[]
assert len(ROLES)==47 and len(set(ROLES))==47 and ROLES.count('values')==1
assert set(HOLES)==set(ROLES)
assert all(BRIDGE[h:h+4]==bytes(4)for holes in HOLES.values()for h in holes)
EXPORTS=(('hia_generation_lease_owner',0,EXPORT_SIZE),
 ('hia_background_optimizer_future_public',FUTURE_AT,len(base.future.BRIDGE)),
 ('hia_generation_lease_owner_sidecar',0,len(owner.sidecar.BRIDGE)),
 ('hia_generation_runtime_global',0,len(global_capsule.OUTER)),
 *frontend.EXPORTS,('hia_generation_runtime_borrow',0,len(borrow.BRIDGE)))
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in(*(x[0]for x in EXPORTS),*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],18,0,1,at,size)for name,at,size in EXPORTS)
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((len(EXPORTS)+2+IMPORTS.index(name))<<32)|4,-4)for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in[
       ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
       ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
       ('.shstrtab',3,0,len(base.common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def call(fn,*args):
    names=('owner','ROLES','MAGIC','IMPORTS','EXPORT_SIZE','SIZE_HOLE','STATIC_RELOCATIONS','DYNAMIC_RELOCATIONS','RELOCATIONS','FUTURE_AT','BRIDGE','HOLES','fixed_parts')
    old={k:getattr(base,k)for k in names}
    try:
        for k in names:setattr(base,k,globals()[k])
        return fn(*args)
    finally:
        for k,v in old.items():setattr(base,k,v)
def fixed_bytes(raw):
    """Encode only build-time immutable bytes, including exact back references."""
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
        if best>=16:
            flush()
            commands.append(f'    component_root_bridge_copy(o,at+{at},at+{prior},{best})')
            step=best
        else:
            if not literal:literal_at=at
            literal.append(raw[at]);step=1
        for pos in range(at,at+step):
            if pos+8<=len(raw):buckets.setdefault(raw[pos:pos+8],[]).append(pos)
        at+=step
    flush()
    calls=[];functions=[]
    for i in range(0,len(commands),120):
        name='component_root_bridge_bytes_'+str(i//120)
        calls.append(name)
        functions.append('def '+name+'(o:mutbuf,at:u64) -> u32:\n'+'\n'.join(commands[i:i+120])+'\n    return 0\n')
    functions.append('''def component_root_bridge_copy(o:mutbuf,to:u64,source:u64,n:u64) -> u32:
    i=0
    while i<n:
        store(o,to+i,byte(o,source+i))
        i=i+1
    return 0
''')
    return calls,'\n'.join(functions)
def source_program():
    old=base.common.emitters
    def emit(name,raw):
        calls,source=fixed_bytes(raw)
        # The packer already zeroes its entire actual output before emitters.
        # Omitting literal zero stores preserves exactly the independent image.
        source=re.sub(r'(?m)^    write\(o,at\+\d+,0,\d+\)\n','',source)
        prefix='runtime_custody_'+name
        return [x.replace('component_root_bridge',prefix)for x in calls],source.replace('component_root_bridge',prefix)
    try:
        base.common.emitters=emit
        source=call(base.source_program)
    finally:base.common.emitters=old
    units=(('global_capsule',global_capsule),('frontend_capsule',frontend),('runtime_borrow',borrow))
    guard=''
    for name,unit in units:
        i=ROLES.index(name);label=name+'_input'
        guard+=f'    {label}=get(w,{1536+8*i})\n    if get(w,{8*i})<{len(unit.BRIDGE)}:\n        return 4294967295\n'
        offsets={x for holes in unit.FIXED_HOLES.values()for x in holes}
        offsets.update(x for x,_ in getattr(unit,'DYNAMIC_RELOCATIONS',()))
        for off in sorted(offsets):guard+=f'    if uint(s,{label}+{off},4)!=0:\n        return 4294967295\n'
    assert source.count('    layout(s,w)\n')==1
    source=source.replace('    layout(s,w)\n',guard+'    layout(s,w)\n')
    gi=ROLES.index('global_capsule');fi=ROLES.index('frontend_capsule');bi=ROLES.index('runtime_borrow')
    global_at=f'get(w,{512+8*gi})';value_at=f'get(w,{512+8*ROLES.index("values")})'
    table=(
      ('global_capsule',global_capsule,dict(owner='64',values=value_at,stable=f'get(w,{512+8*ROLES.index("fixed_stable")})',sha=f'get(w,{512+8*ROLES.index("gen_prepare_sha")})')),
      ('frontend_capsule',frontend,dict(owner='64',values=value_at,global_owner=global_at)),
      ('runtime_borrow',borrow,dict(owner='64',global_owner=global_at,carrier=str(64+owner.CARRIER_OFFSET))))
    patch=''
    for name,unit,targets in table:
        i=ROLES.index(name);at=name+'_at'
        patch+=f'    {at}=get(w,{512+8*i})\n'
        for role,holes in unit.FIXED_HOLES.items():
            for off in holes:patch+=f'    write(o,{at}+{off},{targets[role]}-{at}-{off+4},4)\n'
    for name,unit,first in(('global_capsule',global_capsule,len(BASE_RELOCATIONS)),('frontend_capsule',frontend,len(BASE_RELOCATIONS)+len(global_capsule.DYNAMIC_RELOCATIONS))):
        for i,(off,_)in enumerate(unit.DYNAMIC_RELOCATIONS):
            patch+=f'    write(o,get(w,1040)+{24*(first+i)},{name}_at-64+{off},8)\n'
    patch+='    write(o,get(w,1048)+128,global_capsule_at-64,8)\n'
    for i,(_,at,_)in enumerate(frontend.EXPORTS):patch+=f'    write(o,get(w,1048)+{152+i*24},frontend_capsule_at-64+{at},8)\n'
    patch+='    write(o,get(w,1048)+224,runtime_borrow_at-64,8)\n'
    assert source.count('    return get(w,1088)\n')==1
    return source.replace('    return get(w,1088)\n',patch+'    return get(w,1088)\n')
def reference_object(parts):
    if len(parts)!=47:raise ValueError('all47 native roles required')
    for name,unit in(('global_capsule',global_capsule),('frontend_capsule',frontend),('runtime_borrow',borrow)):
        part=parts[ROLES.index(name)]
        if len(part)<len(unit.BRIDGE):raise ValueError('complete actual capsule required')
        offsets={x for hs in unit.FIXED_HOLES.values()for x in hs}|{x for x,_ in getattr(unit,'DYNAMIC_RELOCATIONS',())}
        if any(part[x:x+4]!=bytes(4)for x in offsets):raise ValueError('fixed native imports must be unresolved')
    raw=bytearray(call(base.reference_object,parts))
    at=64+len(BRIDGE);seen={};positions={}
    for name,part in zip(ROLES,parts):
        if part in seen:position=seen[part]
        else:
            at=(at+15)&~15;position=at;seen[part]=at;at+=len(part)
        positions[name]=position
    table=(
      ('global_capsule',global_capsule,dict(owner=64,values=positions['values'],stable=positions['fixed_stable'],sha=positions['gen_prepare_sha'])),
      ('frontend_capsule',frontend,dict(owner=64,values=positions['values'],global_owner=positions['global_capsule'])),
      ('runtime_borrow',borrow,dict(owner=64,global_owner=positions['global_capsule'],carrier=64+owner.CARRIER_OFFSET)))
    for name,unit,targets in table:
        at=positions[name]
        for role,holes in unit.FIXED_HOLES.items():
            for off in holes:struct.pack_into('<i',raw,at+off,targets[role]-at-off-4)
    sh=struct.unpack_from('<Q',raw,40)[0];rela=struct.unpack_from('<Q',raw,sh+152)[0];sym=struct.unpack_from('<Q',raw,sh+216)[0]
    for name,unit,first in(('global_capsule',global_capsule,len(BASE_RELOCATIONS)),('frontend_capsule',frontend,len(BASE_RELOCATIONS)+len(global_capsule.DYNAMIC_RELOCATIONS))):
        for i,(off,_)in enumerate(unit.DYNAMIC_RELOCATIONS):struct.pack_into('<Q',raw,rela+24*(first+i),positions[name]-64+off)
    struct.pack_into('<Q',raw,sym+128,positions['global_capsule']-64)
    for i,(_,at,_)in enumerate(frontend.EXPORTS):struct.pack_into('<Q',raw,sym+152+i*24,positions['frontend_capsule']-64+at)
    struct.pack_into('<Q',raw,sym+224,positions['runtime_borrow']-64)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_runtime_custody_fusion_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_custody_fusion_packer.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(ROLES),len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
