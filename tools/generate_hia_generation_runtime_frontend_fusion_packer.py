"""Sole root plus fixed public-constructor frontend; old45 profile remains."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_runtime_global_fusion_packer as prior
from tools import generate_hia_generation_runtime_frontend_capsule_packer as front
ROOT=Path(__file__).resolve().parents[1]
ROLES=prior.ROLES+('frontend_capsule',)
MAGIC=int.from_bytes(b'HIAGFUP7','little')
BRIDGE=prior.BRIDGE;IMPORTS=prior.IMPORTS;OLD_RELOCATION_COUNT=len(prior.RELOCATIONS)
RELOCATIONS=prior.RELOCATIONS+front.DYNAMIC_RELOCATIONS
HOLES={name:list(v)for name,v in prior.HOLES.items()};HOLES['frontend_capsule']=[]
def fixed_parts():
    common=prior.small.base.common
    strings=bytearray(b'\0');positions={}
    exports=(('hia_generation_lease_owner',0,prior.small.EXPORT_SIZE),
      ('hia_background_optimizer_future_public',prior.small.FUTURE_AT,len(prior.small.base.future.BRIDGE)),
      ('hia_generation_lease_owner_sidecar',0,len(prior.small.owner.sidecar.BRIDGE)),
      ('hia_generation_runtime_global',0,len(prior.capsule.OUTER)),*front.EXPORTS)
    for name in(*(x[0]for x in exports),*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],18,0,1,at,size)for name,at,size in exports)
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((9+IMPORTS.index(name))<<32)|4,-4)for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in[
       ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
       ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
       ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def call(fn,*args):
    changes=dict(ROLES=ROLES,MAGIC=MAGIC,BRIDGE=BRIDGE,IMPORTS=IMPORTS,RELOCATIONS=RELOCATIONS,HOLES=HOLES,fixed_parts=fixed_parts)
    old={name:getattr(prior,name)for name in changes}
    try:
        for name,value in changes.items():setattr(prior,name,value)
        return fn(*args)
    finally:
        for name,value in old.items():setattr(prior,name,value)
def source_program():
    source=call(prior.source_program)
    fi=ROLES.index('frontend_capsule');gi=ROLES.index('global_capsule')
    guard=f'    frontend_input=get(w,{1536+8*fi})\n    if get(w,{8*fi})<{len(front.BRIDGE)}:\n        return 4294967295\n'
    for off in sorted({x for holes in front.FIXED_HOLES.values()for x in holes}):
        guard+=f'    if uint(s,frontend_input+{off},4)!=0:\n        return 4294967295\n'
    assert source.count('    layout(s,w)\n')==1
    source=source.replace('    layout(s,w)\n',guard+'    layout(s,w)\n')
    patch=f'    frontend_at=get(w,{512+8*fi})\n'
    targets=dict(owner='64',values=f'get(w,{512+8*ROLES.index("values")})',global_owner=f'get(w,{512+8*gi})')
    for name,holes in front.FIXED_HOLES.items():
        for off in holes:patch+=f'    write(o,frontend_at+{off},{targets[name]}-frontend_at-{off+4},4)\n'
    for i,(off,_)in enumerate(front.DYNAMIC_RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{24*(OLD_RELOCATION_COUNT+i)},frontend_at-64+{off},8)\n'
    for i,(_,at,_)in enumerate(front.EXPORTS):
        patch+=f'    write(o,get(w,1048)+{152+i*24},frontend_at-64+{at},8)\n'
    assert source.count('    return get(w,1088)\n')==1
    return source.replace('    return get(w,1088)\n',patch+'    return get(w,1088)\n')
def reference_object(parts):
    if len(parts)!=len(ROLES):raise ValueError('all46 native roles required')
    for index,unit in[(ROLES.index('global_capsule'),prior.capsule),(ROLES.index('frontend_capsule'),front)]:
        if len(parts[index])<len(unit.BRIDGE):raise ValueError('complete actual capsule required')
        for off in{x for holes in unit.FIXED_HOLES.values()for x in holes}:
            if parts[index][off:off+4]!=bytes(4):raise ValueError('unresolved fixed imports required')
    raw=bytearray(call(prior.call,prior.small.base.reference_object,parts))
    at=64+len(BRIDGE);seen={};positions={}
    for name,part in zip(ROLES,parts):
        if part in seen:position=seen[part]
        else:
            at=(at+15)&~15;position=at;seen[part]=at;at+=len(part)
        positions[name]=position
    global_at=positions['global_capsule'];frontend_at=positions['frontend_capsule']
    targets=dict(owner=64,values=positions['values'],stable=positions['fixed_stable'],sha=positions['gen_prepare_sha'])
    for name,holes in prior.capsule.FIXED_HOLES.items():
        for off in holes:struct.pack_into('<i',raw,global_at+off,targets[name]-global_at-off-4)
    targets=dict(owner=64,values=positions['values'],global_owner=global_at)
    for name,holes in front.FIXED_HOLES.items():
        for off in holes:struct.pack_into('<i',raw,frontend_at+off,targets[name]-frontend_at-off-4)
    sh=struct.unpack_from('<Q',raw,40)[0];rela=struct.unpack_from('<Q',raw,sh+152)[0];symtab=struct.unpack_from('<Q',raw,sh+216)[0]
    for i,(off,_)in enumerate(prior.capsule.DYNAMIC_RELOCATIONS):
        struct.pack_into('<Q',raw,rela+24*(len(prior.small.RELOCATIONS)+i),global_at-64+off)
    for i,(off,_)in enumerate(front.DYNAMIC_RELOCATIONS):
        struct.pack_into('<Q',raw,rela+24*(OLD_RELOCATION_COUNT+i),frontend_at-64+off)
    struct.pack_into('<Q',raw,symtab+128,global_at-64)
    for i,(_,off,_)in enumerate(front.EXPORTS):struct.pack_into('<Q',raw,symtab+152+i*24,frontend_at-64+off)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_runtime_frontend_fusion_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_fusion_packer.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(ROLES),len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
