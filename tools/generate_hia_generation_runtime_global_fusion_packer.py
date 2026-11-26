"""Root component profile with a single installed native resource initializer.

The legacy 44-role profile remains unchanged. One bounded global capsule shares
the root's exact existing Value, stable-file and SHA bodies.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_future_component_fusion_packer as small
from tools import generate_hia_generation_runtime_global_capsule_packer as capsule
ROOT=Path(__file__).resolve().parents[1]
ROLES=small.ROLES+('global_capsule',)
MAGIC=int.from_bytes(b'HIAGFUP6','little')
IMPORTS=small.IMPORTS
BRIDGE=small.BRIDGE
HOLES={name:list(v)for name,v in small.HOLES.items()};HOLES['global_capsule']=[]
RELOCATIONS=small.RELOCATIONS+capsule.DYNAMIC_RELOCATIONS
def fixed_parts():
    common=small.base.common
    strings=bytearray(b'\0');positions={}
    exports=(('hia_generation_lease_owner',0,small.EXPORT_SIZE),
      ('hia_background_optimizer_future_public',small.FUTURE_AT,len(small.base.future.BRIDGE)),
      ('hia_generation_lease_owner_sidecar',0,len(small.owner.sidecar.BRIDGE)),
      ('hia_generation_runtime_global',0,len(capsule.OUTER)))
    for name in(*(x[0]for x in exports),*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],18,0,1,at,size)for name,at,size in exports)
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((6+IMPORTS.index(name))<<32)|4,-4)for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in[
       ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
       ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
       ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def call(fn,*args):
    base=small.base
    values={name:getattr(small,name)for name in('owner','EXPORT_SIZE','SIZE_HOLE','STATIC_RELOCATIONS','DYNAMIC_RELOCATIONS','FUTURE_AT')}
    values.update(ROLES=ROLES,MAGIC=MAGIC,IMPORTS=IMPORTS,BRIDGE=BRIDGE,HOLES=HOLES,RELOCATIONS=RELOCATIONS,fixed_parts=fixed_parts)
    saved={name:getattr(base,name)for name in values}
    try:
        for name,value in values.items():setattr(base,name,value)
        return fn(*args)
    finally:
        for name,value in saved.items():setattr(base,name,value)
def source_program():
    old=small.base.common.emitters
    def emit(name,raw):
        return small.fixed_bridge_source(raw)if name=='prefix'else old(name,raw)
    try:
        small.base.common.emitters=emit
        source=call(small.base.source_program)
    finally:small.base.common.emitters=old
    gi=ROLES.index('global_capsule')
    guard=f'''    global_input=get(w,{1536+8*gi})
    if get(w,{8*gi})<{len(capsule.BRIDGE)}:
        return 4294967295
'''
    for off in sorted({x for hs in capsule.FIXED_HOLES.values()for x in hs}|{x for x,_ in capsule.DYNAMIC_RELOCATIONS}):
        guard+=f'    if uint(s,global_input+{off},4)!=0:\n        return 4294967295\n'
    assert source.count('    layout(s,w)\n')==1
    source=source.replace('    layout(s,w)\n',guard+'    layout(s,w)\n')
    patch=f'    global_at=get(w,{512+8*gi})\n'
    targets=dict(owner='64',values=f'get(w,{512+8*ROLES.index("values")})',
       stable=f'get(w,{512+8*ROLES.index("fixed_stable")})',sha=f'get(w,{512+8*ROLES.index("gen_prepare_sha")})')
    for role,holes in capsule.FIXED_HOLES.items():
        for off in holes:patch+=f'    write(o,global_at+{off},{targets[role]}-global_at-{off+4},4)\n'
    for i,(off,_)in enumerate(capsule.DYNAMIC_RELOCATIONS):
        patch+=f'    write(o,get(w,1040)+{24*(len(small.RELOCATIONS)+i)},global_at-64+{off},8)\n'
    patch+='    write(o,get(w,1048)+128,global_at-64,8)\n'
    assert source.count('    return get(w,1088)\n')==1
    return source.replace('    return get(w,1088)\n',patch+'    return get(w,1088)\n')
def reference_object(parts):
    if len(parts)!=len(ROLES):raise ValueError('all 45 actual fixed roles required')
    data=parts[-1]
    if len(data)<len(capsule.BRIDGE):raise ValueError('complete actual global capsule required')
    for off in {x for hs in capsule.FIXED_HOLES.values()for x in hs}|{x for x,_ in capsule.DYNAMIC_RELOCATIONS}:
        if data[off:off+4]!=bytes(4):raise ValueError('unresolved fixed global holes required')
    raw=bytearray(call(small.base.reference_object,parts))
    at=64+len(BRIDGE);seen={};positions={}
    for role,part in zip(ROLES,parts):
        if part in seen:position=seen[part]
        else:
            at=(at+15)&~15;position=at;seen[part]=at;at+=len(part)
        positions[role]=position
    global_at=positions['global_capsule']
    targets=dict(owner=64,values=positions['values'],stable=positions['fixed_stable'],sha=positions['gen_prepare_sha'])
    for role,holes in capsule.FIXED_HOLES.items():
        for off in holes:struct.pack_into('<i',raw,global_at+off,targets[role]-global_at-off-4)
    sh=struct.unpack_from('<Q',raw,40)[0]
    rela=struct.unpack_from('<Q',raw,sh+64*2+24)[0]
    symtab=struct.unpack_from('<Q',raw,sh+64*3+24)[0]
    for i,(off,_)in enumerate(capsule.DYNAMIC_RELOCATIONS):
        struct.pack_into('<Q',raw,rela+24*(len(small.RELOCATIONS)+i),global_at-64+off)
    struct.pack_into('<Q',raw,symtab+128,global_at-64)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_runtime_global_fusion_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_global_fusion_packer.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(ROLES),len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
