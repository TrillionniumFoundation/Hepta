"""Ordered private Runtime constructor root, retaining terminal resource custody.

All old root profiles remain unchanged. The actual last native Runtime holder
retires the resource ledger before its native carrier object may be freed.
"""
from pathlib import Path
from types import SimpleNamespace
import struct,re
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_clang_capture_common as authoring
import ast
def document(source,module):
    tree=ast.parse(source)
    nodes={n.name:n for n in tree.body}
    assert len(nodes)==len(tree.body)
    entry=tree.body[0].name
    selected={entry};pending=[entry]
    while pending:
        for node in ast.walk(nodes[pending.pop()]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in nodes and node.func.id not in selected:
                selected.add(node.func.id);pending.append(node.func.id)
    ordered=[nodes[entry]]+[n for n in tree.body if n.name in selected and n.name!=entry]
    names={n.name:'f'+str(i) for i,n in enumerate(ordered)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in ordered}
    total=authoring.total_scalar_functions(ordered);functions=[]
    for n in ordered:
        b=authoring.CaptureBuilder(n,names,sigs,total);b.statements(n.body)
        functions.append(dict(name=names[n.name],params=[b.param(p) for p in b.params],returns=[b.returns],effects=['read','write','trap'],entry='b0',blocks=b.blocks))
    doc=authoring.compact_authoring_cfg(dict(schema='hepta.hia.program.v9',module=module,functions=functions))
    assert len(functions)<=128 and sum(len(f['blocks']) for f in functions)<=1536 and sum(len(b['ops']) for f in functions for b in f['blocks'])<=8192
    return doc
from tools import generate_hia_generation_future_component_fusion_packer as small
from tools import generate_hia_generation_runtime_global_capsule_packer as global_capsule
from tools import generate_hia_generation_runtime_frontend_install_packer as frontend
from tools import generate_hia_generation_runtime_borrow_packer as borrow
ROOT=Path(__file__).resolve().parents[1]
_stable_hole=global_capsule.resources.OUTER_HOLES['stable']
GLOBAL_STABLE_ENTRY=global_capsule.RESOURCE_AT+_stable_hole+4+struct.unpack_from('<i',global_capsule.resources.BRIDGE,_stable_hole)[0]
base=small.base
HANDLES_PREFIX=bytes.fromhex('535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000000060f82f10100004881fb000100000f82e401000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84a801000083f80a74dc83f8010f84cb00000083f8020f840e01000083f8030f841a01000083f8040f842001000083f8060f842001000083f8070f842201000083f8080f842601000083f80d745f83f80c0f855601000031c9498b44cd004883f8030f8740010000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d404d8d9e00010000e800000000e9ef000000498dbd00009002be80000000498d9500001000b9000004004d8d8600ffffff41b900080000e80000000089c0e9be0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb72498b55004c01f2418b4508418b4d10f00fb10aeb5d498b55004c01f2418b45088702eb4e498b45004c01e8eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f803772f498b7508480334c4498b45104883f803771d498b7d1848033cc4498b4d20fcf3a431c049898578010000e93efeffffb8fdffffff4881c498000000415f415e415d415c5d5bc3')
HANDLES_HOLES=dict(handles=114,effects=285,runtime_borrow=332)
HANDLES_RELOCATIONS=((469,'malloc'),(480,'free'))
EFFECTS=bytes.fromhex('535541544155415641574881eca80000004c899c24980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000080020f82600400004881fb000002000f825304000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000083f8230f84ac01000083f8210f841102000083f8190f844002000083f81b0f841b02000085c00f84e803000083f80a74b883f8010f84bf02000083f8020f840503000083f8030f841103000083f8040f841703000083f8060f841a03000083f8070f841f03000083f8080f842303000083f8150f844903000083f8160f84f501000083f824743583f822743083f820742b83f81a742683f81c742183f81d741c83f817741783f818741283f80c0f826c03000083f8140f87630300008944245031c9498b44cd004883f8030f8749030000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d408b44245083f8240f849100000083f8220f848601000083f8200f84b500000083f81a0f84d800000083f81c0f84d900000083f81d0f84da00000083f8170f84a900000083f8180f84aa00000083f80c0f843501000083f80d0f845001000083f80e0f845101000083f80f0f845201000083f8100f845301000083f8110f845401000083f8120f845501000083f8130f8456010000e800000000e9650200004c8b9c2498000000e800000000e9530200004c89e74c89fe4c89ea4889e94d89f04989d94c8b9c2498000000e800000000e927feffff4c8b84249800000041b900010000e800000000e917020000e800000000e90d020000e800000000e903020000e800000000e9f9010000e800000000e9ef010000e800000000e9e50100004c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9c1fdffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9a5fdffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e989fdffff488d0500000000b90000000049898d20800000e9790100004c8b9c2498000000e800000000e9670100004c8b9c2498000000e800000000e955010000e800000000e94b010000e800000000e941010000e800000000e937010000e800000000e92d010000e800000000e923010000e800000000e919010000e800000000e90f0100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9c0000000498b5500418b4508418b4d10f00fb10ae9ab000000498b5500418b45088702e99c000000498b45004c01f0e990000000498b7d00e800000000e982000000498b7d00e80000000031c0eb75498b45004883f803777d498b7508480334c4498b45104883f803776b498b7d1848033cc4498b4d20fcf3a431c0eb464d8b5d0049837d0810774d4d8b55104d01ea4883ec5031c9498b44ca30488904ccffc183f90a72f0498b3a498b7208498b5210498b4a184d8b42204d8b4a2841ffd34883c45049898588000000e9d5fbffff418b4508eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
EH={'effects': 122, 'typed': 536, 'constructor_directory': 554, 'constructor_policy': 590, 'values': 614, 'information': 624, 'hash': 634, 'snapshot': 644, 'snapshot_retirement': 654, 'snapshot_number': 664, 'typed_policy': 692, 'snapshot_capture': 720, 'capture': 748, 'mapping_span': 760, 'mapping_size': 765, 'generation': 790, 'generation_close': 808, 'identity': 818, 'state': 828, 'retention': 838, 'future': 848, 'call': 858, 'measure': 868, 'directory': 878}
ER=((1019, 'malloc'), (1033, 'free'))
def carrier_bridges():
    changes=dict(HANDLES_PREFIX=HANDLES_PREFIX,HANDLES_HOLES=HANDLES_HOLES,HANDLES_RELOCATIONS=HANDLES_RELOCATIONS)
    old={k:getattr(small.legacy,k)for k in changes}
    kept=small.EFFECTS,small.EH,small.ER
    try:
        for k,v in changes.items():setattr(small.legacy,k,v)
        small.EFFECTS,small.EH,small.ER=EFFECTS,EH,ER
        raw,holes,relocations,size_hole=small.carrier_bridges()
    finally:
        for k,v in old.items():setattr(small.legacy,k,v)
        small.EFFECTS,small.EH,small.ER=kept
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
MAGIC=int.from_bytes(b'HIAGFU11','little')
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
HOLES['global_capsule']=[]
CTOR_DIRECTORY=owner.EFFECTS_OFFSET+EH['constructor_directory']
CTOR_POLICY=owner.EFFECTS_OFFSET+EH['constructor_policy']
HOLES['frontend_capsule']=[CTOR_DIRECTORY,CTOR_POLICY]
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
    """Emit immutable bytes with minimum-cost exact literals and back references.

    The native packer zeroes the entire output before any fixed region is filled.
    A skipped zero therefore denotes that real initial byte, not an external input.
    """
    size=len(raw);buckets={};matches=[]
    for at in range(size):
        best=0;prior=0
        if at+8<=size:
            for old in reversed(buckets.get(raw[at:at+8],())[-96:]):
                n=8
                while at+n<size and raw[old+n]==raw[at+n]:n+=1
                if n>best:best=n;prior=old
            buckets.setdefault(raw[at:at+8],[]).append(at)
        matches.append((best,prior))
    cost=[0]*(size+1);choice=[None]*size
    for at in range(size-1,-1,-1):
        options=[]
        if raw[at]==0:options.append((cost[at+1],-1,('zero',1,0)))
        for n in range(1,min(8,size-at)+1):
            options.append(((4 if n==8 else 5)+cost[at+n],-n,('literal',n,0)))
        maximum,prior=matches[at]
        for n in range(8,maximum+1):
            options.append((6+cost[at+n],-n,('copy',n,prior)))
        result=min(options,key=lambda x:(x[0],x[1]))
        cost[at]=result[0];choice[at]=result[2]
    commands=[];at=0
    while at<size:
        kind,n,prior=choice[at]
        if kind=='copy':commands.append(f'    component_root_bridge_copy(o,at+{at},at+{prior},{n})')
        elif kind=='literal':
            value=int.from_bytes(raw[at:at+n],'little')
            if n==8:commands.append(f'    component_root_bridge_word(o,at+{at},{value})')
            else:commands.append(f'    write(o,at+{at},{value},{n})')
        at+=n
    calls=[];functions=[]
    for i in range(0,len(commands),120):
        name='component_root_bridge_bytes_'+str(i//120)
        calls.append(name)
        functions.append('def '+name+'(o:mutbuf,at:u64) -> u32:\n'+'\n'.join(commands[i:i+120])+'\n    return 0\n')
    functions.append('def component_root_bridge_word(o:mutbuf,at:u64,value:u64) -> u32:\n    word_store(o,at,value)\n    return 0\n')
    functions.append('def component_root_bridge_copy(o:mutbuf,to:u64,source:u64,n:u64) -> u32:\n    i=0\n    while i<n:\n        store(o,to+i,byte(o,source+i))\n        i=i+1\n    return 0\n')
    return calls,'\n'.join(functions)

def source_program():
    old=base.common.emitters
    def emit(name,raw):
        calls,source=fixed_bytes(raw)
        # The packer already zeroes its entire actual output before emitters.
        # Omitting literal zero stores preserves exactly the independent image.
        source=re.sub(r'(?m)^    write\(o,at\+\d+,0,\d+\)\n','',source)
        prefix='runtime_constructor_'+name
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
        ordered=sorted(offsets)
        for start in range(0,len(ordered),8):
            expression='|'.join(f'uint(s,{label}+{off},4)'for off in ordered[start:start+8])
            guard+=f'    if ({expression})!=0:\n        return 4294967295\n'
    si=ROLES.index('sidecar_capsule')
    guard+=f'    sidecar_input=get(w,{1536+8*si})\n    temp_offset=885+uint(s,sidecar_input+881,4)\n'
    guard+=f'    if temp_offset>get(w,{8*si}) or get(w,{8*si})-temp_offset<827:\n        return 4294967295\n'
    guard+='    absolute_offset=temp_offset+462+uint(s,sidecar_input+temp_offset+458,4)\n'
    guard+=f'    if absolute_offset>=get(w,{8*si}):\n        return 4294967295\n'
    assert source.count('    layout(s,w)\n')==1
    source=source.replace('    layout(s,w)\n',guard+'    layout(s,w)\n')
    gi=ROLES.index('global_capsule');fi=ROLES.index('frontend_capsule');bi=ROLES.index('runtime_borrow')
    global_at=f'get(w,{512+8*gi})';value_at=f'get(w,{512+8*ROLES.index("values")})'
    table=(
      ('global_capsule',global_capsule,dict(owner='64',values=value_at,stable=f'get(w,{512+8*ROLES.index("fixed_stable")})',sha=f'get(w,{512+8*ROLES.index("gen_prepare_sha")})')),
      ('frontend_capsule',frontend,dict(owner='64',values=value_at,global_owner=global_at,tempdir=f'get(w,{512+8*ROLES.index("sidecar_capsule")})+temp_offset',absolute=f'get(w,{512+8*ROLES.index("sidecar_capsule")})+absolute_offset',sidecar_entry=f'get(w,{512+8*ROLES.index("sidecar_capsule")})',loader_policy=f'get(w,{512+8*ROLES.index("fixed_loader")})',stable=f'{global_at}+{GLOBAL_STABLE_ENTRY}',sha=f'get(w,{512+8*ROLES.index("gen_prepare_sha")})',mapping=f'get(w,{512+8*ROLES.index("gen_prepare_mapping")})')),
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
    patch+='    write(o,get(w,1048)+248,runtime_borrow_at-64,8)\n'
    patch+=f'    directory_policy=frontend_capsule_at+{frontend.DIRECTORY_POLICY_AT}\n'
    patch+=f'    write(o,{64+CTOR_DIRECTORY},frontend_capsule_at+{frontend.DIRECTORY_AT}-{64+CTOR_DIRECTORY+4},4)\n'
    patch+=f'    write(o,{64+CTOR_POLICY},directory_policy-{64+CTOR_POLICY+4},4)\n'
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
    side=parts[ROLES.index('sidecar_capsule')]
    temp_offset=885+struct.unpack_from('<i',side,881)[0]
    absolute_offset=temp_offset+462+struct.unpack_from('<i',side,temp_offset+458)[0]
    if not 0<=temp_offset<=len(side)-827 or not 0<=absolute_offset<len(side):raise ValueError('fixed nested Path native entry outside actual capsule')
    table=(
      ('global_capsule',global_capsule,dict(owner=64,values=positions['values'],stable=positions['fixed_stable'],sha=positions['gen_prepare_sha'])),
      ('frontend_capsule',frontend,dict(owner=64,values=positions['values'],global_owner=positions['global_capsule'],tempdir=positions['sidecar_capsule']+temp_offset,absolute=positions['sidecar_capsule']+absolute_offset,sidecar_entry=positions['sidecar_capsule'],loader_policy=positions['fixed_loader'],stable=positions['global_capsule']+GLOBAL_STABLE_ENTRY,sha=positions['gen_prepare_sha'],mapping=positions['gen_prepare_mapping'])),
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
    struct.pack_into('<Q',raw,sym+248,positions['runtime_borrow']-64)
    front=parts[ROLES.index('frontend_capsule')]
    target=positions['frontend_capsule']+frontend.DIRECTORY_POLICY_AT
    struct.pack_into('<i',raw,64+CTOR_DIRECTORY,positions['frontend_capsule']+frontend.DIRECTORY_AT-64-CTOR_DIRECTORY-4)
    struct.pack_into('<i',raw,64+CTOR_POLICY,target-64-CTOR_POLICY-4)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_runtime_frontend_installed_fusion_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_installed_fusion_packer.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(ROLES),len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
