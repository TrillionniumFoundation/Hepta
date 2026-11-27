"""Single-Value Runtime constructor and installed BackgroundOptimizer root.

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
from tools import generate_hia_generation_runtime_public_cleanup_factory_packer as frontend
from tools import generate_hia_generation_runtime_borrow_packer as borrow
from tools import generate_hia_generation_background_rank_native_fusion_packer as bg_profile
from tools import generate_hia_generation_background_rank_bind_capsule_packer as bg_capsule
ROOT=Path(__file__).resolve().parents[1]
_stable_hole=global_capsule.resources.OUTER_HOLES['stable']
GLOBAL_STABLE_ENTRY=global_capsule.RESOURCE_AT+_stable_hole+4+struct.unpack_from('<i',global_capsule.resources.BRIDGE,_stable_hole)[0]
base=bg_profile.base
HANDLES_PREFIX=bytes.fromhex('535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000000060f82f10100004881fb000100000f82e401000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84a801000083f80a74dc83f8010f84cb00000083f8020f840e01000083f8030f841a01000083f8040f842001000083f8060f842001000083f8070f842201000083f8080f842601000083f80d745f83f80c0f855601000031c9498b44cd004883f8030f8740010000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d404d8d9e00010000e800000000e9ef000000498dbd00009002be80000000498d9500001000b9000004004d8d8600ffffff41b900080000e80000000089c0e9be0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb72498b55004c01f2418b4508418b4d10f00fb10aeb5d498b55004c01f2418b45088702eb4e498b45004c01e8eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f803772f498b7508480334c4498b45104883f803771d498b7d1848033cc4498b4d20fcf3a431c049898578010000e93efeffffb8fdffffff4881c498000000415f415e415d415c5d5bc3')
HANDLES_HOLES=dict(handles=114,effects=285,runtime_borrow=332)
HANDLES_RELOCATIONS=((469,'malloc'),(480,'free'))
EFFECTS=bytes.fromhex('535541544155415641574881eca80000004c899c24980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000080020f82600400004881fb000002000f825304000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000083f8230f84ac01000083f8210f841102000083f8190f844002000083f81b0f841b02000085c00f84e803000083f80a74b883f8010f84bf02000083f8020f840503000083f8030f841103000083f8040f841703000083f8060f841a03000083f8070f841f03000083f8080f842303000083f8150f844903000083f8160f84f501000083f824743583f822743083f820742b83f81a742683f81c742183f81d741c83f817741783f818741283f80c0f826c03000083f8140f87630300008944245031c9498b44cd004883f8030f8749030000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d408b44245083f8240f849100000083f8220f848601000083f8200f84b500000083f81a0f84d800000083f81c0f84d900000083f81d0f84da00000083f8170f84a900000083f8180f84aa00000083f80c0f843501000083f80d0f845001000083f80e0f845101000083f80f0f845201000083f8100f845301000083f8110f845401000083f8120f845501000083f8130f8456010000e800000000e9650200004c8b9c2498000000e800000000e9530200004c89e74c89fe4c89ea4889e94d89f04989d94c8b9c2498000000e800000000e927feffff4c8b84249800000041b900010000e800000000e917020000e800000000e90d020000e800000000e903020000e800000000e9f9010000e800000000e9ef010000e800000000e9e50100004c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9c1fdffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9a5fdffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e989fdffff488d0500000000b90000000049898d20800000e9790100004c8b9c2498000000e800000000e9670100004c8b9c2498000000e800000000e955010000e800000000e94b010000e800000000e941010000e800000000e937010000e800000000e92d010000e800000000e923010000e800000000e919010000e800000000e90f0100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9c0000000498b5500418b4508418b4d10f00fb10ae9ab000000498b5500418b45088702e99c000000498b45004c01f0e990000000498b7d00e800000000e982000000498b7d00e80000000031c0eb75498b45004883f803777d498b7508480334c4498b45104883f803776b498b7d1848033cc4498b4d20fcf3a431c0eb464d8b5d0049837d0810774d4d8b55104d01ea4883ec5031c9498b44ca30488904ccffc183f90a72f0498b3a498b7208498b5210498b4a184d8b42204d8b4a2841ffd34883c45049898588000000e9d5fbffff418b4508eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
EH={'effects': 122, 'typed': 536, 'constructor_directory': 554, 'constructor_policy': 590, 'values': 614, 'information': 624, 'hash': 634, 'snapshot': 644, 'snapshot_retirement': 654, 'snapshot_number': 664, 'typed_policy': 692, 'snapshot_capture': 720, 'capture': 748, 'mapping_span': 760, 'mapping_size': 765, 'generation': 790, 'generation_close': 808, 'identity': 818, 'state': 828, 'retention': 838, 'future': 848, 'call': 858, 'measure': 868, 'directory': 878}
ER=((1019, 'malloc'), (1033, 'free'))
PUBLIC_COMPONENT=bytes.fromhex('41ba01000000eb1b4531d2eb1641ba02000000eb0e41ba03000000eb0641ba04000000535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4c899424980000004d85e40f84e10500004d85ed0f84d80500004d85f60f84cf05000049f7c6070000000f85c20500004881fb000000200f85b50500004881fd800000000f82a80500004c89e04c01f80f829c05000048898424800000004c89e84801e80f828805000048898424880000004c89f04801d80f827405000048898424900000004c3ba42488000000730e4c3bac24800000000f82540500004c3ba4249000000073274c3bb42480000000731d498d860000001e4939c40f85300500004981ff000040010f87230500004c3bac249000000073274c3bb42488000000731d498d86000000184939c50f85ff0400004881fd000020000f87f20400004c8b9424980000004983fa040f84e30000004983fa020f84350100004981ff800000000f85c90400004d85d274604983fa03743348b84849414750425131493904240f85aa04000049837c2408010f829e04000049837c2408020f8792040000b910000000eb7348b84849414d56474531493904240f857704000049837c2408010f876b040000b910000000eb4c48b84849414750424931493904240f855004000049837c2408000f844404000049837c2410000f843804000049817c2420000100000f852904000049837c2428000f841d040000b93000000049833c0c000f850d04000083c10881f98000000072eae9960000004981ff000100000f82f00300004881fd001000000f82e303000048b84849414d5647583149390424742448b84849414d5647583249390424741448b84849414d56475833493904240f85af03000049837c2408060f87a3030000eb3a4981ff000100000f82940300004881fd000800000f828703000048b84849414d56474632493904240f857303000049837c2408020f8767030000b8270000000f054885c00f8e5703000048898424a00000004983be1000f01f00745649bb48494147504257314d399e1000f01f0f852e0300004d39b61800f01f0f85210300004939862000f01f0f8514030000488d05d5fcffff4939862800f01f0f85000300004883bc2498000000000f84f1020000eb0f4883bc2498000000000f85e002000031c0b901000000f0410fb18e0001f01f85c00f85c8020000498b860000f01f4889442458498b860800f01f4889442460498b863000f01f488944246848c70424000000004c897424084c896424104c896c241849c7860000f01f0000000049c7860800f01f00000000488b8424980000004989863000f01f4c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f840f02000083f8010f84a701000083f8020f848601000083f8030f848201000083f8040f848201000083f8090f843b01000083f80a0f843b01000083f80b0f84c701000083f80c0f841701000083f80d741283f8050f82bd01000083f8080f87b401000089442450498b7d00498b75084889f84801f00f829c0100004839d80f87930100004c01f7498b5510498b4d184889d04801c80f827c0100004839d80f87730100004c01f2837c2450057467837c2450060f848a0000004d89f04989d9837c24500d741f837c24500775304d8b9e1801f01f4d85db0f843a01000041ffd3e9190100004d8b9e2001f01f4d85db0f842201000041ffd3e9010100004d8b9e1001f01f4d85db0f840a01000041ffd3e9e90000004d8b865000f01f41b9000100004d8b9e4800f01f4d85c00f84e50000004d85db0f84dc00000041ffd3e9bb0000004d8b866800f01f41b9000090014d85c00f84be000000e800000000e99b0000004d8b9e4801f01feb104d8b9e1001f01feb074d8b9e2001f01f4d85db0f84920000004c89e74c89fe4c89ea4889e94d89f04989d941ffd3eb624c89f0eb5d488d056dfaffffeb54488b8424a0000000eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f054989860800f01fe9dbfdffff418b864001f01feb2d31c0eb29488b4424584989860000f01f488b4424604989860800f01f488b4424684989863000f01fb8fdffffff49c7860001f01f00000000eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3534154415541564881ec080100004989d44989cd4d89c64885ff0f84950100004883fe100f858b01000048b84849414750424f314839070f857801000048837f08000f856d0100004d85e40f846401000049f7c4070000000f85570100004981fd000000200f854a0100004d85f60f84410100004981f9000800000f85340100004c89e04c01e80f82280100004c89f14c01c90f821c0100004939cc73094939c60f820e01000048b8484941474c4f57314939060f85fb0000004d3976100f85f100000049837e18000f84e600000049837e50010f85db000000b8270000000f05493b46080f85ca000000498d8600020000493946300f85b900000049817e38000100000f85ab0000004889e7b90001000031c0fcf3aa48b84849414750424931488904244c89742408498b46284889442410498b46304889442418498b46384889442420498b869802000048894424284889e7be80000000488d942480000000b9800000004d89e04d89e9e848f8ffff85c0754548b84849414750425231483984248000000075254883bc248800000000751a4883bc24d800000001750f4883bc24e000000001750431c0eb0cb8fbffffffeb05b8fdffffff4881c408010000415e415d415c5bc3')
COMPONENT_POLICY_HOLE=995
COMPONENT_LOADER_HOLE=1349
COMPONENT_BIND_OWNER=1615
PUBLIC_COMPONENT_AT=(len(small.proxy.PROXY)+7)&~7
_public_proxy=bytearray(small.proxy.PROXY+bytes(PUBLIC_COMPONENT_AT-len(small.proxy.PROXY))+PUBLIC_COMPONENT)
for at,target in ((589,PUBLIC_COMPONENT_AT+COMPONENT_BIND_OWNER),(614,PUBLIC_COMPONENT_AT+29),(639,PUBLIC_COMPONENT_AT)):
    assert _public_proxy[at:at+4]==bytes(4)
    struct.pack_into('<i',_public_proxy,at,target-at-4)
PUBLIC_PROXY_BRIDGE=bytes(_public_proxy)
def carrier_bridges():
    raw=bytearray(EFFECTS)
    holes={name:[]for name in small.CARRIER_ROLES if name!='handles'}
    for name in ('effects','state','retention','call','typed','information','snapshot','snapshot_capture','snapshot_number'):
        holes[name].append(EH[name])
    for role,hole in (('information_capture','capture'),('gen_proof_hash','hash'),
                      ('gen_prepare_mapping','mapping_span'),('gen_prepare_retirement_state','directory')):
        holes[role].append(EH[hole])
    holes['values']=[EH['values']]
    holes['typed_policy']=[EH['typed_policy']]
    rel=list(ER)
    def append(body):
        raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(body);return at
    def target(at,to):
        assert raw[at:at+4]==bytes(4),(at,to)
        struct.pack_into('<i',raw,at,to-at-4)
    pa=append(PUBLIC_PROXY_BRIDGE)
    target(EH['generation'],pa)
    target(EH['generation_close'],pa+5)
    holes['generation_proxy'].append(pa+443)
    holes['generation_component'].append(pa+PUBLIC_COMPONENT_AT+COMPONENT_POLICY_HOLE)
    la=append(small.loader.BRIDGE)
    target(pa+PUBLIC_COMPONENT_AT+COMPONENT_LOADER_HOLE,la)
    for name,role in(('loader','fixed_loader'),('catalog','fixed_catalog'),('stable','fixed_stable'),
                     ('sha','gen_prepare_sha'),('mapping','gen_prepare_mapping')):
        holes[role].extend(la+x for x in small.loader.HOLES[name])
    rel.extend((la+off,name)for off,name in small.loader.RELOCATIONS)
    ra=append(small.retirement.BRIDGE)
    target(EH['snapshot_retirement'],ra)
    holes['gen_prepare_retire'].append(ra+small.retirement.HOLES['policy'])
    holes['gen_prepare_retirement_state'].append(ra+small.retirement.HOLES['state'])
    rel.extend((ra+off,name)for off,name in small.retirement.RELOCATIONS)
    for name,module,prefix in [('identity',small.legacy.effects.identity,'identity_'),
                              ('future',small.legacy.effects.future,''),
                              ('measure',small.legacy.effects.measurement,'measurement_')]:
        at=append(module.BRIDGE);target(EH[name],at)
        for role,positions in module.HOLES.items():
            if isinstance(positions,int):positions=[positions]
            role='future'if name=='future'else prefix+role
            holes[role].extend(at+x for x in positions)
        rel.extend((at+off,name)for off,name in module.RELOCATIONS)
    assert all(holes.values()),[name for name,value in holes.items()if not value]
    outer=bytearray(HANDLES_PREFIX)
    outer.extend(bytes((-len(outer))%16));at=len(outer);outer.extend(raw)
    h=HANDLES_HOLES['effects'];struct.pack_into('<i',outer,h,at-h-4)
    outside={'handles':[HANDLES_HOLES['handles']]}
    outside.update({role:[at+x for x in positions]for role,positions in holes.items()})
    outside['runtime_borrow']=[HANDLES_HOLES['runtime_borrow']]
    rel=tuple(sorted(HANDLES_RELOCATIONS+tuple((at+x,name)for x,name in rel)))
    return bytes(outer),outside,rel,at+EH['mapping_size']
CARRIER_BRIDGE,CARRIER_HOLES,CARRIER_RELOCATIONS,CARRIER_SIZE_HOLE=carrier_bridges()
owner=SimpleNamespace(**vars(base.owner))
owner.FINALIZER_PREFIX=bg_profile.owner.FINALIZER_PREFIX
owner.FINALIZER_HOLES=dict(bg_profile.owner.FINALIZER_HOLES)
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
ROLES=small.ROLES+('global_capsule','frontend_capsule','runtime_borrow','background_bind_capsule')
MAGIC=int.from_bytes(b'HIAGBF48','little')
IMPORTS=small.IMPORTS;EXPORT_SIZE=small.EXPORT_SIZE;SIZE_HOLE=owner.SIZE_HOLE
STATIC_RELOCATIONS=tuple(sorted(owner.RELOCATIONS))
DYNAMIC_RELOCATIONS=owner.DYNAMIC_RELOCATIONS
BASE_RELOCATIONS=STATIC_RELOCATIONS+tuple((off,name)for _,off,name in DYNAMIC_RELOCATIONS)+tuple(base.sidecar.RELOCATIONS)+tuple(owner.tempdir.RELOCATIONS)
RELOCATIONS=BASE_RELOCATIONS+global_capsule.DYNAMIC_RELOCATIONS+frontend.DYNAMIC_RELOCATIONS+bg_capsule.DYNAMIC_RELOCATIONS
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
HOLES['background_bind_capsule']=[]
assert len(ROLES)==48 and len(set(ROLES))==48 and ROLES.count('values')==1
assert set(HOLES)==set(ROLES)
assert all(BRIDGE[h:h+4]==bytes(4)for holes in HOLES.values()for h in holes)
EXPORTS=(('hia_generation_lease_owner',0,EXPORT_SIZE),
 ('hia_background_optimizer_future_public',FUTURE_AT,len(base.future.BRIDGE)),
 ('hia_generation_lease_owner_sidecar',0,len(owner.sidecar.BRIDGE)),
 ('hia_generation_runtime_global',0,len(global_capsule.OUTER)),
 *frontend.EXPORTS,('hia_generation_runtime_borrow',0,len(borrow.BRIDGE)),
 ('hia_generation_background_bind',0,len(bg_capsule.OUTER)))
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
        source=call(base._source_program)
    finally:base.common.emitters=old
    # Every grouped read lies in the already bounded immutable capsule prefix.
    # All original unresolved import checks remain mandatory.
    pattern=r'(?:    if uint\(s,[^\n]+\)!=0:\n        return 4294967295\n){2,}'
    def group_imports(match):
        expressions=re.findall(r'    if (uint\(s,[^\n]+\))!=0:',match.group())
        groups=[]
        for start in range(0,len(expressions),8):
            groups.append('    if ('+'|'.join(expressions[start:start+8])+')!=0:\n        return 4294967295\n')
        return ''.join(groups)
    source=re.sub(pattern,group_imports,source)
    units=(('global_capsule',global_capsule),('frontend_capsule',frontend),('runtime_borrow',borrow),('background_bind_capsule',bg_capsule))
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
      ('frontend_capsule',frontend,dict(owner='64',values=value_at,global_owner=global_at,tempdir=f'get(w,{512+8*ROLES.index("sidecar_capsule")})+temp_offset',absolute=f'get(w,{512+8*ROLES.index("sidecar_capsule")})+absolute_offset',sidecar_entry=f'get(w,{512+8*ROLES.index("sidecar_capsule")})',loader_policy=f'get(w,{512+8*ROLES.index("fixed_loader")})',stable=f'{global_at}+{GLOBAL_STABLE_ENTRY}',sha=f'get(w,{512+8*ROLES.index("gen_prepare_sha")})',mapping=f'get(w,{512+8*ROLES.index("gen_prepare_mapping")})',runtime_borrow=f'get(w,{512+8*bi})')),
      ('runtime_borrow',borrow,dict(owner='64',global_owner=global_at,carrier=str(64+owner.CARRIER_OFFSET))),
      ('background_bind_capsule',bg_capsule,dict(owner='64',values=value_at,global_entry=global_at,
       sidecar_entry=f'get(w,{512+8*ROLES.index("sidecar_capsule")})',finalizer=str(64+owner.FINALIZER_OFFSET),
       loader_policy=f'get(w,{512+8*ROLES.index("fixed_loader")})',stable=f'{global_at}+{GLOBAL_STABLE_ENTRY}',
       sha=f'get(w,{512+8*ROLES.index("gen_prepare_sha")})',mapping=f'get(w,{512+8*ROLES.index("gen_prepare_mapping")})')))
    patch=''
    for name,unit,targets in table:
        i=ROLES.index(name);at=name+'_at'
        patch+=f'    {at}=get(w,{512+8*i})\n'
        for role,holes in unit.FIXED_HOLES.items():
            for off in holes:patch+=f'    runtime_fixed_rel32(o,{at}+{off},{targets[role]})\n'
    for name,unit,first in(('global_capsule',global_capsule,len(BASE_RELOCATIONS)),('frontend_capsule',frontend,len(BASE_RELOCATIONS)+len(global_capsule.DYNAMIC_RELOCATIONS)),('background_bind_capsule',bg_capsule,len(BASE_RELOCATIONS)+len(global_capsule.DYNAMIC_RELOCATIONS)+len(frontend.DYNAMIC_RELOCATIONS))):
        for i,(off,_)in enumerate(unit.DYNAMIC_RELOCATIONS):
            patch+=f'    write(o,get(w,1040)+{24*(first+i)},{name}_at-64+{off},8)\n'
    patch+='    write(o,get(w,1048)+128,global_capsule_at-64,8)\n'
    for i,(_,at,_)in enumerate(frontend.EXPORTS):patch+=f'    write(o,get(w,1048)+{152+i*24},frontend_capsule_at-64+{at},8)\n'
    patch+='    write(o,get(w,1048)+272,runtime_borrow_at-64,8)\n'
    patch+='    write(o,get(w,1048)+296,background_bind_capsule_at-64,8)\n'
    for name in ('background_address','background_call'):
        off=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        patch+=f'    runtime_fixed_rel32(o,{off},background_bind_capsule_at)\n'
    patch+=f'    directory_policy=frontend_capsule_at+{frontend.DIRECTORY_POLICY_AT}\n'
    patch+=f'    runtime_fixed_rel32(o,{64+CTOR_DIRECTORY},frontend_capsule_at+{frontend.DIRECTORY_AT})\n'
    patch+=f'    runtime_fixed_rel32(o,{64+CTOR_POLICY},directory_policy)\n'
    # Layout has already fixed these offsets. Share their immutable reads
    # across all fixed rel32 and relocation rows without changing any guard.
    cached=[]
    for slot in sorted({int(x) for x in re.findall(r'get\(w,(\d+)\)',patch)}):
        expression='get(w,'+str(slot)+')'
        if patch.count(expression)>1:
            name='runtime_fixed_slot_'+str(slot)
            cached.append('    '+name+'='+expression+'\n')
            patch=patch.replace(expression,name)
    patch=''.join(cached)+patch
    assert source.count('    return get(w,1088)\n')==1
    return source.replace('    return get(w,1088)\n',patch+'    return get(w,1088)\n')+'\ndef runtime_fixed_rel32(o:mutbuf,site:u64,target:u64) -> u32:\n    write(o,site,target-site-4,4)\n    return 0\n'
def reference_object(parts):
    if len(parts)!=48:raise ValueError('all48 native roles required')
    for name,unit in(('global_capsule',global_capsule),('frontend_capsule',frontend),('runtime_borrow',borrow),('background_bind_capsule',bg_capsule)):
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
      ('frontend_capsule',frontend,dict(owner=64,values=positions['values'],global_owner=positions['global_capsule'],tempdir=positions['sidecar_capsule']+temp_offset,absolute=positions['sidecar_capsule']+absolute_offset,sidecar_entry=positions['sidecar_capsule'],loader_policy=positions['fixed_loader'],stable=positions['global_capsule']+GLOBAL_STABLE_ENTRY,sha=positions['gen_prepare_sha'],mapping=positions['gen_prepare_mapping'],runtime_borrow=positions['runtime_borrow'])),
      ('runtime_borrow',borrow,dict(owner=64,global_owner=positions['global_capsule'],carrier=64+owner.CARRIER_OFFSET)),
      ('background_bind_capsule',bg_capsule,dict(owner=64,values=positions['values'],global_entry=positions['global_capsule'],
       sidecar_entry=positions['sidecar_capsule'],finalizer=64+owner.FINALIZER_OFFSET,
       loader_policy=positions['fixed_loader'],stable=positions['global_capsule']+GLOBAL_STABLE_ENTRY,
       sha=positions['gen_prepare_sha'],mapping=positions['gen_prepare_mapping'])))
    for name,unit,targets in table:
        at=positions[name]
        for role,holes in unit.FIXED_HOLES.items():
            for off in holes:struct.pack_into('<i',raw,at+off,targets[role]-at-off-4)
    sh=struct.unpack_from('<Q',raw,40)[0];rela=struct.unpack_from('<Q',raw,sh+152)[0];sym=struct.unpack_from('<Q',raw,sh+216)[0]
    for name,unit,first in(('global_capsule',global_capsule,len(BASE_RELOCATIONS)),('frontend_capsule',frontend,len(BASE_RELOCATIONS)+len(global_capsule.DYNAMIC_RELOCATIONS)),('background_bind_capsule',bg_capsule,len(BASE_RELOCATIONS)+len(global_capsule.DYNAMIC_RELOCATIONS)+len(frontend.DYNAMIC_RELOCATIONS))):
        for i,(off,_)in enumerate(unit.DYNAMIC_RELOCATIONS):struct.pack_into('<Q',raw,rela+24*(first+i),positions[name]-64+off)
    struct.pack_into('<Q',raw,sym+128,positions['global_capsule']-64)
    for i,(_,at,_)in enumerate(frontend.EXPORTS):struct.pack_into('<Q',raw,sym+152+i*24,positions['frontend_capsule']-64+at)
    struct.pack_into('<Q',raw,sym+272,positions['runtime_borrow']-64)
    struct.pack_into('<Q',raw,sym+296,positions['background_bind_capsule']-64)
    for name in ('background_address','background_call'):
        off=64+owner.FINALIZER_OFFSET+owner.FINALIZER_HOLES[name]
        struct.pack_into('<i',raw,off,positions['background_bind_capsule']-off-4)
    front=parts[ROLES.index('frontend_capsule')]
    target=positions['frontend_capsule']+frontend.DIRECTORY_POLICY_AT
    struct.pack_into('<i',raw,64+CTOR_DIRECTORY,positions['frontend_capsule']+frontend.DIRECTORY_AT-64-CTOR_DIRECTORY-4)
    struct.pack_into('<i',raw,64+CTOR_POLICY,target-64-CTOR_POLICY-4)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_background_runtime_fusion_packer')
    p=ROOT/'examples/hia_bootstrap/generation_background_runtime_fusion_packer.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(ROLES),len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
