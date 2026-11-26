"""Single-arena native root with generation policy admitted from one fixed child.

The previous HIAGFUP4 packer remains unchanged. This profile removes its thirty
embedded generation roles, preserves the shared hash/mapping/retirement leaves,
and installs the fixed proxy before the Runtime can release a GEN workspace.
"""
from pathlib import Path
from types import SimpleNamespace
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_future_managed_fusion_packer as base
from tools import generate_hia_generation_lease_owner_packer as legacy
from tools import generate_hia_generation_lease_owner_generation_proxy_packer as proxy
from tools import generate_hia_native_fixed_component_packer as loader
from tools import generate_hia_multiversion_retirement_packer as retirement
ROOT=Path(__file__).resolve().parents[1]
EFFECTS=bytes.fromhex('535541544155415641574881eca80000004c899c24980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000080020f82070400004881fb000002000f82fa03000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000083f8210f84c101000083f8190f84f001000083f81b0f84cb01000085c00f849803000083f80a74c183f8010f846f02000083f8020f84b502000083f8030f84c102000083f8040f84c702000083f8060f84ca02000083f8070f84cf02000083f8080f84d302000083f8150f84f902000083f8160f84a501000083f822743083f820742b83f81a742683f81c742183f81d741c83f817741783f818741283f80c0f822103000083f8140f87180300008944245031c9498b44cd004883f8030f87fe020000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d408b44245083f8220f844401000083f820747783f81a0f849a00000083f81c0f849b00000083f81d0f849c00000083f817746f83f818747483f80c0f84ff00000083f80d0f841a01000083f80e0f841b01000083f80f0f841c01000083f8100f841d01000083f8110f841e01000083f8120f841f01000083f8130f8420010000e800000000e92f0200004c8b84249800000041b900010000e800000000e917020000e800000000e90d020000e800000000e903020000e800000000e9f9010000e800000000e9ef010000e800000000e9e50100004c89e74c89fe4c89ea4889e94d89f04989d9e800000000e91afeffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9fefdffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9e2fdffff488d0500000000b90000000049898d20800000e9790100004c8b9c2498000000e800000000e9670100004c8b9c2498000000e800000000e955010000e800000000e94b010000e800000000e941010000e800000000e937010000e800000000e92d010000e800000000e923010000e800000000e919010000e800000000e90f0100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9c0000000498b5500418b4508418b4d10f00fb10ae9ab000000498b5500418b45088702e99c000000498b45004c01f0e990000000498b7d00e800000000e982000000498b7d00e80000000031c0eb75498b45004883f803777d498b7508480334c4498b45104883f803776b498b7d1848033cc4498b4d20fcf3a431c0eb464d8b5d0049837d0810774d4d8b55104d01ea4883ec5031c9498b44ca30488904ccffc183f90a72f0498b3a498b7208498b5210498b4a184d8b42204d8b4a2841ffd34883c45049898588000000e92efcffff418b4508eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
EH={"call":769,"capture":659,"directory":789,"effects":122,"future":759,"generation":701,"generation_close":719,"hash":545,"identity":729,"information":535,"mapping_size":676,"mapping_span":671,"measure":779,"retention":749,"snapshot":555,"snapshot_capture":631,"snapshot_number":575,"snapshot_retirement":565,"state":739,"typed":501,"typed_policy":603,"values":525}
ER=((930,'malloc'),(944,'free'))
KEEP_GEN=('gen_proof_hash','gen_prepare_sha','gen_prepare_mapping','gen_prepare_retire','gen_prepare_retirement_state')
NEW_ROLES=('generation_proxy','generation_component','fixed_loader','fixed_catalog','fixed_stable')
CARRIER_ROLES=tuple(x for x in legacy.carrier.ROLES if not x.startswith('gen_')or x in KEEP_GEN)+NEW_ROLES
def carrier_bridges():
    raw=bytearray(EFFECTS)
    holes={name:[]for name in CARRIER_ROLES if name!='handles'}
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
    pa=append(proxy.BRIDGE)
    target(EH['generation'],pa)
    target(EH['generation_close'],pa+5)
    holes['generation_proxy'].append(pa+443)
    holes['generation_component'].append(pa+proxy.COMPONENT_AT+995)
    la=append(loader.BRIDGE)
    target(pa+proxy.COMPONENT_AT+1309,la)
    for name,role in(('loader','fixed_loader'),('catalog','fixed_catalog'),('stable','fixed_stable'),
                     ('sha','gen_prepare_sha'),('mapping','gen_prepare_mapping')):
        holes[role].extend(la+x for x in loader.HOLES[name])
    rel.extend((la+off,name)for off,name in loader.RELOCATIONS)
    ra=append(retirement.BRIDGE)
    target(EH['snapshot_retirement'],ra)
    holes['gen_prepare_retire'].append(ra+retirement.HOLES['policy'])
    holes['gen_prepare_retirement_state'].append(ra+retirement.HOLES['state'])
    rel.extend((ra+off,name)for off,name in retirement.RELOCATIONS)
    for name,module,prefix in [('identity',legacy.effects.identity,'identity_'),
                              ('future',legacy.effects.future,''),
                              ('measure',legacy.effects.measurement,'measurement_')]:
        at=append(module.BRIDGE);target(EH[name],at)
        for role,positions in module.HOLES.items():
            if isinstance(positions,int):positions=[positions]
            role='future'if name=='future'else prefix+role
            holes[role].extend(at+x for x in positions)
        rel.extend((at+off,name)for off,name in module.RELOCATIONS)
    assert all(holes.values()),[name for name,value in holes.items()if not value]
    outer=bytearray(legacy.HANDLES_PREFIX)
    outer.extend(bytes((-len(outer))%16));at=len(outer);outer.extend(raw)
    h=legacy.HANDLES_HOLES['effects'];struct.pack_into('<i',outer,h,at-h-4)
    outside={'handles':[legacy.HANDLES_HOLES['handles']]}
    outside.update({role:[at+x for x in positions]for role,positions in holes.items()})
    rel=tuple(sorted(legacy.HANDLES_RELOCATIONS+tuple((at+x,name)for x,name in rel)))
    return bytes(outer),outside,rel,at+EH['mapping_size']
CARRIER_BRIDGE,CARRIER_HOLES,CARRIER_RELOCATIONS,CARRIER_SIZE_HOLE=carrier_bridges()
owner=SimpleNamespace(**{k:v for k,v in vars(base.owner).items()if not k.startswith('__')})
owner.BRIDGE,owner.HOLES,owner.RELOCATIONS,owner.SIZE_HOLE=owner.bound.patched(
    owner.original.bridges,dict(OWNER=owner.OWNER,OWNER_HOLES=owner.OWNER_HOLES,
      OWNER_RELOCATIONS=owner.OWNER_RELOCATIONS,FINALIZER_PREFIX=owner.FINALIZER_PREFIX,
      FINALIZER_HOLES=owner.FINALIZER_HOLES,CARRIER_BRIDGE=CARRIER_BRIDGE,
      CARRIER_HOLES=CARRIER_HOLES,CARRIER_RELOCATIONS=CARRIER_RELOCATIONS,CARRIER_SIZE_HOLE=CARRIER_SIZE_HOLE))
owner.HOLES['provider_capsule']=[owner.OWNER_HOLES['provider_address'],owner.OWNER_HOLES['provider_call']]
owner.HOLES['sidecar_capsule']=[]
owner.CARRIER_OFFSET=owner.OWNER_HOLES['carrier_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['carrier_address'])[0]
owner.EFFECTS_OFFSET=owner.CARRIER_OFFSET+((len(legacy.HANDLES_PREFIX)+15)&~15)
owner.FINALIZER_OFFSET=owner.OWNER_HOLES['finalizer_address']+4+struct.unpack_from('<i',owner.BRIDGE,owner.OWNER_HOLES['finalizer_address'])[0]
owner.ROLES=('owner_policy','lease_policy','values','typed_policy','finalizer_policy')+CARRIER_ROLES+('provider_capsule','sidecar_capsule')
FUTURE_ROLES=base.FUTURE_ROLES
ROLES=owner.ROLES+tuple('future_public_'+role for role in FUTURE_ROLES)
MAGIC=int.from_bytes(b'HIAGFUP5','little')
IMPORTS=owner.IMPORTS
EXPORT_SIZE=owner.EXPORT_SIZE
SIZE_HOLE=owner.SIZE_HOLE
STATIC_RELOCATIONS=tuple(sorted(owner.RELOCATIONS))
DYNAMIC_RELOCATIONS=owner.DYNAMIC_RELOCATIONS
sidecar=base.sidecar
RELOCATIONS=STATIC_RELOCATIONS+tuple((off,name)for _,off,name in DYNAMIC_RELOCATIONS)+tuple(sidecar.RELOCATIONS)+tuple(owner.tempdir.RELOCATIONS)
raw=bytearray(owner.BRIDGE);raw.extend(bytes((-len(raw))%16));FUTURE_AT=len(raw);raw.extend(base.future.BRIDGE)
BRIDGE=bytes(raw)
HOLES={role:list(holes)for role,holes in owner.HOLES.items()}
for role in FUTURE_ROLES:HOLES['future_public_'+role]=[]
for role,hole in base.future.FIXUPS:
    selected='values'if role=='value'else 'future_public_'+role
    HOLES[selected].append(FUTURE_AT+hole)
assert len(ROLES)<=64 and len(set(ROLES))==len(ROLES)
assert ROLES.count('values')==1
assert all(HOLES[role]for role in ROLES if role!='sidecar_capsule')
assert set(HOLES)==set(ROLES)
assert all(BRIDGE[h:h+4]==bytes(4)for holes in HOLES.values()for h in holes)
CARRIER_SOURCES=[row for row in legacy.CARRIER_SOURCES if row['role']in CARRIER_ROLES]
CARRIER_SOURCES=[dict(row,path='examples/hia_bootstrap/generation_lease_owner_generation_effects.hepta')if row['role']=='effects'else dict(row,path='examples/hia_bootstrap/generation_lease_owner_component_handles.hepta')if row['role']=='handles'else row for row in CARRIER_SOURCES]
CARRIER_SOURCES.extend([
 dict(role='generation_proxy',path='examples/hia_bootstrap/generation_lease_owner_generation_proxy.hepta'),
 dict(role='generation_component',path='examples/hia_bootstrap/generation_lease_owner_component.hepta'),
 dict(role='fixed_loader',path='examples/hia_bootstrap/native_fixed_component_loader.hepta'),
 dict(role='fixed_catalog',path='examples/hia_bootstrap/generation_lease_owner_generation_component_catalog.hepta'),
 dict(role='fixed_stable',path='examples/hia_bootstrap/clang_stable_file.hepta'),
])
def call(fn,*args):
    names=('owner','ROLES','MAGIC','IMPORTS','EXPORT_SIZE','SIZE_HOLE','STATIC_RELOCATIONS',
      'DYNAMIC_RELOCATIONS','RELOCATIONS','FUTURE_AT','BRIDGE','HOLES')
    old={name:getattr(base,name)for name in names}
    try:
        for name in names:setattr(base,name,globals()[name])
        return fn(*args)
    finally:
        for name,value in old.items():setattr(base,name,value)
def fixed_bridge_source(raw):
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
        if best>=24:
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
    original=base.common.emitters
    def emit(name,raw):
        if name=='prefix':
            return fixed_bridge_source(raw)
        return original(name,raw)
    try:
        base.common.emitters=emit
        return call(base.source_program)
    finally:
        base.common.emitters=original
def reference_object(flats):return call(base.reference_object,flats)
def fixed_parts():return call(base.fixed_parts)
def main():
    tree=document(source_program(),'generation_future_component_fusion_packer')
    path=ROOT/'examples/hia_bootstrap/generation_future_component_fusion_packer.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(ROLES),len(tree['functions']),
      sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
