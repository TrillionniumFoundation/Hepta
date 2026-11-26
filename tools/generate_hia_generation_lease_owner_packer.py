"""Source-bound enclosing lease/Value owner, preserving all old carrier consumers.

The sole export constructs the actual fixed carrier and Value arena contexts.
All 49 carrier roles remain ordered; only this new product selects the three
public lifecycle variants. The complete twelve-role Value image is native packed
before insertion into its one fixed role. No callback comes from caller data.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_runtime_handles_packer as carrier
from tools import generate_hia_multiversion_runtime_effects_packer as effects
from tools import generate_hia_generation_lease_public_lifecycle_packer as lifecycle
ROOT=Path(__file__).resolve().parents[1]
OWNER=bytes.fromhex('535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4d85e40f84270400004d85ed0f841e0400004d85f60f84150400004983ff400f820b0400004981ff400000040f87fe0300004881fd008000060f82f10300004881fb000800000f85e403000041f6c6070f85da0300004c89e04c01f80f82ce0300004c89ea4801ea0f82c20300004c89f14801d90f82b60300004c39e876094c39e20f87a80300004c39f076094c39e10f879a0300004c39f276094c39e90f878c03000049c78500010000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f846703000083f80a74dc83f8010f842e01000083f8020f843101000083f8030f843c01000083f8040f844001000083f80c0f847d01000083f80d0f84cf01000083f80e0f84f301000083f80f0f84dd02000083f8100f84b100000083f8110f84c500000083f812743c83f813745f83f814747f83f8150f84fe01000083f8160f841f02000083f8170f844502000083f8180f845802000083f8190f847f020000e9c202000031ffbe00000006ba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05e98e020000498b8538030000498dbc0640030000be080000004829c631d2b83e0100000f05e969020000498bbe20030000498bb628030000b80b0000000f05e94f020000498bbd28030000be06040000ba03000000b8480000000f05e932020000498bbd280300004889fe31d2b8b40100000f05e91a020000b8270000000f05e90e02000031c0b901000000f0410fb14e40f390e9fa01000031c04187464031c0e9ed0100004d89b500020000488d059bfdffff49898508020000488d050000000049898510020000488d050000000049898518020000488d05000000004989852002000031c0e9a7010000498d7c2440498b7424104983bd30020000007424498dbd00100000be800000004983bd3002000002750e498dbd00110000498bb538020000498d9500400000b9000000064d8d860001000041b900010000e800000000e94c010000498d7c2440be40000000498d9500400000b9004000064d8d868000000041b980000000e800000000e91f010000498d7c2440498b7424104983bd3002000000740c498dbd00100000be80000000498d9500400000b9000000064d8d860002000041b900010000e9da000000498dbd00100000be98000000498d9500400000b9000000064d8d860002000041b900010000e9b0000000498dbd00100000be80000000498d9500200000b9800000004d8d860003000041b900010000e800000000e988000000498bb550040000498dbd80800000498b8d58040000fcf3a431c0eb6c498dbd00800000498bb5580400004881c680000000498d9500400000b9004000004d8d860002000041b900010000eb35498bbd50040000e80000000031c0eb2c498dbd00100000be80000000498d9500200000b9002000004d8d860002000041b900010000e800000000eb0049898580010000e97ffcffffb8fdffffff4883c408415f415e415d415c5d5bc39066662e0f1f840000000000')
OWNER_HOLES={"policy":226,"carrier_address":623,"values_address":637,"finalizer_address":651,"carrier_call":751,"lifecycle_call":796,"finalizer_call":947,"values_call":1086}
OWNER_RELOCATIONS=((1040,"free"),)
CARRIER_SOURCES=[
  {
    "role": "handles",
    "path": "examples/hia_bootstrap/generation_lease_owner_handles.hepta"
  },
  {
    "role": "effects",
    "path": "examples/hia_bootstrap/generation_lease_typed_effects.hepta"
  },
  {
    "role": "state",
    "path": "examples/hia_bootstrap/multiversion_runtime_public_state.hepta"
  },
  {
    "role": "retention",
    "path": "examples/hia_bootstrap/generation_retention.hepta"
  },
  {
    "role": "call",
    "path": "examples/hia_bootstrap/multiversion_call.hepta"
  },
  {
    "role": "typed",
    "path": "examples/hia_bootstrap/multiversion_measurement_typed.hepta"
  },
  {
    "role": "information",
    "path": "examples/hia_bootstrap/multiversion_runtime_information.hepta"
  },
  {
    "role": "information_capture",
    "path": "examples/hia_bootstrap/multiversion_runtime_information_capture.hepta"
  },
  {
    "role": "gen_generation",
    "path": "examples/hia_bootstrap/multiversion_runtime_generation.hepta"
  },
  {
    "role": "gen_intake_prepare",
    "path": "examples/hia_bootstrap/multiversion_prepare_intake.hepta"
  },
  {
    "role": "gen_intake_process",
    "path": "examples/hia_bootstrap/multiversion_prepare_process.hepta"
  },
  {
    "role": "gen_intake_intake",
    "path": "examples/hia_bootstrap/multiversion_intake.hepta"
  },
  {
    "role": "gen_intake_admission",
    "path": "examples/hia_bootstrap/core_admission.hepta"
  },
  {
    "role": "gen_intake_canonical",
    "path": "examples/hia_bootstrap/json_canonical.hepta"
  },
  {
    "role": "gen_intake_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "gen_intake_profile",
    "path": "examples/hia_bootstrap/multiversion_profile.hepta"
  },
  {
    "role": "gen_intake_scalar",
    "path": "examples/hia_bootstrap/scalar_profile.hepta"
  },
  {
    "role": "gen_intake_abi",
    "path": "examples/hia_bootstrap/multiversion_abi.hepta"
  },
  {
    "role": "gen_proof_prepare",
    "path": "examples/hia_bootstrap/multiversion_prepare_proof.hepta"
  },
  {
    "role": "gen_proof_process",
    "path": "examples/hia_bootstrap/multiversion_prepare_process.hepta"
  },
  {
    "role": "gen_proof_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "gen_proof_json",
    "path": "examples/hia_bootstrap/native_public_proof_json.hepta"
  },
  {
    "role": "gen_proof_receipt",
    "path": "examples/hia_bootstrap/native_public_proof_receipt.hepta"
  },
  {
    "role": "gen_prepare_owner",
    "path": "examples/hia_bootstrap/multiversion_prepare_owner.hepta"
  },
  {
    "role": "gen_prepare_capture",
    "path": "examples/hia_bootstrap/multiversion_prepare_capture.hepta"
  },
  {
    "role": "gen_prepare_process",
    "path": "examples/hia_bootstrap/multiversion_prepare_process.hepta"
  },
  {
    "role": "gen_prepare_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "gen_prepare_json",
    "path": "examples/hia_bootstrap/native_public_proof_json.hepta"
  },
  {
    "role": "gen_prepare_image",
    "path": "examples/hia_bootstrap/multiversion_prepare_image.hepta"
  },
  {
    "role": "gen_prepare_sha",
    "path": "examples/hia_bootstrap/sha256_stream.hepta"
  },
  {
    "role": "gen_prepare_elf",
    "path": "examples/hia_bootstrap/safe_core_elf_inventory.hepta"
  },
  {
    "role": "gen_prepare_mapping",
    "path": "examples/hia_bootstrap/native_mapping.hepta"
  },
  {
    "role": "gen_prepare_probe",
    "path": "examples/hia_bootstrap/multiversion_probe_owner.hepta"
  },
  {
    "role": "gen_prepare_vectors",
    "path": "examples/hia_bootstrap/multiversion_probes.hepta"
  },
  {
    "role": "gen_prepare_projector",
    "path": "examples/hia_bootstrap/evaluate_reference_wire.hepta"
  },
  {
    "role": "gen_prepare_vm",
    "path": "examples/hia_bootstrap/scalar_reference.hepta"
  },
  {
    "role": "gen_prepare_retire",
    "path": "examples/hia_bootstrap/multiversion_retirement.hepta"
  },
  {
    "role": "gen_prepare_retirement_state",
    "path": "examples/hia_bootstrap/retirement_state.hepta"
  },
  {
    "role": "identity_identity",
    "path": "examples/hia_bootstrap/multiversion_runtime_identity.hepta"
  },
  {
    "role": "identity_numbers",
    "path": "examples/hia_bootstrap/multiversion_runtime_numbers.hepta"
  },
  {
    "role": "identity_values_owner",
    "path": "examples/hia_bootstrap/multiversion_values.hepta"
  },
  {
    "role": "identity_unsigned",
    "path": "examples/hia_bootstrap/unsigned_decimal_values.hepta"
  },
  {
    "role": "future",
    "path": "examples/hia_bootstrap/multiversion_future.hepta"
  },
  {
    "role": "measurement_owner",
    "path": "examples/hia_bootstrap/multiversion_measurement_owner.hepta"
  },
  {
    "role": "measurement_measurement",
    "path": "examples/hia_bootstrap/publication_measurement.hepta"
  },
  {
    "role": "measurement_hash",
    "path": "examples/hia_bootstrap/native_scalar_proof_hash.hepta"
  },
  {
    "role": "snapshot",
    "path": "examples/hia_bootstrap/multiversion_runtime_snapshot.hepta"
  },
  {
    "role": "snapshot_capture",
    "path": "examples/hia_bootstrap/multiversion_runtime_snapshot_capture.hepta"
  },
  {
    "role": "snapshot_number",
    "path": "examples/hia_bootstrap/multiversion_runtime_snapshot_number.hepta"
  }
]
ROLES=('owner_policy','lease_policy','values','typed_policy','finalizer_policy')+carrier.ROLES
MAGIC=int.from_bytes(b'HIAGLOP1','little')
IMPORTS=carrier.IMPORTS
EXPORT_SIZE=len(OWNER)


HANDLES_PREFIX=bytes.fromhex('535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000000060f82bb0100004881fb000100000f82ae01000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f847201000083f80a74dc83f8010f849500000083f8020f84d800000083f8030f84e400000083f8040f84ea00000083f8060f84ea00000083f8070f84ec00000083f8080f84f000000083f80c0f852501000031c9498b44cd004883f8030f870f010000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d404d8d9e00010000e800000000e9be0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb72498b55004c01f2418b4508418b4d10f00fb10aeb5d498b55004c01f2418b45088702eb4e498b45004c01e8eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f803772f498b7508480334c4498b45104883f803771d498b7d1848033cc4498b4d20fcf3a431c049898578010000e974feffffb8fdffffff4881c498000000415f415e415d415c5d5bc3')
HANDLES_HOLES={'handles':114,'effects':280}
HANDLES_RELOCATIONS=((415,'malloc'),(426,'free'))
EFFECTS_PREFIX=bytes.fromhex('535541544155415641574881eca80000004c899c24980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000080020f82df0300004881fb000002000f82d203000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000083f8210f84b301000083f8190f84e201000083f81b0f84bd01000085c00f847003000083f80a74c183f8010f844702000083f8020f848d02000083f8030f849902000083f8040f849f02000083f8060f84a202000083f8070f84a702000083f8080f84ab02000083f8150f84d102000083f8160f849701000083f820742b83f81a742683f81c742183f81d741c83f817741783f818741283f80c0f82fe02000083f8140f87f50200008944245031c9498b44cd004883f8030f87db020000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d408b44245083f820747783f81a0f849a00000083f81c0f849b00000083f81d0f849c00000083f817746f83f818747483f80c0f84ff00000083f80d0f840001000083f80e0f840101000083f80f0f840201000083f8100f840301000083f8110f840401000083f8120f840501000083f8130f8406010000e800000000e9150200004c8b84249800000041b900010000e800000000e9fd010000e800000000e9f3010000e800000000e9e9010000e800000000e9df010000e800000000e9d5010000e800000000e9cb0100004c89e74c89fe4c89ea4889e94d89f04989d9e800000000e928feffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e90cfeffff4c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9f0fdffff488d0500000000b90000000049898d20800000e95f010000e800000000e955010000e800000000e94b010000e800000000e941010000e800000000e937010000e800000000e92d010000e800000000e923010000e800000000e919010000e800000000e90f0100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9c0000000498b5500418b4508418b4d10f00fb10ae9ab000000498b5500418b45088702e99c000000498b45004c01f0e990000000498b7d00e800000000e982000000498b7d00e80000000031c0eb75498b45004883f803777d498b7508480334c4498b45104883f803776b498b7d1848033cc4498b4d20fcf3a431c0eb464d8b5d0049837d0810774d4d8b55104d01ea4883ec5031c9498b44ca30488904ccffc183f90a72f0498b3a498b7208498b5210498b4a184d8b42204d8b4a2841ffd34883c45049898588000000e956fcffff418b4508eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
EFFECTS_HOLES={"effects":122,"typed":487,"values":511,"information":521,"hash":531,"snapshot":541,"snapshot_retirement":551,"snapshot_number":561,"typed_policy":589,"snapshot_capture":617,"capture":645,"mapping_span":657,"mapping_size":662,"generation":679,"identity":689,"state":699,"retention":709,"future":719,"call":729,"measure":739,"directory":749}
EFFECTS_RELOCATIONS=((890,'malloc'),(904,'free'))

def carrier_bridges():
    raw=bytearray(EFFECTS_PREFIX)
    holes={name:[] for name in effects.ROLES}
    for name in ('effects','state','retention','call','typed','information','snapshot','snapshot_capture','snapshot_number'):
        holes[name]=[EFFECTS_HOLES[name]]
    holes['information_capture']=[EFFECTS_HOLES['capture']]
    holes['gen_proof_hash']=[EFFECTS_HOLES['hash']]
    holes['gen_prepare_mapping']=[EFFECTS_HOLES['mapping_span']]
    holes['gen_prepare_retirement_state']=[EFFECTS_HOLES['directory']]
    holes['values']=[EFFECTS_HOLES['values']]
    holes['typed_policy']=[EFFECTS_HOLES['typed_policy']]
    relocations=list(EFFECTS_RELOCATIONS)
    for name,module,prefix in [('generation',effects.generation,'gen_'),
                              ('identity',effects.identity,'identity_'),
                              ('future',effects.future,''),
                              ('measure',effects.measurement,'measurement_')]:
        raw.extend(bytes((-len(raw))%16))
        at=len(raw)
        raw.extend(module.BRIDGE)
        h=EFFECTS_HOLES[name]
        struct.pack_into('<i',raw,h,at-h-4)
        if name=='generation':
            ih=module.OUTER_HOLES['retirement']
            target=at+ih+4+struct.unpack_from('<i',module.BRIDGE,ih)[0]
            h=EFFECTS_HOLES['snapshot_retirement']
            struct.pack_into('<i',raw,h,target-h-4)
        for role,positions in module.HOLES.items():
            if isinstance(positions,int):
                positions=[positions]
            target='future' if name=='future' else prefix+role
            holes[target].extend(at+x for x in positions)
        relocations.extend((at+x,symbol) for x,symbol in module.RELOCATIONS)
    assert all(holes.values())
    outer=bytearray(HANDLES_PREFIX)
    outer.extend(bytes((-len(outer))%16))
    at=len(outer)
    outer.extend(raw)
    h=HANDLES_HOLES['effects']
    struct.pack_into('<i',outer,h,at-h-4)
    outer_holes={'handles':[HANDLES_HOLES['handles']]}
    outer_holes.update({role:[at+x for x in positions] for role,positions in holes.items()})
    relocs=HANDLES_RELOCATIONS+tuple((at+x,symbol) for x,symbol in relocations)
    return bytes(outer),outer_holes,relocs,at+EFFECTS_HOLES['mapping_size']

CARRIER_BRIDGE,CARRIER_HOLES,CARRIER_RELOCATIONS,CARRIER_SIZE_HOLE=carrier_bridges()

FINALIZER_PREFIX=bytes.fromhex('535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4d85e40f84ab0100004d85ed0f84a20100004d85f60f84990100004981ff800000000f858c0100004881fd800000000f827f0100004881fb000100000f857201000041f6c6070f85680100004c89e04c01f80f825c0100004c89ea4801ea0f82500100004c89f14801d90f82440100004c39e876094c39e20f87360100004c39f076094c39e10f87280100004c39f276094c39e90f871a01000049c74560000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84f800000083f801742b83f802743283f803743f83f8040f848100000083f805743c83f806745783f80c0f8481000000e9c3000000b8270000000f05e9ae00000031c0b901000000f0410fb14e08e99c00000031c041874608e991000000498d7e08be80000000ba010000004531d24531c04531c9b8ca0000000f05eb71498d7e08be81000000baffffff7f4531d24531c04531c9b8ca0000000f05eb514d897550488d05000000004989455831c0eb3e498dbe80000000be80000000498b5620498b4e284d8b463041b900010000e80000000048890424498b7620498dbe80000000b980000000fcf3a4488b042449894568e9eefeffffb8fdffffff4883c408415f415e415d415c5d5bc3')
FINALIZER_HOLES={'policy': 213, 'carrier_address': 385, 'carrier_call': 428}

def bridges():
    raw=bytearray(OWNER)
    raw.extend(bytes((-len(raw))%16))
    facet_at=len(raw)
    raw.extend(lifecycle.BRIDGE)
    raw.extend(bytes((-len(raw))%16))
    finalizer_at=len(raw)
    raw.extend(FINALIZER_PREFIX)
    raw.extend(bytes((-len(raw))%16))
    carrier_at=len(raw)
    raw.extend(CARRIER_BRIDGE)
    for name,target in (('carrier_address',carrier_at),('carrier_call',carrier_at),
                        ('lifecycle_call',facet_at),('finalizer_address',finalizer_at),('finalizer_call',finalizer_at)):
        at=OWNER_HOLES[name]
        struct.pack_into('<i',raw,at,target-at-4)
    for name in ('carrier_address','carrier_call'):
        at=finalizer_at+FINALIZER_HOLES[name]
        struct.pack_into('<i',raw,at,carrier_at-at-4)
    holes={'finalizer_policy':[finalizer_at+FINALIZER_HOLES['policy']],
           'owner_policy':[OWNER_HOLES['policy']],
           'lease_policy':[facet_at+lifecycle.HOLES['policy']],
           'values':[OWNER_HOLES['values_address'],OWNER_HOLES['values_call']]}
    for name,values in CARRIER_HOLES.items():
        holes.setdefault(name,[]).extend(carrier_at+x for x in values)
    return bytes(raw),holes,OWNER_RELOCATIONS+tuple((carrier_at+x,symbol) for x,symbol in CARRIER_RELOCATIONS),carrier_at+CARRIER_SIZE_HOLE

BRIDGE,HOLES,RELOCATIONS,SIZE_HOLE=bridges()

def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_generation_lease_owner',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_generation_lease_owner'],18,0,1,0,EXPORT_SIZE)]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((3+IMPORTS.index(name))<<32)|4,-4) for off,name in RELOCATIONS)
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
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        for h in HOLES[role]:struct.pack_into('<i',raw,64+h,len(raw)-64-h-4)
        raw.extend(flat)
    struct.pack_into('<I',raw,64+SIZE_HOLE,len(flats[ROLES.index('gen_prepare_mapping')]))
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original sixteen MiB text bound')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in (relas,symbols,strings,common.SECTIONS):offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
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
        total=total+size
        count=count+1
    if total!=length(s):
        return 4294967295
    layout(w)
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

def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<{n}:
        write(w,512+i*8,at,8)
        at=at+get(w,i*8)
        if i!={n-1}:
            at=(at+15)&18446744073709551600
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
    return source+'\n\n'+'\n\n'.join(functions)+common.HELPERS
def main():
    doc=document(source_program(),'generation_lease_owner_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_packer.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(ROLES),flush=True)

if __name__=='__main__':
    main()
