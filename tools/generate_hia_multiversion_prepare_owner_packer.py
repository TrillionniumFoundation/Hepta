"""Native fixed fifteen-role preparation and same-holder cleanup packaging."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as build
from tools import generate_hia_multiversion_probe_packer as probe
from tools import generate_hia_multiversion_retirement_packer as retire
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fb0000000c0f820d0100004881fd000800000f820001000049c7860000a00b0000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84b900000083f801745e83f8020f82b600000083f8050f87ad000000498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d2883f802741183f803741383f8047415e800000000eb5fe800000000eb58e800000000eb51e800000000eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f054989860800a00be928ffffff418b4508eb05b8fdffffff4881c488000000415f415e415d415c5d5bc3')
OUTER_HOLES={'policy': 114, 'retirement': 198, 'build': 205, 'image': 212, 'probe': 219}
IMAGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb48c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84fc00000083f8010f84a000000083f807741e83f802720f83f804761483f805746883f8067475b8fdffffffe9d400000089442450498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d28837c2450027418837c2450037418837c2450077418e800000000e983000000e800000000eb7ce800000000eb75e800000000eb6e498b7d004c01f7498b7508e800000000eb5c498b7d00498b75084c01f6e800000000eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549894608e9e5feffff418b45084881c488000000415f415e415d415c5d5bc3')
IMAGE_HOLES={'policy': 77, 'mapping': 192, 'sha': 202, 'elf': 209, 'json': 216}
IMAGE_RELOCATIONS=((234, 'dlopen'), (252, 'dlsym'))
ROLES=('owner','capture','process','hash','json','image','sha','elf','mapping','probe','vectors','projector','vm','retire','retirement_state')
IMPORTS=('dlopen','dlsym','dlclose')
MAGIC=int.from_bytes(b'HIAMVGP1','little')
def bridges():
    raw=bytearray(OUTER);holes={k:[] for k in ROLES};holes['owner']=[OUTER_HOLES['policy']];rel=[]
    parts=[('build',build.BRIDGE,build.HOLES,{'prepare':'capture','process':'process','hash':'hash','json':'json'},()),
           ('image',IMAGE,IMAGE_HOLES,{'policy':'image','sha':'sha','elf':'elf','mapping':'mapping','json':'json'},IMAGE_RELOCATIONS),
           ('probe',probe.BRIDGE,probe.HOLES,{'policy':'probe','vectors':'vectors','projector':'projector','vm':'vm'},()),
           ('retirement',retire.BRIDGE,retire.HOLES,{'policy':'retire','state':'retirement_state'},retire.RELOCATIONS)]
    for name,part,loc,mapping,external in parts:
        raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(part)
        struct.pack_into('<i',raw,OUTER_HOLES[name],at-OUTER_HOLES[name]-4)
        for source,target in mapping.items():
            hs=loc[source] if isinstance(loc[source],list) else [loc[source]]
            holes[target]+=[at+x for x in hs]
        rel += [(at+x,n) for x,n in external]
    return bytes(raw),holes,tuple(rel)
BRIDGE,HOLES,RELOCATIONS=bridges()
EXPORT_SIZE=len(OUTER)
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_mv_prepare_owner',*IMPORTS):positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_mv_prepare_owner'],18,0,1,0,EXPORT_SIZE)]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols);relas=b''.join(struct.pack('<QQq',at,((3+IMPORTS.index(name))<<32)|4,-4) for at,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    sections=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        sections.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(sections)
def source_program():
    changes={'BRIDGE':BRIDGE,'HOLES':HOLES,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(build,k) for k in changes}
    try:
        for k,v in changes.items():setattr(build,k,v)
        s=build.source_program()
    finally:
        for k,v in old.items():setattr(build,k,v)
    for a,b in [('length(s)<48','length(s)<136'),('uint(s,8,8)!=4','uint(s,8,8)!=15'),('total=48','total=136'),('while count<4:','while count<15:'),('at=48','at=136'),('while i<4:','while i<15:'),('if i!=3:','if i!=14:')]:
        assert a in s,a;s=s.replace(a,b)
    return s

def reference_object(flats):
    if len(flats)!=15 or any(not f or len(f)>4194304 for f in flats):raise ValueError('fifteen actual bounded roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        for hole in HOLES[role]:struct.pack_into('<i',raw,64+hole,len(raw)-64-hole-4)
        raw.extend(flat)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original 16 MiB text domain')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in [relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'multiversion_prepare_owner_packer');p=ROOT/'examples/hia_bootstrap/multiversion_prepare_owner_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
