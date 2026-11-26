"""Four actual HIA roles for fixed Runtime/BG/LLVM resource custody."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as generic
from tools import generate_hia_clang_stable_file_packer as stable
ROOT=Path(__file__).resolve().parents[1]
ROLES=('resources','catalog','stable','sha')
MAGIC=int.from_bytes(b'HIANGRP1','little')
IMPORTS=('dlsym',)
OUTER=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84e30300004d85ed0f84da0300004d85f60f84d103000049f7c6070000000f85c40300004981ff800000000f85b70300004881fd000002000f82aa0300004881fb000080000f859d0300004c89e04c01f80f829103000048898424800000004c89e84801e80f827d03000048898424880000004c89f04801d80f826903000048898424900000004c3ba42488000000730e4c3bac24800000000f82490300004c3ba42490000000730e4c3bb424800000000f82310300004c3bac2490000000730e4c3bb424880000000f821903000048b84849414e47525131493904240f85050300004d8b5424084983fa040f87f602000031c9b9100000004983fa03750a83f918720583f928760b49833c0c000f85d402000083c10881f98000000072dab8270000000f054885c00f8eb902000048898424a000000049833e00743a49bb4849414e475257314d391e0f85980200004d3976080f858e020000493946100f8584020000488d056efeffff493946180f8573020000eb0c49837c2408000f856502000048c70424000000004c897424084c896424104c896c241849c78580000000000000004d89b500020000488d0526feffff498985080200004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f840b02000083f8010f84ac01000083f802743483f803744383f805744d83f806747a83f8070f848600000083f80a0f82e001000083f80c0f86e900000083f80f74a4e9cd01000031c0b901000000f0410fb14e28f390e9a901000049c746280000000031c0e99a01000031ff488d35b8010000e8000000004885c00f84830100004989c3488d3d7afdffff498db6800c000041ffd389c0e968010000498b45004885c00f846b0100000fb600e953010000498b4d204885c97465498b55004883fa030f874c010000498b7508480334d40f823e0100004885f60f84350100004889f04801c80f8229010000498b55104883fa030f871b010000498b7d1848033cd40f820d0100004885ff0f84040100004889f84801c80f82f8000000fcf3a431c0e9de00000089842498000000498b7d00498b75084889f84801f00f82d30000004839d80f87ca0000004c01f7498b5510498b4d184889d04801c80f82b30000004839d80f87aa0000004c01f24d8b45204d8b4d284c89c04c01c80f82930000004839d80f878a0000004d01f083bc24980000000a740c83bc24980000000b7409eb0ee800000000eb0ce800000000eb05e80000000089c0eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549898588000000e9d6fdffff31c0eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3646c6164647200')
OUTER_HOLES={"policy":500,"catalog":927,"stable":934,"sha":941}
OUTER_RELOCATIONS=[[623,"dlsym"]]
def bridges():
    raw=bytearray(OUTER)
    holes={role:[]for role in ROLES}
    for label in ('policy','catalog','sha'):
        holes['resources' if label=='policy' else label].append(OUTER_HOLES[label])
    raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(stable.BRIDGE)
    struct.pack_into('<i',raw,OUTER_HOLES['stable'],at-OUTER_HOLES['stable']-4)
    for role,offset in stable.FIXUPS:
        holes['stable' if role=='owner' else role].append(at+offset)
    return bytes(raw),holes,tuple(OUTER_RELOCATIONS)
BRIDGE,HOLES,RELOCATIONS=bridges()
def fixed_parts():
    exports=(('hia_native_runtime_resources',0,len(OUTER)),)
    strings=bytearray(b'\0');positions={}
    for name in [*(row[0]for row in exports),*IMPORTS]:
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],18,0,1,at,size)for name,at,size in exports)
    first_import=len(symbols)
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    relas=b''.join(struct.pack('<QQq',at,((first_import+IMPORTS.index(name))<<32)|4,-4)for at,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    symbols=b''.join(symbols)
    sections=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
      ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
      ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
      ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        sections.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(sections)
def source_program():
    changes=dict(ROLES=ROLES,MAGIC=MAGIC,BRIDGE=BRIDGE,HOLES=HOLES,fixed_parts=fixed_parts)
    saved={name:getattr(generic,name)for name in changes}
    try:
        for name,value in changes.items():setattr(generic,name,value)
        source=generic.source_program()
    finally:
        for name,value in saved.items():setattr(generic,name,value)
    return source
def reference_object(flats):
    if len(flats)!=4 or any(not part or len(part)>4194304 for part in flats):
        raise ValueError('four actual bounded native roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,part in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        for offset in HOLES[name]:struct.pack_into('<i',raw,64+offset,len(raw)-64-offset-4)
        raw.extend(part)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original 16 MiB text domain')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in [relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));section_at=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,section_at);struct.pack_into('<QQ',raw,section_at+88,64,textsize)
    for index,offset in enumerate(offsets,2):struct.pack_into('<Q',raw,section_at+64*index+24,offset)
    return bytes(raw)
def main():
    tree=document(source_program(),'native_runtime_resources_packer')
    path=ROOT/'examples/hia_bootstrap/native_runtime_resources_packer.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),flush=True)
if __name__=='__main__':main()
