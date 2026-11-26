"""Five native roles for fixed installed component custody and exact admission."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as generic
from tools import generate_hia_clang_stable_file_packer as stable
ROOT=Path(__file__).resolve().parents[1]
ROLES=('loader','catalog','stable','sha','mapping')
MAGIC=int.from_bytes(b'HIANLCP1','little')
IMPORTS=('dlopen','dlsym','dlclose')
OUTER=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84670400004d85ed0f845e0400004d85f60f845504000049f7c6070000000f85480400004981ff800000000f853b0400004881fd000002000f822e0400004881fb000090010f85210400004c89e04c01f80f821504000048898424800000004c89e84801e80f820104000048898424880000004c89f04801d80f82ed03000048898424900000004c3ba42488000000730e4c3bac24800000000f82cd0300004c3ba42490000000730e4c3bb424800000000f82b50300004c3bac2490000000730e4c3bb424880000000f829d03000048b84849414e4c435131493904240f85890300004d8b5424084983fa040f877a03000031c9b91000000083f91075054d85d2741b4983fa03750a83f918720583f928760b49833c0c000f854e03000083c10881f98000000072d04d85d2750c49837c2410000f8432030000b8270000000f054885c00f8e2203000048898424a000000049833e00743a49bb4849414e4c4357314d391e0f85010300004d3976080f85f7020000493946100f85ed020000488d0553feffff493946180f85dc020000eb0c49837c2408000f85ce02000048c70424000000004c897424084c896424104c896c241849c78580000000000000004d89b500020000488d050bfeffff498985080200004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f847402000083f8010f841502000083f802745383f803746283f805746c83f8060f849500000083f8070f84a100000083f8080f840d01000083f8090f841a01000083f80a0f823302000083f80d0f862d01000083f80e0f841401000083f80f7485e91702000031c0b901000000f0410fb14e28f390e9f301000049c746280000000031c0e9e401000031ff488d3502020000e8000000004885c00f84cd0100004989c3488d3d40fdffff498db6800c000041ffd389c0e9b2010000498b45004885c00f84b50100000fb600e99d010000498b4d204885c97465498b55004883fa030f8796010000498b7508480334d40f82880100004885f60f847f0100004889f04801c80f8273010000498b55104883fa030f8765010000498b7d1848033cd40f82570100004885ff0f844e0100004889f84801c80f8242010000fcf3a431c0e928010000498dbe00200000be02000000e800000000e912010000498b7e48498db600400000e800000000e9fd000000498b7e48e80000000089c0e9ed00000089842498000000498b7d00498b75084889f84801f00f82e20000004839d80f87d90000004c01f7498b5510498b4d184889d04801c80f82c20000004839d80f87b90000004c01f24d8b45204d8b4d284c89c04c01c80f82a20000004839d80f87990000004d01f083bc24980000000a741b83bc24980000000b741883bc24980000000c7415e800000000eb13e800000000eb0ce800000000eb05e80000000089c0eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549898588000000e96dfdffff31c0eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3646c6164647200')
OUTER_HOLES={"policy":527,"mapping":1052,"catalog":1059,"stable":1066,"sha":1073}
OUTER_RELOCATIONS=[[681,"dlsym"],[872,"dlopen"],[893,"dlsym"],[907,"dlclose"]]
def bridges():
    raw=bytearray(OUTER)
    holes={role:[]for role in ROLES}
    for label in ('policy','catalog','sha','mapping'):
        holes['loader' if label=='policy' else label].append(OUTER_HOLES[label])
    raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(stable.BRIDGE)
    struct.pack_into('<i',raw,OUTER_HOLES['stable'],at-OUTER_HOLES['stable']-4)
    for role,offset in stable.FIXUPS:
        holes['stable' if role=='owner' else role].append(at+offset)
    return bytes(raw),holes,tuple(OUTER_RELOCATIONS)
BRIDGE,HOLES,RELOCATIONS=bridges()
def fixed_parts():
    exports=(('hia_native_fixed_component_loader',0,len(OUTER)),)
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
    for old,new in [('length(s)<48','length(s)<56'),('uint(s,8,8)!=4','uint(s,8,8)!=5'),
      ('total=48','total=56'),('while count<4:','while count<5:'),('at=48','at=56'),
      ('while i<4:','while i<5:'),('if i!=3:','if i!=4:')]:
        assert old in source,old
        source=source.replace(old,new)
    return source
def reference_object(flats):
    if len(flats)!=5 or any(not part or len(part)>4194304 for part in flats):
        raise ValueError('five actual bounded native roles required')
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
    tree=document(source_program(),'native_fixed_component_packer')
    path=ROOT/'examples/hia_bootstrap/native_fixed_component_packer.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),flush=True)
if __name__=='__main__':main()
