"""Fixed eight-role artifact capture, fresh LLVM and same-holder retirement."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_owner_packer as prepare
from tools import generate_hia_multiversion_prepare_build_packer as generic
from tools import generate_hia_multiversion_retirement_packer as retirement
ROOT=Path(__file__).resolve().parents[1]
ROLES=('image','sha','elf','mapping','json','retire','retirement_state','llvm')
MAGIC=int.from_bytes(b'HIAGCIP2','little')
IMPORTS=('dlopen','dlsym','dlclose')
IMAGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb48c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f841601000083f8010f84ba00000083f807742783f808742283f802721383f804761883f805747d83f8060f8486000000b8fdffffffe9e500000089442450498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d28837c245002741f837c2450037422837c2450077422837c2450087422e800000000e98d000000e800000000e983000000e800000000eb7ce800000000eb75e800000000eb6e498b7d004c01f7498b7508e800000000eb5c498b7d00498b75084c01f6e800000000eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549894608e9cbfeffff418b45084881c488000000415f415e415d415c5d5bc3')
IMAGE_HOLES={"policy":77,"mapping":208,"sha":218,"elf":228,"json":235,"llvm":242}
IMAGE_RELOCATIONS=[[260,"dlopen"],[278,"dlsym"]]
def bridges():
    raw=bytearray(IMAGE)
    holes={role:[]for role in ROLES}
    for label,offset in IMAGE_HOLES.items():
        holes['image' if label=='policy' else label].append(offset)
    rel=list(IMAGE_RELOCATIONS)
    raw.extend(bytes((-len(raw))%16));retire_at=len(raw);raw.extend(retirement.BRIDGE)
    for label,offset in retirement.HOLES.items():
        target='retire' if label=='policy' else 'retirement_state'
        for at in offset if isinstance(offset,list) else [offset]:holes[target].append(retire_at+at)
    rel.extend((retire_at+at,name)for at,name in retirement.RELOCATIONS)
    return bytes(raw),holes,tuple(rel),retire_at
BRIDGE,HOLES,RELOCATIONS,RETIRE_AT=bridges()
def fixed_parts():
    exports=(('hia_generation_lease_owner_clang_fresh_image',0,len(IMAGE)),
             ('hia_generation_lease_owner_clang_fresh_image_retire',RETIRE_AT,len(retirement.BRIDGE)))
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
    for old,new in [('length(s)<48','length(s)<80'),('uint(s,8,8)!=4','uint(s,8,8)!=8'),
      ('total=48','total=80'),('while count<4:','while count<8:'),('at=48','at=80'),
      ('while i<4:','while i<8:'),('if i!=3:','if i!=7:')]:
        assert old in source,old
        source=source.replace(old,new)
    return source
def reference_object(flats):
    if len(flats)!=8 or any(not part or len(part)>4194304 for part in flats):
        raise ValueError('eight actual bounded native roles required')
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
    tree=document(source_program(),'generation_lease_owner_clang_fresh_image_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_clang_fresh_image_packer.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),flush=True)
if __name__=='__main__':main()
