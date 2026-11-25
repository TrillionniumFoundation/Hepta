"""Pure HIA packaging for the private same-holder retirement entry."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb48c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f849f00000083f801741483f802745b83f803747eb8fdffffffe98a0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb31498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d28e800000000eb09498b7d00e80000000049894608e942ffffff418b45084881c488000000415f415e415d415c5d5bc3')
RELOCATIONS=((235, 'dlclose'),)
HOLES={'policy': 77, 'state': 224}
EXPORT_SIZE=270
ROLES=('policy','state')
MAGIC=int.from_bytes(b'HIAMVRP1','little')
def fixed_parts():
    strings=b'\0hia_mv_retire\0dlclose\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),
        struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE),
        struct.pack('<IBBHQQ',15,16,0,0,0,0)])
    assert strings[15:]==b'dlclose\0'
    relas=b''.join(struct.pack('<QQq',off,(3<<32)|4,-4) for off,name in RELOCATIONS)
    assert [n for _,n in RELOCATIONS]==['dlclose']
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,strings,b''.join(rows)
def source_program():
    changes={'BRIDGE':BRIDGE,'RELOCATIONS':RELOCATIONS,'HOLES':HOLES,'EXPORT_SIZE':EXPORT_SIZE,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(base,k) for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        source=base.source_program()
    finally:
        for k,v in old.items():setattr(base,k,v)
    for a,b in [('length(s)<48','length(s)<32'),('uint(s,8,8)!=4','uint(s,8,8)!=2'),('total=48','total=32'),
                ('while count<4:','while count<2:'),('at=48','at=32'),('while i<4:','while i<2:'),('if i!=3:','if i!=1:')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(flats):
    if len(flats)!=2 or any(not x or len(x)>4194304 for x in flats):raise ValueError('two actual bounded flats required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));struct.pack_into('<i',raw,64+HOLES[role],len(raw)-64-HOLES[role]-4);raw.extend(flat)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('text extent')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:
        offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'multiversion_retirement_packer');p=ROOT/'examples/hia_bootstrap/multiversion_retirement_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']))
if __name__=='__main__':main()
