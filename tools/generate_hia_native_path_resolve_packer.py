from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd800000000f82330100004881fb001003000f82260100004d85ed0f841d0100004d85f60f84140100004c89e04c01f80f82080100004c89ea4801ea0f82fc0000004c89f14801d90f82f00000004939cd73094939d60f82e20000004d85ff74254d85e40f84d40000004939d473094939c50f82c60000004939cc73094939c60f82b80000004d8976104c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f849a00000083f80374dc83f8010f85870000004d8b553831c9498b44cd084d89d34183e30349c1ea024585db742e4183fb0174124183fb0274184839d8775b4c01f07256eb164c39f8774f4c01e0724aeb0a4839e877434c01e8723e488944cc20ffc183f90672b14d85d2752d488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549894608e94cffffffb8fdffffff4881c488000000415f415e415d415c5d5bc3')
HOLES={'policy': 194}
RELOCATIONS=()
EXPORT_SIZE=378

ROLES=('policy',)
MAGIC=int.from_bytes(b'HIAPTRP1','little')
def fixed_parts():
    strings=b'\0hia_native_path_resolve\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0) for name in ()])
    relas=b''.join(struct.pack('<QQq',off,((3+('malloc','free').index(name))<<32)|4,-4) for off,name in RELOCATIONS)
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
    for a,b in [('length(s)<48','length(s)<24'),('uint(s,8,8)!=4','uint(s,8,8)!=1'),('total=48','total=24'),('while count<4:','while count<1:'),('at=48','at=24'),('while i<4:','while i<1:'),('if i!=3:','if i!=0:')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(flats):
    if len(flats)!=1 or not flats[0] or len(flats[0])>4194304:raise ValueError('one bounded actual path resolution policy required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    raw.extend(bytes((-len(raw))%16));struct.pack_into('<i',raw,64+HOLES['policy'],len(raw)-64-HOLES['policy']-4);raw.extend(flats[0]);textsize=len(raw)-64
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'native_path_resolve_packer');p=ROOT/'examples/hia_bootstrap/native_path_resolve_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
