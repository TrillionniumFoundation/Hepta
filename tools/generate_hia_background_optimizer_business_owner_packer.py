from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd800000000f822a0100004881fb004010000f821d0100004d85e40f84140100004d85ed0f840b0100004d85f60f84020100004c89e04c01f80f82f60000004c89ea4801ea0f82ea0000004c89f14801d90f82de0000004939d473094939c50f82d00000004939cc73094939c60f82c20000004939cd73094939d60f82b40000004c896c24704d8dae0040000048c7c50000100048c7c30040000049c785800000000000000049c785a80200000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d94983bda8020000007507e800000000eb0f4983bda8020000017540e80000000085c00f842001000083f80a74c183f801743383f8040f84a000000083f8060f84a900000083f8070f84ab00000083f8080f84af00000083f8097415b8fdffffffe9e300000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb6f4c89d14d8b5d0041ffd389c0eb61498b45004839e80f8373ffffff4c01e8eb4f498b7d00e800000000eb44498b7d00e80000000031c0eb37498b45004883f8030f8748ffffff498b7508480334c4498b45104883f8030f8732ffffff498b7d1848033cc4498b4d20fcf3a431c0eb00498985c0010000e9a6feffff85c07510488b7c24704c89eeb980000000fcf3a44881c488000000415f415e415d415c5d5bc3')
HOLES={'policy': 266, 'publication': 283}
RELOCATIONS=((497, 'malloc'), (508, 'free'))
EXPORT_SIZE=621
ROLES=('policy','publication')
MAGIC=int.from_bytes(b'HIABWOP1','little')
def fixed_parts():
    strings=b'\0hia_background_business_owner\0malloc\0free\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0) for name in ('malloc','free')])
    relas=b''.join(struct.pack('<QQq',off,((3+('malloc','free').index(name))<<32)|4,-4) for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,strings,b''.join(rows)

def apply(function,*args):
    changes={'BRIDGE':BRIDGE,'RELOCATIONS':RELOCATIONS,'HOLES':HOLES,'EXPORT_SIZE':EXPORT_SIZE,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(base,k) for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        return function(*args)
    finally:
        for k,v in old.items():setattr(base,k,v)
def source_program():
    source=apply(base.source_program)
    for old,new in [('length(s)<48','length(s)<32'),('uint(s,8,8)!=4','uint(s,8,8)!=2'),('total=48','total=32'),('while count<4:','while count<2:'),('at=48','at=32'),('while i<4:','while i<2:'),('if i!=3:','if i!=1:')]:
        assert old in source,old
        source=source.replace(old,new)
    return source
def reference_object(flats):
    if len(flats)!=2 or any(not x or len(x)>4194304 for x in flats):
        raise ValueError('two bounded actual execution policies required')
    prefix,relas,symbols,strings,sections=fixed_parts()
    raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        struct.pack_into('<i',raw,64+HOLES[role],len(raw)-64-HOLES[role]-4)
        raw.extend(flat)
    if len(raw)-64>16777216:
        raise ValueError('owned text exceeds original shared linker domain')
    textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:
        offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'background_optimizer_business_owner_packer');p=ROOT/'examples/hia_bootstrap/background_optimizer_business_owner_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
