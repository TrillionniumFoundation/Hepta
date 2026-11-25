from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000200000f82870000004881fb00010000727e49c745400000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f843b01000083f80a74dc83f801744083f8020f848600000083f8030f849600000083f8060f84a000000083f8070f84a200000083f8080f84a600000083f8090f84d4000000b8fdffffffe9f10000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e99600000049837d002075a0498d5620418b4508418b4d10f00fb10aeb7d49837d00207587498d5620418b45088702eb6a498b7d00e800000000eb5f498b7d00e80000000031c0eb52498b45004883f8030f8755ffffff498b7508480334c4498b45104883f8030f873fffffff498b7d1848033cc4498b4d20fcf3a431c0eb1b498b7d00498b7508498b5510498b4d184531c04531c9e800000000498985c0010000e9a6feffff4881c488000000415f415e415d415c5d5bc3')
HOLES={'policy': 107, 'values': 418}
RELOCATIONS=((321, 'malloc'), (332, 'free'))
EXPORT_SIZE=452

ROLES=('policy','values')
MAGIC=int.from_bytes(b'HIAMVUP1','little')
def fixed_parts():
    strings=b'\0hia_mv_values\0malloc\0free\0'
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
def source_program():
    changes={'BRIDGE':BRIDGE,'RELOCATIONS':RELOCATIONS,'HOLES':HOLES,'EXPORT_SIZE':EXPORT_SIZE,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(base,k) for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        source=base.source_program()
    finally:
        for k,v in old.items():setattr(base,k,v)
    for a,b in [('length(s)<48','length(s)<32'),('uint(s,8,8)!=4','uint(s,8,8)!=2'),('total=48','total=32'),('while count<4:','while count<2:'),('at=48','at=32'),('while i<4:','while i<2:'),('if i!=3:','if i!=1:')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(flats):
    if len(flats)!=2 or any(not f or len(f)>4194304 for f in flats):
        raise ValueError('two bounded actual value roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        struct.pack_into('<i',raw,64+HOLES[name],len(raw)-64-HOLES[name]-4)
        raw.extend(flat)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original shared linker text domain')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'multiversion_values_packer');p=ROOT/'examples/hia_bootstrap/multiversion_values_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
