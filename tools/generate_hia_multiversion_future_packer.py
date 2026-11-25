from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000200000f829000000049c745400000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f846a01000083f80a74dc83f801745283f8020f849800000083f8030f84b900000083f8040f84d500000083f8050f84e400000083f8060f84f300000083f8070f84f600000083f8080f84fa00000083f8090f8401010000b8fdffffffe9120100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9b3000000498b55004881fa8000000074094881fa8400000075914c01f2418b4508418b4d10f00fb10ae989000000498b55004881fa80000000740d4881fa840000000f8563ffffff4c01f2418b45088702eb64498b7500498dbd00010000b908000000fcf348a531c0eb4c498b7d00498db500010000b908000000fcf348a531c0eb34bf40000000e800000000eb28498b7d00e80000000031c0eb1b4d8b5d004c89f7498b750841ffd3eb0b4d8b5d00498b7d0841ffd3498985c0010000e977feffff418b45084881c488000000415f415e415d415c5d5bc3')
HOLES={'policy': 98}
RELOCATIONS=((414, 'malloc'), (425, 'free'))
EXPORT_SIZE=494

ROLES=('policy',)
MAGIC=int.from_bytes(b'HIAMVFP1','little')
def fixed_parts():
    strings=b'\0hia_mv_future\0malloc\0free\0'
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
    for a,b in [('length(s)<48','length(s)<24'),('uint(s,8,8)!=4','uint(s,8,8)!=1'),('total=48','total=24'),('while count<4:','while count<1:'),('at=48','at=24'),('while i<4:','while i<1:'),('if i!=3:','if i!=0:')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(flats):
    if len(flats)!=1 or not flats[0] or len(flats[0])>4194304:raise ValueError('one bounded actual future owner required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    raw.extend(bytes((-len(raw))%16));struct.pack_into('<i',raw,64+HOLES['policy'],len(raw)-64-HOLES['policy']-4);raw.extend(flats[0]);textsize=len(raw)-64
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'multiversion_future_packer');p=ROOT/'examples/hia_bootstrap/multiversion_future_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
