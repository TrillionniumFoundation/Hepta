"""Native fixed three-role gettempdir assembly; one libc environ lookup."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ecc81000004881f9800000000f82f70200004981f9002003000f85f10200004885ff0f84e80200004885d20f84df0200004d85c00f84d602000049f7c0070000000f85c90200004883fe200f82bf0200004889f84801f00f82b30200004989d24901ca0f82a70200004d89c34d01cb0f829b0200004839d076094939fa0f878d0200004c39c076094939fb0f877f0200004d39c276094939d30f87710200004989fc4989f7488954242048894c24284c8dac24c0000000bd001000004d89c64c89cb49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84f101000083f80a74dc83f8010f84c400000083f8020f840a01000083f8030f842101000083f8040f843201000083f8050f844401000083f8090f845c01000083f8080f847401000083f80f747b83f80c0f82c001000083f80d0f87b70100008944246031c9498b44cd004883f8040f879d010000498b54cd08480314c4488954cc6883c10383f90972db488b7c2468498b7510488b942480000000498b4d284c8b8424980000004d8b4d408b44246083f80c740ae800000000e92b010000e800000000e9210100004d89b5a000000031c0e9130100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc3049c1ea02ffc183f90672e0488b7c2430488b742438488b5424404c8b5424484c8b4424504c8b4c2458498b45000f05e9c400000049837d00180f85e1000000498d5618418b4508418b4d10f00fb10ae9a400000049837d00180f85c1000000498d5618418b45088702e98a000000498b45004883f8040f87a4000000498b5508480314c44889d0eb6f31ff488d35a5000000e8000000004885c07405488b00eb5748c7c0ffffffffeb4e498b45004885c0746d49837d0801740c49837d0808755f488b00eb320fb600eb2d498b45004883f804774b498b7508480334c4498b45104883f8047739498b7d1848033cc4498b4d20fcf3a431c049898588000000e9f0fdffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c4c8100000415f415e415d415c5d5bc3656e7669726f6e00')
HOLES={'policy':259,'absolute':458,'codec':448}
RELOCATIONS=((655,'dlsym'),)
EXPORT_SIZE=827
ROLES=('policy','absolute','codec')
MAGIC=int.from_bytes(b'HIAGTDP1','little')
def fixed_parts():
    names=('dlsym',)
    strings=b'\0hia_generation_lease_owner_tempdir\0dlsym\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0)for name in names])
    relas=b''.join(struct.pack('<QQq',off,((3+names.index(name))<<32)|4,-4)for off,name in RELOCATIONS)
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
    old={k:getattr(base,k)for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        source=base.source_program()
    finally:
        for k,v in old.items():setattr(base,k,v)
    for a,b in [('length(s)<48','length(s)<40'),('uint(s,8,8)!=4','uint(s,8,8)!=3'),
                ('total=48','total=40'),('while count<4:','while count<3:'),
                ('at=48','at=40'),('while i<4:','while i<3:'),('if i!=3:','if i!=2:')]:
        assert a in source,a
        source=source.replace(a,b)
    return source
def reference_object(flats):
    if len(flats)!=3 or any(not x or len(x)>4194304 for x in flats):raise ValueError('three bounded actual native roles required')
    if len(BRIDGE)+sum(len(x)+15 for x in flats)>16777216:raise ValueError('original text bound')
    prefix,relas,symbols,strings,sections=fixed_parts()
    raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        hole=HOLES[role]
        struct.pack_into('<i',raw,64+hole,len(raw)-64-hole-4)
        raw.extend(flat)
    size=len(raw)-64
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:
        offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    doc=document(source_program(),'generation_lease_owner_tempdir_packer')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_tempdir_packer.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),flush=True)
if __name__=='__main__':main()
