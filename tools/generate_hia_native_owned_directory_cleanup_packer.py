from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ecc80001004881f9800000000f82d50100004981f9001000000f85cf0100004881fe800000000f82c20100004885ff0f84b90100004885d20f84b00100004d85c00f84a701000049f7c0070000000f859a0100004889f84801f00f828e0100004989d24901ca0f82820100004d89c34d01cb0f82760100004839d076094939fa0f87680100004c39c076094939fb0f875a0100004d39c276094939d30f874c0100004989fc4989f7488954242048894c24284c8dac24c0000000bd000001004d89c64c89cb49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84cc00000083f80a74dc83f801742683f802746d83f803747783f808747a83f80f0f85cb0000004d89b5c800000031c0e9900000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc3049c1ea02ffc183f90672e0488b7c2430488b742438488b5424404c8b5424484c8b4424504c8b4c2458498b45000f05eb4431c0b901000000f0410fb14e18eb3531c041874618eb2d498b45004883f803774b498b7508480334c4498b45104883f8037739498b7d1848033cc4498b4d20fcf3a431c049898588000000e915ffffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c4c8000100415f415e415d415c5d5bc3')
HOLES={'policy': 262}
RELOCATIONS=()
EXPORT_SIZE=529

ROLES=('policy',)
MAGIC=int.from_bytes(b'HIARMTP1','little')
def fixed_parts():
    strings=b'\0hia_native_owned_directory_cleanup\0'
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
    if len(flats)!=1 or not flats[0] or len(flats[0])>4194304:raise ValueError('one bounded actual owned-directory cleanup policy required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    raw.extend(bytes((-len(raw))%16));struct.pack_into('<i',raw,64+HOLES['policy'],len(raw)-64-HOLES['policy']-4);raw.extend(flats[0]);textsize=len(raw)-64
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'native_owned_directory_cleanup_packer');p=ROOT/'examples/hia_bootstrap/native_owned_directory_cleanup_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
