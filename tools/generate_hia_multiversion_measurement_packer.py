"""Native fixed measurement capture, policy and hash packaging."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as base
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4881fd8000000072744881fb00000100726b49c78600100000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0744a83f801724583f8027740498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d2883f8017407e800000000eb05e80000000049898608100000eba0b8fdffffff4883c408415f415e415d415c5d5bc3')
EXPORT_SIZE=len(OUTER)
ROLES=('owner','measurement','hash')
IMPORTS=()
MAGIC=int.from_bytes(b'HIAMVMP1','little')
BRIDGE=OUTER
HOLES={'owner': [80], 'measurement': [144], 'hash': [137]}
RELOCATIONS=()
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_mv_measurement',*IMPORTS):positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_mv_measurement'],18,0,1,0,EXPORT_SIZE)]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols);relas=b''.join(struct.pack('<QQq',at,((3+IMPORTS.index(name))<<32)|4,-4) for at,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    sections=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        sections.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(sections)
def source_program():
    changes={'BRIDGE':BRIDGE,'HOLES':HOLES,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(base,k) for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        s=base.source_program()
    finally:
        for k,v in old.items():setattr(base,k,v)
    for a,b in [('length(s)<48','length(s)<40'),('uint(s,8,8)!=4','uint(s,8,8)!=3'),('total=48','total=40'),('while count<4:','while count<3:'),('at=48','at=40'),('while i<4:','while i<3:'),('if i!=3:','if i!=2:')]:
        assert a in s,a;s=s.replace(a,b)
    return s
def reference_object(flats):
    if len(flats)!=3 or any(not f or len(f)>4194304 for f in flats):raise ValueError('three actual bounded roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        for hole in HOLES[role]:struct.pack_into('<i',raw,64+hole,len(raw)-64-hole-4)
        raw.extend(flat)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original 16 MiB text domain')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in [relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    t=document(source_program(),'multiversion_measurement_packer');p=ROOT/'examples/hia_bootstrap/multiversion_measurement_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
