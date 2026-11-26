"""Native shared-arena provider component with fixed external owner imports.

The enclosing fusion resolves the three owner symbols to its one carrier,
effects adapter and Value image. No public request supplies these bindings.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
from tools import generate_hia_multiversion_background_payload_packer as payload
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ecc81000004881f9800000000f82680300004981f9000300000f85620300004885ff0f84590300004885d20f84500300004d85c00f844703000049f7c0070000000f853a0300004881fe800000000f822d0300004889f84801f00f82210300004989d24901ca0f82150300004d89c34d01cb0f82090300004839d076094939fa0f87fb0200004c39c076094939fb0f87ed0200004d39c276094939d30f87df0200004989fc4989f7488954242048894c24284c8dac24c0000000bd001000004d89c64c89cb49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f845f02000083f80a74dc83f8010f846601000083f8020f84ac01000083f8030f84c001000083f8040f84ce01000083f8060f84dc01000083f8070f84de01000083f8080f84e201000083f80f0f849d00000083f80c0f822a02000083f8100f87210200008944246031c9498b44cd004883f8040f8707020000498b54cd08480314c4488954cc6883c10383f90972db488b7c2468498b7510488b942480000000498b4d284c8b8424980000004d8b4d408b44246083f80c741883f80d741d83f81074224d8b5e58e800000000e987010000e800000000e97d010000e800000000e973010000e800000000e9690100004d89b580030000498d8600fbffff49898588030000488d05e8fdffff49898590030000488d05bdffffff486315b2ffffff4801d049898598030000488d059bffffff48631590ffffff4801d0498985a0030000488d0597ffffff4863158cffffff4801d0498985a8030000488d0589ffffff4863157effffff4801d0498985b003000031c0e9df0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc3049c1ea02ffc183f90672e0488b7c2430488b742438488b5424404c8b5424484c8b4424504c8b4c2458498b45000f05e99000000049837d00180f85ad000000498d5618418b4508418b4d10f00fb10aeb7349837d00180f8590000000498d5618418b45088702eb5c498b45004883f804777a498b5508480314c44889d0eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f804774b498b7508480334c4498b45104883f8047739498b7d1848033cc4498b4d20fcf3a431c049898588000000e982fdffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c4c8100000415f415e415d415c5d5bc3')
OUTER_HOLES={'provider':262,'effects':469,'handles':479,'payload':489,'values':499}
OUTER_RELOCATIONS=((805,'malloc'),(816,'free'))
IMPORTS=('malloc','free','hia_owner_carrier','hia_owner_effects','hia_owner_values')
ROLES=('provider','payload')
MAGIC=int.from_bytes(b'HIAGPP01','little')
EXPORT_SIZE=len(OUTER)
def bridges():
    raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));pa=len(raw);raw.extend(payload.BRIDGE)
    at=OUTER_HOLES['payload'];struct.pack_into('<i',raw,at,pa-at-4)
    holes={'provider':OUTER_HOLES['provider'],'payload':pa+payload.HOLES['policy']}
    relocs=tuple(OUTER_RELOCATIONS)+tuple((pa+x,n)for x,n in payload.RELOCATIONS)
    relocs+=tuple((OUTER_HOLES[k],n)for k,n in [('handles','hia_owner_carrier'),('effects','hia_owner_effects'),('values','hia_owner_values')])
    return bytes(raw),holes,relocs,pa
BRIDGE,HOLES,RELOCATIONS,PAYLOAD_OFFSET=bridges()
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_generation_lease_owner_provider',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_generation_lease_owner_provider'],18,0,1,0,EXPORT_SIZE)]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((3+IMPORTS.index(name))<<32)|4,-4)for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def source_program():
    changes={'BRIDGE':BRIDGE,'RELOCATIONS':RELOCATIONS,'HOLES':HOLES,'EXPORT_SIZE':EXPORT_SIZE,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
    old={k:getattr(base,k)for k in changes}
    try:
        for k,v in changes.items():setattr(base,k,v)
        source=base.source_program()
    finally:
        for k,v in old.items():setattr(base,k,v)
    for a,b in [('length(s)<48','length(s)<32'),('uint(s,8,8)!=4','uint(s,8,8)!=2'),('total=48','total=32'),('while count<4:','while count<2:'),('at=48','at=32'),('while i<4:','while i<2:'),('if i!=3:','if i!=1:')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(flats):
    if len(flats)!=2 or any(not x or len(x)>4194304 for x in flats):raise ValueError('two actual bounded provider/payload policies required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));at=64+HOLES[name];struct.pack_into('<i',raw,at,len(raw)-at-4);raw.extend(flat)
    textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def main():
    doc=document(source_program(),'generation_lease_owner_provider_packer')
    p=ROOT/'examples/hia_bootstrap/generation_lease_owner_provider_packer.hepta';p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),flush=True)
if __name__=='__main__':main()
