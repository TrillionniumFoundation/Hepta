"""Native compound Future resource, fixed Future/Value imports and real registry."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
from tools import generate_hia_future_resource_registry_packer as registry
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ecc89001004881f9800000000f822f0300004981f9000200000f85290300004885ff0f84200300004885d20f84170300004d85c00f840e03000049f7c0070000000f85010300004881fe800000000f82f40200004889f84801f00f82e80200004989d24901ca0f82dc0200004d89c34d01cb0f82d00200004839d076094939fa0f87c20200004c39c076094939fb0f87b40200004d39c276094939d30f87a60200004989fc4989f7488954242048894c24284c8dac24c0000000bd009001004d89c64c89cb49c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f842602000083f80a74dc83f8010f842d01000083f8020f847301000083f8030f848701000083f8040f849501000083f8060f84a301000083f8070f84a501000083f8080f84a901000083f80f0f848a00000083f80c0f82f101000083f80e0f87e80100008944246031c9498b44cd004883f8030f87ce010000498b54cd08480314c4488954cc6883c10383f90972db488b7c2468498b7510488b942480000000498b4d284c8b8424980000004d8b4d408b44246083f80c740f83f80d7414e800000000e957010000e800000000e94d010000e800000000e9430100004d89b580010000488d0509feffff49898588010000488d05d5ffffff486315caffffff4801d049898590010000488d05c7ffffff486315bcffffff4801d049898598010000488d059bffffff48631590ffffff4801d0498985a001000031c0e9df0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc3049c1ea02ffc183f90672e0488b7c2430488b742438488b5424404c8b5424484c8b4424504c8b4c2458498b45000f05e99000000049837d00580f85ad000000498d5658418b4508418b4d10f00fb10aeb7349837d00580f8590000000498d5658418b45088702eb5c498b45004883f804777a498b5508480314c44889d0eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f804774b498b7508480334c4498b45104883f8047739498b7d1848033cc4498b4d20fcf3a431c049898588000000e9bbfdffff488b7c24204c89eeb910000000fcf348a531c0eb0cb8feffffffeb05b8fdffffff4881c4c8900100415f415e415d415c5d5bc3')
OUTER_HOLES={'owner': 262, 'registry': 460, 'future': 470, 'values': 480}
OUTER_RELOCATIONS=((748, 'malloc'), (759, 'free'))
IMPORTS=('malloc','free','hia_resource_future','hia_resource_values')
ROLES=('owner','registry')
MAGIC=int.from_bytes(b'HIAFROP1','little')
EXPORT_SIZE=len(OUTER)
def bridges():
    raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));pa=len(raw);raw.extend(registry.BRIDGE)
    at=OUTER_HOLES['registry'];struct.pack_into('<i',raw,at,pa-at-4)
    holes={'owner':OUTER_HOLES['owner'],'registry':pa+registry.HOLES['policy']}
    relocs=tuple(OUTER_RELOCATIONS)+tuple((pa+x,n)for x,n in registry.RELOCATIONS)
    relocs+=tuple((OUTER_HOLES[k],n)for k,n in [('future','hia_resource_future'),('values','hia_resource_values')])
    return bytes(raw),holes,relocs,pa
BRIDGE,HOLES,RELOCATIONS,REGISTRY_OFFSET=bridges()
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_future_resource_owner',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_future_resource_owner'],18,0,1,0,EXPORT_SIZE)]
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
    if len(flats)!=2 or any(not x or len(x)>4194304 for x in flats):raise ValueError('two actual bounded owner/registry policies required')
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
    doc=document(source_program(),'future_resource_owner_packer')
    p=ROOT/'examples/hia_bootstrap/future_resource_owner_packer.hepta';p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),flush=True)
if __name__=='__main__':main()
