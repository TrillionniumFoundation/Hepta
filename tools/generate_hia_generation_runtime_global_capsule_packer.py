"""Native global resource capsule with fixed imports into the sole root.

Three HIA policies, no Value/Runtime copy. The parent resolves the declared
owner/Value/stable/SHA imports statically to its existing exact native bodies.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as generic
from tools import generate_hia_native_runtime_resources_packer as resources
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAGGCP1','little')
ROLES=('global','resources','catalog')
IMPORTS=('dlsym','hia_global_owner','hia_global_values','hia_global_stable','hia_global_sha')
OUTER=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84820300004d85ed0f84790300004d85f60f847003000049f7c6070000000f85630300004981ff800000000f85560300004881fd004002000f82490300004881fb000800000f853c0300004c89e04c01f80f823003000048898424800000004c89e84801e80f821c03000048898424880000004c89f04801d80f820803000048898424900000004c3ba42488000000730e4c3bac24800000000f82e80200004c3ba42490000000730e4c3bb424800000000f82d00200004c3bac2490000000730e4c3bb424880000000f82b802000048b84849414747495131493904240f85a40200004d8b5424084983fa040f8795020000b9100000004983fa03750a83f918720583f928760b49833c0c000f857502000083c10881f98000000072dab8270000000f054885c00f8e5a02000049bb484941474c4f57314d391e0f8547020000493946080f853d0200004d3976100f853302000049837e50010f8528020000488d0500000000493946180f85170200004889842498000000488d0500000000493946280f85fe01000048898424a0000000498d8600020000493946300f85e501000049817e38000100000f85d701000048c70424000000004c897424084c896424104c896c241849c78580000000000000004d89b500020000488d05f9fdffff49898508020000488d050000000049898510020000488b84249800000049898518020000488b8424a0000000498985200200004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f845101000083f8010f84f200000083f802741883f803742783f807743183f80a0f849d000000e92f01000031c0b901000000f0410fb14e40f390e90b01000049c746400000000031c0e9fc000000498b4d204885c97465498b55004883fa030f87f5000000498b7508480334d40f82e70000004885f60f84de0000004889f04801c80f82d2000000498b55104883fa030f87c4000000498b7d1848033cd40f82b60000004885ff0f84ad0000004889f84801c80f82a1000000fcf3a431c0e987000000498dbd00100000be80000000498d9500400000b9000002004d8b86400400004d8b8e480400004d85c0746c4981f9000080007563e80000000089c0eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549898588000000e990feffff31c0eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
OUTER_HOLES=dict(root=393,values=418,resources_address=529,policy=589,resources_call=844)
raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));RESOURCE_AT=len(raw);raw.extend(resources.BRIDGE)
for label in('resources_address','resources_call'):
    at=OUTER_HOLES[label];struct.pack_into('<i',raw,at,RESOURCE_AT-at-4)
BRIDGE=bytes(raw)
HOLES=dict(global_policy=[OUTER_HOLES['policy']],resources=[RESOURCE_AT+x for x in resources.HOLES['resources']],catalog=[RESOURCE_AT+x for x in resources.HOLES['catalog']])
HOLES['global']=HOLES.pop('global_policy')
FIXED_HOLES=dict(owner=[OUTER_HOLES['root']],values=[OUTER_HOLES['values']],
 stable=[RESOURCE_AT+x for x in resources.HOLES['stable']],sha=[RESOURCE_AT+x for x in resources.HOLES['sha']])
DYNAMIC_RELOCATIONS=tuple((RESOURCE_AT+x,name)for x,name in resources.RELOCATIONS)
RELOCATIONS=DYNAMIC_RELOCATIONS+tuple((x,'hia_global_'+role)for role,holes in FIXED_HOLES.items()for x in holes)
assert all(BRIDGE[x:x+4]==bytes(4)for holes in HOLES.values()for x in holes)
assert all(BRIDGE[x:x+4]==bytes(4)for _,holes in FIXED_HOLES.items()for x in holes)
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in('hia_generation_runtime_global',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_generation_runtime_global'],18,0,1,0,len(OUTER))]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',at,((3+IMPORTS.index(name))<<32)|4,-4)for at,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in[
       ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
       ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
       ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def source_program():
    vals=dict(ROLES=ROLES,MAGIC=MAGIC,BRIDGE=BRIDGE,HOLES=HOLES,fixed_parts=fixed_parts)
    old={name:getattr(generic,name)for name in vals}
    try:
        for name,value in vals.items():setattr(generic,name,value)
        source=generic.source_program()
    finally:
        for name,value in old.items():setattr(generic,name,value)
    for a,b in[('length(s)<48','length(s)<40'),('uint(s,8,8)!=4','uint(s,8,8)!=3'),
                ('total=48','total=40'),('while count<4:','while count<3:'),('at=48','at=40'),
                ('while i<4:','while i<3:'),('if i!=3:','if i!=2:'),
                ('get(w,256)-64>16777216','get(w,256)-64>4194304')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(parts):
    if len(parts)!=3 or any(not x or len(x)>4194304 for x in parts):raise ValueError('three bounded actual HIA policies required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,part in zip(ROLES,parts):
        raw.extend(bytes((-len(raw))%16));at=len(raw)
        for off in HOLES[name]:struct.pack_into('<i',raw,64+off,at-64-off-4)
        raw.extend(part)
    size=len(raw)-64
    if size>4194304:raise ValueError('original parent role bound')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in[relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
    for i,at in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_runtime_global_capsule_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_global_capsule_packer.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
