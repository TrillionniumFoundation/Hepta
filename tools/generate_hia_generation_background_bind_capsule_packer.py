"""Native installed BackgroundOptimizer binder with fixed loader imports.

This capsule contains only the binder policy and reviewed child catalog.
The sole root supplies its existing Value, loader policy, stable reader,
SHA and mapping bodies. Public requests cannot choose these entries.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as generic
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAGBCP1','little')
ROLES=('bind','catalog')
OUTER=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84080400004d85ed0f84ff0300004d85f60f84f603000049f7c6070000000f85e90300004981ff80000000740d4981ffc00000000f85d30300004881fd000030000f82c60300004881fb000800000f85b90300004c89e04c01f80f82ad03000048898424800000004c89e84801e80f829903000048898424880000004c89f04801d80f828503000048898424900000004c3ba42488000000730e4c3bac24800000000f82650300004c3ba42490000000730e4c3bb424800000000f824d0300004c3bac2490000000730e4c3bb424880000000f823503000048c70424000000004c897424084c896424104c896c241849c78580002000000000004d89b500022000488d05d1feffff49898508022000488d050000000049898510022000488d050000000049898518022000488d050000000049898520022000488d050000000049898528022000488d050000000049898530022000488d0500000000498985380220004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f848202000083f8010f841a02000083f802744e83f803745d83f807746783f8040f84e200000083f80a0f84e000000083f80b0f840401000083f80c0f843301000083f80d0f845b01000083f80e0f848701000083f80f0f84a4010000e92f02000031c0b901000000f0410fb14e40f390e90602000049c746400000000031c0e9f7010000498b8d200020004885c97471498b95000020004883fa030f87ef010000498bb508002000480334d40f82de0100004885f60f84d50100004889f04801c80f82c9010000498b95100020004883fa030f87b8010000498bbd1800200048033cd40f82a70100004885ff0f849e0100004889f84801c80f8292010000fcf3a431c0e97301000031c0e96c010000498dbd00102000be80000000498d9500402000b9004002004d89f041b900080000e80000000089c0e93f010000498dbd00102000be80000000498d9500402000b9000002004d8b85200420004981c00010000041b900009001e80000000089c0e907010000498dbd00102000be80000000498d9500402000b9002000004d8d860002000041b900010000e80000000089c0e9d6000000498dbd00102000498bb500002000498d9500402000b9004000004d8b852004200041b90002000041ff95c004200089c0e9a10000004c89e74c89fe4c89eab9000020004d8b852004200041b90002000041ff95b804200089c0eb7b4c89e7be800000004c89eab9000010004d8b852004200041b90002000041ff95c804200089c0eb534d8b950800200031c9498b84cd100020004d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672dd488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b85000020000f0549898588002000e95ffdffff418b85d8002000eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
OUTER_HOLES={'finalizer_address': 369, 'global_address': 341, 'global_call': 725, 'loader_address': 355, 'loader_call': 781, 'policy': 413, 'root_address': 313, 'sidecar_address': 383, 'value_address': 327, 'value_call': 830}
LOADER=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84670400004d85ed0f845e0400004d85f60f845504000049f7c6070000000f85480400004981ff800000000f853b0400004881fd000002000f822e0400004881fb000090010f85210400004c89e04c01f80f821504000048898424800000004c89e84801e80f820104000048898424880000004c89f04801d80f82ed03000048898424900000004c3ba42488000000730e4c3bac24800000000f82cd0300004c3ba42490000000730e4c3bb424800000000f82b50300004c3bac2490000000730e4c3bb424880000000f829d03000048b84849414e4c435131493904240f85890300004d8b5424084983fa040f877a03000031c9b91000000083f91075054d85d2741b4983fa03750a83f918720583f928760b49833c0c000f854e03000083c10881f98000000072d04d85d2750c49837c2410000f8432030000b8270000000f054885c00f8e2203000048898424a000000049833e00743a49bb4849414e4c4357314d391e0f85010300004d3976080f85f7020000493946100f85ed020000488d0553feffff493946180f85dc020000eb0c49837c2408000f85ce02000048c70424000000004c897424084c896424104c896c241849c78580000000000000004d89b500020000488d050bfeffff498985080200004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f847402000083f8010f841502000083f802745383f803746283f805746c83f8060f849500000083f8070f84a100000083f8080f840d01000083f8090f841a01000083f80a0f823302000083f80d0f862d01000083f80e0f841401000083f80f7485e91702000031c0b901000000f0410fb14e28f390e9f301000049c746280000000031c0e9e401000031ff488d3502020000e8000000004885c00f84cd0100004989c3488d3d40fdffff498db6800c000041ffd389c0e9b2010000498b45004885c00f84b50100000fb600e99d010000498b4d204885c97465498b55004883fa030f8796010000498b7508480334d40f82880100004885f60f847f0100004889f04801c80f8273010000498b55104883fa030f8765010000498b7d1848033cd40f82570100004885ff0f844e0100004889f84801c80f8242010000fcf3a431c0e928010000498dbe00200000be02000000e800000000e912010000498b7e48498db600400000e800000000e9fd000000498b7e48e80000000089c0e9ed00000089842498000000498b7d00498b75084889f84801f00f82e20000004839d80f87d90000004c01f7498b5510498b4d184889d04801c80f82c20000004839d80f87b90000004c01f24d8b45204d8b4d284c89c04c01c80f82a20000004839d80f87990000004d01f083bc24980000000a741b83bc24980000000b741883bc24980000000c7415e800000000eb13e800000000eb0ce800000000eb05e80000000089c0eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549898588000000e96dfdffff31c0eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3646c6164647200')
LOADER_HOLES={'policy': 527, 'mapping': 1052, 'catalog': 1059, 'stable': 1066, 'sha': 1073}
LOADER_RELOCATIONS=((681, 'dlsym'), (872, 'dlopen'), (893, 'dlsym'), (907, 'dlclose'))
raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));LOADER_AT=len(raw);raw.extend(LOADER)
for name in ('loader_address','loader_call'):
    off=OUTER_HOLES[name];struct.pack_into('<i',raw,off,LOADER_AT-off-4)
BRIDGE=bytes(raw)
HOLES=dict(bind=[OUTER_HOLES['policy']],catalog=[LOADER_AT+LOADER_HOLES['catalog']])
FIXED_HOLES=dict(
 owner=[OUTER_HOLES['root_address']],
 sidecar_entry=[OUTER_HOLES['sidecar_address']],
 values=[OUTER_HOLES['value_address'],OUTER_HOLES['value_call']],
 global_entry=[OUTER_HOLES['global_address'],OUTER_HOLES['global_call']],
 finalizer=[OUTER_HOLES['finalizer_address']],
 loader_policy=[LOADER_AT+LOADER_HOLES['policy']],
 stable=[LOADER_AT+LOADER_HOLES['stable']],
 sha=[LOADER_AT+LOADER_HOLES['sha']],
 mapping=[LOADER_AT+LOADER_HOLES['mapping']])
DYNAMIC_RELOCATIONS=tuple((LOADER_AT+x,name)for x,name in LOADER_RELOCATIONS)
IMPORTS=('dlopen','dlsym','dlclose',*('hia_bg_'+name for name in FIXED_HOLES))
RELOCATIONS=DYNAMIC_RELOCATIONS+tuple((x,'hia_bg_'+name)for name,holes in FIXED_HOLES.items()for x in holes)
assert all(BRIDGE[x:x+4]==bytes(4)for holes in HOLES.values()for x in holes)
assert all(BRIDGE[x:x+4]==bytes(4)for holes in FIXED_HOLES.values()for x in holes)
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_generation_background_bind',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),
             struct.pack('<IBBHQQ',positions['hia_generation_background_bind'],18,0,1,0,len(OUTER))]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',at,((3+IMPORTS.index(name))<<32)|4,-4)for at,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
       ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
       ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
       ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def source_program():
    vals=dict(ROLES=ROLES,MAGIC=MAGIC,BRIDGE=BRIDGE,HOLES=HOLES,fixed_parts=fixed_parts)
    saved={k:getattr(generic,k)for k in vals}
    try:
        for k,v in vals.items():setattr(generic,k,v)
        source=generic.source_program()
    finally:
        for k,v in saved.items():setattr(generic,k,v)
    for a,b in [('length(s)<48','length(s)<32'),('uint(s,8,8)!=4','uint(s,8,8)!=2'),
                ('total=48','total=32'),('while count<4:','while count<2:'),('at=48','at=32'),
                ('while i<4:','while i<2:'),('if i!=3:','if i!=1:'),
                ('get(w,256)-64>16777216','get(w,256)-64>4194304')]:
        assert a in source,a;source=source.replace(a,b)
    return source
def reference_object(parts):
    if len(parts)!=2 or any(not p or len(p)>4194304 for p in parts):raise ValueError('two actual bounded HIA policies required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,part in zip(ROLES,parts):
        raw.extend(bytes((-len(raw))%16));at=len(raw)
        for off in HOLES[name]:struct.pack_into('<i',raw,64+off,at-64-off-4)
        raw.extend(part)
    size=len(raw)-64
    if size>4194304:raise ValueError('original parent role bound')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
    for i,at in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_background_bind_capsule_packer')
    p=ROOT/'examples/hia_bootstrap/generation_background_bind_capsule_packer.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
