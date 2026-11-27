"""Fixed native public-constructor frontend capsule, with one external Value.

The three entrypoints capture all VFY dependency roles statically. The parent
resolves owner, Value and installed-global references to its unique bodies.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as generic
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIARTFP1','little')
ROLES=('bind','options','verify','vfy','transport','json','process','typed','freeze','raw','freezeraw')
BIND=bytes.fromhex("535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84ce0300004d85ed0f84c50300004d85f60f84bc03000049f7c6070000000f85af0300004981ff800000000f85a20300004881fd000010000f85950300004881fb000800000f85880300004c89e04c01f80f827c03000048898424800000004c89e84801e80f826803000048898424880000004c89f04801d80f825403000048898424900000004c3ba42488000000730e4c3bac24800000000f82340300004c3ba42490000000730e4c3bb424800000000f821c0300004c3bac2490000000730e4c3bb424880000000f820403000048b84849415254425131493904240f85f002000049837c2408010f87e4020000b91000000049833c0c000f85d402000083c10881f98000000072eab8270000000f054885c00f8eb902000049bb484941474c4f57314d391e0f85a6020000493946080f859c0200004d3976100f859202000049837e50010f8587020000488d0500000000493946180f85760200004889842498000000488d0500000000493946280f855d02000048898424a0000000498d8600020000493946300f854402000049817e38000100000f853602000049837c240800751b31c949837c0d00000f852002000083c10881f90001000072e9eb2848b84849415254464331493945000f85ff0100004d396d100f85f50100004d3975180f85eb01000048c70424000000004c897424084c896424104c896c241849c78500010000000000004d89b5000200004d89ad08020000488b84249800000049898510020000488b8424a000000049898518020000488d050000000049898520020000488d050000000049898528020000488d050000000049898530020000488d050000000049898538020000488d050000000049898540020000488d050000000049898548020000488d050000000049898550020000488d050000000049898558020000488d0500000000498985600200004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84fc00000083f8010f849400000083f802741483f803742383f80a742d83f80b7456e9de00000031c0b901000000f0410fb14e40f390e9ba00000049c746400000000031c0e9ab000000498dbd00800000be80000000498d9500000400b9004000004d8d860002000041b900010000e80000000089c0eb7d498dbd00800000be80000000498d9500000400b9004002004d89f041b900080000e80000000089c0eb534d8b950803000031c9498b84cd100300004d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672dd488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b85000300000f0549898508010000e9e5feffff31c0eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3")
OPTIONS=bytes.fromhex("535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd008000000f82cc0000004881fb002000000f85bf0000004d85e40f84b60000004d85ed0f84ad0000004d85f60f84a40000004c89e04c01f80f82980000004c89ea4801ea0f828c0000004c89f14801d90f82800000004939d473054939c572764939cc73054939c6726c4939cd73054939d6726249c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84f600000083f80a74dc83f801742183f8040f848e00000083f8080f849700000083f8097415b8fdffffffe9cb00000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb574c89d14d8b5d0041ffd389c0eb49498b45004839e80f8373ffffff4c01e8eb37498b45004883f8030f8760ffffff498b7508480334c4498b45104883f8030f874affffff498b7d1848033cc4498b4d20fcf3a431c0eb0049898500040000e9ebfeffff4881c488000000415f415e415d415c5d5bc3")
VERIFY=bytes.fromhex("535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000008000f82cc0000004881fb002000000f85bf0000004d85e40f84b60000004d85ed0f84ad0000004d85f60f84a40000004c89e04c01f80f82980000004c89ea4801ea0f828c0000004c89f14801d90f82800000004939d473054939c572764939cc73054939c6726c4939cd73054939d6726249c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84f600000083f80a74dc83f801742183f8040f848e00000083f8080f849700000083f8097415b8fdffffffe9cb00000048c744247800000000eb0948c7442478010000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c244848837c2478007508498b45000f05eb574c89d14d8b5d0041ffd389c0eb49498b45004839e80f8373ffffff4c01e8eb37498b45004883f8030f8760ffffff498b7508480334c4498b45104883f8030f874affffff498b7d1848033cc4498b4d20fcf3a431c0eb0049898500040000e9ebfeffff4881c488000000415f415e415d415c5d5bc3")
BIND_HOLES={"freeze_address_hole":692,"freezeraw_address_hole":720,"global_address_hole":608,"global_call_hole":911,"json_address_hole":650,"policy_hole":750,"process_address_hole":664,"raw_address_hole":706,"root_address_hole":374,"transport_address_hole":636,"typed_address_hole":678,"value_address_hole":399,"value_call_hole":869,"verify_address_hole":622}
raw=bytearray(BIND);raw.extend(bytes((-len(raw))%16));OPTIONS_AT=len(raw);raw.extend(OPTIONS)
raw.extend(bytes((-len(raw))%16));VERIFY_AT=len(raw);raw.extend(VERIFY)
raw.extend(bytes((-len(raw))%16));MALLOC_AT=len(raw);raw.extend(bytes.fromhex('4883ec08e8')+bytes(4)+bytes.fromhex('4883c408c3'));FREE_AT=len(raw);raw.extend(bytes.fromhex('4883ec08e8')+bytes(4)+bytes.fromhex('4883c408c3'))
BRIDGE=bytes(raw)
HOLES={name:[]for name in ROLES}
HOLES['bind']=[BIND_HOLES['policy_hole']]
HOLES['options']=[OPTIONS_AT+207]
HOLES['verify']=[VERIFY_AT+207]
for name,label in [('vfy','verify'),('transport','transport'),('json','json'),('process','process'),('typed','typed'),('freeze','freeze'),('raw','raw'),('freezeraw','freezeraw')]:
    HOLES[name]=[BIND_HOLES[label+'_address_hole']]
FIXED_HOLES=dict(owner=[BIND_HOLES['root_address_hole']],
 values=[BIND_HOLES['value_address_hole'],BIND_HOLES['value_call_hole']],
 global_owner=[BIND_HOLES['global_address_hole'],BIND_HOLES['global_call_hole']])
IMPORTS=('malloc','free','hia_frontend_owner','hia_frontend_values','hia_frontend_global_owner')
DYNAMIC_RELOCATIONS=((MALLOC_AT+5,'malloc'),(FREE_AT+5,'free'))
RELOCATIONS=DYNAMIC_RELOCATIONS+tuple((off,'hia_frontend_'+name)for name,holes in FIXED_HOLES.items()for off in holes)
LEAF_RELOCATIONS=(('transport',425,MALLOC_AT),('transport',436,FREE_AT),('freeze',425,MALLOC_AT),('freeze',436,FREE_AT))
EXPORTS=(('hia_generation_runtime_frontend_bind',0,len(BIND)),
 ('hia_generation_runtime_constructor_options',OPTIONS_AT,len(OPTIONS)),
 ('hia_generation_runtime_verify',VERIFY_AT,len(VERIFY)))
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in(*(x[0]for x in EXPORTS),*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
    symbols.extend(struct.pack('<IBBHQQ',positions[name],18,0,1,at,n)for name,at,n in EXPORTS)
    symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',at,((5+IMPORTS.index(name))<<32)|4,-4)for at,name in RELOCATIONS)
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
    for a,b in[('length(s)<48','length(s)<104'),('uint(s,8,8)!=4','uint(s,8,8)!=11'),
                ('total=48','total=104'),('while count<4:','while count<11:'),('at=48','at=104'),
                ('while i<4:','while i<11:'),('if i!=3:','if i!=10:'),
                ('get(w,256)-64>16777216','get(w,256)-64>4194304')]:
        assert a in source,a;source=source.replace(a,b)
    patch=''
    for name,off,stub in LEAF_RELOCATIONS:
        patch+=f'    write(o,get(w,{128+8*ROLES.index(name)})+{off},64+{stub}-get(w,{128+8*ROLES.index(name)})-{off+4},4)\n'
    assert source.count('    return get(w,320)\n')==1
    return source.replace('    return get(w,320)\n',patch+'    return get(w,320)\n')
def reference_object(parts):
    if len(parts)!=11 or any(not x or len(x)>4194304 for x in parts):raise ValueError('eleven actual bounded roles')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);positions={}
    for name,part in zip(ROLES,parts):
        raw.extend(bytes((-len(raw))%16));at=len(raw);positions[name]=at
        for off in HOLES[name]:struct.pack_into('<i',raw,64+off,at-64-off-4)
        raw.extend(part)
    for name,off,stub in LEAF_RELOCATIONS:
        at=positions[name]+off
        if raw[at:at+4]!=bytes(4):raise ValueError('exact unresolved leaf import required')
        struct.pack_into('<i',raw,at,64+stub-at-4)
    size=len(raw)-64
    if size>4194304:raise ValueError('original root role limit')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in[relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
    for i,at in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
    return bytes(raw)
def main():
    tree=document(source_program(),'generation_runtime_frontend_capsule_packer')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_capsule_packer.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
