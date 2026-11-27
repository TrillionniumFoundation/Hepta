"""Native installed frontend control and session proxies.
All policy, mapping, stable-reader and SHA dependencies are fixed links to the
same root bodies; only this child's reviewed catalog and two HIA policies are
included. No second Value or root global registry is packaged.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as generic
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIARTIP1','little')
ROLES=('install','proxy','catalog')
OUTER=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84320300004d85ed0f84290300004d85f60f842003000049f7c6070000000f85130300004981ff800000000f85060300004881fd000030000f82f90200004881fb000800000f85ec0200004c89e04c01f80f82e002000048898424800000004c89e84801e80f82cc02000048898424880000004c89f04801d80f82b802000048898424900000004c3ba42488000000730e4c3bac24800000000f82980200004c3ba42490000000730e4c3bb424800000000f82800200004c3bac2490000000730e4c3bb424880000000f826802000048c70424000000004c897424084c896424104c896c241849c78580002000000000004d89b500022000488d05dafeffff49898508022000488d050000000049898510022000488d050000000049898518022000488d050000000049898520022000488d050000000049898528022000488d050000000049898530022000488d050000000049898538022000488d0500000000498985400220004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84a701000083f8010f843f01000083f802742a83f803743983f807744383f8040f84be00000083f80a0f84bc00000083f80b0f84e0000000e97801000031c0b901000000f0410fb14e40f390e94f01000049c746400000000031c0e940010000498b8d200020004885c97471498b95000020004883fa030f8738010000498bb508002000480334d40f82270100004885f60f841e0100004889f04801c80f8212010000498b95100020004883fa030f8701010000498bbd1800200048033cd40f82f00000004885ff0f84e70000004889f84801c80f82db000000fcf3a431c0e9bc00000031c0e9b5000000498dbd00102000be80000000498d9500402000b9004002004d89f041b900080000e80000000089c0e988000000498dbd00102000be80000000498d9500402000b9000002004d8b85200420004981c00010000041b900009001e80000000089c0eb534d8b950800200031c9498b84cd100020004d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672dd488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b85000020000f0549898588002000e93afeffff418b85d8002000eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
OUTER_HOLES={'absolute_address_hole': 360, 'global_address_hole': 332, 'global_call_hole': 694, 'loader_address_hole': 346, 'loader_call_hole': 750, 'policy_hole': 418, 'root_address_hole': 304, 'sidecar_address_hole': 374, 'tempdir_address_hole': 388, 'value_address_hole': 318}
PROXY=bytes.fromhex('b800000000eb49660f1f840000000000b801000000eb39660f1f840000000000b802000000eb29660f1f840000000000b803000000eb19660f1f840000000000b804000000eb09660f1f840000000000535541544155415641574881ecd820000048894424584c895c24604989fc4989f74989d54889cd4d89c64c89cb4d85e40f84270300004d85ed0f841e0300004d85f60f84150300004c89e04c01f80f82090300004c89e84801e80f82fd0200004c89f04801d80f82f1020000488b44245885c0747583f801742283f8027444488b5424604881fa000200000f82cc0200004881ea0002000031c9eb614881fb002000000f85b40200004981fe001000000f82a7020000498d8e00f0ffff488b5118eb3a4881fb002000000f858d0200004981fe004000000f8280020000498d8e00c0ffff488b5118eb134881fb000800000f85660200004c89f24c89e94885d20f845702000048f7c2070000000f854a020000488954245048894c2468488dbc24c000000031c0b900040000fcf348ab4c8d9424c0000000488b442458498982000200004d89a2080200004d89ba100200004d89aa180200004989aa200200004d89b22802000049899a30020000488b44245049898238020000488b44246849898240020000488d050000000049898248020000488d050000000049898250020000488d05000000004989825802000048c7042400000000488b44245048894424084c896424104c895424184c89e74c89fe488d9424c0000000b9002000004c8b44245041b900080000e80000000085c00f845d01000083f8010f84f700000083f802741d83f803743083f804743f83f807744183f80a0f84b1000000e93b010000488b54245031c0b901000000f00fb14a40f390e90d010000488b54245048c742400000000031c0e9f900000031c0e9f20000004c8d9424c0000000498b4a204885c97464498b124883fa030f87ea000000498b7208480334d40f82dc0000004885f60f84d30000004889f04801c80f82c7000000498b52104883fa030f87b9000000498b7a1848033cd40f82ab0000004885ff0f84a20000004889f84801c80f8296000000fcf3a431c0eb794c89e74c89fe4c89ea4889e94d89f04989d94c8b5c24504981c300020000ff94243803000089c0eb504c8d9c24c00000004d8b530831c9498b44cb104c89d283e203480304d4488944cc2049c1ea02ffc183f90672e1498b03488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c24480f054889842448010000e978feffff8b842430030000eb05b8fdffffff4881c4d8200000415f415e415d415c5d5bc3')
PROXY_HOLES={'install_address_hole': 501, 'policy_hole': 571, 'root_address_hole': 473, 'value_address_hole': 487}
LOADER=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f84670400004d85ed0f845e0400004d85f60f845504000049f7c6070000000f85480400004981ff800000000f853b0400004881fd000002000f822e0400004881fb000090010f85210400004c89e04c01f80f821504000048898424800000004c89e84801e80f820104000048898424880000004c89f04801d80f82ed03000048898424900000004c3ba42488000000730e4c3bac24800000000f82cd0300004c3ba42490000000730e4c3bb424800000000f82b50300004c3bac2490000000730e4c3bb424880000000f829d03000048b84849414e4c435131493904240f85890300004d8b5424084983fa040f877a03000031c9b91000000083f91075054d85d2741b4983fa03750a83f918720583f928760b49833c0c000f854e03000083c10881f98000000072d04d85d2750c49837c2410000f8432030000b8270000000f054885c00f8e2203000048898424a000000049833e00743a49bb4849414e4c4357314d391e0f85010300004d3976080f85f7020000493946100f85ed020000488d0553feffff493946180f85dc020000eb0c49837c2408000f85ce02000048c70424000000004c897424084c896424104c896c241849c78580000000000000004d89b500020000488d050bfeffff498985080200004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f847402000083f8010f841502000083f802745383f803746283f805746c83f8060f849500000083f8070f84a100000083f8080f840d01000083f8090f841a01000083f80a0f823302000083f80d0f862d01000083f80e0f841401000083f80f7485e91702000031c0b901000000f0410fb14e28f390e9f301000049c746280000000031c0e9e401000031ff488d3502020000e8000000004885c00f84cd0100004989c3488d3d40fdffff498db6800c000041ffd389c0e9b2010000498b45004885c00f84b50100000fb600e99d010000498b4d204885c97465498b55004883fa030f8796010000498b7508480334d40f82880100004885f60f847f0100004889f04801c80f8273010000498b55104883fa030f8765010000498b7d1848033cd40f82570100004885ff0f844e0100004889f84801c80f8242010000fcf3a431c0e928010000498dbe00200000be02000000e800000000e912010000498b7e48498db600400000e800000000e9fd000000498b7e48e80000000089c0e9ed00000089842498000000498b7d00498b75084889f84801f00f82e20000004839d80f87d90000004c01f7498b5510498b4d184889d04801c80f82c20000004839d80f87b90000004c01f24d8b45204d8b4d284c89c04c01c80f82a20000004839d80f87990000004d01f083bc24980000000a741b83bc24980000000b741883bc24980000000c7415e800000000eb13e800000000eb0ce800000000eb05e80000000089c0eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549898588000000e96dfdffff31c0eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3646c6164647200')
LOADER_HOLES={'policy': 527, 'mapping': 1052, 'catalog': 1059, 'stable': 1066, 'sha': 1073}
LOADER_RELOCATIONS=((681, 'dlsym'), (872, 'dlopen'), (893, 'dlsym'), (907, 'dlclose'))

raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));LOADER_AT=len(raw);raw.extend(LOADER)
raw.extend(bytes((-len(raw))%16));PROXY_AT=len(raw);raw.extend(PROXY)
for name in ('loader_address_hole','loader_call_hole'):
 off=OUTER_HOLES[name];struct.pack_into('<i',raw,off,LOADER_AT-off-4)
off=PROXY_AT+PROXY_HOLES['install_address_hole'];struct.pack_into('<i',raw,off,-off-4)
BRIDGE=bytes(raw)
DIRECTORY_AT=PROXY_AT+48
DIRECTORY_POLICY_AT=PROXY_AT+64
HOLES=dict(install=[OUTER_HOLES['policy_hole']],proxy=[PROXY_AT+PROXY_HOLES['policy_hole']],catalog=[LOADER_AT+LOADER_HOLES['catalog']])
FIXED_HOLES=dict(owner=[OUTER_HOLES['root_address_hole'],PROXY_AT+PROXY_HOLES['root_address_hole']],
 values=[OUTER_HOLES['value_address_hole'],PROXY_AT+PROXY_HOLES['value_address_hole']],
 global_owner=[OUTER_HOLES['global_address_hole'],OUTER_HOLES['global_call_hole']],
 sidecar_entry=[OUTER_HOLES['sidecar_address_hole']],
 absolute=[OUTER_HOLES['absolute_address_hole']],tempdir=[OUTER_HOLES['tempdir_address_hole']],
 loader_policy=[LOADER_AT+LOADER_HOLES['policy']],stable=[LOADER_AT+LOADER_HOLES['stable']],
 sha=[LOADER_AT+LOADER_HOLES['sha']],mapping=[LOADER_AT+LOADER_HOLES['mapping']])
DYNAMIC_RELOCATIONS=tuple((LOADER_AT+off,name)for off,name in LOADER_RELOCATIONS)
IMPORTS=('dlopen','dlsym','dlclose',*('hia_frontend_'+name for name in FIXED_HOLES))
RELOCATIONS=DYNAMIC_RELOCATIONS+tuple((off,'hia_frontend_'+name)for name,hs in FIXED_HOLES.items()for off in hs)
EXPORTS=(('hia_generation_runtime_frontend_bind',PROXY_AT,16),
 ('hia_generation_runtime_constructor_options',PROXY_AT+16,16),
 ('hia_generation_runtime_verify',PROXY_AT+32,16),
 ('hia_generation_runtime_frontend_install',0,len(OUTER)))
assert all(BRIDGE[h:h+4]==bytes(4)for hs in HOLES.values()for h in hs)
assert all(BRIDGE[h:h+4]==bytes(4)for hs in FIXED_HOLES.values()for h in hs)
def fixed_parts():
 strings=bytearray(b'\0');positions={}
 for name in(*(x[0]for x in EXPORTS),*IMPORTS):
  positions[name]=len(strings);strings.extend(name.encode()+b'\0')
 symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0)]
 symbols.extend(struct.pack('<IBBHQQ',positions[name],18,0,1,at,n)for name,at,n in EXPORTS)
 symbols.extend(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0)for name in IMPORTS)
 symbols=b''.join(symbols)
 relas=b''.join(struct.pack('<QQq',at,((2+len(EXPORTS)+IMPORTS.index(name))<<32)|4,-4)for at,name in RELOCATIONS)
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
 sections=[bytes(64)]
 for name,kind,flags,size,link,info,align,extent in[
   ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
   ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
   ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
  sections.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
 return header+BRIDGE,relas,symbols,bytes(strings),b''.join(sections)
def source_program():
 vals=dict(ROLES=ROLES,MAGIC=MAGIC,BRIDGE=BRIDGE,HOLES=HOLES,fixed_parts=fixed_parts)
 saved={k:getattr(generic,k)for k in vals}
 try:
  for k,v in vals.items():setattr(generic,k,v)
  source=generic.source_program()
 finally:
  for k,v in saved.items():setattr(generic,k,v)
 for a,b in [('length(s)<48','length(s)<40'),('uint(s,8,8)!=4','uint(s,8,8)!=3'),
             ('total=48','total=40'),('while count<4:','while count<3:'),('at=48','at=40'),
             ('while i<4:','while i<3:'),('if i!=3:','if i!=2:'),
             ('get(w,256)-64>16777216','get(w,256)-64>4194304')]:
  assert a in source,a;source=source.replace(a,b)
 return source
def reference_object(parts):
 if len(parts)!=3 or any(not b or len(b)>4194304 for b in parts):raise ValueError('three actual bounded policies required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
 for name,part in zip(ROLES,parts):
  raw.extend(bytes((-len(raw))%16));at=len(raw)
  for off in HOLES[name]:struct.pack_into('<i',raw,64+off,at-64-off-4)
  raw.extend(part)
 size=len(raw)-64
 if size>4194304:raise ValueError('original bounded component limit')
 raw.extend(bytes((-len(raw))%8));offsets=[]
 for data in[relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(data)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
 for i,at in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
 return bytes(raw)
def main():
 t=document(source_program(),'generation_runtime_frontend_install_packer')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_install_packer.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
