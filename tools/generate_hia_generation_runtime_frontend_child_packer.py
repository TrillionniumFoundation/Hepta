"""Independent fixed Runtime frontend child, with the sole parent Value.
The installed parent supplies authenticated closed bindings. The request frames
contain no entry, context, path-authority or dependency table.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as generic
from tools import generate_hia_generation_runtime_verified_frontend_capsule_packer as old
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIARTCP1','little')
ROLES=old.ROLES+('directory','windows')
BIND=bytes.fromhex('535541544155415641574881eca80000004989fc4989f74989d54889cd4d89c64c89cb4d85e40f845c0400004d85ed0f84530400004d85f60f844a04000049f7c6070000000f853d0400004981ff800000000f85300400004881fd000010000f85230400004881fb000800000f85160400004c89e04c01f80f820a04000048898424800000004c89e84801e80f82f603000048898424880000004c89f04801d80f82e203000048898424900000004c3ba42488000000730e4c3bac24800000000f82c20300004c3ba42490000000730e4c3bb424800000000f82aa0300004c3bac2490000000730e4c3bb424880000000f829203000048b84849415254425131493904240f857e03000049837c2408010f8772030000b91000000049833c0c000f856203000083c10881f98000000072eab8270000000f054885c00f8e4703000049bb484941474c4f57314d391e0f8534030000493946080f852a0300004d3976100f852003000049837e50010f85150300004d8b96400400004d85d20f84050300004981be48040000000080000f85f40200004981c2000670000f82e702000048b84849415254414d314939020f85d40200004d3972100f85ca02000049837a30020f85bf02000049837a40000f85b402000049837a48000f84a9020000498b8698020000493982e80000000f85950200004c89542450498b8270010000493946180f857f0200004889842498000000498b8260010000493946280f856602000048898424a0000000498d8600020000493946300f854d02000049817e38000100000f853f02000049837c240800751b31c949837c0d00000f852902000083c10881f90001000072e9eb2848b84849415254464331493945000f85080200004d396d100f85fe0100004d3975180f85f401000048c70424000000004c897424084c896424104c896c241849c78500010000000000004d89b5000200004d89ad08020000488b84249800000049898510020000488b8424a000000049898518020000488b442450488b805001000049898520020000488d050000000049898528020000488d050000000049898530020000488d050000000049898538020000488d050000000049898540020000488d050000000049898548020000488d050000000049898550020000488d050000000049898558020000488d0500000000498985600200004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f840001000083f8010f849800000083f802741483f803742383f80a742d83f80b7458e9e200000031c0b901000000f0410fb14e40f390e9be00000049c746400000000031c0e9af000000498dbd00800000be80000000498d9500000400b9004000004d8d860002000041b90001000041ff951802000089c0eb7f498dbd00800000be80000000498d9500000400b9004002004d89f041b90008000041ff952002000089c0eb534d8b950803000031c9498b84cd100300004d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672dd488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b85000300000f0549898508010000e9e1feffff31c0eb05b8fdffffff4881c4a8000000415f415e415d415c5d5bc3')
BIND_HOLES={'freeze_address_hole': 830, 'freezeraw_address_hole': 858, 'json_address_hole': 788, 'policy_hole': 888, 'process_address_hole': 802, 'raw_address_hole': 844, 'transport_address_hole': 774, 'typed_address_hole': 816, 'verify_address_hole': 760}
DIRECTORY=bytes.fromhex('535541544155415641574883ec684c895c24604989fc4989f74989d54889cd4d89c64c89cb4981ff800000000f859a0300004881fd008000000f828d0300004881fb000008000f858003000048b84849415254445131493904240f856c030000498b4424084883f8010f875d0300004885c0750c49837c2418000f844c030000b9100000004885c0750a83f918720583f928760b49833c0c000f852d03000083c10881f98000000072db48c70424000000004c897424084c896424104c896c241849833e00744048b848494152544457314939060f85f20200004d39b6900000000f85e5020000488b442460493946300f85d6020000b8270000000f05493946080f85c502000049c78600010000000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f849702000083f80a74dc83f8010f843302000083f8020f847d01000083f8047405e97f0200004c8b5424604d85d20f846c020000498d8200feffff48ba484941474c4f57314839100f85520200004c3950300f854802000048817838000100000f853a02000048837850010f852f02000048ba4849414753435831483990700400000f85180200004883b878040000020f850a0200004883b8b8040000000f84fc010000488b90800400004885d20f84ec0100004881c200100000488b88400400004885c90f84d50100004881b848040000000080000f85c40100004881c1000670000f82b701000049bb4849415254414d314c39190f85a4010000483941100f859a01000048837930020f858f01000048837940000f858401000048837948000f84790100004c8b98980200004c3999e80000000f85650100004c8b99780100004d85db0f84550100004c895c24504c8b99800100004d85db0f84400100004c895c2458488b8960010000483948280f852a0100004d89b58000000049898d880000004d8995900000004989959800000031c0e9f7000000498bbe48010000498bb650010000498b9658010000498b8e600100004d8b86680100004d8b8e70010000418b864001000085c0741e83f801742f83f802743b83f803743c83f804745683f8057458e9b40000004889f84889d74889f14889c6fcf3a431c0e98e0000004c8b44246041b90001000041ff5628eb7dff542450eb77488b4424604c8b80800200004981c00010000041b900200300ff542458eb58e800000000eb51e800000000eb4a4d8b553831c9498b44cd084d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549898608010000e94afdffff31c0eb05b8fdffffff4883c468415f415e415d415c5d5bc3')
DIRECTORY_HOLES={'policy_hole': 293, 'pure_hole': 869, 'windows_hole': 876}

raw=bytearray(BIND);raw.extend(bytes((-len(raw))%16));OPTIONS_AT=len(raw);raw.extend(old.prior.OPTIONS)
raw.extend(bytes((-len(raw))%16));VERIFY_AT=len(raw);raw.extend(old.DISPATCH);VERIFY_BODY_AT=len(raw);raw.extend(old.prior.VERIFY)
raw.extend(bytes((-len(raw))%16));ERROR_AT=len(raw);raw.extend(old.error.BRIDGE)
struct.pack_into('<i',raw,VERIFY_AT+27,ERROR_AT-VERIFY_AT-31)
struct.pack_into('<i',raw,VERIFY_AT+32,VERIFY_BODY_AT-VERIFY_AT-36)
raw.extend(bytes((-len(raw))%16));DIRECTORY_AT=len(raw);raw.extend(DIRECTORY)
raw.extend(bytes((-len(raw))%16));DIRECTORY_POLICY_AT=len(raw);raw.extend(b'\xe9'+bytes(4))
raw.extend(bytes((-len(raw))%16));MALLOC_AT=len(raw);raw.extend(bytes.fromhex('4883ec08e8')+bytes(4)+bytes.fromhex('4883c408c3'))
FREE_AT=len(raw);raw.extend(bytes.fromhex('4883ec08e8')+bytes(4)+bytes.fromhex('4883c408c3'))
BRIDGE=bytes(raw)
HOLES={name:[]for name in ROLES}
HOLES['bind']=[BIND_HOLES['policy_hole']]
HOLES['options']=[OPTIONS_AT+207];HOLES['verify']=[VERIFY_BODY_AT+207];HOLES['exception']=[ERROR_AT+207]
for name,label in [('vfy','verify'),('transport','transport'),('json','json'),('process','process'),('typed','typed'),('freeze','freeze'),('raw','raw'),('freezeraw','freezeraw')]:
 HOLES[name]=[BIND_HOLES[label+'_address_hole']]
HOLES['directory']=[DIRECTORY_AT+DIRECTORY_HOLES['policy_hole'],DIRECTORY_AT+DIRECTORY_HOLES['pure_hole'],DIRECTORY_POLICY_AT+1]
HOLES['windows']=[DIRECTORY_AT+DIRECTORY_HOLES['windows_hole']]
IMPORTS=('malloc','free')
RELOCATIONS=((MALLOC_AT+5,'malloc'),(FREE_AT+5,'free'))
LEAF_RELOCATIONS=(('transport',425,MALLOC_AT),('transport',436,FREE_AT),('freeze',425,MALLOC_AT),('freeze',436,FREE_AT))
EXPORTS=(('hia_generation_runtime_frontend_child_bind',0,len(BIND)),
 ('hia_generation_runtime_frontend_child_options',OPTIONS_AT,len(old.prior.OPTIONS)),
 ('hia_generation_runtime_frontend_child_verify',VERIFY_AT,len(old.DISPATCH)+len(old.prior.VERIFY)),
 ('hia_generation_runtime_frontend_child_directory',DIRECTORY_AT,len(DIRECTORY)),
 ('hia_generation_runtime_frontend_child_directory_policy',DIRECTORY_POLICY_AT,5))
assert len(ROLES)==14 and len(set(ROLES))==14
assert all(BRIDGE[h:h+4]==bytes(4)for hs in HOLES.values()for h in hs)
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
 for a,b in [('length(s)<48','length(s)<128'),('uint(s,8,8)!=4','uint(s,8,8)!=14'),
             ('total=48','total=128'),('while count<4:','while count<14:'),('at=48','at=128'),
             ('while i<4:','while i<14:'),('if i!=3:','if i!=13:'),
             ('get(w,256)-64>16777216','get(w,256)-64>4194304')]:
  assert a in source,a;source=source.replace(a,b)
 patch=''
 for name,off,stub in LEAF_RELOCATIONS:
  patch+=f'    write(o,get(w,{128+8*ROLES.index(name)})+{off},64+{stub}-get(w,{128+8*ROLES.index(name)})-{off+4},4)\n'
 assert source.count('    return get(w,320)\n')==1
 return source.replace('    return get(w,320)\n',patch+'    return get(w,320)\n')
def reference_object(parts):
 if len(parts)!=14 or any(not b or len(b)>4194304 for b in parts):raise ValueError('fourteen actual bounded policies required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);positions={}
 for name,part in zip(ROLES,parts):
  raw.extend(bytes((-len(raw))%16));at=len(raw);positions[name]=at
  for off in HOLES[name]:struct.pack_into('<i',raw,64+off,at-64-off-4)
  raw.extend(part)
 for name,off,stub in LEAF_RELOCATIONS:
  at=positions[name]+off
  if raw[at:at+4]!=bytes(4):raise ValueError('actual unresolved fixed leaf import required')
  struct.pack_into('<i',raw,at,64+stub-at-4)
 size=len(raw)-64
 if size>4194304:raise ValueError('original bounded component limit')
 raw.extend(bytes((-len(raw))%8));offsets=[]
 for data in[relas,symbols,strings,common.SECTIONS]:offsets.append(len(raw));raw.extend(data)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,size)
 for i,at in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
 return bytes(raw)
def main():
 t=document(source_program(),'generation_runtime_frontend_child_packer')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_frontend_child_packer.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
