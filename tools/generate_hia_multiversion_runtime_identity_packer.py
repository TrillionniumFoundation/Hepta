"""Native fixed packing of the runtime identity/number/value composition."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_build_packer as base
from tools import generate_hia_multiversion_runtime_numbers_packer as numbers
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd00100000727d4881fb00800000727449c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f844601000083f80a74dc83f801743383f802747d83f8030f849600000083f8080f84aa00000083f80b0f84fa00000083f80c0f84fd000000b8fdffffffe9090100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9ae00000049817d0048750000759d498d9648750000418b4508418b4d10f00fb10ae98c00000049817d00487500000f8577ffffff498d9648750000418b45088702eb6f498b45004883f8030f875affffff498b7508480334c4498b45104883f8030f8744ffffff498b7d1848033cc4498b4d20fcf3a431c0eb38498b7d004c01ef498b7508498b55104c01ea498b4d184d8b45204d01f04d8b4d28c3e8d9ffffffe800000000eb0ae8cdffffffe80000000049898588000000e99bfeffff4881c488000000415f415e415d415c5d5bc3')
OUTER_HOLES={'policy': 106, 'numbers': 416, 'values': 428}
ROLES=('identity','numbers','values_owner','unsigned')
IMPORTS=('malloc','free')
MAGIC=int.from_bytes(b'HIAMVIP1','little')
EXPORT_SIZE=len(OUTER)
def bridges():
 raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(numbers.BRIDGE)
 struct.pack_into('<i',raw,OUTER_HOLES['numbers'],at-OUTER_HOLES['numbers']-4)
 inner=numbers.OUTER_HOLES['values'];target=at+inner+4+struct.unpack_from('<i',numbers.BRIDGE,inner)[0]
 struct.pack_into('<i',raw,OUTER_HOLES['values'],target-OUTER_HOLES['values']-4)
 holes={'identity':[OUTER_HOLES['policy']]}
 for name,positions in numbers.HOLES.items():holes[name]=[at+x for x in positions]
 return bytes(raw),holes,tuple((at+x,name) for x,name in numbers.RELOCATIONS)
BRIDGE,HOLES,RELOCATIONS=bridges()
def fixed_parts():
 strings=bytearray(b'\0');positions={}
 for name in ('hia_mv_runtime_identity',*IMPORTS):positions[name]=len(strings);strings.extend(name.encode()+b'\0')
 symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_mv_runtime_identity'],18,0,1,0,EXPORT_SIZE)]
 for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
 symbols=b''.join(symbols);relas=b''.join(struct.pack('<QQq',at,((3+IMPORTS.index(name))<<32)|4,-4) for at,name in RELOCATIONS)
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
 rows=[bytes(64)]
 for name,kind,flags,size,link,info,align,extent in [('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
  rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
 return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def source_program():
 changes={'BRIDGE':BRIDGE,'HOLES':HOLES,'ROLES':ROLES,'MAGIC':MAGIC,'fixed_parts':fixed_parts}
 old={k:getattr(base,k) for k in changes}
 try:
  for k,v in changes.items():setattr(base,k,v)
  return base.source_program()
 finally:
  for k,v in old.items():setattr(base,k,v)
def reference_object(flats):
 if len(flats)!=4 or any(not x or len(x)>4194304 for x in flats):raise ValueError('four bounded actual roles required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
 for name,part in zip(ROLES,flats):
  raw.extend(bytes((-len(raw))%16))
  for h in HOLES[name]:struct.pack_into('<i',raw,64+h,len(raw)-64-h-4)
  raw.extend(part)
 textsize=len(raw)-64
 if textsize>16777216:raise ValueError('original sixteen MiB text domain')
 raw.extend(bytes((-len(raw))%8));offsets=[]
 for part in (relas,symbols,strings,common.SECTIONS):offsets.append(len(raw));raw.extend(part)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
 for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
 return bytes(raw)
def main():
 tree=document(source_program(),'multiversion_runtime_identity_packer');p=ROOT/'examples/hia_bootstrap/multiversion_runtime_identity_packer.hepta';p.write_text(render_assembly(tree));print(p.name,p.stat().st_size,len(tree['functions']),flush=True)
if __name__=='__main__':main()
