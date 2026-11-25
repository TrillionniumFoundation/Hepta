"""Source-bound pure-HIA packaging for the complete fixed rank engine.

The 21 native inputs retain the per-flat 4 MiB and final 16 MiB text limits.
The mechanical parent and process bridges only execute HIA-selected effects.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fd000001000f82f90300004d85ed0f84f00300004c89e84801e80f82e403000048894424684c89e04c01f80f82d303000048894424604d85ff74194d85e40f84c00300004c3b64246873094c39e80f87b00300004d85f674434885db0f84a20300004c89f04801d80f829603000048894424704c3b74246873094c39e80f87810300004d85ff74564c3b742460734f4c3b6424700f826a030000eb424885db0f855f030000b80900000031ffbe00001000ba0300000041ba2200000049c7c0ffffffff4531c90f05483d01f0ffff0f83fe0200004989c6bb00001000eb0048c70424000000004c897424084c896424104c896c241849895d104d8975284d896d784c89e74c89fe4c89ea4889e94d89f04989d9e80000000083f80775174c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84c402000083f80374c083f8020f84d901000083f8050f842102000083f801740983f8040f857e02000048894424504d8b951001000031c9498b84cd180100004d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672dd488b7c2420488b742428488b5424304c8b4424404c8b4c244848837c24500175134c8b542438498b85080100000f05e954010000488b4c2438498b85080100004883f8010f84b90000004883f8020f84b60000004883f8030f84b30000004883f8040f84b00000004883f8050f84ad0000004883f8060f84aa0000004883f8070f84a70000004883f8080f84a40000004883f8090f84a10000004883f80a0f849e0000004883f80b0f849b0000004883f80c0f84980000004883f80d0f84950000004883f80e0f84920000004883f80f0f848f0000004883f8100f848c0000004883f8110f84890000004883f8130f84860000004883f8140f8483000000e94a010000e800000000eb7ee800000000eb77e800000000eb70e800000000eb69e800000000eb62e800000000eb5be800000000eb54e800000000eb4de800000000eb46e800000000eb3fe800000000eb38e800000000eb31e800000000eb2ae800000000eb23e800000000eb1ce818010000eb15e800000000eb0ee800000000eb07e800000000eb0049894508e9defdffff4c89f74889de498b9500010000488954245841ba010000004531c0b8190000000f05483d01f0ffff731a4989c6488b5c24584c8974240849895d104d897528e99afdffff49c7457001000000e98dfdffff498b85100100004889c183e00348c1e90283e103498bbd1801000048033cc4498bb520010000480334cc498b8d2801000049894d084839f7761c488d040e4839c77313488d7c0fff488d740efffdf3a4fce937fdfffffcf3a4e92ffdffff49c785a00f000003000000eb0b49c785a00f00000400000049c785a80f00000200000049c785b80f00000000000031c0eb05b8fdffffff4881c488000000415f415e415d415c5d5bc3535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fb000040010f82c30000004881fd800000000f82b600000049c706000000004d89761048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0747383f80374e083f801741683f802756f498b86b80000004885c0744f488b00eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549894608e972ffffff418b4508eb05b8fdffffff4881c488000000415f415e415d415c5d5bc3')
ROLES=("main","tasks","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","r13","r14","r15","r16","r17","r19","r20")
HOLES={'main': 313, 'tasks': 341, 'r1': 699, 'r2': 706, 'r3': 713, 'r4': 720, 'r5': 727, 'r6': 734, 'r7': 741, 'r8': 748, 'r9': 755, 'r10': 762, 'r11': 769, 'r12': 776, 'r13': 783, 'r14': 790, 'r15': 797, 'r17': 811, 'r19': 818, 'r20': 825, 'r16': 1202}
EXPORT_SIZE=1088
MAGIC=int.from_bytes(b'HIANEP02','little')
REQUEST_HEADER=24+8*len(ROLES)
def fixed_parts():
 strings=b'\0hia_ndu_rank_engine\0'
 symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)])
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
 rows=[bytes(64)]
 for name,kind,flags,size,link,info,align,extent in [
  ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,0,3,1,8,24),
  ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
  ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
  rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
 return header+BRIDGE,b'',symbols,strings,b''.join(rows)
def reference_object(flats):
 if len(flats)!=len(ROLES) or any(not x or len(x)>4194304 for x in flats):raise ValueError('twenty-one bounded actual HIA roles required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
 for role,flat in zip(ROLES,flats):
  raw.extend(bytes((-len(raw))%16));struct.pack_into('<i',raw,64+HOLES[role],len(raw)-64-HOLES[role]-4);raw.extend(flat)
 if len(raw)-64>16777216:raise ValueError('owned text exceeds preserved linker domain')
 textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));offsets=[]
 for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
 for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
 return bytes(raw)
def reference_flat(flats):
 obj=reference_object(flats);sh=struct.unpack_from('<Q',obj,40)[0];n=struct.unpack_from('<Q',obj,sh+96)[0];return obj[64:64+n]
def source_program():
 prefix,relas,symbols,strings,sections=fixed_parts()
 functions=[];calls={}
 for name,raw in [('prefix',prefix),('tail',relas+symbols+strings+base.SECTIONS),('sections',sections),('flat_bridge',BRIDGE)]:
  calls[name],src=base.emitters(name,raw);functions.append(src)
 source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<512:
        return 4294967294
    if length(s)<{REQUEST_HEADER} or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=21:
        return 4294967295
    if uint(s,184,8)>1:
        return 4294967295
    total={REQUEST_HEADER}
    i=0
    while i<21:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304:
            return 4294967295
        write(w,i*8,n,8)
        total=total+n
        i=i+1
    if total!=length(s):
        return 4294967295
    layout(w)
    if get(w,344)-64>16777216:
        return 4294967295
    if uint(s,184,8)==1:
        return pack_flat(s,o,w)
    n=get(w,400)
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for key,at in [('prefix','0'),('tail','get(w,352)'),('sections','get(w,392)')]:
  for fn in calls[key]:source+=f'    {fn}(o,{at})\n'
 source+='''    sections=get(w,392)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,344)-64,8)
    write(o,sections+152,get(w,352),8)
    write(o,sections+216,get(w,360),8)
    write(o,sections+280,get(w,368),8)
    write(o,sections+344,get(w,376),8)
    write(o,sections+408,get(w,384),8)
'''
 for i,role in enumerate(ROLES):source+=f'    write(o,{64+HOLES[role]},get(w,{176+8*i})-{64+HOLES[role]+4},4)\n'
 source+=f'''    at={REQUEST_HEADER}
    i=0
    while i<21:
        copy(s,o,at,get(w,176+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,400)

def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<21:
        write(w,176+i*8,at,8)
        at=at+get(w,i*8)
        if i!=20:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,344,at,8)
    at=(at+7)&18446744073709551608
    write(w,352,at,8)
    write(w,360,at,8)
    at=at+{len(symbols)}
    write(w,368,at,8)
    at=at+{len(strings)}
    write(w,376,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,384,at,8)
    at=(at+7)&18446744073709551608
    write(w,392,at,8)
    write(w,400,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value
'''
 source+='''
def pack_flat(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,344)-64
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for fn in calls['flat_bridge']:source+=f'    {fn}(o,0)\n'
 for i,role in enumerate(ROLES):source+=f'    write(o,{HOLES[role]},get(w,{176+8*i})-{64+HOLES[role]+4},4)\n'
 source+=f'''    at={REQUEST_HEADER}
    i=0
    while i<21:
        copy(s,o,at,get(w,176+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
 return source+'\n'+'\n'.join(functions)+base.HELPERS
def program():return document(source_program(),'ndu_rank_engine_packer')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/ndu_rank_engine_packer.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
