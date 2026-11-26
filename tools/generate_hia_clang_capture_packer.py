"""Five fixed HIA policies for native Linux compiler capture.

The development reference builds only ELF relocation records. Production consumes
the five compiled HIA bodies through HIACCPK1 and the native runtime linker.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('555341544155415641574881ecc80000004989fc4989f54989d64989cf4c89c34c89cd4d85e40f84c20300004d85f60f84b90300004885db0f84b003000048f7c3070000000f85a30300004981fd800000000f82960300004981ff000100000f82890300004881fd001000000f827c0300004c89e04c01e80f827003000048894424504c89f04c01f80f825f03000048894424404889d84801e80f824e03000048894424484c3b642440730b4c3b7424500f82370300004c3b642448730b483b5c24500f82250300004c3b742448730b483b5c24400f821303000048b84849414341503031493904240f85ff020000498b4424084885c00f84800000004883f8010f85e70200004981fd800000000f85da02000048b84849414341573031483983680200000f85c302000048399b600100000f85b60200004839ab800100000f85a9020000b91000000049833c0c000f859902000083c10881f98000000072eab8270000000f05483b83b00200000f857a02000048c703bc020000eb1b4883bb68020000000f85630200004889dfb90010000031c0fcf3aa4c89a3680100004c89b37001000048899b780100004889ab800100004c89e74c89ee4c89f24c89f94989d84989e9e80000000085c00f842002000083f8010f844601000083f8050f84c301000083f8060f84d901000083f80a74c183f80b742683f80c743a83f80d0f84a500000083f80e743a83f80f746e83f8100f84ed000000e9d00100004c89e74c89ee4c89f24c89f94989d84989e9e800000000eb944c89e74c89ee4c89f24c89f9eb56488bbb20010000488bb328010000488b9338010000488b8b400100004885ff0f84840100004885d20f847b0100004839ce0f8372010000eb1d4c89e74c89ee488b9338010000488b8b400100004885d20f84530100004989d84989e9e800000000e920ffffff488b83f00100004883f8010f8732010000488d044048c1e003488bbc0390010000488bb40398010000488b9403c0010000488b8c03d00100004885ff0f84010100004885d20f84f80000004989d84989e9e800000000e9c5feffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e9a9feffff31c94d8b5638498b44ce084c89d283e20349c1ea0285d2743283fa01750e4c39e80f83a50000004c01e0eb1f83fa02750e4c39f80f83920000004c01f0eb0c4839e80f83840000004801d8488904ccffc183f90672b04d85d27571498b06488b3c24488b742408488b5424104c8b5424184c8b4424204c8b4c24280f0548894308e90cfeffff31ff488d3554000000e8000000004885c07433488b0048894308e9edfdffff498b064885c0741f49837e0801740c49837e08087511488b00eb030fb60048894308e9c6fdffffb8fdffffff4881c4c8000000415f415e415d415c5b5dc3656e7669726f6e00')
ROLES=('owner','admit','child','streams','storage')
FIXUPS=(('owner', 455), ('admit', 561), ('child', 674), ('streams', 765), ('storage', 793))
DLSYM_AT=946
EXPORT_SIZE=1037
MAGIC=int.from_bytes(b'HIACCPK1','little')
def fixed_parts():
 strings=b'\0hia_clang_capture\0dlsym\0'
 symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE),struct.pack('<IBBHQQ',strings.index(b'dlsym'),16,0,0,0,0)])
 relas=struct.pack('<QQq',DLSYM_AT,(3<<32)|4,-4)
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
 rows=[bytes(64)]
 for name,kind,flags,size,link,info,align,extent in [
  ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
  ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
  ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
  rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
 return header+BRIDGE,relas,symbols,strings,b''.join(rows)
def reference_object(flats):
 if len(flats)!=5 or any(not x or len(x)>4194304 for x in flats):raise ValueError('five actual bounded HIA policies required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);by_role={}
 for role,flat in zip(ROLES,flats):
  raw.extend(bytes((-len(raw))%16));by_role[role]=len(raw);raw.extend(flat)
 for role,hole in FIXUPS:struct.pack_into('<i',raw,64+hole,by_role[role]-64-hole-4)
 if len(raw)-64>16777216:raise ValueError('preserved text domain')
 textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));offsets=[]
 for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
 for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
 return bytes(raw)
def source_program():
 prefix,relas,symbols,strings,sections=fixed_parts();functions=[];calls={}
 for name,raw in [('prefix',prefix),('tail',relas+symbols+strings+base.SECTIONS),('sections',sections)]:
  calls[name],src=base.emitters(name,raw);functions.append(src)
 source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<512:
        return 4294967294
    if length(s)<56 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=5:
        return 4294967295
    total=56
    i=0
    while i<5:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304:
            return 4294967295
        write(w,i*8,n,8)
        total=total+n
        i=i+1
    if total!=length(s):
        return 4294967295
    layout(w)
    if get(w,80)-64>16777216:
        return 4294967295
    n=get(w,136)
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for key,at in [('prefix','0'),('tail','get(w,88)'),('sections','get(w,128)')]:
  for fn in calls[key]:source+=f'    {fn}(o,{at})\n'
 source+='''    sections=get(w,128)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,80)-64,8)
    write(o,sections+152,get(w,88),8)
    write(o,sections+216,get(w,96),8)
    write(o,sections+280,get(w,104),8)
    write(o,sections+344,get(w,112),8)
    write(o,sections+408,get(w,120),8)
'''
 for role,hole in FIXUPS:source+=f'    write(o,{64+hole},get(w,{40+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=56
    i=0
    while i<5:
        copy(s,o,at,get(w,40+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,136)

def layout(w:mutbuf) -> u64:
'''
 source+=f'    at=({len(prefix)}+15)&18446744073709551600\n'
 source+='''    i=0
    while i<5:
        write(w,40+i*8,at,8)
        at=at+get(w,i*8)
        if i!=4:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,80,at,8)
    at=(at+7)&18446744073709551608
    write(w,88,at,8)
'''
 for size,slot in [(len(relas),96),(len(symbols),104),(len(strings),112),(len(base.SECTIONS),120)]:
  source+=f'    at=at+{size}\n    write(w,{slot},at,8)\n'
 source+='''    at=(at+7)&18446744073709551608
    write(w,128,at,8)
    write(w,136,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value
'''
 return source+'\n'+'\n'.join(functions)+base.HELPERS
def program():return document(source_program(),'clang_capture_packer')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/clang_capture_packer.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
