"""Ten closed HIA roles for native verified Core to LLVM rendering."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574883ec284989fc4989f54989d64989cf4c89c34c89cd4d85e40f84c50100004d85f60f84bc0100004885db0f84b30100004983fd400f82a90100004881fd000000080f829c0100004c89e04c01e80f8290010000488904244c89f04c01f80f828001000048894424084889d84801e80f826f01000048894424104c3b642408730a4c3b34240f82590100004c3b642410730a483b1c240f82480100004c3b742410730b483b5c24080f823601000048c78300008001000000004c89e74c89ee4c89f24c89f94989d84989e9e80000000085c00f840401000083f80274dc83f80b742d83f814745983f815745d83f816746183f817746583f818746983f81b747683f81a746883f8197475e9da000000498d7c2440498d75c04889dab9000080014c8d830000800641b900008001e80000000089c0488983d0008001e979ffffff4c8d1d54000000eb3d4c8d1d52000000eb344c8d1d50000000eb2b4c8d1d4e000000eb224c8d1d4c000000eb194c8d1d4a000000eb104c8d1d48000000eb074c8d1d460000004c89e74c89ee4c89f24c89f94989d84989e941ffe3e800000000eb2fe800000000eb28e800000000eb21e800000000eb1ae800000000eb13e800000000eb0ce800000000eb05e80000000083f8020f84dffeffffeb0d8b8398008001eb05b8fdffffff4883c428415f415e415d415c5d5bc3')
ROLES=('owner','decode','module','scalar','memory','bulk','flow','analysis','vector','outline')
FIXUPS=(('owner', 214), ('decode', 312), ('module', 471), ('scalar', 422), ('memory', 429), ('bulk', 436), ('flow', 443), ('analysis', 450), ('vector', 457), ('outline', 464))
EXPORT_SIZE=514
def fixed_parts():
 strings=b'\0hia_program_llvm\0'
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
 if len(flats)!=10 or any(not x or len(x)>4194304 for x in flats):raise ValueError('ten actual bounded HIA roles required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
 offsets_by_role={}
 for role,flat in zip(ROLES,flats):
  raw.extend(bytes((-len(raw))%16));offsets_by_role[role]=len(raw);raw.extend(flat)
 for role,hole in FIXUPS:struct.pack_into('<i',raw,64+hole,offsets_by_role[role]-64-hole-4)
 if len(raw)-64>16777216:raise ValueError('preserved text domain')
 textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));offsets=[]
 for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
 offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
 for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
 return bytes(raw)
def reference_flat(flats):
 obj=reference_object(flats);sh=struct.unpack_from('<Q',obj,40)[0];n=struct.unpack_from('<Q',obj,sh+96)[0];return obj[64:64+n]
def source_program():
 prefix,relas,symbols,strings,sections=fixed_parts();functions=[];calls={}
 for name,raw in [('prefix',prefix),('tail',relas+symbols+strings+base.SECTIONS),('sections',sections),('flat_bridge',BRIDGE)]:
  calls[name],src=base.emitters(name,raw);functions.append(src)
 source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<512:
        return 4294967294
    if length(s)<104 or uint(s,0,8)!={int.from_bytes(b'HIALLPK1','little')} or uint(s,8,8)!=10:
        return 4294967295
    if uint(s,96,8)>1:
        return 4294967295
    total=104
    i=0
    while i<10:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304:
            return 4294967295
        write(w,i*8,n,8)
        total=total+n
        i=i+1
    if total!=length(s):
        return 4294967295
    layout(w)
    if get(w,160)-64>16777216:
        return 4294967295
    if uint(s,96,8)==1:
        return pack_flat(s,o,w)
    n=get(w,216)
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for key,at in [('prefix','0'),('tail','get(w,168)'),('sections','get(w,208)')]:
  for fn in calls[key]:source+=f'    {fn}(o,{at})\n'
 source+='''    sections=get(w,208)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,160)-64,8)
    write(o,sections+152,get(w,168),8)
    write(o,sections+216,get(w,176),8)
    write(o,sections+280,get(w,184),8)
    write(o,sections+344,get(w,192),8)
    write(o,sections+408,get(w,200),8)
'''
 for role,hole in FIXUPS:source+=f'    write(o,{64+hole},get(w,{80+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=104
    i=0
    while i<10:
        copy(s,o,at,get(w,80+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,216)

def layout(w:mutbuf) -> u64:
'''
 source+=f'    at=({len(prefix)}+15)&18446744073709551600\n'
 source+='''    i=0
    while i<10:
        write(w,80+i*8,at,8)
        at=at+get(w,i*8)
        if i!=9:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,160,at,8)
    at=(at+7)&18446744073709551608
    write(w,168,at,8)
    write(w,176,at,8)
'''
 source+=f'''    at=at+{len(symbols)}
    write(w,184,at,8)
    at=at+{len(strings)}
    write(w,192,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,200,at,8)
    at=(at+7)&18446744073709551608
    write(w,208,at,8)
    write(w,216,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value

def pack_flat(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,160)-64
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for fn in calls['flat_bridge']:source+=f'    {fn}(o,0)\n'
 for role,hole in FIXUPS:source+=f'    write(o,{hole},get(w,{80+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=104
    i=0
    while i<10:
        copy(s,o,at,get(w,80+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
 return source+'\n'+'\n'.join(functions)+base.HELPERS
def program():return document(source_program(),'program_llvm_packer')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/program_llvm_packer.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
