"""Fixed native stable-file policy and streaming SHA packer."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('555341544155415641574883ec684989fc4989f54989d64989cf4c89c34c89cd4d85e40f84010300004d85f60f84f80200004885db0f84ef02000048f7c3070000000f85e20200004981fdc00000000f82d50200004981ff000100000f82c80200004881fd002010000f82bb0200004c89e04c01e80f82af02000048894424504c89f04c01f80f829e02000048894424404889d84801e80f828d02000048894424484c3b642440730b4c3b7424500f82760200004c3b642448730b483b5c24500f82640200004c3b742448730b483b5c24400f825202000048b848494153464c3031493904240f853e02000049837c240803743749837c2408020f872a02000048837b30000f851f0200004889dfb90020000031c0fcf3aa48899b600200004889ab68020000e9a70000004981fdc00000000f85f2010000b91000000049833c0c000f85e201000083c10881f9c000000072ea48b84849415346573031483943300f85c301000048395b200f85b90100004839ab680200000f85ac010000b8270000000f05483b43280f859b01000048c7038403000048c743100000000048c743180000000048c783900000000000000048c783b00000000100000048c783d00000000000000048c783d8000000000000004c89e74c89ee4c89f24c89f94989d84989e9e80000000085c00f843e01000083f80a74dc83f8010f84b100000083f802740a83f8037446e921010000488dbbff1f0000488bb3b80000004881fe010010000f8701010000488d9330020000b9200000004c8d830004000041b900100000e80000000089c048894308eb83488dbb00200000488bb3c0000000488b53704885d20f84c0000000488b4b78488b83800000004839c80f87ac0000004829c14801c20f82a00000004839ce0f87970000004881fe000010000f878a0000004989d84989e9e800000000e939ffffff31c94d8b5638498b44ce084c89d283e20349c1ea0285d2742683fa01750a4c39e873574c01e0eb1783fa02750a4c39f873484c01f0eb084839e8733e4801d8488904ccffc183f90672bc4d85d2752b498b06488b3c24488b742408488b5424104c8b5424184c8b4424204c8b4c24280f0548894308e9a8feffffb8fdffffff4883c468415f415e415d415c5b5dc3')
ROLES=('owner','sha')
FIXUPS=(('owner', 485), ('owner', 679), ('sha', 579))
EXPORT_SIZE=830
MAGIC=int.from_bytes(b'HIASFPA1','little')
def fixed_parts():
 strings=b'\0hia_clang_stable_file\0'
 symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)])
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
 rows=[bytes(64)]
 for name,kind,flags,size,link,info,align,extent in [('.text',1,6,0,0,0,16,0),('.rela.text',4,0,0,3,1,8,24),('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
  rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
 return header+BRIDGE,b'',symbols,strings,b''.join(rows)
def reference_object(parts):
 if len(parts)!=2 or any(not x or len(x)>4194304 for x in parts):raise ValueError('two bounded actual HIA bodies required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);offsets={}
 for role,part in zip(ROLES,parts):
  raw.extend(bytes((-len(raw))%16));offsets[role]=len(raw);raw.extend(part)
 for role,at in FIXUPS:struct.pack_into('<i',raw,64+at,offsets[role]-64-at-4)
 if len(raw)-64>16777216:raise ValueError('original text limit')
 textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));tail=[]
 for part in [relas,symbols,strings,base.SECTIONS]:tail.append(len(raw));raw.extend(part)
 tail.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
 for i,at in enumerate(tail,2):struct.pack_into('<Q',raw,sh+64*i+24,at)
 return bytes(raw)
def reference_flat(parts):
 obj=reference_object(parts);sh=struct.unpack_from('<Q',obj,40)[0];n=struct.unpack_from('<Q',obj,sh+96)[0];return obj[64:64+n]
def source_program():
 prefix,relas,symbols,strings,sections=fixed_parts();calls={};functions=[]
 for name,raw in [('prefix',prefix),('tail',symbols+strings+base.SECTIONS),('sections',sections),('flat_bridge',BRIDGE)]:
  calls[name],source=base.emitters(name,raw);functions.append(source)
 source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<512:
        return 4294967294
    if length(s)<40 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=2 or uint(s,32,8)>1:
        return 4294967295
    total=40
    i=0
    while i<2:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304:
            return 4294967295
        write(w,i*8,n,8)
        total=total+n
        i=i+1
    if total!=length(s):
        return 4294967295
    layout(w)
    if get(w,32)-64>16777216:
        return 4294967295
    if uint(s,32,8)==1:
        return flat(s,o,w)
    n=get(w,88)
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for key,at in [('prefix','0'),('tail','get(w,40)'),('sections','get(w,80)')]:
  for fn in calls[key]:source+=f'    {fn}(o,{at})\n'
 source+='''    sections=get(w,80)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,32)-64,8)
    write(o,sections+152,get(w,40),8)
    write(o,sections+216,get(w,48),8)
    write(o,sections+280,get(w,56),8)
    write(o,sections+344,get(w,64),8)
    write(o,sections+408,get(w,72),8)
'''
 for role,hole in FIXUPS:source+=f'    write(o,{64+hole},get(w,{16+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=40
    i=0
    while i<2:
        copy(s,o,at,get(w,16+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,88)

def layout(w:mutbuf) -> u64:
'''
 source+=f'    at=({len(prefix)}+15)&18446744073709551600\n'
 source+='''    i=0
    while i<2:
        write(w,16+i*8,at,8)
        at=at+get(w,i*8)
        if i!=1:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,32,at,8)
    at=(at+7)&18446744073709551608
    write(w,40,at,8)
    write(w,48,at,8)
'''
 source+=f'''    at=at+{len(symbols)}
    write(w,56,at,8)
    at=at+{len(strings)}
    write(w,64,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,72,at,8)
    at=(at+7)&18446744073709551608
    write(w,80,at,8)
    write(w,88,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value

def flat(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,32)-64
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for fn in calls['flat_bridge']:source+=f'    {fn}(o,0)\n'
 for role,hole in FIXUPS:source+=f'    write(o,{hole},get(w,{16+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=40
    i=0
    while i<2:
        copy(s,o,at,get(w,16+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
 return source+'\n'+'\n'.join(functions)+base.HELPERS
def program():return document(source_program(),'clang_stable_file_packer')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/clang_stable_file_packer.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
