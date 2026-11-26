"""Fixed HIA capsule packaging; Python is a development oracle only."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('555341544155415641574883ec684989fc4989f54989d64989cf4c89c34c89cd4d85e40f841b0300004d85f60f84120300004885db0f840903000048f7c3070000000f85fc0200004983fd200f82f20200004981ff800000000f82e50200004881fd001000000f82d80200004c89e04c01e80f82cc02000048894424504c89f04c01f80f82bb02000048894424404889d84801e80f82aa02000048894424484c3b642440730b4c3b7424500f82930200004c3b642448730b483b5c24500f82810200004c3b742448730b483b5c24400f826f02000048b84849414357483031493904240f855b02000049837c240801743149837c2408000f874702000048837b30000f853c0200004889dfb90010000031c0fcf3aa48895b4048896b38e9930000004983fd200f8518020000b91000000049833c0c000f850802000083c10883f92072ed48b84849414357573031483943300f85ec01000048395b200f85e201000048396b380f85d8010000b8270000000f05483b43280f85c701000048c7038403000048c743100000000048c743180000000048c783200100000100000048c783300100000000000048c78338010000000000004c89e74c89ee4c89f24c89f94989d84989e9e80000000085c00f847501000083f80a74dc83f8010f849600000083f8050f841301000083f8060f842901000083f80e740a83f80f744de941010000488bbb40010000488bb348010000488b9350010000488b8b580100004885ff0f841c0100004885d20f84130100004889f84801f00f82070100004889d04801c80f82fb000000eb1d4c89e74c89ee488b93d8000000488b8be00000004885d20f84dc0000004989d84989e9e800000000e954ffffff31c94d8b5638498b44ce084c89d283e20349c1ea0285d2743283fa01750e4c39e80f83a50000004c01e0eb1f83fa02750e4c39f80f83920000004c01f0eb0c4839e80f83840000004801d8488904ccffc183f90672b04d85d27571498b06488b3c24488b742408488b5424104c8b5424184c8b4424204c8b4c24280f0548894308e9b7feffff31ff488d3551000000e8000000004885c07433488b0048894308e998feffff498b064885c0741f49837e0801740c49837e08087511488b00eb030fb60048894308e971feffffb8fdffffff4883c468415f415e415d415c5b5dc3656e7669726f6e00')
ROLES=('owner',)
FIXUPS=(('owner',456),('owner',623),)
RELOCATIONS=((776,'dlsym'),)
IMPORTS=('dlsym',)
EXPORT='hia_clang_which'
EXPORT_SIZE=864
MAGIC=int.from_bytes(b'HIACWPK1','little')
def fixed_parts():
 strings=b'\0'+EXPORT.encode()+b'\0'+b''.join(x.encode()+b'\0'for x in IMPORTS)
 symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0)for name in IMPORTS])
 relas=b''.join(struct.pack('<QQq',offset,((3+IMPORTS.index(name))<<32)|4,-4)for offset,name in RELOCATIONS)
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
 rows=[bytes(64)]
 for name,kind,flags,size,link,info,align,extent in [('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
  rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
 return header+BRIDGE,relas,symbols,strings,b''.join(rows)
def reference_object(parts):
 if len(parts)!=len(ROLES)or any(not x or len(x)>4194304 for x in parts):raise ValueError('actual bounded HIA role count')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix);offsets={}
 for role,part in zip(ROLES,parts):
  raw.extend(bytes((-len(raw))%16));offsets[role]=len(raw);raw.extend(part)
 for role,hole in FIXUPS:
  assert raw[64+hole:68+hole]==bytes(4)
  struct.pack_into('<i',raw,64+hole,offsets[role]-64-hole-4)
 if len(raw)-64>16777216:raise ValueError('original text limit')
 textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));tail=[]
 for data in [relas,symbols,strings,base.SECTIONS]:tail.append(len(raw));raw.extend(data)
 tail.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
 for i,at in enumerate(tail,2):struct.pack_into('<Q',raw,sh+i*64+24,at)
 return bytes(raw)
def reference_flat(parts):
 raw=reference_object(parts);sh=struct.unpack_from('<Q',raw,40)[0];n=struct.unpack_from('<Q',raw,sh+96)[0];return raw[64:64+n]
def source_program():
 prefix,relas,symbols,strings,sections=fixed_parts();calls={};functions=[]
 for name,raw in [('prefix',prefix),('tail',relas+symbols+strings+base.SECTIONS),('sections',sections),('flat_prefix',BRIDGE)]:
  calls[name],source=base.emitters(name,raw);functions.append(source)
 count=len(ROLES);header=(count+3)*8;mode_at=16+count*8;T=16*count
 src=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<{T+64}:
        return 4294967294
    if length(s)<{header} or uint(s,0,8)!={MAGIC} or uint(s,8,8)!={count} or uint(s,{mode_at},8)>1:
        return 4294967295
    total={header}
    i=0
    while i<{count}:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304:
            return 4294967295
        write(w,i*8,n,8)
        total=total+n
        i=i+1
    if length(s)!=total:
        return 4294967295
    layout(w)
    if get(w,{T})-64>16777216:
        return 4294967295
    if uint(s,{mode_at},8)==1:
        return flat(s,o,w)
    n=get(w,{T+56})
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for key,at in [('prefix','0'),('tail',f'get(w,{T+8})'),('sections',f'get(w,{T+48})')]:
  for fn in calls[key]:src+=f'    {fn}(o,{at})\n'
 src+=f'''    sections=get(w,{T+48})
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,{T})-64,8)
'''
 for i in range(2,7):src+=f'    write(o,sections+{64*i+24},get(w,{T+8*(i-1)}),8)\n'
 for role,hole in FIXUPS:src+=f'    write(o,{64+hole},get(w,{count*8+8*ROLES.index(role)})-{64+hole+4},4)\n'
 src+=f'''    at={header}
    i=0
    while i<{count}:
        copy(s,o,at,get(w,{count*8}+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,{T+56})

def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<{count}:
        write(w,{count*8}+i*8,at,8)
        at=at+get(w,i*8)
        if i!={count-1}:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,{T},at,8)
    at=(at+7)&18446744073709551608
    write(w,{T+8},at,8)
    at=at+{len(relas)}
    write(w,{T+16},at,8)
    at=at+{len(symbols)}
    write(w,{T+24},at,8)
    at=at+{len(strings)}
    write(w,{T+32},at,8)
    at=at+{len(base.SECTIONS)}
    write(w,{T+40},at,8)
    at=(at+7)&18446744073709551608
    write(w,{T+48},at,8)
    write(w,{T+56},at+448,8)
    return 0

def flat(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,{T})-64
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for fn in calls['flat_prefix']:src+=f'    {fn}(o,0)\n'
 for role,hole in FIXUPS:src+=f'    write(o,{hole},get(w,{count*8+8*ROLES.index(role)})-{64+hole+4},4)\n'
 src+=f'''    at={header}
    i=0
    while i<{count}:
        copy(s,o,at,get(w,{count*8}+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value
'''
 return src+'\n'+'\n'.join(functions)+base.HELPERS
def main():
 t=document(source_program(),'clang_which_packer');p=ROOT/'examples/hia_bootstrap/clang_which_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,flush=True)
if __name__=='__main__':main()
