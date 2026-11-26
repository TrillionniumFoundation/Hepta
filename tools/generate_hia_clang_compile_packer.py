"""Fixed HIA capsule packaging; Python is a development oracle only."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('555341544155415641574883ec6848c7442460000000004989fc4989f54989d64989cf4c89c34c89cd4d85e40f84b10500004d85f60f84a80500004885db0f849f05000048f7c3070000000f85920500004981fd000100000f82850500004981ff000200000f82780500004881fd000000200f826b0500004c89e04c01e80f825f05000048894424504c89f04c01f80f824e05000048894424404889d84801e80f823d05000048894424484c3b642440730b4c3b7424500f82260500004c3b642448730b483b5c24500f82140500004c3b742448730b483b5c24400f820205000048b8484941434c423031493904240f85ee04000049837c2408010f87e204000031c0ba01000000f0480fb193f03f00000f85c504000048c74424600100000049837c24080174564981ff000210000f82ae04000048837b30000f85a3040000b8270000000f054885c00f8e9304000048894424584889dfb90010000031c0fcf3aa488b44245848894328488d058efeffff488983d0000000e99d0000004981fd000100000f8558040000b91000000049833c0c000f854804000083c10881f90001000072ea48b8484941434c573031483943300f852904000048395b200f851f04000048396b380f8515040000488d052bfeffff483983d00000000f8501040000b8270000000f05483b43280f85f003000048c7038403000048c783a80200000100000048c783380300000000000048c783400300000000000048896b3848895b404c8963484c896b504c8973584c897b60488d0500000000488983c000000048b80000000000000000488983c80000004c89e74c89ee4c89f24c89f94989d84989e9e80000000085c00f847703000083f80a74dc83f8010f84e302000083f8020f842f01000083f8030f848302000083f8040f84ac02000083f864743883f865744f83f866746683f867747d83f8680f849000000083f8690f84a300000083f86a0f84b600000083f86b0f84c9000000e9110300004c89e74c89ee4c89f24c89f94989d84989e9e800000000e976ffffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e95affffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e93effffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e922ffffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e906ffffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e9eafeffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e9cefeffff4c89e74c89ee4c89f24c89f94989d84989e9e800000000e9b2feffff8b838000000085c00f84ee000000488bbb88000000488bb390000000488b9398000000488b8ba00000004c8b83a80000004c8b8bb000000083f801744b83f802744d83f803744f83f804745183f805745383f806745583f807745783f808745983f809745b83f80a745d83f80b745f83f80c746183f80d746383f80e746583f80f7467e9a4010000e800000000eb62e800000000eb5be800000000eb54e800000000eb4de800000000eb46e800000000eb3fe800000000eb38e800000000eb31e800000000eb2ae800000000eb23e800000000eb1ce800000000eb15e800000000eb0ee800000000eb07e800000000eb0089c048894308e99ffdffff488b8b90000000483b8ba00000000f871c0100004885c9743b488bb388000000488bbb980000004885f60f84000100004885ff0f84f70000004889f04801c80f82eb0000004889f84801c80f82df000000fcf3a448c7430800000000e93efdffff31ff488d35ed000000e8000000004885c074164989c3488d3dcffaffff488db30008000041ffd389c048894308e90cfdffff488b83200800004885c00f848d0000000fb60048894308e9f0fcffff31c94d8b5638498b44ce084c89d283e20349c1ea0285d2742683fa01750a4c39e8735e4c01e0eb1783fa02750a4c39f8734f4c01f0eb084839e873454801d8488904ccffc183f90672bc4d85d27532498b06488b3c24488b742408488b5424104c8b5424184c8b4424204c8b4c24280f0548894308e976fcffffb8fcffffffeb05b8fdffffff48837c246000740b48c783f03f0000000000004883c468415f415e415d415c5b5dc3646c6164647200')
ROLES=('owner','prepare','location','tools','execute','publish','transport','diagnostics','cleanup','buffers','receipt','hash','admission','canonical','llvm','llvm_meta','which','path','file','capture','object','shared','identity','rmtree','catalog')
FIXUPS=(('catalog', 566), ('owner', 613), ('prepare', 746), ('tools', 774), ('execute', 802), ('publish', 830), ('transport', 858), ('diagnostics', 886), ('cleanup', 914), ('location', 942), ('hash', 1088), ('admission', 1095), ('canonical', 1102), ('llvm', 1109), ('llvm_meta', 1116), ('which', 1123), ('path', 1130), ('file', 1137), ('capture', 1144), ('object', 1151), ('shared', 1158), ('identity', 1165), ('rmtree', 1172), ('receipt', 1179), ('buffers', 1186))
RELOCATIONS=()
DYNAMIC_RELOCATIONS=(('@bridge',1310,'dlsym'),('which',776,'dlsym'),('capture',1010,'dlsym'))
ENTRY_OFFSETS={'capture':64,'path':64}
LENGTH_FIXUPS=(('catalog', 579),)
IMPORTS=('dlsym',)
EXPORT='hia_clang_compile'
EXTRA_EXPORTS=(('hia_program_llvm','llvm'),('hia_program_llvm_metadata','llvm_meta'))
EXPORT_SIZE=1553
MAGIC=int.from_bytes(b'HIACLPP2','little')
def fixed_parts():
 strings=b'\0'+EXPORT.encode()+b'\0'+b''.join(name.encode()+b'\0'for name,role in EXTRA_EXPORTS)+b''.join(x.encode()+b'\0'for x in IMPORTS)
 symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,EXPORT_SIZE)]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),18,0,1,0,0)for name,role in EXTRA_EXPORTS]+[struct.pack('<IBBHQQ',strings.index(name.encode()+b'\0'),16,0,0,0,0)for name in IMPORTS])
 relas=b''.join(struct.pack('<QQq',0,((3+len(EXTRA_EXPORTS)+IMPORTS.index(name))<<32)|4,-4)for role,offset,name in DYNAMIC_RELOCATIONS)
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
  struct.pack_into('<i',raw,64+hole,offsets[role]+ENTRY_OFFSETS.get(role,0)-64-hole-4)
 for role,hole in LENGTH_FIXUPS:struct.pack_into('<Q',raw,64+hole,len(parts[ROLES.index(role)]))
 if len(raw)-64>16777216:raise ValueError('original text limit')
 textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8));tail=[]
 for data in [relas,symbols,strings,base.SECTIONS]:tail.append(len(raw));raw.extend(data)
 tail.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
 for i,(role,at,name)in enumerate(DYNAMIC_RELOCATIONS):struct.pack_into('<Q',raw,tail[0]+i*24,at if role=='@bridge'else offsets[role]-64+at)
 for index,(name,role)in enumerate(EXTRA_EXPORTS,3):struct.pack_into('<QQ',raw,tail[1]+index*24+8,offsets[role]-64,len(parts[ROLES.index(role)]))
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
 for index,(name,role)in enumerate(EXTRA_EXPORTS,3):
  src+=f'    write(o,get(w,{T+16})+{index*24+8},get(w,{count*8+8*ROLES.index(role)})-64,8)\n'
  src+=f'    write(o,get(w,{T+16})+{index*24+16},get(w,{8*ROLES.index(role)}),8)\n'
 for role,hole in FIXUPS:src+=f'    write(o,{64+hole},get(w,{count*8+8*ROLES.index(role)})+{ENTRY_OFFSETS.get(role,0)}-{64+hole+4},4)\n'
 for role,hole in LENGTH_FIXUPS:src+=f'    write(o,{64+hole},get(w,{8*ROLES.index(role)}),8)\n'
 for i,(role,at,name)in enumerate(DYNAMIC_RELOCATIONS):
  value=str(at)if role=='@bridge'else f'get(w,{count*8+8*ROLES.index(role)})-64+{at}'
  src+=f'    write(o,get(w,{T+8})+{i*24},{value},8)\n'
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
 for role,hole in FIXUPS:src+=f'    write(o,{hole},get(w,{count*8+8*ROLES.index(role)})+{ENTRY_OFFSETS.get(role,0)}-{64+hole+4},4)\n'
 for role,hole in LENGTH_FIXUPS:src+=f'    write(o,{hole},get(w,{8*ROLES.index(role)}),8)\n'
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
 t=document(source_program(),'clang_compile_packer');p=ROOT/'examples/hia_bootstrap/clang_compile_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,flush=True)
if __name__=='__main__':main()
