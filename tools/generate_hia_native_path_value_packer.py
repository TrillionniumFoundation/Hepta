"""Native path owner and fixed TypeError formatter packaging.
The two captured HIA roles are emitted with the readable syscall capsule.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd008000000f82560200004881fb001000000f82490200004d85ed0f84400200004d85f60f84370200004c89e84801e80f822b02000048894424684c89f04801d80f821a02000048894424704c3b74246873094c39e80f87050200004c89e04c01f80f82f901000048894424604d85ff74294d85e40f84e60100004c3b64246873094c39e80f87d60100004c3b64247073094c39f00f87c601000049c785000100000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f848a01000083f80a74dc83f8020f84ba00000083f8030f84ea00000083f8080f840901000083f801740e83f809740983f80b0f855701000048894424584d8b958800000031c9498b84cd900000004d89d34183e3034a0304dc0f822b010000488944cc2049c1ea02ffc183f90672d74d85d20f8512010000488b7c2420488b742428488b542430488b4c24384c8b4424404c8b4c244848837c245801741448837c24580b741d41ff9580000000e9cc0000004989ca498b85800000000f05e9bb000000e800000000e9b10000004d8b958000000041f6c2070f85ac0000004989db4983eb084d39da0f879c0000004d01f2498b8588000000498b9590000000f0490fb112eb784d8b958000000041f6c20775774989db4983eb084d39da776b4d01f2498b8590000000498702eb504d8b95800000004983fa03774f498bb5880000004a0334d472424d8b95900000004983fa037735498bbd980000004a033cd47228498b8da00000004889f04801c872194889f84801c87211fcf3a431c0498985000f0000e95cfeffffb8fdffffff4881c498000000415f415e415d415c5d5bc3')
ROLES=('policy','error')
HOLES={'policy':245,'error':448}
EXPORT_SIZE=669
def fixed_parts():
 strings=b'\0hia_native_path_value\0'
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
 if len(flats)!=2 or any(not x or len(x)>4194304 for x in flats):raise ValueError('two actual bounded HIA roles required')
 prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
 for role,flat in zip(ROLES,flats):
  raw.extend(bytes((-len(raw))%16));struct.pack_into('<i',raw,64+HOLES[role],len(raw)-64-HOLES[role]-4);raw.extend(flat)
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
    if length(s)<40 or uint(s,0,8)!={int.from_bytes(b'HIANPP01','little')} or uint(s,8,8)!=2:
        return 4294967295
    if uint(s,32,8)>1:
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
    if get(w,128)-64>16777216:
        return 4294967295
    if uint(s,32,8)==1:
        return pack_flat(s,o,w)
    n=get(w,184)
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for key,at in [('prefix','0'),('tail','get(w,136)'),('sections','get(w,176)')]:
  for fn in calls[key]:source+=f'    {fn}(o,{at})\n'
 source+='''    sections=get(w,176)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,128)-64,8)
    write(o,sections+152,get(w,136),8)
    write(o,sections+216,get(w,144),8)
    write(o,sections+280,get(w,152),8)
    write(o,sections+344,get(w,160),8)
    write(o,sections+408,get(w,168),8)
'''
 for i,role in enumerate(ROLES):source+=f'    write(o,{64+HOLES[role]},get(w,{64+8*i})-{64+HOLES[role]+4},4)\n'
 source+='''    at=40
    i=0
    while i<2:
        copy(s,o,at,get(w,64+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,184)

def layout(w:mutbuf) -> u64:
'''
 source+=f'    at=({len(prefix)}+15)&18446744073709551600\n'
 source+='''    i=0
    while i<2:
        write(w,64+i*8,at,8)
        at=at+get(w,i*8)
        if i!=1:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,128,at,8)
    at=(at+7)&18446744073709551608
    write(w,136,at,8)
    write(w,144,at,8)
'''
 source+=f'''    at=at+{len(symbols)}
    write(w,152,at,8)
    at=at+{len(strings)}
    write(w,160,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,168,at,8)
    at=(at+7)&18446744073709551608
    write(w,176,at,8)
    write(w,184,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value

def pack_flat(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,128)-64
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
 for fn in calls['flat_bridge']:source+=f'    {fn}(o,0)\n'
 for i,role in enumerate(ROLES):source+=f'    write(o,{HOLES[role]},get(w,{64+8*i})-{64+HOLES[role]+4},4)\n'
 source+='''    at=40
    i=0
    while i<2:
        copy(s,o,at,get(w,64+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
 return source+'\n'+'\n'.join(functions)+base.HELPERS
def program():return document(source_program(),'native_path_value_packer')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/native_path_value_packer.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)

