"""Pure HIA packaging of shared report/accounting policy and the fixed value owner."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574883ec784989fc4989f74989d54889cd4d89c64c89cb4881fd002000000f82670100004881fb008000000f825a0100004d85ed0f84510100004d85f60f84480100004c89e84801e80f823c01000048894424604c89f04801d80f822b01000048894424684c3b74246073094c39e80f87160100004c89e04c01f80f820a01000048894424584d85ff74294d85e40f84f70000004c3b64246073094c39e80f87e70000004c3b64246873094c39f00f87d70000004983ff08721448b84849414252503032493b04240f84bd000000498b46084889442450488d05000000004989460849c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0746183f80a74e083f80475524d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b542430488b4c24384c8b4424404c8b4c2448e80000000049898588000000eb89b8fdffffff488b54245049895608eb05b8fdffffff4883c478415f415e415d415c5d5bc3')
ROLES=('policy','value')
FIXUPS=(('policy', 288), ('value', 227), ('value', 375))
EXPORT_SIZE=424
def fixed_parts():
 strings=b'\0hia_background_optimizer_report\0'
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
    if length(s)<40 or uint(s,0,8)!={int.from_bytes(b'HIABPK01','little')} or uint(s,8,8)!=2:
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
 for role,hole in FIXUPS:source+=f'    write(o,{64+hole},get(w,{64+8*ROLES.index(role)})-{64+hole+4},4)\n'
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
 for role,hole in FIXUPS:source+=f'    write(o,{hole},get(w,{64+8*ROLES.index(role)})-{64+hole+4},4)\n'
 source+='''    at=40
    i=0
    while i<2:
        copy(s,o,at,get(w,64+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
 return source+'\n'+'\n'.join(functions)+base.HELPERS
def program():return document(source_program(),'background_optimizer_report_packer')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/background_optimizer_report_packer.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)
