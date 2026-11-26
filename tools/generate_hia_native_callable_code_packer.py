"""Fixed source-bound native callable code owner packer."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base

ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('4881f9002000000f83c80000004881f9800000000f82b50000004881fe800000000f85a80000004885ff0f849f0000004885d20f84960000004d85c00f848d0000004981f9000100000f858000000048b8484941565246513148390775714889f84801f072694989d24901ca72614839c273054c39d772574d89c34d01cb724f4c39da73054d39d07245535541544155415641574881ec082000004989d54889e2b900200000e82a00000085c0750e4c89ef4889e6b910000000f348a54881c408200000415f415e415d415c5d5bc3b8fdffffffc3535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd002000000f82600200004881fb000100000f85530200004d85ed0f844a0200004d85f60f84410200004c89e84801e80f823502000048894424684c89f04801d80f822402000048894424704c3b74246873094c39e80f870f0200004c89e04c01f80f820302000048894424604d85ff74294d85e40f84f00100004c3b64246873094c39e80f87e00100004c3b64247073094c39f00f87d001000049c78580000000000000004d89b59000000048c70424000000004c897424084c896c24104c896424184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f848d01000083f80a74dc83f801743b83f8020f843601000083f8030f844c01000083f8040f848200000083f8050f849700000083f8060f84bf00000083f8070f84e8000000e9480100004d8b95b800000031c9498b84cdc00000004d89d34183e3074183fb030f87210100004a0304dc488944cc2849c1ea03ffc183f90672d3488b7c2428488b742430488b5424384c8b5424404c8b4424484c8b4c2450498b85b00000000f05e9d50000004c89e74c89fe4c89ea4889e94d8b46104d8b4e28e800000000e9b7000000498bbd38010000498bb548010000498b9520010000b9000010004d8b855001000041b900001000e800000000e986000000498bbdf0010000498bb520020000488d9700001000b9000010004c8d870000200041b900001000498b8520010000ffd0eb544c89e74c89fe4c89ea4889e94d8b85280200004d8b8d30020000e800000000eb334d8b95c00000004d01f2498b85c8000000498b95d0000000f0490fb112eb144d8b95c00000004d01f2498b85d000000049870249898588000000e959feffffb8fdffffff4881c498000000415f415e415d415c5d5bc3')
ROLES=('owner','registry','buffers','compiler')
HOLES=(465, 665, 800, 714)


def fixed_parts():
    strings=b'\0hia_native_callable_code_owner\0'
    symbols=b''.join([bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',1,18,0,1,0,len(BRIDGE))])
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,0,3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(base.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',base.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,symbols,strings,b''.join(rows)


def reference_object(flats):
    if len(flats)!=4 or any(not x or len(x)>4194304 for x in flats):
        raise ValueError('four actual bounded HIA roles required')
    prefix,symbols,strings,sections=fixed_parts()
    raw=bytearray(prefix)
    for hole,flat in zip(HOLES,flats):
        raw.extend(bytes((-len(raw))%16))
        struct.pack_into('<i',raw,64+hole,len(raw)-64-hole-4)
        raw.extend(flat)
    if len(raw)-64>16777216:
        raise ValueError('preserved text domain')
    textsize=len(raw)-64
    raw.extend(bytes((-len(raw))%8))
    offsets=[]
    for part in (b'',symbols,strings,base.SECTIONS):
        offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)


def reference_flat(flats):
    obj=reference_object(flats);sh=struct.unpack_from('<Q',obj,40)[0]
    n=struct.unpack_from('<Q',obj,sh+96)[0]
    return obj[64:64+n]


def source_program():
    prefix,symbols,strings,sections=fixed_parts();functions=[];calls={}
    for name,raw in (('prefix',prefix),('tail',symbols+strings+base.SECTIONS),('sections',sections),('bridge',BRIDGE)):
        calls[name],src=base.emitters(name,raw);functions.append(src)
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<512:
        return 4294967294
    if length(s)<56 or uint(s,0,8)!={int.from_bytes(b'HIACOP01','little')} or uint(s,8,8)!=4 or uint(s,48,8)>1:
        return 4294967295
    total=56
    i=0
    while i<4:
        n=uint(s,16+i*8,8)
        if n==0 or n>4194304:
            return 4294967295
        write(w,i*8,n,8)
        total=total+n
        i=i+1
    if total!=length(s):
        return 4294967295
    layout(w)
    if get(w,256)-64>16777216:
        return 4294967295
    if uint(s,48,8)==1:
        return pack_flat(s,o,w)
    n=get(w,312)
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
    for key,at in (('prefix','0'),('tail','get(w,264)'),('sections','get(w,304)')):
        for fn in calls[key]:source+=f'    {fn}(o,{at})\n'
    source+='''    sections=get(w,304)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,256)-64,8)
    write(o,sections+152,get(w,264),8)
    write(o,sections+216,get(w,272),8)
    write(o,sections+280,get(w,280),8)
    write(o,sections+344,get(w,288),8)
    write(o,sections+408,get(w,296),8)
'''
    for i,hole in enumerate(HOLES):source+=f'    write(o,{64+hole},get(w,{128+i*8})-{64+hole+4},4)\n'
    source+='''    at=56
    i=0
    while i<4:
        copy(s,o,at,get(w,128+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,312)
def layout(w:mutbuf) -> u64:
'''
    source+=f'    at=({len(prefix)}+15)&18446744073709551600\n'
    source+='''    i=0
    while i<4:
        write(w,128+i*8,at,8)
        at=at+get(w,i*8)
        if i!=3:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,256,at,8)
    at=(at+7)&18446744073709551608
    write(w,264,at,8)
    write(w,272,at,8)
'''
    source+=f'''    at=at+{len(symbols)}
    write(w,280,at,8)
    at=at+{len(strings)}
    write(w,288,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,296,at,8)
    at=(at+7)&18446744073709551608
    write(w,304,at,8)
    write(w,312,at+448,8)
    return 0
def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value
def pack_flat(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,256)-64
    if length(o)<n:
        return 4294967294
    i=0
    while i<n:
        store(o,i,0)
        i=i+1
'''
    for fn in calls['bridge']:source+=f'    {fn}(o,0)\n'
    for i,hole in enumerate(HOLES):source+=f'    write(o,{hole},get(w,{128+i*8})-{64+hole+4},4)\n'
    source+='''    at=56
    i=0
    while i<4:
        copy(s,o,at,get(w,128+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
    return source+'\n'+'\n'.join(functions)+base.HELPERS


def program():return document(source_program(),'native_callable_code_packer')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/native_callable_code_packer.hepta'
    path.write_text(render_assembly(program()))
    print(path.name,path.stat().st_size,flush=True)
