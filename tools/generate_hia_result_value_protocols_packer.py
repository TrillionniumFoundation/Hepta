"""Explicit thirteen-role Value protocols image; earlier packers stay fixed."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_multiversion_image_packer as base

ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec9800000048c7842480000000000000004989fc4989f74989d54889cd4d89c64c89cb4881fd002000000f829e0200004881fb000100000f82910200004d85ed0f84880200004d85f60f847f0200004c89e84801e80f827302000048894424684c89f04801d80f826202000048894424704c3b74246873094c39e80f874d0200004c89e04c01f80f824102000048894424604d85ff74294d85e40f842e0200004c3b64246873094c39e80f871e0200004c3b64247073094c39f00f870e020000f049ff467848c78424800000000100000049c785800000000000000048c70424000000004c896424104c896c24184c897424204c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84c101000083f80a74dc83f8020f847e01000083f8030f848b01000083f801740e83f807740983f8040f85970100004889442458498b461048894424084d8b95c800000031c9498b84cdd00000004d89d34183e3074183fb040f87620100004a0304dc488944cc2849c1ea03ffc183f90672d3488b7c2428488b742430488b5424384c8b4424484c8b4c245048837c24580175134c8b542440498b85c00000000f05e90e010000488b4c244048837c2458070f84b4000000498b85c00000004883f80174474883f802744b4883f803744f4883f80474534883f80574574883f80674584883f80874594883f809745a4883f80a745b4883f80b745c4883f80c745d4883f80d745ee9b5000000e800000000e99f000000e800000000e995000000e800000000e98b000000e800000000e981000000e800000000eb7ae800000000eb73e800000000eb6ce800000000eb65e800000000eb5ee800000000eb57e800000000eb50e800000000eb49498b86800000004885c074124d8b86880000004d8b8e90000000ffd0eb2bb8fdffffffeb244d8b55004d01f2498b4508498b5510f0490fb112eb0e4d8b55004d01f2498b451049870249898588000000e925feffffb8fdffffff4883bc2480000000007405f049ff4e784881c498000000415f415e415d415c5d5bc3')
ROLES=('owner','core','import','export','capture','format','number','dict_iterator','classes','class_mro','records','resources','protocols')
HOLES=(274, 550, 560, 570, 580, 590, 597, 604, 611, 618, 625, 632, 639)


def fixed_parts():
    strings=b'\0hia_result_value\0'
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
    if len(flats)!=13 or any(not x or len(x)>4194304 for x in flats):
        raise ValueError('thirteen actual bounded HIA roles required')
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
    if length(s)<128 or uint(s,0,8)!={int.from_bytes(b'HIABVP06','little')} or uint(s,8,8)!=13 or uint(s,120,8)>1:
        return 4294967295
    total=128
    i=0
    while i<13:
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
    if uint(s,120,8)==1:
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
    source+='''    at=128
    i=0
    while i<13:
        copy(s,o,at,get(w,128+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,312)
def layout(w:mutbuf) -> u64:
'''
    source+=f'    at=({len(prefix)}+15)&18446744073709551600\n'
    source+='''    i=0
    while i<13:
        write(w,128+i*8,at,8)
        at=at+get(w,i*8)
        if i!=12:
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
    source+='''    at=128
    i=0
    while i<13:
        copy(s,o,at,get(w,128+i*8)-64,get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return n
'''
    return source+'\n'+'\n'.join(functions)+base.HELPERS


def program():return document(source_program(),'result_value_protocols_packer')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/result_value_protocols_packer.hepta'
    path.write_text(render_assembly(program()))
    print(path.name,path.stat().st_size,flush=True)
