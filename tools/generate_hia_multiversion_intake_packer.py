"""HIA ET_REL packaging of seven actual Core intake roles."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574883ec084989fc4989f74989d54889cd4d89c64c89cb4881fb0000000a0f82a000000049c706000000004c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c0747583f802727e83f8077779498b7e104c01f7498b7618498b56204c01f2498b4e284d8b46304d01f04d8b4e3883f802741b83f803741d83f804741f83f805742183f8067423e800000000eb21e800000000eb1ae800000000eb13e800000000eb0ce800000000eb05e80000000049894608e970ffffff418b8680000000eb05b8fdffffff4883c408415f415e415d415c5d5bc3')
HOLES={'policy': 71, 'admission': 155, 'canonical': 162, 'hash': 169, 'profile': 176, 'scalar': 183, 'abi': 148}
EXPORT_SIZE=225

ROLES=('policy','admission','canonical','hash','profile','scalar','abi')
MAGIC=int.from_bytes(b'HIAMVIK1','little')
RELOCATIONS=()
def fixed_parts():
    strings=b'\0hia_mv_intake\0'
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
    if len(flats)!=7 or any(not x or len(x)>4194304 for x in flats):raise ValueError('seven bounded actual HIA roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16));struct.pack_into('<i',raw,64+HOLES[role],len(raw)-64-HOLES[role]-4);raw.extend(flat)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original shared linker text domain')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for data in [relas,symbols,strings,base.SECTIONS]:offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def source_program():
    prefix,relas,symbols,strings,sections=fixed_parts();tail=relas+symbols+strings+base.SECTIONS
    functions=[];calls={}
    for name,raw in [('prefix',prefix),('tail',tail),('sections',sections)]:
        calls[name],src=base.emitters(name,raw);functions.append(src)
    src=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<192:
        return 4294967294
    if length(s)<72 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=7:
        return 4294967295
    count=0
    total=72
    while count<7:
        size=uint(s,16+count*8,8)
        if size==0 or size>4194304:
            return 4294967295
        write(w,count*8,size,8)
        total=total+size
        count=count+1
    if length(s)!=total:
        return 4294967295
    layout(w)
    if get(w,128)-64>16777216:
        return 4294967295
    size=get(w,184)
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for key,start in [('prefix','0'),('tail','get(w,136)'),('sections','get(w,176)')]:
        for fn in calls[key]:src+=f'    {fn}(o,{start})\n'
    src+='''    sections=get(w,176)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,128)-64,8)
    write(o,sections+152,get(w,136),8)
    write(o,sections+216,get(w,144),8)
    write(o,sections+280,get(w,152),8)
    write(o,sections+344,get(w,160),8)
    write(o,sections+408,get(w,168),8)
'''
    for i,role in enumerate(ROLES):src+=f'    write(o,{64+HOLES[role]},get(w,{64+8*i})-{64+HOLES[role]+4},4)\n'
    src+='''    at=72
    i=0
    while i<7:
        copy(s,o,at,get(w,64+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,184)
'''
    src+=f'''
def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<7:
        write(w,64+i*8,at,8)
        at=at+get(w,i*8)
        if i!=6:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,128,at,8)
    at=(at+7)&18446744073709551608
    write(w,136,at,8)
    at=at+{len(relas)}
    write(w,144,at,8)
    at=at+{len(symbols)}
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
'''
    return src+'\n\n'+'\n\n'.join(functions)+base.HELPERS

def main():
    tree=document(source_program(),'multiversion_intake_packer');p=ROOT/'examples/hia_bootstrap/multiversion_intake_packer.hepta';p.write_text(render_assembly(tree));print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
