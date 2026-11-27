"""Native ET_REL packaging of the complete fixed normalization/intake closure."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as base
from tools import generate_hia_multiversion_intake_packer as inner
from tools import generate_hia_multiversion_prepare_process_packer as proc
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fb000000100f82270100004881fd400100000f821a01000049c706000000004d89764048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84d300000083f80674dc83f801747683f805746383f807741283f8020f82c100000083f8040f87b8000000498b7e104c01f7498b7618498b56204c01f2498b4e284d8b46304d01f04d8b4e3883f802741183f803741383f8077415e800000000eb6de800000000eb66e800000000eb5fe800000000eb58498b46484885c0744f488b00eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f0549894608e90effffff418b4508eb05b8fdffffff4881c488000000415f415e415d415c5d5bc3')
OUTER_HOLES={"hash":213,"intake":227,"policy":114,"process":220,"raw":234}

ROLES=('prepare','process','intake','admission','canonical','hash','profile','scalar','abi','raw')
MAGIC=int.from_bytes(b'HIAMVNK2','little')
def bridges():
    raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));pp=len(raw);raw.extend(proc.BRIDGE);raw.extend(bytes((-len(raw))%16));ip=len(raw);raw.extend(inner.BRIDGE)
    for name,target in [('process',pp),('intake',ip)]:struct.pack_into('<i',raw,OUTER_HOLES[name],target-OUTER_HOLES[name]-4)
    holes={'prepare':[OUTER_HOLES['policy']],'process':[pp+proc.HOLES['policy']],'intake':[ip+inner.HOLES['policy']]}
    for name in ROLES[3:-1]:holes[name]=[ip+inner.HOLES[name]]
    holes['raw']=[OUTER_HOLES['raw']]
    holes['hash'].append(OUTER_HOLES['hash'])
    return bytes(raw),holes
BRIDGE,HOLES=bridges()
EXPORT_SIZE=len(OUTER)
def fixed_parts():
    strings=b'\0hia_mv_prepare_admission\0'
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
    if len(flats)!=10 or any(not x or len(x)>4194304 for x in flats):raise ValueError('ten bounded actual HIA roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        for hole in HOLES[name]:struct.pack_into('<i',raw,64+hole,len(raw)-64-hole-4)
        raw.extend(flat)
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
    if length(w)<328:
        return 4294967294
    if length(s)<96 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=10:
        return 4294967295
    count=0
    total=96
    while count<10:
        size=uint(s,16+count*8,8)
        if size==0 or size>4194304:
            return 4294967295
        write(w,count*8,size,8)
        total=total+size
        count=count+1
    if length(s)!=total:
        return 4294967295
    layout(w)
    if get(w,256)-64>16777216:
        return 4294967295
    size=get(w,320)
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for key,start in [('prefix','0'),('tail','get(w,272)'),('sections','get(w,312)')]:
        for fn in calls[key]:src+=f'    {fn}(o,{start})\n'
    src+='''    sections=get(w,312)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,256)-64,8)
    write(o,sections+152,get(w,272),8)
    write(o,sections+216,get(w,280),8)
    write(o,sections+280,get(w,288),8)
    write(o,sections+344,get(w,296),8)
    write(o,sections+408,get(w,304),8)
'''
    for i,name in enumerate(ROLES):
        for hole in HOLES[name]:src+=f'    write(o,{64+hole},get(w,{128+8*i})-{64+hole+4},4)\n'
    src+='''    at=96
    i=0
    while i<10:
        copy(s,o,at,get(w,128+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,320)
'''
    src+=f'''
def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<10:
        write(w,128+i*8,at,8)
        at=at+get(w,i*8)
        if i!=9:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,256,at,8)
    at=(at+7)&18446744073709551608
    write(w,272,at,8)
    at=at+{len(relas)}
    write(w,280,at,8)
    at=at+{len(symbols)}
    write(w,288,at,8)
    at=at+{len(strings)}
    write(w,296,at,8)
    at=at+{len(base.SECTIONS)}
    write(w,304,at,8)
    at=(at+7)&18446744073709551608
    write(w,312,at,8)
    write(w,320,at+448,8)
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
    t=document(source_program(),'multiversion_prepare_admission_packer');p=ROOT/'examples/hia_bootstrap/multiversion_prepare_admission_packer.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
