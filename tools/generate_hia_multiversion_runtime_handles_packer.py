"""Fixed owned runtime/lease carrier and the qualified 43-role HIA runtime."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_shared_linker as shared
from tools import generate_hia_multiversion_runtime_effects_packer as effects
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000000060f82b40100004881fb000100000f82a701000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f846b01000083f80a74dc83f8010f848e00000083f8020f84d100000083f8030f84dd00000083f8040f84e300000083f8060f84e300000083f8070f84e500000083f8080f84e900000083f80c0f851e01000031c9498b44cd004883f8030f8708010000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d40e800000000e9be0000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb72498b55004c01f2418b4508418b4d10f00fb10aeb5d498b55004c01f2418b45088702eb4e498b45004c01e8eb45498b7d00e800000000eb3a498b7d00e80000000031c0eb2d498b45004883f803772f498b7508480334c4498b45104883f803771d498b7d1848033cc4498b4d20fcf3a431c049898578010000e97bfeffffb8fdffffff4881c498000000415f415e415d415c5d5bc3')
OUTER_HOLES={'handles': 114, 'effects': 273}
OUTER_RELOCATIONS=((408, 'malloc'), (419, 'free'))
IMPORTS=effects.IMPORTS
ROLES=('handles',)+effects.ROLES
MAGIC=int.from_bytes(b'HIAMVHK2','little')
EXPORT_SIZE=len(OUTER)
SIZE_HOLE=((len(OUTER)+15)&~15)+effects.SIZE_HOLE
def bridges():
 raw=bytearray(OUTER);raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(effects.BRIDGE)
 h=OUTER_HOLES['effects'];struct.pack_into('<i',raw,h,at-h-4)
 holes={'handles':[OUTER_HOLES['handles']]}
 holes.update({name:[at+x for x in values] for name,values in effects.HOLES.items()})
 return bytes(raw),holes,tuple(OUTER_RELOCATIONS)+tuple((at+x,symbol) for x,symbol in effects.RELOCATIONS)
BRIDGE,HOLES,RELOCATIONS=bridges()
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_mv_runtime_handles',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_mv_runtime_handles'],18,0,1,0,EXPORT_SIZE)]
    for name in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((3+IMPORTS.index(name))<<32)|4,-4) for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def reference_object(flats):
    if len(flats)!=len(ROLES) or any(not f or len(f)>4194304 for f in flats):raise ValueError('all fixed actual roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        for h in HOLES[role]:struct.pack_into('<i',raw,64+h,len(raw)-64-h-4)
        raw.extend(flat)
    struct.pack_into('<I',raw,64+SIZE_HOLE,len(flats[ROLES.index('gen_prepare_mapping')]))
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original sixteen MiB text bound')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in (relas,symbols,strings,common.SECTIONS):offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def source_program():
    prefix,relas,symbols,strings,sections=fixed_parts();tail=relas+symbols+strings+common.SECTIONS
    n=len(ROLES);head=16+8*n;functions=[];calls={}
    assert n<=64
    for name,raw in [('prefix',prefix),('tail',tail),('sections',sections)]:
        calls[name],src=common.emitters(name,raw);functions.append(src)
    source=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<2048:
        return 4294967294
    if length(s)<{head} or uint(s,0,8)!={MAGIC} or uint(s,8,8)!={n}:
        return 4294967295
    count=0
    total={head}
    while count<{n}:
        size=uint(s,16+count*8,8)
        if size==0 or size>4194304:
            return 4294967295
        write(w,count*8,size,8)
        total=total+size
        count=count+1
    if total!=length(s):
        return 4294967295
    layout(w)
    if get(w,1024)-64>16777216:
        return 4294967295
    size=get(w,1088)
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for name,start in [('prefix','0'),('tail','get(w,1040)'),('sections','get(w,1080)')]:
        for fn in calls[name]:source+=f'    {fn}(o,{start})\n'
    source+='''    sections=get(w,1080)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,1024)-64,8)
    write(o,sections+152,get(w,1040),8)
    write(o,sections+216,get(w,1048),8)
    write(o,sections+280,get(w,1056),8)
    write(o,sections+344,get(w,1064),8)
    write(o,sections+408,get(w,1072),8)
'''
    for i,name in enumerate(ROLES):
        for h in HOLES[name]:source+=f'    write(o,{64+h},get(w,{512+8*i})-{64+h+4},4)\n'
    source+=f'    write(o,{64+SIZE_HOLE},get(w,{8*ROLES.index("gen_prepare_mapping")}),4)\n'
    source+=f'''    at={head}
    i=0
    while i<{n}:
        copy(s,o,at,get(w,512+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,1088)

def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<{n}:
        write(w,512+i*8,at,8)
        at=at+get(w,i*8)
        if i!={n-1}:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,1024,at,8)
    at=(at+7)&18446744073709551608
    write(w,1040,at,8)
    at=at+{len(relas)}
    write(w,1048,at,8)
    at=at+{len(symbols)}
    write(w,1056,at,8)
    at=at+{len(strings)}
    write(w,1064,at,8)
    at=at+{len(common.SECTIONS)}
    write(w,1072,at,8)
    at=(at+7)&18446744073709551608
    write(w,1080,at,8)
    write(w,1088,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value
'''
    return source+'\n\n'+'\n\n'.join(functions)+common.HELPERS
def linker_source():
    source=shared.source_program()
    start=source.index('\ndef allowed_import(');end=source.index('\ndef check_calls(',start)
    lines=['def allowed_import(s:readbuf,first:u64,end:u64) -> u64:']
    for bit,name in enumerate(IMPORTS):
        raw=name.encode()+bytes([0])
        lines += [f'    if end-first>={len(raw)} and uint(s,first,{len(raw)})=={int.from_bytes(raw,"little")}:',f'        return {1<<bit}']
    lines.append('    return 0')
    return source[:start]+'\n'+'\n'.join(lines)+'\n'+source[end:]
def main():
 d=document(source_program(),'multiversion_runtime_handles_packer')
 p=ROOT/'examples/hia_bootstrap/multiversion_runtime_handles_packer.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks']) for f in d['functions']),flush=True)
if __name__=='__main__':main()
