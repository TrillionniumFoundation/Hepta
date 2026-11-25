"""HIA-only packaging of the multiversion image owner's mechanical capsule.

The assembler is used only by the independent development provenance check.
Production pack() emits an owned ET_REL from four actual HIA flat images.
The separate shared-linker profile preserves the existing general ELF grammar
and changes only its closed loader import vocabulary.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_shared_linker as shared
ROOT=Path(__file__).resolve().parents[1]
BRIDGE=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb48c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84ea00000083f801742683f802721783f804766883f8050f84a700000083f8060f84b0000000b8fdffffffe9c30000004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05eb6a89442450498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d28837c245002740e837c245003740ee800000000eb30e800000000eb29e800000000eb22498b7d004c01f7498b7508e800000000eb10498b7d00498b75084c01f6e80000000049894608e9f7feffff418b45084881c488000000415f415e415d415c5d5bc3')
RELOCATIONS=((292, 'dlopen'), (310, 'dlsym'))
HOLES={'policy': 77, 'sha': 267, 'elf': 274, 'mapping': 260}
EXPORT_SIZE=345
ROLES=('policy','sha','elf','mapping')
IMPORTS=('dlopen','dlsym')
MAGIC=int.from_bytes(b'HIAMVPK1','little')
SECTIONS=b'\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0'

def fixed_parts():
    names=('hia_mv_image',*IMPORTS)
    strings=bytearray(b'\0');positions={}
    for name in names:
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),
             struct.pack('<IBBHQQ',positions[names[0]],18,0,1,0,EXPORT_SIZE)]
    indexes={}
    for name in IMPORTS:
        indexes[name]=len(symbols)
        symbols.append(struct.pack('<IBBHQQ',positions[name],16,0,0,0,0))
    relas=b''.join(struct.pack('<QQq',off,(indexes[name]<<32)|4,-4) for off,name in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for name,kind,flags,size,link,info,align,extent in [
        ('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),
        ('.symtab',2,0,24*len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),
        ('.shstrtab',3,0,len(SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',SECTIONS.index(name.encode()+b'\0'),kind,flags,0,0,size,link,info,align,extent))
    return header+BRIDGE,relas,b''.join(symbols),bytes(strings),b''.join(rows)

def reference_object(flats):
    if len(flats)!=4 or any(not x or len(x)>4194304 for x in flats):raise ValueError('four bounded nonempty flat images required')
    prefix,relas,symbols,strings,sections=fixed_parts()
    raw=bytearray(prefix)
    for role,flat in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        struct.pack_into('<i',raw,64+HOLES[role],len(raw)-64-HOLES[role]-4)
        raw.extend(flat)
    if len(raw)-64>16777216:raise ValueError('owned text exceeds preserved linker domain')
    textsize=len(raw)-64;raw.extend(bytes((-len(raw))%8))
    offsets=[]
    for data in [relas,symbols,strings,SECTIONS]:
        offsets.append(len(raw));raw.extend(data)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8))
    sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh)
    struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,offset in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,offset)
    return bytes(raw)

def emitters(name,raw):
    funcs=[];calls=[]
    for group,start in enumerate(range(0,len(raw),384)):
        fn='emit_'+name+'_'+str(group);calls.append(fn)
        lines=[f'def {fn}(o:mutbuf, base:u64) -> u64:']
        for at in range(start,min(start+384,len(raw)),8):
            chunk=raw[at:at+8]
            if any(chunk):lines.append(f'    write(o, base + {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})')
        lines.append('    return 0');funcs.append('\n'.join(lines))
    return calls,'\n\n'.join(funcs)

def source_program():
    prefix,relas,symbols,strings,sections=fixed_parts()
    tail=relas+symbols+strings+SECTIONS
    functions=[];calls={}
    for name,raw in [('prefix',prefix),('tail',tail),('sections',sections)]:
        calls[name],src=emitters(name,raw);functions.append(src)
    src=f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w)<128:
        return 4294967294
    if length(s)<48 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=4:
        return 4294967295
    count=0
    total=48
    while count<4:
        size=uint(s,16+count*8,8)
        if size==0 or size>4194304:
            return 4294967295
        write(w,count*8,size,8)
        total=total+size
        count=count+1
    if length(s)!=total:
        return 4294967295
    layout(w)
    if get(w,64)-64>16777216:
        return 4294967295
    size=get(w,120)
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for key,base in [('prefix','0'),('tail','get(w,72)'),('sections','get(w,112)')]:
        for fn in calls[key]:src+=f'    {fn}(o,{base})\n'
    src+='''    sections=get(w,112)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,64)-64,8)
    write(o,sections+152,get(w,72),8)
    write(o,sections+216,get(w,80),8)
    write(o,sections+280,get(w,88),8)
    write(o,sections+344,get(w,96),8)
    write(o,sections+408,get(w,104),8)
'''
    for i,role in enumerate(ROLES):
        src+=f'    write(o,{64+HOLES[role]},get(w,{32+8*i})-{64+HOLES[role]+4},4)\n'
    src+='''    at=48
    i=0
    while i<4:
        copy(s,o,at,get(w,32+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,120)
'''
    src+=f'''
def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<4:
        write(w,32+i*8,at,8)
        at=at+get(w,i*8)
        if i!=3:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,64,at,8)
    at=(at+7)&18446744073709551608
    write(w,72,at,8)
    at=at+{len(relas)}
    write(w,80,at,8)
    at=at+{len(symbols)}
    write(w,88,at,8)
    at=at+{len(strings)}
    write(w,96,at,8)
    at=at+{len(SECTIONS)}
    write(w,104,at,8)
    at=(at+7)&18446744073709551608
    write(w,112,at,8)
    write(w,120,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value
'''
    return src+'\n\n'+'\n\n'.join(functions)+HELPERS

HELPERS='''
def copy(s:readbuf,o:mutbuf,source:u64,target:u64,count:u64) -> u64:
    i=0
    while i<count:
        store(o,target+i,byte(s,source+i))
        i=i+1
    return 0
def uint(s:readbuf,at:u64,count:u64) -> u64:
    value=0
    i=0
    while i<count:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value
def write(o:mutbuf,at:u64,value:u64,count:u64) -> u64:
    i=0
    while i<count:
        store(o,at+i,(value>>(8*i))&255)
        i=i+1
    return 0
'''

def shared_source():
    source=shared.source_program()
    start=source.index('\ndef allowed_import(');end=source.index('\ndef check_calls(',start)
    lines=['def allowed_import(s:readbuf,first:u64,end:u64) -> u64:']
    for bit,name in enumerate(('dlopen','dlsym','dlclose')):
        raw=name.encode()+bytes([0])
        lines += [f'    if end-first>={len(raw)} and uint(s,first,{len(raw)})=={int.from_bytes(raw,"little")}:',f'        return {1<<bit}']
    lines.append('    return 0')
    return source[:start]+'\n'+'\n'.join(lines)+'\n'+source[end:]

def main():
    roles=[('multiversion_image_packer',document(source_program(),'multiversion_image_packer')),
           ('multiversion_shared_linker',shared.document(shared_source(),'multiversion_shared_linker'))]
    for name,tree in roles:
        p=ROOT/'examples/hia_bootstrap'/(name+'.hepta');p.write_text(render_assembly(tree))
        print(name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
