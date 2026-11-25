"""Closed native packaging of the MV runtime effect composition.

The fixed bridge provides OS facts and calls only the embedded role entries.
All decisions, lock ordering, acquisition and retirement are HIA policies.
"""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_shared_linker as shared
from tools import generate_hia_multiversion_runtime_generation_packer as generation
from tools import generate_hia_multiversion_runtime_identity_packer as identity
from tools import generate_hia_multiversion_future_packer as future
from tools import generate_hia_multiversion_measurement_packer as measurement
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ec980000004989fc4989f74989d54889cd4d89c64c89cb4881fd000080020f822b0300004881fb000002000f821e03000049c785800000000000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000083f8190f843701000085c00f84ce02000083f80a74d383f8010f84a501000083f8020f84eb01000083f8030f84f701000083f8040f84fd01000083f8060f840002000083f8070f840502000083f8080f840902000083f8150f842f02000083f8160f84f500000083f817741783f818741283f80c0f827002000083f8140f87670200008944245031c9498b44cd004883f8030f874d020000498b54cd08480314c4488954cc5883c10383f90972db488b7c2458498b7510488b542470498b4d284c8b8424880000004d8b4d408b44245083f817745783f818745c83f80c0f849100000083f80d0f849200000083f80e0f849300000083f80f0f849400000083f8100f849500000083f8110f849600000083f8120f849700000083f8130f8498000000e800000000e9a7010000e800000000e99d010000e800000000e9930100004c89e74c89fe4c89ea4889e94d89f04989d9e800000000e9a4feffff488d0500000000b90000000049898d20800000e95f010000e800000000e955010000e800000000e94b010000e800000000e941010000e800000000e937010000e800000000e92d010000e800000000e923010000e800000000e919010000e800000000e90f0100004d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f05e9c0000000498b5500418b4508418b4d10f00fb10ae9ab000000498b5500418b45088702e99c000000498b45004c01f0e990000000498b7d00e800000000e982000000498b7d00e80000000031c0eb75498b45004883f803777d498b7508480334c4498b45104883f803776b498b7d1848033cc4498b4d20fcf3a431c0eb464d8b5d0049837d0810774d4d8b55104d01ea4883ec5031c9498b44ca30488904ccffc183f90a72f0498b3a498b7208498b5210498b4a184d8b42204d8b4a2841ffd34883c45049898588000000e90afdffff418b4508eb05b8fdffffff4881c498000000415f415e415d415c5d5bc3')
OUTER_HOLES={'effects': 114, 'typed': 409, 'information': 419, 'hash': 429, 'capture': 457, 'mapping_span': 469, 'mapping_size': 474, 'generation': 491, 'identity': 501, 'state': 511, 'retention': 521, 'future': 531, 'call': 541, 'measure': 551, 'directory': 561}
OUTER_RELOCATIONS=((702, 'malloc'), (716, 'free'))
SIZE_HOLE=OUTER_HOLES['mapping_size']
IMPORTS=('dlopen','dlsym','dlclose','malloc','free')
ROLES=('effects','state','retention','call','typed','information','information_capture')+tuple('gen_'+x for x in generation.ROLES)+tuple('identity_'+x for x in identity.ROLES)+('future',)+tuple('measurement_'+x for x in measurement.ROLES)
MAGIC=int.from_bytes(b'HIAMVEK2','little')
EXPORT_SIZE=len(OUTER)
def bridges():
    raw=bytearray(OUTER)
    holes={name:[] for name in ROLES}
    for name in ('effects','state','retention','call','typed'):holes[name]=[OUTER_HOLES[name]]
    holes['information']=[OUTER_HOLES['information']]
    holes['information_capture']=[OUTER_HOLES['capture']]
    holes['gen_proof_hash']=[OUTER_HOLES['hash']]
    holes['gen_prepare_mapping']=[OUTER_HOLES['mapping_span']]
    holes['gen_prepare_retirement_state']=[OUTER_HOLES['directory']]
    relocations=list(OUTER_RELOCATIONS)
    for name,module,prefix in [('generation',generation,'gen_'),('identity',identity,'identity_'),('future',future,''),('measure',measurement,'measurement_')]:
        raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(module.BRIDGE)
        h=OUTER_HOLES[name];struct.pack_into('<i',raw,h,at-h-4)
        for role,positions in module.HOLES.items():
            if isinstance(positions,int):positions=[positions]
            target='future' if name=='future' else prefix+role
            holes[target].extend(at+x for x in positions)
        relocations.extend((at+x,symbol) for x,symbol in module.RELOCATIONS)
    assert all(holes.values())
    return bytes(raw),holes,tuple(relocations)
BRIDGE,HOLES,RELOCATIONS=bridges()
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for name in ('hia_mv_runtime_effects',*IMPORTS):
        positions[name]=len(strings);strings.extend(name.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_mv_runtime_effects'],18,0,1,0,EXPORT_SIZE)]
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
    for name,t in [('multiversion_runtime_effects_packer',document(source_program(),'multiversion_runtime_effects_packer')),('multiversion_runtime_linker',shared.document(linker_source(),'multiversion_runtime_linker'))]:
        p=ROOT/'examples/hia_bootstrap'/(name+'.hepta');p.write_text(render_assembly(t))
        print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
