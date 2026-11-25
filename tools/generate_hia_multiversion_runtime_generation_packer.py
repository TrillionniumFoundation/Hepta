"""Native closed packing of the runtime's actual staged generation owner."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image_packer as common
from tools import generate_hia_multiversion_prepare_admission_packer as intake
from tools import generate_hia_multiversion_prepare_proof_packer as proof
from tools import generate_hia_multiversion_prepare_owner_packer as prepare
ROOT=Path(__file__).resolve().parents[1]
OUTER=bytes.fromhex('535541544155415641574881ec880000004989fc4989f74989d54889cd4d89c64c89cb4881fb000000200f82350100004881fd001000000f822801000049c7860000401f0000000048c70424000000004c897424084c896424104c896c24184c89e74c89fe4c89ea4889e94d89f04989d9e80000000085c00f84e100000083f8010f848200000083f8020f82da00000083f8080f87d1000000498b7d004c01f7498b7508498b55104c01f2498b4d184d8b45204d01f04d8b4d2883f802742083f803742283f804742483f805742683f806742883f807742ae800000000eb74e800000000eb6de800000000eb66e800000000eb5fe800000000eb58e800000000eb51e800000000eb4a4d8b550831c9498b44cd104d89d34183e3034a0304dc488944cc2049c1ea02ffc183f90672e0488b7c2420488b742428488b5424304c8b5424384c8b4424404c8b4c2448498b45000f054989860800401fe900ffffff418b4508eb05b8fdffffff4881c488000000415f415e415d415c5d5bc3')
OUTER_HOLES={'generation':114,'retirement':217,'intake':224,'proof':231,'prepare':238,'capture':245,'image':252,'probe':259}
ROLES=('generation',)+tuple('intake_'+x for x in intake.ROLES)+tuple('proof_'+x for x in proof.ROLES)+tuple('prepare_'+x for x in prepare.ROLES)
IMPORTS=('dlopen','dlsym','dlclose')
MAGIC=int.from_bytes(b'HIAMVGK2','little')
def bridges():
    raw=bytearray(OUTER);holes={k:[] for k in ROLES};holes['generation']=[OUTER_HOLES['generation']];rel=[]
    for name,module in [('intake',intake),('proof',proof),('prepare',prepare)]:
        raw.extend(bytes((-len(raw))%16));at=len(raw);raw.extend(module.BRIDGE)
        if name!='prepare':
            h=OUTER_HOLES[name];struct.pack_into('<i',raw,h,at-h-4)
        for role,positions in module.HOLES.items():
            if isinstance(positions,int):positions=[positions]
            holes[name+'_'+role]+=[at+x for x in positions]
        rel.extend((at+x,n) for x,n in getattr(module,'RELOCATIONS',()))
        if name=='prepare':
            holes['prepare_owner'].append(OUTER_HOLES['prepare'])
            for outer,inner in [('capture','build'),('image','image'),('probe','probe'),('retirement','retirement')]:
                ih=prepare.OUTER_HOLES[inner]
                target=at+ih+4+struct.unpack_from('<i',module.BRIDGE,ih)[0]
                oh=OUTER_HOLES[outer];struct.pack_into('<i',raw,oh,target-oh-4)
    return bytes(raw),holes,tuple(rel)
BRIDGE,HOLES,RELOCATIONS=bridges()
EXPORT_SIZE=len(OUTER)
def fixed_parts():
    strings=bytearray(b'\0');positions={}
    for n in ('hia_mv_runtime_generation',*IMPORTS):positions[n]=len(strings);strings.extend(n.encode()+b'\0')
    symbols=[bytes(24),struct.pack('<IBBHQQ',0,3,0,1,0,0),struct.pack('<IBBHQQ',positions['hia_mv_runtime_generation'],18,0,1,0,EXPORT_SIZE)]
    for n in IMPORTS:symbols.append(struct.pack('<IBBHQQ',positions[n],16,0,0,0,0))
    symbols=b''.join(symbols)
    relas=b''.join(struct.pack('<QQq',off,((3+IMPORTS.index(n))<<32)|4,-4) for off,n in RELOCATIONS)
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,0,0,64,0,0,64,7,5)
    rows=[bytes(64)]
    for n,t,f,z,l,i,a,e in [('.text',1,6,0,0,0,16,0),('.rela.text',4,0,len(relas),3,1,8,24),('.symtab',2,0,len(symbols),4,2,8,24),('.strtab',3,0,len(strings),0,0,1,0),('.shstrtab',3,0,len(common.SECTIONS),0,0,1,0),('.note.GNU-stack',1,0,0,0,0,1,0)]:
        rows.append(struct.pack('<IIQQQQIIQQ',common.SECTIONS.index(n.encode()+b'\0'),t,f,0,0,z,l,i,a,e))
    return header+BRIDGE,relas,symbols,bytes(strings),b''.join(rows)
def reference_object(flats):
    if len(flats)!=len(ROLES) or any(not x or len(x)>4194304 for x in flats):raise ValueError('all thirty-one actual bounded roles required')
    prefix,relas,symbols,strings,sections=fixed_parts();raw=bytearray(prefix)
    for name,part in zip(ROLES,flats):
        raw.extend(bytes((-len(raw))%16))
        for h in HOLES[name]:struct.pack_into('<i',raw,64+h,len(raw)-64-h-4)
        raw.extend(part)
    textsize=len(raw)-64
    if textsize>16777216:raise ValueError('original sixteen MiB text domain')
    raw.extend(bytes((-len(raw))%8));offsets=[]
    for part in (relas,symbols,strings,common.SECTIONS):offsets.append(len(raw));raw.extend(part)
    offsets.append(len(raw));raw.extend(bytes((-len(raw))%8));sh=len(raw);raw.extend(sections)
    struct.pack_into('<Q',raw,40,sh);struct.pack_into('<QQ',raw,sh+88,64,textsize)
    for i,off in enumerate(offsets,2):struct.pack_into('<Q',raw,sh+64*i+24,off)
    return bytes(raw)
def source_program():
    prefix,relas,symbols,strings,sections=fixed_parts();tail=relas+symbols+strings+common.SECTIONS
    n=len(ROLES);head=16+8*n;functions=[];calls={}
    assert n==31
    for name,raw in [('prefix',prefix),('tail',tail),('sections',sections)]:
        calls[name],src=common.emitters(name,raw);functions.append(src)
    src=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<1024:
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
    if get(w,768)-64>16777216:
        return 4294967295
    size=get(w,832)
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
    for key,start in [('prefix','0'),('tail','get(w,784)'),('sections','get(w,824)')]:
        for fn in calls[key]:src+=f'    {fn}(o,{start})\n'
    src+='''    sections=get(w,824)
    write(o,40,sections,8)
    write(o,sections+88,64,8)
    write(o,sections+96,get(w,768)-64,8)
    write(o,sections+152,get(w,784),8)
    write(o,sections+216,get(w,792),8)
    write(o,sections+280,get(w,800),8)
    write(o,sections+344,get(w,808),8)
    write(o,sections+408,get(w,816),8)
'''
    for i,name in enumerate(ROLES):
        for h in HOLES[name]:src+=f'    write(o,{64+h},get(w,{256+8*i})-{64+h+4},4)\n'
    src+=f'''    at={head}
    i=0
    while i<{n}:
        copy(s,o,at,get(w,256+i*8),get(w,i*8))
        at=at+get(w,i*8)
        i=i+1
    return get(w,832)

def layout(w:mutbuf) -> u64:
    at=({len(prefix)}+15)&18446744073709551600
    i=0
    while i<{n}:
        write(w,256+i*8,at,8)
        at=at+get(w,i*8)
        if i!={n-1}:
            at=(at+15)&18446744073709551600
        i=i+1
    write(w,768,at,8)
    at=(at+7)&18446744073709551608
    write(w,784,at,8)
    at=at+{len(relas)}
    write(w,792,at,8)
    at=at+{len(symbols)}
    write(w,800,at,8)
    at=at+{len(strings)}
    write(w,808,at,8)
    at=at+{len(common.SECTIONS)}
    write(w,816,at,8)
    at=(at+7)&18446744073709551608
    write(w,824,at,8)
    write(w,832,at+448,8)
    return 0

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(8*i))
        i=i+1
    return value
'''
    return src+'\n\n'+'\n\n'.join(functions)+common.HELPERS
def main():
    d=document(source_program(),'multiversion_runtime_generation_packer')
    p=ROOT/'examples/hia_bootstrap/multiversion_runtime_generation_packer.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks']) for f in d['functions']),flush=True)
if __name__=='__main__':main()
