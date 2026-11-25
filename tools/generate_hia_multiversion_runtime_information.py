"""Detached public generation/publication JSON from actual fixed-owner facts.

This private pure formatter grants no proof, mapping or publication authority.
The effect owner captures the supplied fields while the generation is alive.
All public decimal digits are emitted in full, not converted to a machine word.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
TYPES=('bool','i8','u8','i16','u16','i32','u32','i64','u64','isize','usize')
MAGIC=int.from_bytes(b'HIAMVGI1','little');REPLY=int.from_bytes(b'HIAMVIR2','little');ABI=int.from_bytes(b'HIAMVAB1','little');PUB=int.from_bytes(b'HIAMVPI1','little')
POLICY=r'''
def runtime_information(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)>=128 and length(w)>=8192:
        if word(s,0)==PUB:
            return publication(s,o,w)
    if length(s)<512 or length(w)<8192:
        return 4294967293
    if word(s,0)!=MAGIC or word(s,8)>1:
        return 4294967293
    gn=word(s,16)
    an=word(s,24)
    en=word(s,32)
    mn=word(s,40)
    if gn>length(s)-512 or en>length(s)-512-gn or an>length(s)-512-gn-en or mn!=length(s)-512-gn-en-an:
        return 4294967293
    if decimal(s,512,gn)==0 or word(s,48)>1 or word(s,88)>1:
        return 4294967293
    mode=word(s,8)
    if mode==0:
        if en!=0 or mn!=0 or word(s,96)!=0 or word(s,104)!=0:
            return 4294967293
    else:
        if decimal(s,512+gn,en)==0 or word(s,104)>=9223372036854775808:
            return 4294967293
    a=512+gn+en
    if an<16 or word(s,a)!=ABI:
        return 4294967293
    count=word(s,a+8)
    if count==0 or count>16 or an!=16+count*320 or word(s,280)!=count:
        return 4294967293
    if word(s,56)>count or word(s,64)>count or word(s,80)<64 or word(s,80)>67108864 or word(s,272)!=word(s,80):
        return 4294967293
    if (word(s,136)&15)!=15:
        return 4294967293
    used=0
    i=0
    while i<count:
        row=a+16+i*320
        index=word(s,row)
        n=word(s,row+8)
        argc=word(s,row+16)
        ret=word(s,row+24)
        if index>=count or (used&(1<<index))!=0 or n==0 or n>128 or argc>16 or ret==0 or ret>11 or word(s,288+i*8)>=word(s,80):
            return 4294967293
        used=used|(1<<index)
        j=0
        while j<n:
            if byte(s,row+32+j)==0 or byte(s,row+32+j)>127:
                return 4294967293
            j=j+1
        while j<128:
            if byte(s,row+32+j)!=0:
                return 4294967293
            j=j+1
        j=0
        while j<16:
            t=word(s,row+160+j*8)
            if j<argc:
                if t==0 or t>11:
                    return 4294967293
            elif t!=0:
                return 4294967293
            j=j+1
        j=288
        while j<320:
            if word(s,row+j)!=0:
                return 4294967293
            j=j+8
        i=i+1
    i=288+count*8
    while i<512:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    put(w,0,32)
    put(w,8,0)
    put(w,16,0)
    put(w,24,a)
    put(w,32,count)
    load_literals(w)
    render(s,o,w)
    if get(w,16)!=0:
        return 4294967293
    required=get(w,0)
    if length(o)<required:
        return 4294967294
    put(w,0,32)
    put(w,8,1)
    render(s,o,w)
    put(o,0,REPLY)
    put(o,8,word(s,8))
    put(o,16,0)
    put(o,24,required-32)
    return 0

def publication(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word(s,8)!=2:
        return 4294967293
    gn=word(s,16)
    en=word(s,24)
    mn=word(s,32)
    if gn==0 or gn>length(s)-128 or en>length(s)-128-gn or mn!=length(s)-128-gn-en:
        return 4294967293
    if decimal(s,128+gn,en)==0 or word(s,48)>=9223372036854775808:
        return 4294967293
    i=56
    while i<128:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    load_literals(w)
    put(w,0,32)
    put(w,8,0)
    put(w,16,0)
    publication_render(s,o,w)
    if get(w,16)!=0:
        return 4294967293
    required=get(w,0)
    if length(o)<required:
        return 4294967294
    put(w,0,32)
    put(w,8,1)
    publication_render(s,o,w)
    put(o,0,REPLY)
    put(o,8,1)
    put(o,16,0)
    put(o,24,required-32)
    return 0

def publication_render(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    LIT(o,w,"{\"generation\":")
    raw(s,o,w,128,word(s,16))
    LIT(o,w,",\"selection_epoch\":")
    raw(s,o,w,128+word(s,16),word(s,24))
    LIT(o,w,",\"prepare_ns\":")
    number(o,w,word(s,40))
    LIT(o,w,",\"max_prepare_ns\":")
    number(o,w,word(s,48))
    if word(s,32)!=0:
        LIT(o,w,",\"measurement_admission\":")
        raw(s,o,w,128+word(s,16)+word(s,24),word(s,32))
    emit(o,w,125)
    return 0


def render(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if word(s,8)==1:
        LIT(o,w,"{\"generation\":")
    information(s,o,w)
    if word(s,8)==1:
        LIT(o,w,",\"selection_epoch\":")
        raw(s,o,w,512+word(s,16),word(s,32))
        LIT(o,w,",\"prepare_ns\":")
        number(o,w,word(s,96))
        LIT(o,w,",\"max_prepare_ns\":")
        number(o,w,word(s,104))
        if word(s,40)!=0:
            LIT(o,w,",\"measurement_admission\":")
            raw(s,o,w,512+word(s,16)+word(s,32)+word(s,24),word(s,40))
        emit(o,w,125)
    return 0

def information(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    LIT(o,w,"{\"generation\":")
    raw(s,o,w,512,word(s,16))
    LIT(o,w,",\"program_sha256\":")
    digest(s,o,w,144)
    LIT(o,w,",\"input_sha256\":")
    digest(s,o,w,176)
    LIT(o,w,",\"artifact_sha256\":")
    digest(s,o,w,208)
    LIT(o,w,",\"artifact_bytes\":")
    number(o,w,word(s,80))
    LIT(o,w,",\"abi\":[")
    i=0
    while i<get(w,32):
        if i!=0:
            emit(o,w,44)
        row=get(w,24)+16+i*320
        LIT(o,w,"{\"function\":")
        quoted(s,o,w,row+32,word(s,row+8))
        LIT(o,w,",\"parameters\":[")
        j=0
        while j<word(s,row+16):
            if j!=0:
                emit(o,w,44)
            type_name(o,w,word(s,row+160+j*8))
            j=j+1
        LIT(o,w,"],\"result\":")
        type_name(o,w,word(s,row+24))
        emit(o,w,125)
        i=i+1
    LIT(o,w,"],\"translation_proofs\":")
    number(o,w,word(s,64))
    LIT(o,w,",\"native_probe_calls\":")
    number(o,w,word(s,72))
    LIT(o,w,",\"baseline\":")
    boolean(o,w,word(s,48))
    LIT(o,w,",\"admission_profile\":")
    if word(s,88)==0:
        LIT(o,w,"\"hepta.hia.scalar-multiversion.linux-x86_64.v1\"")
    else:
        LIT(o,w,"\"hepta.hia.scalar-multiversion-proved-total.linux-x86_64.v1\"")
    LIT(o,w,",\"totality_proofs\":")
    number(o,w,word(s,56))
    LIT(o,w,",\"loaded_mapping\":{\"schema\":\"hepta.native.loaded-symbol-identity.v1\",\"device_major\":")
    number(o,w,word(s,112))
    LIT(o,w,",\"device_minor\":")
    number(o,w,word(s,120))
    LIT(o,w,",\"inode\":")
    number(o,w,word(s,128))
    LIT(o,w,",\"file_bytes\":")
    number(o,w,word(s,272))
    LIT(o,w,",\"seals\":")
    number(o,w,word(s,136))
    LIT(o,w,",\"symbols\":{")
    i=0
    while i<get(w,32):
        if i!=0:
            emit(o,w,44)
        row=get(w,24)+16+i*320
        quoted(s,o,w,row+32,word(s,row+8))
        LIT(o,w,":{\"file_offset\":")
        number(o,w,word(s,288+i*8))
        LIT(o,w,",\"permissions\":\"r-xp\"}")
        i=i+1
    LIT(o,w,"},\"basis\":\"actual entry address in kernel executable mapping of the sealed descriptor\",\"serialized_evidence_is_authority\":false,\"checker_sha256\":")
    digest(s,o,w,240)
    LIT(o,w,"}}")
    return 0

def type_name(o:mutbuf,w:mutbuf,t:u64) -> u64:
TYPE_CASES
    return 0

def decimal(s:readbuf,at:u64,n:u64) -> u64:
    if n==0 or (n>1 and byte(s,at)==48):
        return 0
    i=0
    while i<n:
        c=byte(s,at+i)
        if c<48 or c>57:
            return 0
        i=i+1
    return 1

def boolean(o:mutbuf,w:mutbuf,b:u64) -> u64:
    if b==0:
        LIT(o,w,"false")
    else:
        LIT(o,w,"true")
    return 0

def number(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if value==0:
        emit(o,w,48)
        return 0
    i=0
    while value!=0:
        divided=divide10(value)
        digit=value-divided*10
        store(w,64+i,48+digit)
        value=divided
        i=i+1
    while i>0:
        i=i-1
        emit(o,w,byte(w,64+i))
    return 0

def divide10(value:u64) -> u64:
    result=0
    remainder=0
    bit=64
    while bit>0:
        bit=bit-1
        remainder=(remainder<<1)|((value>>bit)&1)
        result=result<<1
        if remainder>=10:
            remainder=remainder-10
            result=result|1
    return result


def digest(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    emit(o,w,34)
    i=0
    while i<32:
        c=byte(s,at+i)
        emit(o,w,hex_digit(c>>4))
        emit(o,w,hex_digit(c&15))
        i=i+1
    emit(o,w,34)
    return 0

def hex_digit(c:u64) -> u64:
    if c<10:
        return 48+c
    return 87+c

def quoted(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    emit(o,w,34)
    i=0
    while i<n:
        c=byte(s,at+i)
        if c==34 or c==92:
            emit(o,w,92)
            emit(o,w,c)
        elif c<32:
            emit(o,w,92)
            emit(o,w,117)
            emit(o,w,48)
            emit(o,w,48)
            emit(o,w,hex_digit(c>>4))
            emit(o,w,hex_digit(c&15))
        else:
            emit(o,w,c)
        i=i+1
    emit(o,w,34)
    return 0

def raw(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        emit(o,w,byte(s,at+i))
        i=i+1
    return 0

def literal(o:mutbuf,w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        emit(o,w,byte(w,1024+at+i))
        i=i+1
    return 0

def emit(o:mutbuf,w:mutbuf,c:u64) -> u64:
    at=get(w,0)
    if at==18446744073709551615:
        put(w,16,1)
        return 0
    if get(w,8)==1:
        store(o,at,c)
    put(w,0,at+1)
    return 0

def word(s:readbuf,at:u64) -> u64:
    result=0
    i=0
    while i<8:
        result=result|(byte(s,at+i)<<(i*8))
        i=i+1
    return result

def get(s:mutbuf,at:u64) -> u64:
    result=0
    i=0
    while i<8:
        result=result|(byte(s,at+i)<<(i*8))
        i=i+1
    return result

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(8*i))&255)
        i=i+1
    return 0
'''
def source_program():
    import json
    src=POLICY.replace('TYPE_CASES','\n'.join('    if t==%d:\n        LIT(o,w,%s)\n        return 0'%(i,json.dumps('"'+name+'"')) for i,name in enumerate(TYPES,1)))
    table=bytearray();known={}
    def lit(m):
        data=json.loads(m.group(1)).encode()
        if data not in known:known[data]=len(table);table.extend(data)
        return 'literal(o,w,%d,%d)'%(known[data],len(data))
    src=re.sub(r'LIT\(o,w,("(?:\\.|[^"\\])*")\)',lit,src)
    assert len(table)<4096
    load=['def load_literals(w:mutbuf) -> u64:']
    for at in range(0,len(table),8):
        data=bytes(table[at:at+8]).ljust(8,b'\0')
        load.append('    put(w,%d,%d)'%(1024+at,int.from_bytes(data,'little')))
    load.append('    return 0')
    src+='\n'+'\n'.join(load)+'\n'
    for k,v in [('MAGIC',MAGIC),('REPLY',REPLY),('ABI',ABI),('PUB',PUB)]:src=re.sub(r'\b'+k+r'\b',str(v),src)
    return src
def main():
    t=document(source_program(),'runtime_information')
    p=ROOT/'examples/hia_bootstrap/multiversion_runtime_information.hepta';p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),sum(len(b['ops']) for f in t['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
