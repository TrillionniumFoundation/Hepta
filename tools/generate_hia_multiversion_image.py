"""HIA generation image capture, seal, loader and mapping custody.

Private synchronous owner. All state decisions and role requests are HIA;
mechanical actions perform one syscall, one fixed native role call, dlopen or
dlsym. The caller supplies an actual native-build binding, never a public proof
boolean. Failure returns the same retained pin/memfd/library holder for the
existing retirement owner, and does not guess that an uncertain close succeeded.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from hepta.hia_safe_core_elf_inventory_native import OWNED_SHARED_EXPECTED_WORK,OWNED_SHARED_SYMBOL_WORK,OWNED_SHARED_SYMBOL_CAPACITY,OWNED_SHARED_SYMBOL_HEAD
ROOT=Path(__file__).resolve().parents[1]
CONSTANTS={
'NONE':(1<<64)-1,'INPUT_MAGIC':int.from_bytes(b'HIAMVI01','little'),'STATE_MAGIC':int.from_bytes(b'HIAMVIS1','little'),
'RESULT_MAGIC':int.from_bytes(b'HIAMVIR1','little'),'ABI_MAGIC':int.from_bytes(b'HIAMVAB1','little'),
'ELF_MAGIC':int.from_bytes(b'HIAELFA2','little'),'MAP_MAGIC':int.from_bytes(b'HIAMAP01','little'),'MAP_REPLY':int.from_bytes(b'HIAMPR01','little'),
'WORK_BYTES':160<<20,'PATH':8192,'MEMNAME':12288,'FDPATH':12544,'SYMNAME':12800,'MAPSPATH':13056,
'ABI':65536,'SHA_OUT':16384,'SHA_WORK':20480,'SHA_CHUNK':5<<20,
'ELF_WORK':1<<20,'ELF_OUT':3<<20,'ELF_WORK_SIZE':OWNED_SHARED_EXPECTED_WORK,'ELF_OUT_SIZE':OWNED_SHARED_SYMBOL_CAPACITY,'ELF_SYMBOL_WORK':OWNED_SHARED_SYMBOL_WORK,'ELF_HEAD':OWNED_SHARED_SYMBOL_HEAD,
'DATA':8<<20,'READBACK':73<<20,'MAPS':140<<20,'MAP_WORK':158<<20,'MAP_OUT':(158<<20)+8192
}
POLICY=r'''
def multiversion_image(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<WORK_BYTES or length(o)<512:
        return 4294967293
    phase=get(w,0)
    if phase==0:
        return image_begin(s,o,w)
    if get(w,16)!=STATE_MAGIC:
        return 4294967293
    if phase<40:
        return image_capture(s,o,w,phase)
    if phase<60:
        return image_seal(s,o,w,phase)
    if phase<90:
        return image_load(s,o,w,phase)
    if phase==900:
        if get(w,8)>=18446744073709547521:
            put(w,176,get(w,8))
        put(w,0,902)
        return image_fail(o,w,get(w,88),get(w,96))
    if phase==901:
        put(w,192,choose(get(w,8)==0,1,0))
        put(w,0,902)
        return image_result(o,w)
    if phase==902 or phase==999:
        return image_result(o,w)
    return 4294967293

def image_begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or readword(s,0)!=INPUT_MAGIC:
        return 4294967293
    path_n=readword(s,8)
    abi_n=readword(s,16)
    expected_n=readword(s,24)
    if path_n==0 or path_n>4095 or path_n>length(s)-64:
        return 4294967293
    if abi_n!=length(s)-64-path_n or abi_n<16:
        return 4294967293
    a=64+path_n
    if readword(s,a)!=ABI_MAGIC:
        return 4294967293
    count=readword(s,a+8)
    if count==0 or count>16 or abi_n!=16+count*320 or expected_n<64 or expected_n>67108864:
        return 4294967293
    i=0
    while i<path_n:
        if byte(s,64+i)==0:
            return 4294967293
        store(w,PATH+i,byte(s,64+i))
        i=i+1
    store(w,PATH+path_n,0)
    i=0
    while i<abi_n:
        store(w,ABI+i,byte(s,a+i))
        i=i+1
    i=0
    while i<count:
        record=ABI+16+i*320
        name_n=get(w,record+8)
        if name_n==0 or name_n>128 or get(w,record+16)>16 or get(w,record+24)==0 or get(w,record+24)>11:
            return 4294967293
        j=0
        while j<name_n:
            ch=byte(w,record+32+j)
            if ch==0 or ch>127:
                return 4294967293
            j=j+1
        i=i+1
    i=16
    while i<4096:
        store(w,i,0)
        i=i+1
    put(w,16,STATE_MAGIC)
    put(w,32,NONE)
    put(w,40,NONE)
    put(w,48,NONE)
    put(w,64,expected_n)
    put(w,80,count)
    i=0
    while i<32:
        store(w,1700+i,byte(s,32+i))
        i=i+1
    return image_syscall(o,w,10,39,0,0,0,0,0,0,0)

def image_capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    raw=get(w,8)
    if phase==10:
        if raw==0 or raw>=18446744073709547521:
            return image_fail(o,w,1,raw)
        put(w,24,raw)
        return image_syscall(o,w,11,262,20,18446744073709551516,PATH,512,256,0,0)
    if phase==11:
        if raw==18446744073709551612:
            return image_syscall(o,w,11,262,20,18446744073709551516,PATH,512,256,0,0)
        if raw!=0:
            return image_fail(o,w,2,raw)
        put(w,104,1)
        return image_syscall(o,w,12,257,4,18446744073709551516,PATH,657408,0,0,0)
    if phase==12:
        if raw==18446744073709551612:
            return image_syscall(o,w,12,257,4,18446744073709551516,PATH,657408,0,0,0)
        if raw>=18446744073709547521:
            return image_fail(o,w,3,raw)
        put(w,32,raw)
        return image_syscall(o,w,13,5,4,raw,656,0,0,0,0)
    if phase==13:
        if raw==18446744073709551612:
            return image_syscall(o,w,13,5,4,get(w,32),656,0,0,0,0)
        if raw!=0:
            return image_fail(o,w,4,raw)
        if (get(w,512+24)&61440)!=32768 or (get(w,656+24)&61440)!=32768 or get(w,512)!=get(w,656) or get(w,520)!=get(w,664):
            return image_fail(o,w,5,0)
        return image_syscall(o,w,14,262,20,18446744073709551516,PATH,800,256,0,0)
    if phase==14:
        if raw==18446744073709551612:
            return image_syscall(o,w,14,262,20,18446744073709551516,PATH,800,256,0,0)
        if raw!=0:
            return image_fail(o,w,4,raw)
        if get(w,800)!=get(w,656) or get(w,808)!=get(w,664):
            return image_fail(o,w,5,0)
        put(w,112,1)
        return image_syscall(o,w,20,257,4,18446744073709551516,PATH,657408,0,0,0)
    if phase==20:
        if raw==18446744073709551612:
            return image_syscall(o,w,20,257,4,18446744073709551516,PATH,657408,0,0,0)
        if raw>=18446744073709547521:
            return image_fail(o,w,6,raw)
        put(w,40,raw)
        return image_syscall(o,w,21,5,4,raw,944,0,0,0,0)
    if phase==21:
        if raw==18446744073709551612:
            return image_syscall(o,w,21,5,4,get(w,40),944,0,0,0,0)
        if raw!=0:
            return image_fail(o,w,7,raw)
        n=get(w,944+48)
        if (get(w,944+24)&61440)!=32768 or n<64 or n>67108864:
            return image_fail(o,w,8,0)
        put(w,200,n)
        put(w,72,0)
        return image_syscall(o,w,22,0,4,get(w,40),DATA,n+1,0,0,0)
    if phase==22:
        used=get(w,72)
        n=get(w,200)
        if raw==18446744073709551612:
            return image_syscall(o,w,22,0,4,get(w,40),DATA+used,n+1-used,0,0,0)
        if raw>=18446744073709547521 or raw>n+1-used:
            return image_fail(o,w,9,raw)
        used=used+raw
        put(w,72,used)
        if used>n:
            return image_fail(o,w,10,0)
        if raw!=0:
            return image_syscall(o,w,22,0,4,get(w,40),DATA+used,n+1-used,0,0,0)
        if used!=n:
            return image_fail(o,w,10,0)
        return image_syscall(o,w,23,5,4,get(w,40),1088,0,0,0,0)
    if phase==23:
        if raw==18446744073709551612:
            return image_syscall(o,w,23,5,4,get(w,40),1088,0,0,0,0)
        if raw!=0:
            return image_fail(o,w,7,raw)
        if image_same_stat(w,944,1088)==0:
            return image_fail(o,w,10,0)
        return image_syscall(o,w,24,262,20,18446744073709551516,PATH,1232,256,0,0)
    if phase==24:
        if raw==18446744073709551612:
            return image_syscall(o,w,24,262,20,18446744073709551516,PATH,1232,256,0,0)
        if raw!=0:
            return image_fail(o,w,7,raw)
        if image_same_stat(w,944,1232)==0 or get(w,944)!=get(w,656) or get(w,952)!=get(w,664):
            return image_fail(o,w,10,0)
        fd=get(w,40)
        put(w,40,NONE)
        return image_syscall(o,w,25,3,0,fd,0,0,0,0,0)
    if phase==25:
        if raw!=0:
            put(w,176,raw)
            return image_fail(o,w,11,raw)
        if get(w,200)!=get(w,64):
            return image_fail(o,w,12,0)
        store(w,SHA_CHUNK,0)
        return image_role(o,w,40,2,SHA_CHUNK,1,SHA_OUT,32,SHA_WORK,1184)
    return 4294967293

def image_seal(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    raw=get(w,8)
    if phase==40:
        if raw!=0:
            return image_fail(o,w,13,raw)
        put(w,72,0)
        return image_hash_chunk(o,w)
    if phase==41:
        if raw!=0:
            return image_fail(o,w,13,raw)
        put(w,72,get(w,72)+get(w,152))
        return image_hash_chunk(o,w)
    if phase==42:
        if raw!=32 or image_equal(w,SHA_OUT,1700,32)==0:
            return image_fail(o,w,12,raw)
        put(w,ELF_WORK,ELF_MAGIC)
        put(w,ELF_WORK+ELF_SYMBOL_WORK,get(w,80))
        i=0
        while i<get(w,80):
            source=ABI+16+i*320
            n=get(w,source+8)
            target=ELF_WORK+ELF_SYMBOL_WORK+8+i*520
            put(w,target,n)
            image_copy(w,target+8,source+32,n)
            i=i+1
        return image_role(o,w,43,3,DATA,get(w,64),ELF_OUT,ELF_OUT_SIZE,ELF_WORK,ELF_WORK_SIZE)
    if phase==43:
        if raw<64 or raw>ELF_OUT_SIZE:
            return image_fail(o,w,14,raw)
        count=get(w,ELF_OUT+8)
        if get(w,ELF_OUT)!=0 or count>65536 or get(w,ELF_OUT+16)!=1 or raw!=ELF_HEAD+count*24:
            return image_fail(o,w,14,get(w,ELF_OUT))
        i=24
        while i<64:
            if get(w,ELF_OUT+i)!=0:
                return image_fail(o,w,14,0)
            i=i+8
        image_memname(w)
        return image_syscall(o,w,44,319,1,MEMNAME,3,0,0,0,0)
    if phase==44:
        if raw>=18446744073709547521:
            return image_fail(o,w,15,raw)
        put(w,48,raw)
        put(w,72,0)
        return image_syscall(o,w,45,1,4,raw,DATA,get(w,64),0,0,0)
    if phase==45:
        used=get(w,72)
        if raw==18446744073709551612:
            return image_syscall(o,w,45,1,4,get(w,48),DATA+used,get(w,64)-used,0,0,0)
        if raw==0 or raw>=18446744073709547521 or raw>get(w,64)-used:
            return image_fail(o,w,16,raw)
        used=used+raw
        put(w,72,used)
        if used<get(w,64):
            return image_syscall(o,w,45,1,4,get(w,48),DATA+used,get(w,64)-used,0,0,0)
        return image_syscall(o,w,46,72,0,get(w,48),1033,15,0,0,0)
    if phase==46:
        if raw==18446744073709551612:
            return image_syscall(o,w,46,72,0,get(w,48),1033,15,0,0,0)
        if raw!=0:
            return image_fail(o,w,17,raw)
        return image_syscall(o,w,47,72,0,get(w,48),1034,0,0,0,0)
    if phase==47:
        if raw==18446744073709551612:
            return image_syscall(o,w,47,72,0,get(w,48),1034,0,0,0,0)
        if raw!=15:
            return image_fail(o,w,17,raw)
        return image_syscall(o,w,48,17,4,get(w,48),READBACK,get(w,64)+1,0,0,0)
    if phase==48:
        if raw==18446744073709551612:
            return image_syscall(o,w,48,17,4,get(w,48),READBACK,get(w,64)+1,0,0,0)
        if raw!=get(w,64) or image_equal(w,DATA,READBACK,get(w,64))==0:
            return image_fail(o,w,18,raw)
        image_fdpath(w,get(w,48))
        put(w,0,60)
        put(o,0,FDPATH)
        put(o,8,2)
        return 5
    return 4294967293

def image_load(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    raw=get(w,8)
    if phase==60:
        if raw==0:
            return image_fail(o,w,19,0)
        put(w,56,raw)
        put(w,208,0)
        return image_symbol(o,w)
    if phase==61:
        if raw==0:
            return image_fail(o,w,20,0)
        i=get(w,208)
        put(w,2048+i*8,raw)
        put(w,208,i+1)
        return image_symbol(o,w)
    if phase==62:
        if raw==18446744073709551612:
            return image_syscall(o,w,62,5,4,get(w,48),1376,0,0,0,0)
        if raw!=0:
            return image_fail(o,w,21,raw)
        if (get(w,1376+24)&61440)!=32768 or get(w,1376+48)!=get(w,64):
            return image_fail(o,w,21,0)
        return image_syscall(o,w,63,72,0,get(w,48),1034,0,0,0,0)
    if phase==63:
        if raw==18446744073709551612:
            return image_syscall(o,w,63,72,0,get(w,48),1034,0,0,0,0)
        if raw>=18446744073709547521 or (raw&15)!=15:
            return image_fail(o,w,21,raw)
        image_maps_path(w)
        return image_syscall(o,w,64,257,4,18446744073709551516,MAPSPATH,524288,0,0,0)
    if phase==64:
        if raw==18446744073709551612:
            return image_syscall(o,w,64,257,4,18446744073709551516,MAPSPATH,524288,0,0,0)
        if raw>=18446744073709547521:
            return image_fail(o,w,22,raw)
        put(w,40,raw)
        put(w,72,0)
        return image_syscall(o,w,65,0,4,raw,MAPS,16777217,0,0,0)
    if phase==65:
        used=get(w,72)
        if raw==18446744073709551612:
            return image_syscall(o,w,65,0,4,get(w,40),MAPS+used,16777217-used,0,0,0)
        if raw>=18446744073709547521 or raw>16777217-used:
            return image_fail(o,w,22,raw)
        used=used+raw
        put(w,72,used)
        if used>16777216:
            return image_fail(o,w,23,0)
        if raw!=0:
            return image_syscall(o,w,65,0,4,get(w,40),MAPS+used,16777217-used,0,0,0)
        fd=get(w,40)
        put(w,40,NONE)
        return image_syscall(o,w,66,3,0,fd,0,0,0,0,0)
    if phase==66:
        if raw!=0:
            put(w,176,raw)
            return image_fail(o,w,22,raw)
        dev=get(w,1376)
        put(w,MAP_WORK,MAP_MAGIC)
        put(w,MAP_WORK+8,get(w,80))
        put(w,MAP_WORK+16,((dev&1048320)>>8)|((dev&18446726481523507200)>>32))
        put(w,MAP_WORK+24,(dev&255)|((dev&17592184995840)>>12))
        put(w,MAP_WORK+32,get(w,1384))
        put(w,MAP_WORK+40,get(w,64))
        put(w,MAP_WORK+48,4300)
        put(w,MAP_WORK+56,0)
        i=0
        while i<get(w,80):
            put(w,MAP_WORK+64+i*8,get(w,2048+i*8))
            i=i+1
        return image_role(o,w,67,4,MAPS,get(w,72),MAP_OUT,16+get(w,80)*8,MAP_WORK,8192)
    if phase==67:
        if raw!=0 or get(w,MAP_OUT)!=MAP_REPLY or get(w,MAP_OUT+8)!=get(w,80):
            return image_fail(o,w,24,raw)
        return image_syscall(o,w,68,5,4,get(w,48),1520,0,0,0,0)
    if phase==68:
        if raw==18446744073709551612:
            return image_syscall(o,w,68,5,4,get(w,48),1520,0,0,0,0)
        if raw!=0 or get(w,1376)!=get(w,1520) or get(w,1384)!=get(w,1528) or get(w,1376+48)!=get(w,1520+48):
            return image_fail(o,w,25,raw)
        return image_syscall(o,w,69,72,0,get(w,48),1034,0,0,0,0)
    if phase==69:
        if raw==18446744073709551612:
            return image_syscall(o,w,69,72,0,get(w,48),1034,0,0,0,0)
        if raw>=18446744073709547521 or (raw&15)!=15:
            return image_fail(o,w,25,raw)
        put(w,0,999)
        return image_result(o,w)
    return 4294967293

def image_hash_chunk(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,72)
    n=get(w,64)-used
    if n==0:
        store(w,SHA_CHUNK,2)
        return image_role(o,w,42,2,SHA_CHUNK,1,SHA_OUT,32,SHA_WORK,1184)
    if n>1048576:
        n=1048576
    store(w,SHA_CHUNK,1)
    image_copy(w,SHA_CHUNK+1,DATA+used,n)
    put(w,152,n)
    return image_role(o,w,41,2,SHA_CHUNK,n+1,SHA_OUT,32,SHA_WORK,1184)

def image_symbol(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,208)
    if i==get(w,80):
        return image_syscall(o,w,62,5,4,get(w,48),1376,0,0,0,0)
    record=ABI+16+i*320
    n=get(w,record+8)
    image_copy(w,SYMNAME,record+32,n)
    store(w,SYMNAME+n,0)
    put(w,0,61)
    put(o,0,get(w,56))
    put(o,8,SYMNAME)
    return 6

def image_fail(o:mutbuf,w:mutbuf,status:u64,raw:u64) -> u32:
    if get(w,88)==0:
        put(w,88,status)
        put(w,96,raw)
    fd=get(w,40)
    if fd!=NONE:
        put(w,40,NONE)
        return image_syscall(o,w,900,3,0,fd,0,0,0,0,0)
    fd=get(w,32)
    if get(w,112)==0 and fd!=NONE and get(w,120)==0:
        put(w,120,1)
        return image_syscall(o,w,901,3,0,fd,0,0,0,0,0)
    put(w,0,902)
    return image_result(o,w)

def image_result(o:mutbuf,w:mutbuf) -> u32:
    i=0
    while i<512:
        store(o,i,0)
        i=i+1
    put(o,0,RESULT_MAGIC)
    put(o,8,get(w,88))
    put(o,16,get(w,96))
    put(o,24,get(w,32))
    put(o,32,get(w,48))
    put(o,40,get(w,56))
    put(o,48,get(w,64))
    put(o,56,get(w,80))
    i=0
    while i<32:
        store(o,64+i,byte(w,SHA_OUT+i))
        i=i+1
    put(o,96,get(w,656))
    put(o,104,get(w,664))
    put(o,112,get(w,112))
    put(o,120,get(w,104))
    put(o,128,get(w,120))
    put(o,136,get(w,192))
    put(o,144,get(w,24))
    put(o,152,get(w,176))
    if get(w,88)==0:
        i=0
        while i<get(w,80):
            put(o,256+i*8,get(w,2048+i*8))
            put(o,384+i*8,get(w,MAP_OUT+16+i*8))
            i=i+1
    return 0

def image_syscall(o:mutbuf,w:mutbuf,phase:u64,nr:u64,flags:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,0,phase)
    put(o,0,nr)
    put(o,8,flags)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def image_role(o:mutbuf,w:mutbuf,phase:u64,action:u64,source:u64,size:u64,output:u64,capacity:u64,work:u64,workspace:u64) -> u32:
    put(w,0,phase)
    put(o,0,source)
    put(o,8,size)
    put(o,16,output)
    put(o,24,capacity)
    put(o,32,work)
    put(o,40,workspace)
    return action

def image_same_stat(w:mutbuf,a:u64,b:u64) -> u64:
    if get(w,a)!=get(w,b) or get(w,a+8)!=get(w,b+8) or (get(w,a+24)&4294967295)!=(get(w,b+24)&4294967295) or get(w,a+48)!=get(w,b+48):
        return 0
    if get(w,a+88)!=get(w,b+88) or get(w,a+96)!=get(w,b+96) or get(w,a+104)!=get(w,b+104) or get(w,a+112)!=get(w,b+112):
        return 0
    return 1

def image_equal(w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return 0
        i=i+1
    return 1

def image_copy(w:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,target+i,byte(w,source+i))
        i=i+1
    return 0

def image_memname(w:mutbuf) -> u64:
MEMNAME_LITERAL
    i=0
    while i<32:
        value=byte(w,SHA_OUT+i)
        a=value>>4
        b=value&15
        store(w,MEMNAME+10+i*2,choose(a<10,a+48,a+87))
        store(w,MEMNAME+11+i*2,choose(b<10,b+48,b+87))
        i=i+1
    store(w,MEMNAME+74,0)
    return 0

def image_fdpath(w:mutbuf,fd:u64) -> u64:
FDPATH_LITERAL
    n=0
    going=True
    while going:
        divided=image_div10(fd)
        store(w,4000+n,48+fd-divided*10)
        fd=divided
        n=n+1
        if fd==0:
            going=False
    i=0
    while i<n:
        store(w,FDPATH+14+i,byte(w,4000+n-1-i))
        i=i+1
    store(w,FDPATH+14+n,0)
    return 0

def image_maps_path(w:mutbuf) -> u64:
MAPSPATH_LITERAL
    return 0

def image_div10(value:u64) -> u64:
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

def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
'''
def source_program():
    import re
    raw=POLICY
    for key,value in [('MEMNAME',b'hepta-hia-'),('FDPATH',b'/proc/self/fd/'),('MAPSPATH',b'/proc/self/maps\0')]:
        raw=raw.replace(key+'_LITERAL','\n'.join(f'    store(w,{key}+{i},{c})' for i,c in enumerate(value)))
    for key,value in CONSTANTS.items():raw=re.sub(r'\b'+key+r'\b',str(value),raw)
    return raw
def main():
    tree=document(source_program(),'multiversion_image')
    p=ROOT/'examples/hia_bootstrap/multiversion_image.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']))
if __name__=='__main__':main()
