"""Original Condition.wait timeout conversion using owned native values."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={"MAGIC":int.from_bytes("HIABFP01".encode(),'little'),
"REPLY":int.from_bytes("HIAPFTR1".encode(),'little'),
"VREQUEST":int.from_bytes("HIABVQ01".encode(),'little'),
"VREPLY":int.from_bytes("HIABVR01".encode(),'little'),
"PHASE":128,
"ERROR":136,
"CLASS":144,
"KIND":152,
"NS":160,
"INFINITE":168,
"DETAIL":176,
"CAP":200,
"FEEDBACK":448,
"RQ":2048,
"VP":4096,
"RAW":12288,
"OUT":16384}
SOURCE=r'''
def future_timeout(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or length(o)<OUT or length(w)<256 or readword(s,0)!=MAGIC:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        zero(o,128,OUT-128)
        packet(o,5)
        copy_input(s,104,o,RQ+24,24)
        return value(o,w,1)
    if phase==1:
        if ok(o)==False:
            return finish(o,choose(get(o,VP+8)==1,3,1),choose(get(o,VP+8)==5,103,107))
        within(o,CAP,VP+24,24)
        packet(o,7)
        within(o,RQ+24,CAP,24)
        return value(o,w,2)
    if phase==2:
        if ok(o)==False:
            return fail(o,1,107)
        kind=get(o,VP+16)
        put(o,KIND,kind)
        if kind==0:
            put(o,INFINITE,1)
            return fail(o,0,0)
        if kind!=1 and kind!=2 and kind!=3:
            put(o,DETAIL,kind)
            return fail(o,1,104)
        n=get(o,VP+72)
        packet(o,19)
        within(o,RQ+24,CAP,24)
        put(o,RQ+112,choose(n<32,n,32))
        return value(o,w,3)
    if phase==3:
        if ok(o)==False:
            return fail(o,1,107)
        kind=get(o,KIND)
        if kind==1:
            put(o,NS,choose(byte(o,RAW)==0,0,1000000000))
            return fail(o,0,0)
        if kind==2:
            return integer_timeout(o)
        return float_timeout(o)
    if phase==900:
        if get(o,CAP)!=0:
            packet(o,6)
            within(o,RQ+24,CAP,24)
            return value(o,w,901)
        return finish(o,get(o,ERROR),get(o,CLASS))
    if phase==901:
        if ok(o)==False:
            return finish(o,1,107)
        zero(o,CAP,24)
        return finish(o,get(o,ERROR),get(o,CLASS))
    return finish(o,1,107)

def integer_timeout(o:mutbuf) -> u32:
    n=get(o,VP+72)
    if n==0:
        return fail(o,1,107)
    if byte(o,RAW)==45:
        return fail(o,0,0)
    if n>10:
        put(o,DETAIL,1)
        return fail(o,1,106)
    value=0
    i=0
    while i<n:
        value=value*10+byte(o,RAW+i)-48
        i=i+1
    if value>9223372036:
        put(o,DETAIL,1)
        return fail(o,1,106)
    put(o,NS,value*1000000000)
    return fail(o,0,0)

def float_timeout(o:mutbuf) -> u32:
    bits=get(o,RAW)
    exp=(bits>>52)&2047
    mantissa=bits&4503599627370495
    if (bits>>63)!=0 or (exp==2047 and mantissa!=0):
        return fail(o,0,0)
    if exp==2047:
        put(o,DETAIL,2)
        return fail(o,1,106)
    if exp==0 and mantissa==0:
        return fail(o,0,0)
    if exp!=0:
        mantissa=mantissa|4503599627370496
    else:
        exp=1
    a=(mantissa&4294967295)*1000000000
    b=(mantissa>>32)*1000000000
    lo=a+(b<<32)
    hi=(b>>32)+choose(lo<a,1,0)
    length=bit_length(lo)
    if hi!=0:
        length=64+bit_length(hi)
    shift=0
    kept=lo
    if length>53:
        shift=length-53
        kept=(lo>>shift)|(hi<<(64-shift))
        rem=lo&((1<<shift)-1)
        halfway=1<<(shift-1)
        if rem>halfway or (rem==halfway and (kept&1)!=0):
            kept=kept+1
    scale=exp+shift
    if scale>=1075:
        left=scale-1075
        if left>=63:
            put(o,DETAIL,2)
            return fail(o,1,106)
        if kept>(9223372036854775807>>left):
            put(o,DETAIL,2)
            return fail(o,1,106)
        put(o,NS,kept<<left)
        return fail(o,0,0)
    right=1075-scale
    if right>=64:
        put(o,NS,1)
    else:
        put(o,NS,(kept>>right)+choose((kept&((1<<right)-1))!=0,1,0))
    return fail(o,0,0)
def bit_length(n:u64) -> u64:
    result=0
    while n!=0:
        n=n>>1
        result=result+1
    return result
def packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,VREQUEST)
    put(o,RQ+8,op)
    return 0
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,128,VP,8256,get(w,112),get(w,120))
def ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and get(o,VP+8)==0
def fail(o:mutbuf,status:u64,kind:u64) -> u32:
    put(o,ERROR,status)
    put(o,CLASS,kind)
    return again(o,900)
def finish(o:mutbuf,status:u64,kind:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,kind)
    put(o,24,get(o,NS))
    put(o,32,get(o,INFINITE))
    put(o,40,get(o,DETAIL))
    return 0

def invoke(o:mutbuf,next:u64,fn:u64,src:u64,sn:u64,dest:u64,dn:u64,ctx:u64,cn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,51)
    put(o,16,src)
    put(o,24,sn)
    put(o,32,dest)
    put(o,40,dn)
    put(o,48,ctx)
    put(o,56,cn)
    return 9
def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10
def within(o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,at+i))
        i=i+1
    return 0
def copy_input(s:readbuf,at:u64,o:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value
def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)
def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
def narrow(n:u64) -> u32:
    return n
'''
def source_program():
 s=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_future_public_timeout')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_timeout.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
