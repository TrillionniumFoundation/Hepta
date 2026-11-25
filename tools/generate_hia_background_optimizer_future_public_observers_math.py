"""Exact binary64 arithmetic for original Future observer deadlines."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v,'little')for k,v in {'REQ':b'HIABFM01','REP':b'HIABFMR1'}.items()}
C.update({'SIGN':9223372036854775808,'FRAC':4503599627370495,'HIDDEN':4503599627370496,'INF':9218868437227405312,'MAX':18446744073709551615})
SOURCE=r'''
def observer_math(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(o)<128 or length(w)<512 or word_load(s,0)!=REQ:
        return 4294967293
    mode=word_load(s,8)
    if mode>4:
        return 4294967293
    if mode==3:
        if word_load(s,16)!=length(s)-128 or length(s)==128:
            return 4294967293
    elif length(s)!=128:
        return 4294967293
    i=choose(mode==0 or mode==1,32,24)
    while i<128:
        if word_load(s,i)!=0:
            return 4294967293
        i=i+8
    zero(o,128)
    word_store(o,0,REP)
    a=word_load(s,16)
    if mode==0:
        word_store(o,24,add(a,word_load(s,24)))
    elif mode==1:
        word_store(o,24,add(a,word_load(s,24)^SIGN))
    elif mode==2:
        word_store(o,24,seconds(a))
    elif mode==3:
        return integer(s,o,w)
    else:
        return timeout(o,a)
    return 0

def jam(n:u64,shift:u64) -> u64:
    if shift==0:
        return n
    if shift>=64:
        return choose(n!=0,1,0)
    return (n>>shift)|choose((n&((1<<shift)-1))!=0,1,0)

def add(a:u64,b:u64) -> u64:
    ea=(a>>52)&2047
    eb=(b>>52)&2047
    ma=a&FRAC
    mb=b&FRAC
    sa=a>>63
    sb=b>>63
    if ea==2047:
        if ma!=0:
            return a|2251799813685248
        if eb==2047 and mb!=0:
            return b|2251799813685248
        if eb==2047 and sa!=sb:
            return 18444492273895866368
        return a
    if eb==2047:
        if mb!=0:
            return b|2251799813685248
        return b
    if ea!=0:
        ma=ma|HIDDEN
    else:
        ea=1
    if eb!=0:
        mb=mb|HIDDEN
    else:
        eb=1
    if ea<eb or (ea==eb and ma<mb):
        temp=ea
        ea=eb
        eb=temp
        temp=ma
        ma=mb
        mb=temp
        temp=sa
        sa=sb
        sb=temp
    ma=ma<<3
    mb=jam(mb<<3,ea-eb)
    value=0
    if sa==sb:
        value=ma+mb
        if value>=72057594037927936:
            value=jam(value,1)
            ea=ea+1
    else:
        value=ma-mb
        if value==0:
            return 0
        while value<36028797018963968 and ea>1:
            value=value<<1
            ea=ea-1
    kept=value>>3
    remainder=value&7
    if remainder>4 or (remainder==4 and (kept&1)!=0):
        kept=kept+1
    if kept>=9007199254740992:
        kept=kept>>1
        ea=ea+1
    if ea>=2047:
        return (sa<<63)|INF
    if kept<HIDDEN:
        ea=0
    return (sa<<63)|(ea<<52)|(kept&FRAC)

def unsigned_float(n:u64) -> u64:
    if n==0:
        return 0
    bits=bit_length(n)
    exp=bits-1+1023
    kept=n
    if bits<=53:
        kept=n<<(53-bits)
    else:
        shift=bits-53
        kept=n>>shift
        rem=n&((1<<shift)-1)
        half=1<<(shift-1)
        if rem>half or (rem==half and (kept&1)!=0):
            kept=kept+1
        if kept>=9007199254740992:
            kept=kept>>1
            exp=exp+1
    return (exp<<52)|(kept&FRAC)

def seconds(ns:u64) -> u64:
    if ns==0:
        return 0
    a=unsigned_float(ns)
    exp=((a>>52)&2047)-29
    am=(a&FRAC)|HIDDEN
    divisor=8388608000000000
    if am<divisor:
        am=am<<1
        exp=exp-1
    remainder=am-divisor
    q=1
    i=0
    while i<54:
        remainder=remainder<<1
        q=q<<1
        if remainder>=divisor:
            remainder=remainder-divisor
            q=q|1
        i=i+1
    kept=q>>2
    low=q&3
    if low>2 or (low==2 and (remainder!=0 or (kept&1)!=0)):
        kept=kept+1
    if kept>=9007199254740992:
        kept=kept>>1
        exp=exp+1
    return (exp<<52)|(kept&FRAC)

def integer(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=length(s)-128
    sign=0
    at=128
    if byte(s,at)==45:
        sign=SIGN
        at=at+1
    if at==length(s):
        return 4294967293
    if length(s)-at>1 and byte(s,at)==48:
        return 4294967293
    j=at
    while j<length(s):
        c=byte(s,j)
        if c<48 or c>57:
            return 4294967293
        j=j+1
    if length(s)-at>309:
        return overflow(o,1)
    zero(w,512)
    used=1
    while at<length(s):
        carry=byte(s,at)-48
        i=0
        while i<used:
            v=word_load(w,i*8)*10+carry
            word_store(w,i*8,v&4294967295)
            carry=v>>32
            i=i+1
        if carry!=0:
            word_store(w,used*8,carry)
            used=used+1
        at=at+1
    bits=(used-1)*32+bit_length(word_load(w,(used-1)*8))
    if bits==0:
        word_store(o,24,0)
        return 0
    if bits>1024:
        return overflow(o,1)
    kept=0
    i=0
    while i<53:
        kept=kept<<1
        if bits>i:
            kept=kept|integer_bit(w,bits-i-1)
        i=i+1
    if bits>53:
        round=integer_bit(w,bits-54)
        sticky=0
        i=0
        while i<bits-54:
            sticky=sticky|integer_bit(w,i)
            i=i+1
        if round!=0 and (sticky!=0 or (kept&1)!=0):
            kept=kept+1
    exp=bits-1+1023
    if kept>=9007199254740992:
        kept=kept>>1
        exp=exp+1
    if exp>=2047:
        return overflow(o,1)
    word_store(o,24,sign|(exp<<52)|(kept&FRAC))
    return 0

def integer_bit(w:mutbuf,at:u64) -> u64:
    return (word_load(w,(at//32)*8)>>(at%32))&1

def timeout(o:mutbuf,bits:u64) -> u32:
    exp=(bits>>52)&2047
    mantissa=bits&FRAC
    if (bits>>63)!=0 or (exp==2047 and mantissa!=0):
        return 0
    if exp==2047:
        return overflow(o,2)
    if exp==0 and mantissa==0:
        return 0
    if exp!=0:
        mantissa=mantissa|HIDDEN
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
            return overflow(o,2)
        if kept>(9223372036854775807>>left):
            return overflow(o,2)
        word_store(o,24,kept<<left)
        return 0
    right=1075-scale
    if right>=64:
        word_store(o,24,1)
    else:
        word_store(o,24,(kept>>right)+choose((kept&((1<<right)-1))!=0,1,0))
    return 0

def overflow(o:mutbuf,detail:u64) -> u32:
    word_store(o,8,1)
    word_store(o,16,106)
    word_store(o,32,detail)
    return 0

def bit_length(n:u64) -> u64:
    result=0
    while n!=0:
        n=n>>1
        result=result+1
    return result

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

def zero(w:mutbuf,n:u64) -> u64:
    i=0
    while i<n:
        store(w,i,0)
        i=i+1
    return 0
'''
def source_program():
 s=SOURCE
 for name,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+name+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_future_public_observers_math')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_observers_math.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
if __name__=='__main__':main()
