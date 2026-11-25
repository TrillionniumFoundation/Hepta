"""Author exact bounded-input arithmetic for native NDU ranking.

All public operands are validated by the owner with their original exact-type
rules. This role retains full 128-bit intermediate products; it does not clip
costs, margins, or integer counters. It never supplies proof authority.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIANRC01','little'),'REPLY':int.from_bytes(b'HIANRR01','little'),'MAXIMUM':9223372036854775807,'MASK':4294967295,'BAD':4294967293,'SHORT':4294967294}
SOURCE=r'''
def rank_cost(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(w)<256 or read64(s,0)!=REQUEST:
        return BAD
    mode=read64(s,8)
    if mode>3:
        return BAD
    i=88
    while i<128:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    if mode==0:
        i=32
        while i<88:
            if read64(s,i)!=0:
                return BAD
            i=i+8
    else:
        i=16
        while i<64:
            if read64(s,i)>MAXIMUM:
                return BAD
            i=i+8
        if read64(s,48)==0 or read64(s,72)>MAXIMUM or read64(s,80)==0 or read64(s,80)>5000:
            return BAD
    if length(o)<256:
        return SHORT
    zero(w,256)
    if mode==0:
        q32(w,read64(s,16),read64(s,24))
    else:
        base=read64(s,16)
        uncertainty=read64(s,24)
        lower=0
        if base>uncertainty:
            lower=base-uncertainty
        put(w,144,lower)
        multiply(w,64,lower,read64(s,48))
        multiply(w,80,read64(s,32)+read64(s,40),read64(s,48))
        add_pair(w,48,read64(s,56),0,read64(s,64),0)
        difference(w,96,read64(s,72),0,get(w,48),get(w,56))
        add_pair(w,160,get(w,80),get(w,88),get(w,48),get(w,56))
        difference(w,120,get(w,64),get(w,72),get(w,160),get(w,168))
        if mode==3:
            reason=0
            if get(w,96)!=0:
                reason=5
            elif get(w,120)!=0 or pair_zero(w,128):
                reason=6
            put(w,24,reason)
        else:
            proof_allowance(w,mode,read64(s,80))
    zero(o,256)
    put(o,0,REPLY)
    put(o,8,mode)
    i=16
    while i<152:
        put(o,i,get(w,i))
        i=i+8
    return 0

def q32(w:mutbuf,low:u64,high:u64) -> u64:
    if high!=0 or low>MAXIMUM:
        put(w,16,1)
        return 0
    whole=low//1000000
    remainder=low%1000000
    if whole>2147483647:
        put(w,16,2)
        return 0
    scaled=remainder*4294967296
    fraction=scaled//1000000
    rest=scaled%1000000
    value=(whole<<32)+fraction
    if rest>500000 or (rest==500000 and (value&1)!=0):
        if value==MAXIMUM:
            put(w,16,2)
            return 0
        value=value+1
    put(w,40,value)
    return 0

def proof_allowance(w:mutbuf,mode:u64,requested:u64) -> u64:
    reason=0
    budget_zero=pair_zero(w,104)
    margin_zero=pair_zero(w,128)
    if get(w,96)!=0 or (mode==1 and budget_zero):
        reason=choose(mode==1,1,5)
    elif get(w,120)!=0 or margin_zero:
        reason=choose(mode==1,2,6)
    elif get(w,112)==0 and get(w,104)<1000000:
        reason=choose(mode==1,3,7)
    elif get(w,136)==0 and get(w,128)<=1000000:
        reason=choose(mode==1,4,8)
    put(w,24,reason)
    if reason!=0:
        return 0
    amount=requested
    if get(w,112)==0 and get(w,104)<amount*1000000:
        amount=get(w,104)//1000000
    if get(w,136)==0 and get(w,128)<=amount*1000000:
        amount=(get(w,128)-1)//1000000
    put(w,32,amount)
    return 0

def pair_zero(w:mutbuf,at:u64) -> bool:
    return get(w,at)==0 and get(w,at+8)==0

def multiply(w:mutbuf,at:u64,a:u64,b:u64) -> u64:
    a0=a&MASK
    a1=a>>32
    b0=b&MASK
    b1=b>>32
    first=a0*b0
    middle=a1*b0+(first>>32)
    low_middle=middle&MASK
    high_middle=middle>>32
    last=a0*b1+low_middle
    high=a1*b1+high_middle+(last>>32)
    low=(last<<32)|(first&MASK)
    put(w,at,low)
    put(w,at+8,high)
    return 0

def add_pair(w:mutbuf,at:u64,al:u64,ah:u64,bl:u64,bh:u64) -> u64:
    low=al+bl
    high=ah+bh
    if low<al:
        high=high+1
    put(w,at,low)
    put(w,at+8,high)
    return 0

def difference(w:mutbuf,at:u64,al:u64,ah:u64,bl:u64,bh:u64) -> u64:
    negative=ah<bh or (ah==bh and al<bl)
    first_low=al
    first_high=ah
    second_low=bl
    second_high=bh
    if negative:
        first_low=bl
        first_high=bh
        second_low=al
        second_high=ah
    low=first_low-second_low
    high=first_high-second_high
    if first_low<second_low:
        high=high-1
    put(w,at,choose(negative,1,0))
    put(w,at+8,low)
    put(w,at+16,high)
    return 0

def choose(test:bool,a:u64,b:u64) -> u64:
    if test:
        return a
    return b

def read64(s:readbuf,at:u64) -> u64:
    result=0
    i=0
    while i<8:
        result=result|(byte(s,at+i)<<(i*8))
        i=i+1
    return result

def get(w:mutbuf,at:u64) -> u64:
    result=0
    i=0
    while i<8:
        result=result|(byte(w,at+i)<<(i*8))
        i=i+1
    return result

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def zero(w:mutbuf,n:u64) -> u64:
    i=0
    while i<n:
        store(w,i,0)
        i=i+1
    return 0
'''
def source_program():
    text=SOURCE
    for key,value in C.items():text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'ndu_rank_cost')
if __name__=='__main__':
    tree=program();target=ROOT/'examples/hia_bootstrap/ndu_rank_cost.hepta'
    target.write_text(render_assembly(tree))
    print(target.name,target.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
