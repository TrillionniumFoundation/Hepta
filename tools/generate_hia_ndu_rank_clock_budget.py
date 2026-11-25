"""Exact IEEE-754 bridge allowance selection and nanosecond conversion."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIANRB01','little'),'REPLY':int.from_bytes(b'HIANBR01','little'),'SIXTY':4633641066610819072,'MASK':4294967295,'FRACTION':4503599627370495,'HIDDEN':4503599627370496,'BAD':4294967293,'SHORT':4294967294}
SOURCE=r'''
def rank_clock_budget(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(w)<128 or read64(s,0)!=REQUEST or read64(s,16)>1:
        return BAD
    i=32
    while i<64:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    if length(o)<64:
        return SHORT
    bits=read64(s,8)
    integer=read64(s,16)
    remaining=read64(s,24)
    status=0
    selected=0
    chosen=0
    ratio=0
    duration=0
    value=0
    if bits==0 or bits>SIXTY:
        status=1
    else:
        if integer==1:
            exponent=(bits>>52)&2047
            if exponent<1023:
                return BAD
            shift=1075-exponent
            if (bits&((1<<shift)-1))!=0:
                return BAD
        if remaining==0:
            status=2
        else:
            selected=bits
            if remaining<60000000000:
                ratio=seconds_bits(w,remaining)
                if ratio<bits:
                    selected=ratio
                    integer=0
                    chosen=1
            duration=nano_integer(w,selected)
            if integer==1:
                value=((selected&FRACTION)|HIDDEN)>>(1075-((selected>>52)&2047))
    zero(o,64)
    put(o,0,REPLY)
    put(o,8,status)
    if status==0:
        put(o,16,selected)
        put(o,24,integer)
        put(o,32,duration)
        put(o,40,ratio)
        put(o,48,value)
        put(o,56,chosen)
    return 0

def seconds_bits(w:mutbuf,nanoseconds:u64) -> u64:
    width=bits(nanoseconds)
    biased=64+width-30
    if biased>=64:
        if nanoseconds<(1000000000<<(biased-64)):
            biased=biased-1
    else:
        if (nanoseconds<<(64-biased))<1000000000:
            biased=biased-1
    amount=116-biased
    low=0
    high=0
    if amount>=64:
        high=nanoseconds<<(amount-64)
    else:
        low=nanoseconds<<amount
        high=nanoseconds>>(64-amount)
    put(w,0,low)
    put(w,8,high)
    quotient=divide_billion(w)
    rest=get(w,16)
    if rest>500000000 or (rest==500000000 and (quotient&1)!=0):
        quotient=quotient+1
    if quotient==9007199254740992:
        quotient=quotient>>1
        biased=biased+1
    return ((biased+959)<<52)|(quotient-HIDDEN)

def divide_billion(w:mutbuf) -> u64:
    low=get(w,0)
    high=get(w,8)
    remainder=0
    quotient=0
    step=4
    while step!=0:
        step=step-1
        limb=0
        if step>=2:
            limb=(high<<((3-step)*32))>>32
        else:
            limb=(low>>((step)*32))&MASK
        value=(remainder<<32)|limb
        quotient=(quotient<<32)|(value//1000000000)
        remainder=value%1000000000
    put(w,16,remainder)
    return quotient

def nano_integer(w:mutbuf,number:u64) -> u64:
    exponent=(number>>52)&2047
    if exponent==0:
        return 0
    mantissa=(number&FRACTION)|HIDDEN
    multiply(w,mantissa,1000000000)
    low=get(w,0)
    high=get(w,8)
    width=bits(low)
    if high!=0:
        width=64+bits(high)
    remove=width-53
    quotient=(low>>remove)|(high<<(64-remove))
    rest=low&((1<<remove)-1)
    half=1<<(remove-1)
    if rest>half or (rest==half and (quotient&1)!=0):
        quotient=quotient+1
    shift=1075-exponent-remove
    if shift>=64:
        return 0
    return quotient>>shift

def multiply(w:mutbuf,a:u64,b:u64) -> u64:
    a0=a&MASK
    a1=a>>32
    b0=b&MASK
    b1=b>>32
    first=a0*b0
    middle=a1*b0+(first>>32)
    last=a0*b1+(middle&MASK)
    high=a1*b1+(middle>>32)+(last>>32)
    low=(last<<32)|(first&MASK)
    put(w,0,low)
    put(w,8,high)
    return 0

def bits(value:u64) -> u64:
    answer=0
    while value!=0:
        answer=answer+1
        value=value>>1
    return answer

def read64(s:readbuf,at:u64) -> u64:
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
def program():return document(source_program(),'ndu_rank_clock_budget')
if __name__=='__main__':
    tree=program();target=ROOT/'examples/hia_bootstrap/ndu_rank_clock_budget.hepta'
    target.write_text(render_assembly(tree));print(target.name,target.stat().st_size,flush=True)
