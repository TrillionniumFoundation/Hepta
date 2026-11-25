"""HIA exact scalar-call codec, independent of generic object/array decoding.

The native runtime supplies types from its actual admitted ABI and holds the
generation for the entire fixed SysV call. No function address enters this wire.
s is a complete JSON scalar array (mode0) or empty (mode1 actual RAX rendering).
w: mode,argc,result-type,16 arg-types,actualRAX at offsets0,8,16,24,160.
Accepted scalars exactly represent original exact bool/int argument values;
objects, floats, strings, null and nested arrays cannot enter this scalar ABI.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
POLICY=r'''
def multiversion_call(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<512 or length(o)<152 or length(s)>8388608:
        return 4294967280
    mode=get(w,0)
    argc=get(w,8)
    result=get(w,16)
    if mode>1 or argc>16 or result==0 or result>11:
        return 4294967280
    base=length(w)-256
    i=0
    while i<168:
        store(w,base+i,byte(w,i))
        i=i+1
    put(w,base+168,0)
    put(w,base+176,0)
    if mode==1:
        if length(s)!=0:
            return 4294967280
        return call_render(o,w,base,result,get(w,base+160))
    at=call_space(s,0)
    if at==length(s) or byte(s,at)!=91:
        return 4294967281
    at=call_space(s,at+1)
    i=0
    while i<argc:
        if at==length(s) or byte(s,at)==93:
            return 4294967281
        typ=get(w,base+24+i*8)
        put(w,base+176,i)
        put(w,base+184,at)
        if typ==0 or typ>11:
            return 4294967280
        value=call_value(s,w,base,typ)
        if get(w,base+168)!=0:
            return get(w,base+168)
        put(w,base+24+i*8,value)
        at=call_space(s,get(w,base+184))
        i=i+1
        if i<argc:
            if at==length(s) or byte(s,at)!=44:
                return 4294967281
            at=call_space(s,at+1)
    if at==length(s) or byte(s,at)!=93:
        return 4294967281
    at=call_space(s,at+1)
    if at!=length(s):
        return 4294967281
    put(o,0,CALL_MAGIC)
    put(o,8,argc)
    put(o,16,result)
    i=0
    while i<16:
        value=0
        if i<argc:
            value=get(w,base+24+i*8)
        put(o,24+i*8,value)
        i=i+1
    return 152

def call_space(s:readbuf,at:u64) -> u64:
    while at<length(s):
        ch=byte(s,at)
        if ch!=32 and ch!=9 and ch!=10 and ch!=13:
            return at
        at=at+1
    return at

def call_value(s:readbuf,w:mutbuf,base:u64,typ:u64) -> u64:
    at=get(w,base+184)
    if at>=length(s):
        put(w,base+168,4294967282)
        return 0
    if typ==1:
        if length(s)-at>=4:
            if byte(s,at)==116 and byte(s,at+1)==114 and byte(s,at+2)==117 and byte(s,at+3)==101:
                put(w,base+184,at+4)
                return 1
        if length(s)-at>=5:
            if byte(s,at)==102 and byte(s,at+1)==97 and byte(s,at+2)==108 and byte(s,at+3)==115 and byte(s,at+4)==101:
                put(w,base+184,at+5)
                return 0
        put(w,base+168,4294967282)
        return 0
    negative=byte(s,at)==45
    pos=at+choose(negative,1,0)
    if pos==length(s) or byte(s,pos)<48 or byte(s,pos)>57:
        put(w,base+168,4294967282)
        return 0
    first=pos
    bits=call_width(typ)
    signed=(typ&1)==0
    limit=18446744073709551615
    if signed:
        limit=(1<<(bits-1))-choose(negative,0,1)
    elif bits<64:
        limit=(1<<bits)-1
    ten_q=call_div10(limit)
    ten_r=limit-ten_q*10
    value=0
    going=True
    while going:
        if pos==length(s):
            going=False
        else:
            ch=byte(s,pos)
            if ch<48 or ch>57:
                going=False
            else:
                if pos>first and byte(s,first)==48:
                    put(w,base+168,4294967282)
                    return 0
                digit=ch-48
                if value>ten_q or (value==ten_q and digit>ten_r):
                    put(w,base+168,4294967283)
                    return 0
                value=value*10+digit
                pos=pos+1
    put(w,base+184,pos)
    if negative and signed==False and value!=0:
        put(w,base+168,4294967283)
        return 0
    if negative and value!=0:
        return (18446744073709551615-value)+1
    return value

def call_div10(value:u64) -> u64:
    quotient=0
    remainder=0
    bit=64
    while bit>0:
        bit=bit-1
        remainder=(remainder<<1)|((value>>bit)&1)
        if remainder>=10:
            remainder=remainder-10
            quotient=quotient|(1<<bit)
    return quotient

def call_width(typ:u64) -> u64:
    if typ==2 or typ==3:
        return 8
    if typ==4 or typ==5:
        return 16
    if typ==6 or typ==7:
        return 32
    return 64

def call_render(o:mutbuf,w:mutbuf,base:u64,typ:u64,raw:u64) -> u32:
    if typ==1:
        if (raw&255)!=0:
            store(o,0,116)
            store(o,1,114)
            store(o,2,117)
            store(o,3,101)
            return 4
        store(o,0,102)
        store(o,1,97)
        store(o,2,108)
        store(o,3,115)
        store(o,4,101)
        return 5
    bits=call_width(typ)
    mask=18446744073709551615
    if bits<64:
        mask=(1<<bits)-1
    value=raw&mask
    negative=(typ&1)==0 and (value&(1<<(bits-1)))!=0
    if negative:
        value=(mask-value)+1
    at=0
    if negative:
        store(o,0,45)
        at=1
    n=0
    going=True
    while going:
        divided=call_div10(value)
        store(w,base+192+n,48+value-divided*10)
        value=divided
        n=n+1
        if value==0:
            going=False
    i=0
    while i<n:
        store(o,at+i,byte(w,base+192+n-1-i))
        i=i+1
    return at+n

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
def source_program():return POLICY.replace('CALL_MAGIC',str(int.from_bytes(b'HIAMVCAL','little')))
def main():
    tree=document(source_program(),'multiversion_call')
    p=ROOT/'examples/hia_bootstrap/multiversion_call.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']))
if __name__=='__main__':main()
