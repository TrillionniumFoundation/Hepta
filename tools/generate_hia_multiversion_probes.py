"""Generate the exact original finite multiversion VM probe vectors in HIA.

This supplies no proof. All-input proofs and actual mapping admission precede
the finite artifact cross-check. The ordering is the original sorted tuple set,
including each scalar domain, each single-position vector and seven diagonals.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
POLICY=r'''
def multiversion_probes(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<16 or length(o)<304 or length(w)<32768:
        return 4294967293
    selector=get(o,0)
    count=readword(s,8)
    if readword(s,0)!=ABI_MAGIC or count==0 or count>16 or selector>=count or length(s)!=16+count*320:
        return 4294967293
    record=16+selector*320
    n=readword(s,record+16)
    name_n=readword(s,record+8)
    result=readword(s,record+24)
    if n>16 or name_n==0 or name_n>128 or result==0 or result>11 or readword(s,record)>=count:
        return 4294967293
    put(w,0,0)
    put(w,8,n)
    i=0
    while i<16:
        put(w,2048+i*8,0)
        if i<n:
            typ=readword(s,record+160+i*8)
            if typ==0 or typ>11:
                return 4294967293
            probe_domain(w,512+i*96,typ)
        i=i+1
    probe_append(w)
    i=0
    while i<n:
        domain=512+i*96
        j=0
        while j<get(w,domain+8):
            put(w,2048+i*8,get(w,domain+16+j*8))
            probe_append(w)
            j=j+1
        put(w,2048+i*8,0)
        i=i+1
    offset=0
    while offset<7:
        i=0
        while i<n:
            domain=512+i*96
            j=offset+i
            size=get(w,domain+8)
            while j>=size:
                j=j-size
            put(w,2048+i*8,get(w,domain+16+j*8))
            i=i+1
        probe_append(w)
        offset=offset+1
    count=get(w,0)
    if count==0 or count>168 or length(o)<304+count*128:
        return 4294967294
    i=1
    while i<count:
        probe_copy(w,30720,4096+i*128)
        j=i
        moving=True
        while moving:
            if j==0:
                moving=False
            elif probe_less(w,30720,4096+(j-1)*128)==0:
                moving=False
            else:
                probe_copy(w,4096+j*128,4096+(j-1)*128)
                j=j-1
        probe_copy(w,4096+j*128,30720)
        i=i+1
    i=0
    while i<304:
        store(o,i,0)
        i=i+1
    put(o,0,RESULT_MAGIC)
    put(o,8,count)
    put(o,16,n)
    put(o,24,result)
    put(o,32,readword(s,record))
    put(o,40,name_n)
    i=0
    while i<name_n:
        store(o,48+i,byte(s,record+32+i))
        i=i+1
    i=0
    while i<n:
        put(o,176+i*8,get(w,512+i*96))
        i=i+1
    i=0
    while i<count*128:
        store(o,304+i,byte(w,4096+i))
        i=i+1
    return 304+count*128

def probe_domain(w:mutbuf,at:u64,typ:u64) -> u64:
    put(w,at,typ)
    put(w,at+16,0)
    put(w,at+24,1)
    if typ==1:
        put(w,at+8,2)
        return 0
    bits=64
    if typ==2 or typ==3:
        bits=8
    elif typ==4 or typ==5:
        bits=16
    elif typ==6 or typ==7:
        bits=32
    if (typ&1)!=0:
        hi=18446744073709551615
        if bits<64:
            hi=(1<<bits)-1
        put(w,at+8,6)
        put(w,at+32,hi>>1)
        put(w,at+40,(hi>>1)+1)
        put(w,at+48,hi-1)
        put(w,at+56,hi)
        return 0
    half=1<<(bits-1)
    lo=(18446744073709551615-half)+1
    hi=half-1
    put(w,at+8,10)
    put(w,at+16,lo)
    put(w,at+24,lo+1)
    put(w,at+32,(18446744073709551615-(half>>1))+1)
    put(w,at+40,0)
    put(w,at+48,1)
    put(w,at+56,hi>>1)
    put(w,at+64,(hi>>1)+1)
    put(w,at+72,hi-1)
    put(w,at+80,hi)
    put(w,at+88,18446744073709551615)
    return 0

def probe_append(w:mutbuf) -> u64:
    n=get(w,0)
    i=0
    while i<n:
        same=1
        j=0
        while j<16:
            if get(w,4096+i*128+j*8)!=get(w,2048+j*8):
                same=0
            j=j+1
        if same!=0:
            return 0
        i=i+1
    if n>=168:
        put(w,0,169)
        return 0
    probe_copy(w,4096+n*128,2048)
    put(w,0,n+1)
    return 0

def probe_less(w:mutbuf,a:u64,b:u64) -> u64:
    i=0
    while i<get(w,8):
        x=get(w,a+i*8)
        y=get(w,b+i*8)
        if x!=y:
            typ=get(w,512+i*96)
            if (typ&1)==0 and (x>>63)!=(y>>63):
                return x>>63
            return choose(x<y,1,0)
        i=i+1
    return 0

def probe_copy(w:mutbuf,target:u64,source:u64) -> u64:
    i=0
    while i<128:
        store(w,target+i,byte(w,source+i))
        i=i+1
    return 0

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
    return POLICY.replace('ABI_MAGIC',str(int.from_bytes(b'HIAMVAB1','little'))).replace('RESULT_MAGIC',str(int.from_bytes(b'HIAMVPV1','little')))
def main():
    tree=document(source_program(),'multiversion_probes')
    p=ROOT/'examples/hia_bootstrap/multiversion_probes.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']))
if __name__=='__main__':main()
