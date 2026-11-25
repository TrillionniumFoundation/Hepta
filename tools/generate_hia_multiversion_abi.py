"""Materialize sorted ABI facts after actual Core and scalar-profile admission.

This private role grants no verification or publication authority. Input is the
exact HIASCP01 complete fact frame; w[0:144] is the actual HIASCR01 decision.
The result HIAMVAB1 has a 16-byte header and fixed 320-byte records. All bytes
are committed to output only after the entire fact extent and permutation have
been checked. Function indices always refer to the original Core array.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
TYPES=('bool','i8','u8','i16','u16','i32','u32','i64','u64','isize','usize')
POLICY=r'''
def multiversion_abi(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(s)>8388608 or length(w)<8192 or length(o)<16:
        return 4294967293
    if readword(s,0)!=REQUEST_MAGIC or readword(s,48)!=1 or get(w,0)!=RESULT_MAGIC:
        return 4294967293
    n=readword(s,32)
    if n==0 or n>16 or get(w,8)!=n:
        return 4294967293
    if length(o)<16+n*320:
        return 4294967294
    mask=0
    i=0
    while i<n:
        index=get(w,16+i*8)
        if index>=n:
            return 4294967293
        flag=1<<index
        if (mask&flag)!=0:
            return 4294967293
        mask=mask|flag
        put(w,256+i*8,index)
        i=i+1
    put(w,0,56)
    put(w,8,0)
    put(w,16,length(s))
    abi_text(s,w)
    exports=readword(s,40)
    explicit=readword(s,24)
    if readword(s,8)!=0 or readword(s,16)>1 or explicit>1:
        return 4294967293
    if (explicit==0 and exports!=0) or (explicit==1 and exports!=n):
        return 4294967293
    i=0
    while i<exports:
        abi_text(s,w)
        i=i+1
    i=0
    while i<n:
        size=abi_number(s,w)
        at=get(w,0)
        if get(w,8)!=0 or at>length(s) or size>length(s)-at:
            return 4294967293
        end=at+size
        put(w,16,end)
        base=512+i*320
        j=0
        while j<320:
            store(w,base+j,0)
            j=j+1
        put(w,base,i)
        name=abi_text(s,w)
        name_n=get(w,24)
        if get(w,8)!=0 or name_n==0 or name_n>128:
            return 4294967293
        put(w,base+8,name_n)
        j=0
        while j<name_n:
            store(w,base+32+j,byte(s,name+j))
            j=j+1
        argc=abi_number(s,w)
        if argc>16:
            return 4294967293
        put(w,base+16,argc)
        j=0
        while j<argc:
            typ=abi_type(s,w)
            if typ==0:
                return 4294967293
            put(w,base+160+j*8,typ)
            j=j+1
        if abi_number(s,w)!=1:
            return 4294967293
        result=abi_type(s,w)
        if result==0 or get(w,8)!=0:
            return 4294967293
        put(w,base+24,result)
        put(w,0,end)
        put(w,16,length(s))
        i=i+1
    if get(w,8)!=0 or get(w,0)!=length(s):
        return 4294967293
    put(o,0,ABI_MAGIC)
    put(o,8,n)
    i=0
    while i<n:
        source=512+get(w,256+i*8)*320
        j=0
        while j<320:
            store(o,16+i*320+j,byte(w,source+j))
            j=j+1
        i=i+1
    return 16+n*320

def abi_number(s:readbuf,w:mutbuf) -> u64:
    at=get(w,0)
    end=get(w,16)
    if at>end or end-at<8:
        put(w,8,1)
        return 0
    put(w,0,at+8)
    return readword(s,at)

def abi_text(s:readbuf,w:mutbuf) -> u64:
    size=abi_number(s,w)
    at=get(w,0)
    end=get(w,16)
    put(w,24,0)
    if get(w,8)!=0 or at>end or size>end-at:
        put(w,8,1)
        return 0
    put(w,24,size)
    put(w,0,at+size)
    return at

def abi_type(s:readbuf,w:mutbuf) -> u64:
    at=abi_text(s,w)
    size=get(w,24)
    if get(w,8)!=0:
        return 0
TYPE_CASES
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
    cases=[]
    for code,name in enumerate(TYPES,1):
        condition=' and '.join([f'size=={len(name)}']+[f'byte(s,at+{j})=={c}' for j,c in enumerate(name.encode())])
        cases.append(f'    if {condition}:\n        return {code}')
    raw=POLICY.replace('TYPE_CASES','\n'.join(cases))
    for name,magic in [('REQUEST_MAGIC',b'HIASCP01'),('RESULT_MAGIC',b'HIASCR01'),('ABI_MAGIC',b'HIAMVAB1')]:
        raw=raw.replace(name,str(int.from_bytes(magic,'little')))
    return raw
def main():
    tree=document(source_program(),'multiversion_abi')
    p=ROOT/'examples/hia_bootstrap/multiversion_abi.hepta'
    p.write_text(render_assembly(tree));print(p.name,p.stat().st_size,len(tree['functions']))
if __name__=='__main__':main()
