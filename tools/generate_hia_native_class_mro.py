"""C3 merge for actual, lock-captured native class linearizations.

This pure algorithm grants no class identity or execution authority. The class
owner must validate and retain actual bases before constructing this private
frame, and must publish a new class only after the merge has completed.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
CONSTANTS=dict(MAX=(1<<64)-1,BAD=4294967293,SHORT=4294967294,WORK=4294967292,
    MAGIC=int.from_bytes(b'HIAC3M01','little'),REPLY=int.from_bytes(b'HIAC3R01','little'))
SOURCE=r'''
def native_class_mro(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or readword(s,0)!=MAGIC:
        return BAD
    i=24
    while i<64:
        if readword(s,i)!=0:
            return BAD
        i=i+8
    bases=readword(s,8)
    total=readword(s,16)
    if bases>(length(s)-64)//24 or total>(length(s)-64)//8:
        return BAD
    at=64
    seen=0
    i=0
    while i<bases:
        if at>length(s) or length(s)-at<16:
            return BAD
        name=readword(s,at)
        n=readword(s,at+8)
        if name==0 or n==0 or n>(length(s)-at-16)//8:
            return BAD
        if readword(s,at+16)!=name:
            return BAD
        if seen>total or n>total-seen:
            return BAD
        seen=seen+n
        j=0
        while j<n:
            if readword(s,at+16+j*8)==0:
                return BAD
            j=j+1
        at=at+16+n*8
        i=i+1
    if at!=length(s) or seen!=total:
        return BAD
    if bases>576460752303423484:
        return WORK
    result=96+bases*32
    if total>MAX-bases or total+bases>(MAX-result)//8:
        return WORK
    required=result+(total+bases)*8
    if length(w)<64:
        return WORK
    put(w,8,required)
    if length(w)<required:
        return WORK
    put(w,16,result)
    put(w,24,0)
    put(w,32,0)
    at=64
    i=0
    while i<bases:
        row=64+i*32
        n=readword(s,at+8)
        put(w,row,at+16)
        put(w,row+8,n)
        put(w,row+16,0)
        put(w,row+24,readword(s,at))
        at=at+16+n*8
        i=i+1
    row=64+bases*32
    put(w,row,MAX)
    put(w,row+8,bases)
    put(w,row+16,0)
    put(w,row+24,0)
    i=0
    while i<bases:
        j=i+1
        while j<bases:
            if get(w,64+i*32+24)==get(w,64+j*32+24):
                put(w,result,get(w,64+i*32+24))
                put(w,24,1)
                put(w,32,1)
                return deliver(o,w)
            j=j+1
        i=i+1
    while True:
        candidate=0
        empty=0
        i=0
        while i<=bases and candidate==0:
            row=64+i*32
            cursor=get(w,row+16)
            if cursor>=get(w,row+8):
                empty=empty+1
            else:
                head=item(s,w,i,cursor)
                conflict=False
                j=0
                while j<=bases and conflict==False:
                    other=64+j*32
                    k=get(w,other+16)+1
                    while k<get(w,other+8) and conflict==False:
                        if item(s,w,j,k)==head:
                            conflict=True
                        k=k+1
                    j=j+1
                if conflict==False:
                    candidate=head
            i=i+1
        if candidate==0:
            if empty==bases+1:
                return deliver(o,w)
            put(w,24,2)
            put(w,32,0)
            i=0
            while i<=bases:
                row=64+i*32
                cursor=get(w,row+16)
                if cursor<get(w,row+8):
                    head=item(s,w,i,cursor)
                    j=0
                    duplicate=False
                    while j<get(w,32):
                        if get(w,result+j*8)==head:
                            duplicate=True
                        j=j+1
                    if duplicate==False:
                        n=get(w,32)
                        put(w,result+n*8,head)
                        put(w,32,n+1)
                i=i+1
            return deliver(o,w)
        n=get(w,32)
        put(w,result+n*8,candidate)
        put(w,32,n+1)
        i=0
        while i<=bases:
            row=64+i*32
            cursor=get(w,row+16)
            if cursor<get(w,row+8) and item(s,w,i,cursor)==candidate:
                put(w,row+16,cursor+1)
            i=i+1
    return BAD

def item(s:readbuf,w:mutbuf,row:u64,index:u64) -> u64:
    at=get(w,64+row*32)
    if at==MAX:
        return get(w,64+index*32+24)
    return readword(s,at+index*8)

def deliver(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,32)
    if n>(MAX-32)//8:
        return SHORT
    required=32+n*8
    put(w,0,required)
    if length(o)<required:
        return SHORT
    put(o,0,REPLY)
    put(o,8,get(w,24))
    put(o,16,n)
    put(o,24,0)
    i=0
    at=get(w,16)
    while i<n:
        put(o,32+i*8,get(w,at+i*8))
        i=i+1
    return 0

def get(w:mutbuf,p:u64) -> u64:
    return word_load(w,p)
def readword(s:readbuf,p:u64) -> u64:
    return word_load(s,p)
def put(w:mutbuf,p:u64,v:u64) -> u64:
    word_store(w,p,v)
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in CONSTANTS.items():source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def program():return document(source_program(),'native_class_mro')
if __name__=='__main__':
    from hepta.hia_program import verify_program
    doc=program();verify_program(doc);raw=render_assembly(doc).encode();p=ROOT/'examples/hia_bootstrap/native_class_mro.hepta';p.write_bytes(raw);print(p,len(raw))
