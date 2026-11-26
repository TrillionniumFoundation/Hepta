"""Owned Path.resolve profile for native compiler discovery.

The existing resolution algorithm is retained verbatim except that descriptor
close requests pass through HIA custody, and the sealed result is borrowed until
the explicit same-process retirement operation acknowledges actual closure.
"""
from pathlib import Path
import re
from tools import generate_hia_native_path_resolve as original
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update(MAGIC=int.from_bytes(b'HIAPTO01','little'),REPLY=int.from_bytes(b'HIAPOR01','little'),
 OWN_MAGIC=int.from_bytes(b'HIAPOW01','little'),OWN_TAG=2304,OWN_SELF=2312,OWN_PID=2320,OWN_EXTENT=2328,
 OWN_FD=2336,OWN_NEXT=2344,OWN_COUNT=2352,OWN_UNKNOWN=2360,OWN_METHOD=2368,OWN_DONE=2376,
 OWN_INDEX=2384,OWN_ERROR=2392,OWN_FDS=2400)
WRAPPER=r'''
def owned_resolve(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<32 or length(o)<128 or length(w)<200704:
        return 4294967293
    if word_load(s,0)!=MAGIC or word_load(s,16)!=length(s)-32 or word_load(s,24)!=0:
        return 4294967293
    mode=word_load(s,8)
    if mode>2:
        return 4294967293
    if get(w,OWN_TAG)==0:
        if mode==2 or get(w,OWN_DONE)!=0:
            return 4294967293
        if mode==1 and (length(s)<34 or byte(s,32)!=34 or byte(s,length(s)-1)!=34):
            return 4294967293
        put(w,OWN_TAG,OWN_MAGIC)
        put(w,OWN_SELF,get(w,16))
        put(w,OWN_EXTENT,length(w))
        put(w,OWN_UNKNOWN,0)
        put(w,OWN_COUNT,0)
        put(w,OWN_METHOD,0)
        put(w,OWN_ERROR,0)
        put(w,OWN_DONE,0)
        i=0
        while i<6:
            put(w,256+i*8,NONE)
            i=i+1
        return raw_call(o,w,610,39,0,0,0,0,0,0,0)
    if get(w,OWN_TAG)!=OWN_MAGIC or get(w,OWN_SELF)!=get(w,16) or get(w,OWN_EXTENT)!=length(w):
        return 4294967293
    if get(w,OWN_DONE)==1:
        if mode!=2 or length(s)!=32:
            return 4294967293
        put(w,OWN_DONE,0)
        return raw_call(o,w,611,39,0,0,0,0,0,0,0)
    phase=get(w,0)
    r=get(w,8)
    if phase==610:
        put(w,OWN_PID,r)
        put(w,0,0)
    elif phase==611:
        if r!=get(w,OWN_PID):
            put(w,OWN_DONE,1)
            return 4294967293
        if get(w,264)!=NONE:
            retain_fd(w,get(w,264))
            put(w,264,NONE)
        put(w,OWN_INDEX,0)
        put(w,OWN_ERROR,0)
        return retire_next(o,w)
    elif phase==620 or phase==621:
        if phase==620 and r==18446744073709551578:
            put(w,OWN_METHOD,1)
            return raw_call(o,w,621,3,0,get(w,OWN_FD),0,0,0,0,0)
        if failed(r):
            if phase==621:
                put(w,OWN_UNKNOWN,1)
            else:
                retain_fd(w,get(w,OWN_FD))
        put(w,0,get(w,OWN_NEXT))
        put(w,8,r)
        return 3
    elif phase==630 or phase==631:
        if phase==630 and r==18446744073709551578:
            put(w,OWN_METHOD,1)
            return raw_call(o,w,631,3,0,get(w,OWN_FD),0,0,0,0,0)
        index=get(w,OWN_INDEX)
        if failed(r):
            if get(w,OWN_ERROR)==0:
                put(w,OWN_ERROR,r)
            if phase==631:
                put(w,OWN_UNKNOWN,1)
                put(w,OWN_FDS+index*8,NONE)
        else:
            put(w,OWN_FDS+index*8,NONE)
        put(w,OWN_INDEX,index+1)
        return retire_next(o,w)
    result=resolve_legacy(s,o,w)
    if result==owned_zero():
        return owned_result(o,w,0)
    return result

def owned_zero() -> u32:
    return 0

def retain_fd(w:mutbuf,fd:u64) -> u64:
    n=get(w,OWN_COUNT)
    i=0
    while i<n:
        if get(w,OWN_FDS+i*8)==fd:
            return 0
        i=i+1
    if n>=8:
        put(w,OWN_UNKNOWN,1)
        return 0
    put(w,OWN_FDS+n*8,fd)
    put(w,OWN_COUNT,n+1)
    return 0

def owned_call(o:mutbuf,w:mutbuf,next:u64,nr:u64,flags:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    if nr!=3:
        return raw_call(o,w,next,nr,flags,a,b,c,d,e,f)
    put(w,OWN_FD,a)
    put(w,OWN_NEXT,next)
    if get(w,OWN_METHOD)==1:
        return raw_call(o,w,621,3,0,a,0,0,0,0,0)
    return raw_call(o,w,620,436,0,a,a,0,0,0,0)

def retire_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,OWN_INDEX)
    while i<get(w,OWN_COUNT):
        fd=get(w,OWN_FDS+i*8)
        put(w,OWN_INDEX,i)
        if fd!=NONE:
            put(w,OWN_FD,fd)
            if get(w,OWN_METHOD)==1:
                return raw_call(o,w,631,3,0,fd,0,0,0,0,0)
            return raw_call(o,w,630,436,0,fd,fd,0,0,0,0)
        i=i+1
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,32,NONE)
    if get(w,OWN_ERROR)!=0:
        put(o,8,4)
        put(o,16,get(w,OWN_ERROR))
        put(o,24,630)
    return owned_result(o,w,1)

def owned_result(o:mutbuf,w:mutbuf,retiring:u64) -> u32:
    pending=choose(get(w,264)!=NONE,1,0)
    i=0
    while i<get(w,OWN_COUNT):
        if get(w,OWN_FDS+i*8)!=NONE:
            pending=pending+1
        i=i+1
    unknown=get(w,OWN_UNKNOWN)
    put(o,88,choose(unknown!=0,2,choose(pending!=0,1,0)))
    put(o,96,choose(unknown==0,1,0))
    put(o,104,choose(retiring==1 and pending==0 and unknown==0,1,0))
    put(o,112,pending)
    put(o,120,unknown)
    put(w,OWN_DONE,1)
    if retiring==1 and pending==0 and unknown==0:
        zero(w,0,4096)
    return 0
'''
def source_program():
 source=original.SOURCE.replace('def resolve(', 'def resolve_legacy(').replace('def call(', 'def raw_call(')
 source=re.sub(r'\bcall\(', 'owned_call(', source)
 marker='        put(w,264,NONE)\n    return 0\n\ndef closing'
 assert source.count(marker)==1
 source=source.replace(marker,'    return 0\n\ndef closing')
 source=WRAPPER+'\n'+source
 for name,value in C.items():source=re.sub(r'\b'+name+r'\b',str(value),source)
 return source
def main():
 d=document(source_program(),'native_path_resolve_owned')
 assert len(d['functions'])<=128 and sum(len(f['blocks'])for f in d['functions'])<=1536 and sum(len(b['ops'])for f in d['functions']for b in f['blocks'])<=8192
 p=ROOT/'examples/hia_bootstrap/native_path_resolve_owned.hepta';p.write_text(render_assembly(d))
 print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
