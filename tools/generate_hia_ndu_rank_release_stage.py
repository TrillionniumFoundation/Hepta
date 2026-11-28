"""Source-build transport for the closed NDU rank construction profiles.

Only framing and complete input/output transfer live here. Each selected native
packer independently validates every role and its original size limits. The old
NDU leaf, public packers and their protocols remain unchanged.
"""
from pathlib import Path
from hashlib import sha256
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/source_ndu_rank_pack.hepta"
SOURCE=r'''
def policy(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<96:
        return 17
    phase=word_load(w,0)
    state=word_load(w,16)
    if phase==0:
        if state!=0 or length(s)!=21:
            return reject(w,16)
        if word_load(s,0)!=1 or word_load(s,8)!=5:
            return reject(w,16)
        if byte(s,16)!=98 or byte(s,17)!=117 or byte(s,18)!=105 or byte(s,19)!=108 or byte(s,20)!=100:
            return reject(w,16)
        word_store(w,16,1)
        return 0
    if phase==1:
        if state!=1 or frame_valid(s)==False:
            return reject(w,16)
        word_store(w,40,length(s))
        word_store(w,16,2)
        return 0
    if state!=2 or length(s)!=word_load(w,40):
        return reject(w,16)
    if phase==2:
        return 2
    if phase==4:
        if length(o)<length(s):
            return reject(w,17)
        at=0
        while length(s)-at>=8:
            word_store(o,at,word_load(s,at))
            at=at+8
        while at<length(s):
            store(o,at,byte(s,at))
            at=at+1
        word_store(w,80,length(s))
        return 0
    if phase==5:
        size=word_load(w,72)
        if size==0 or size>16777216 or length(o)<size:
            return reject(w,18)
        word_store(w,88,size)
        word_store(w,16,3)
        return 0
    return reject(w,16)

def frame_valid(s:readbuf) -> bool:
    if length(s)<16 or length(s)>33554432:
        return False
    magic=word_load(s,0)
    count=0
    header=0
    offset=8
    cap=4194304
    if magic==ENGINE:
        if length(s)<192 or word_load(s,8)!=21 or word_load(s,184)!=1:
            return False
        count=21
        header=192
        offset=16
    elif magic==OWNER:
        if length(s)<64 or word_load(s,56)!=1:
            return False
        count=6
        header=64
    elif magic==ERROR:
        count=1
        header=16
    elif magic==SCALAR:
        count=9
        header=80
    elif magic==CALL:
        count=10
        header=88
    elif magic==FACADE:
        count=16
        header=136
        cap=8388608
    elif magic==PAYLOAD:
        if length(s)<32 or word_load(s,16)!=0 or word_load(s,24)!=0:
            return False
        count=1
        header=32
        cap=1048576
    elif magic==CONTEXT:
        if length(s)<64 or word_load(s,32)!=192 or word_load(s,40)!=0 or word_load(s,48)!=0 or word_load(s,56)!=0:
            return False
        count=3
        header=64
    else:
        return False
    if length(s)<header:
        return False
    at=header
    i=0
    while i<count:
        n=word_load(s,offset+i*8)
        if n<16 or n>cap or n>length(s)-at:
            return False
        at=at+n
        i=i+1
    if magic==CONTEXT:
        return length(s)-at==192
    return at==length(s)

def reject(w:mutbuf,code:u32) -> u32:
    word_store(w,16,255)
    word_store(w,88,0)
    return code
'''
def program():
    import re
    kinds={"ENGINE":b"HIANEP02","OWNER":b"HIANOP02","ERROR":b"HIAERR01",
           "SCALAR":b"HIAMVK02","CALL":b"HIAMCK01","FACADE":b"HIANFP01",
           "PAYLOAD":b"HIANKPL1","CONTEXT":b"HIANKP02"}
    source=SOURCE
    for name,magic in kinds.items():source=re.sub(r"\b"+name+r"\b",str(int.from_bytes(magic,"little")),source)
    return document(source,"source_ndu_rank_pack")
def render():return render_assembly(program()).encode()
if __name__=="__main__":
    raw=render();(ROOT/OUTPUT).write_bytes(raw);print(OUTPUT,len(raw),sha256(raw).hexdigest())
