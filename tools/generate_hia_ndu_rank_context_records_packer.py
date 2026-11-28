"""Native current-context packer with three immutable construction identities.

The existing context bridge's full admission and action bodies are preserved.
After its original buffer admission, a fixed bounded copy supplies the records
from this sealed image to the context policy. Caller records are never accepted.
The original HIANKP01 packer and fixed v1 context remain separate.
"""
from pathlib import Path
from hashlib import sha256
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools import generate_hia_ndu_rank_context_packer as prior
from tools.generate_hia_ndu_rank_context_payload import ALLOC,FREE_OFFSET,literal,COMMON
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_context_records_packer.hepta"
RECORD_AT=15000
RECORD_BYTES=192
PREFIX_CUT=prior.BRIDGE.index(bytes.fromhex("53554154415541564157"))
assert prior.BRIDGE[:PREFIX_CUT].endswith(bytes.fromhex("eb06b8fdffffffc3"))
# Save exactly the three caller argument registers consumed by rep movsb.
# r8 remains the originally admitted workspace base; all six arguments restore.
COPY=bytes.fromhex("575651488d3500000000498db8")+RECORD_AT.to_bytes(4,"little")+bytes.fromhex("b9c0000000fcf3a4595e5f")
BRIDGE=prior.BRIDGE[:PREFIX_CUT]+COPY+prior.BRIDGE[PREFIX_CUT:]
HOLES={key:offset+(len(COPY)if offset>=PREFIX_CUT else 0)for key,offset in prior.HOLES.items()}
RECORD_HOLE=PREFIX_CUT+6
POLICY=r'''
def pack_context(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or readword(s,0)!=MAGIC or readword(s,32)!=192 or readword(s,40)!=0 or readword(s,48)!=0 or readword(s,56)!=0:
        return 4294967295
    a=readword(s,8)
    b=readword(s,16)
    c=readword(s,24)
    if a<16 or a>4194304 or b<16 or b>4194304 or c<16 or c>4194304:
        return 4294967295
    if a+b+c+192!=length(s)-64:
        return 4294967295
    records=64+a+b+c
    if identities(s,records)==False:
        return 4294967295
    total=PREFIX+a+b+c+ALLOC_SIZE+192
    if length(o)<total:
        return 4294967294
    emit_bridge(o,0)
    i=0
    while i<a+b+c:
        store(o,PREFIX+i,byte(s,64+i))
        i=i+1
    emit_allocator(o,PREFIX+a+b+c)
    i=0
    while i<192:
        store(o,PREFIX+a+b+c+ALLOC_SIZE+i,byte(s,records+i))
        i=i+1
    put32(o,POLICY_HOLE,PREFIX-POLICY_HOLE-4)
    put32(o,SHA_HOLE,PREFIX+a-SHA_HOLE-4)
    put32(o,PAYLOAD_HOLE,PREFIX+a+b-PAYLOAD_HOLE-4)
    put32(o,MALLOC_HOLE,PREFIX+a+b+c-MALLOC_HOLE-4)
    put32(o,FREE_HOLE,PREFIX+a+b+c+FREE_OFFSET-FREE_HOLE-4)
    put32(o,RECORD_HOLE,PREFIX+a+b+c+ALLOC_SIZE-RECORD_HOLE-4)
    return total

def identities(s:readbuf,at:u64) -> bool:
    i=0
    while i<3:
        p=at+i*64
        if readword(s,p)!=IDENTITY or readword(s,p+8)!=choose(i==2,3,i) or readword(s,p+56)!=0:
            return False
        n=readword(s,p+16)
        if i==0 and (n<176 or n>8388608):
            return False
        if i==1 and (n<176 or n>16777216):
            return False
        if i==2:
            if n!=10100891:
                return False
            if readword(s,p+24)!=T0 or readword(s,p+32)!=T1 or readword(s,p+40)!=T2 or readword(s,p+48)!=T3:
                return False
        i=i+1
    return True
'''
def program():
    before=Path(prior.__file__).read_bytes()
    assert BRIDGE[:PREFIX_CUT]+BRIDGE[PREFIX_CUT+len(COPY):]==prior.BRIDGE
    # The complete threshold digest is fixed; its data semantics do not vary.
    pins=bytes.fromhex("735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706")
    values={"MAGIC":int.from_bytes(b"HIANKP02","little"),"IDENTITY":int.from_bytes(b"HIANKI01","little"),
            "PREFIX":len(BRIDGE),"ALLOC_SIZE":len(ALLOC),"FREE_OFFSET":FREE_OFFSET,"RECORD_HOLE":RECORD_HOLE}
    values.update({key.upper()+"_HOLE":value for key,value in HOLES.items()})
    values.update({"T"+str(i):int.from_bytes(pins[i*8:i*8+8],"little")for i in range(4)})
    source=re.sub(r"\b[A-Z][A-Z_0-9]*\b",lambda m:str(values.get(m.group(),m.group())),POLICY)
    source+=COMMON+literal("emit_bridge",BRIDGE)+literal("emit_allocator",ALLOC)
    if Path(prior.__file__).read_bytes()!=before:raise ValueError("original context packer changed")
    return source
if __name__=="__main__":
    raw=render_assembly(document(program(),"ndu_rank_context_records_packer")).encode()
    (ROOT/OUTPUT).write_bytes(raw);print(OUTPUT,len(raw),sha256(raw).hexdigest())
