"""Current native NDU context using immutable same-construction records.

The input/call/result protocols and complete ownership policy remain unchanged.
HIANKP02 supplies exactly three records from the context's own immutable image;
the caller supplies descriptors only. Original v1 sources and pins remain fixed.
"""
from hashlib import sha256
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools import generate_hia_ndu_rank_context as prior
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_context_records.hepta"
PRIOR_AUTHOR_SHA256="b7b572d3209b8ae9540e3ada9d5c6ea37b735e5420ef6aec239278f4835d7ef8"
RECORD_AT=15000
IDENTITY=int.from_bytes(b"HIANKI01","little")
EXTRA=r'''
def record_slot(i:u64) -> u64:
    return 15000+choose(i==3,2,i)*64

def records_valid(w:mutbuf) -> bool:
    i=0
    while i<3:
        p=15000+i*64
        if get(w,p)!=IDENTITY or get(w,p+8)!=choose(i==2,3,i) or get(w,p+56)!=0:
            return False
        n=get(w,p+16)
        if i==0 and (n<176 or n>8388608):
            return False
        if i==1 and (n<176 or n>16777216):
            return False
        if i==2:
            if n!=10100891:
                return False
            if get(w,p+24)!=T0 or get(w,p+32)!=T1 or get(w,p+40)!=T2 or get(w,p+48)!=T3:
                return False
        i=i+1
    return True

def expected_hash(w:mutbuf,i:u64) -> u64:
    at=record_slot(i)+24
    count=0
    while count<32:
        store(w,17920+count,byte(w,at+count))
        count=count+1
    return 0
'''
def program():
    original=Path(prior.__file__).read_bytes()
    if sha256(original).hexdigest()!=PRIOR_AUTHOR_SHA256:
        raise ValueError("fixed original native context author differs")
    source=prior.SOURCE
    changes=(
      ("if length(s)!=128 or readword(s,40)!=0:",
       "if length(s)!=128 or (op!=3 and readword(s,40)!=0):"),
      ("put(o,176,clock_value(o))",
       "started=readword(s,40)\n        if started==0 or started>clock_value(o):\n            return done(o,w,1)\n        put(o,176,started)"),
      ("            zero(w,0,131072)",
       "            if records_valid(w)==False:\n                return done(o,w,7)\n            zero(w,0,15000)\n            zero(w,15192,131072)"),
      ("get(w,2096)!=expected_size(i)", "get(w,2096)!=expected_size(w,i)"),
      ("def expected_size(i:u64) -> u64:\n    return choose(i==0,5980873,choose(i==1,16159172,10100891))",
       "def expected_size(w:mutbuf,i:u64) -> u64:\n    return get(w,record_slot(i)+16)"),
    )
    for old,new in changes:
        if source.count(old)!=1:raise ValueError("context record predecessor differs: "+old)
        source=source.replace(old,new,1)
    constants=dict(prior.C)
    constants.update({name:int.from_bytes(value,"little")for name,value in {
        "REQUEST":b"HIANKC02","REPLY":b"HIANKS02","STATE":b"HIANKT02","RANK_REPLY":b"HIANKR02"}.items()})
    digest=bytes.fromhex("735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706")
    constants.update({"IDENTITY":IDENTITY,**{"T"+str(i):int.from_bytes(digest[i*8:i*8+8],"little")for i in range(4)}})
    text=re.sub(r"\b[A-Z][A-Z_0-9]*\b",lambda m:str(constants.get(m.group(),m.group())),source+EXTRA)
    if Path(prior.__file__).read_bytes()!=original:raise ValueError("original context author changed")
    return text
if __name__=="__main__":
    raw=render_assembly(document(program(),"ndu_rank_context_records")).encode()
    (ROOT/OUTPUT).write_bytes(raw);print(OUTPUT,len(raw),sha256(raw).hexdigest())
