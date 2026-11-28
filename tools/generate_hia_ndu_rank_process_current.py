"""Explicit NDU proof descriptor transport; original HIANPS01/02 are retained.

HIANPS03 is role-2-only. It captures one extra sealed, unlinked, mode-0500
constructor descriptor and supplies only that owned descriptor to HIANPT01 or HIANPR01.
The original deadline/cancellation/process group/stream/seal rules remain.
"""
from pathlib import Path
from hashlib import sha256
import re
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_ndu_rank_process as prior
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_process_current.hepta"
PRIOR_SHA256="4b4c364a110f33fcdd71994f97b81f0c4c584c5abe033909765360f5a50f59ed"
MAGIC3=int.from_bytes(b"HIANPS03","little")
TYPED=int.from_bytes(b"HIANPT01","little")
RAW=int.from_bytes(b"HIANPR01","little")

def source_program():
    original=Path(prior.__file__).read_bytes()
    if sha256(original).hexdigest()!=PRIOR_SHA256:raise ValueError("fixed NDU process author differs")
    text=prior.SOURCE
    def one(old,new):
        nonlocal text
        if text.count(old)!=1:raise ValueError("NDU process exact predecessor differs: "+old[:80])
        text=text.replace(old,new,1)
    one("if magic!=MAGIC and magic!=MAGIC2:","if magic!=MAGIC and magic!=MAGIC2 and magic!=MAGIC3:")
    one("if magic==MAGIC2 and readword(s,64)>18446744073709551607:",
        "if (magic==MAGIC2 or magic==MAGIC3) and readword(s,64)>18446744073709551607:")
    one("    i=72\n    while i<128:","""    i=72
    if magic==MAGIC3:
        if role!=2 or readword(s,72)<3 or readword(s,72)>2147483647 or n<64:
            return 4294967293
        if (readword(s,128)!=TYPED and readword(s,128)!=RAW) or readword(s,184)!=0:
            return 4294967293
        i=80
    while i<128:""")
    one("    put(w,216,readword(s,48))","    put(w,216,readword(s,48))\n    put(w,344,choose(magic==MAGIC3,readword(s,72),0))")
    if text.count("while i<10:")!=2:raise ValueError("process descriptor inventory differs")
    text=text.replace("while i<10:","while i<11:")
    target="""        return call(o,w,6,39,0,0,0,0,0,0,0)
    if phase==6:"""
    new="""        if get(w,600)==MAGIC3:
            return call(o,w,31,72,0,get(w,344),1030,3,0,0,0)
        return call(o,w,6,39,0,0,0,0,0,0,0)
    if phase==31:
        if failed(result):
            return fail(o,w,3,result)
        put(w,336,result)
        return call(o,w,32,72,0,result,1034,0,0,0,0)
    if phase==32:
        if result!=15:
            return fail(o,w,3,result)
        zero(w,STAT,144)
        return call(o,w,33,5,4,get(w,336),STAT,0,0,0,0)
    if phase==33:
        if failed(result) or get(w,STAT+16)!=0 or (getn(w,STAT+24,4)&61440)!=32768 or (getn(w,STAT+24,4)&511)!=320 or get(w,STAT+48)<176 or get(w,STAT+48)>8388608:
            return fail(o,w,3,result)
        put(w,INPUT+56,get(w,336))
        return call(o,w,6,39,0,0,0,0,0,0,0)
    if phase==6:"""
    one(target,new)
    one("""    if phase==66:
        return call(o,w,67,322,84,get(w,328),EMPTY,ARGV,ENVP,4096,0)""","""    if phase==66:
        if get(w,600)==MAGIC3:
            return call(o,w,68,72,0,get(w,336),2,0,0,0,0)
        return call(o,w,67,322,84,get(w,328),EMPTY,ARGV,ENVP,4096,0)
    if phase==68:
        return call(o,w,67,322,84,get(w,328),EMPTY,ARGV,ENVP,4096,0)""")
    text=text.replace("if get(w,600)==MAGIC2:","if get(w,600)==MAGIC2 or get(w,600)==MAGIC3:")
    one("if get(w,600)!=MAGIC2:","if get(w,600)!=MAGIC2 and get(w,600)!=MAGIC3:")
    for name,word in [("normalizer",prior.TEXT[1]),("proof",prior.TEXT[2]),("build",prior.TEXT[3]),("diagnostic",prior.TEXT[4])]:
        text+="\ndef text_"+name+"(w:mutbuf,at:u64) -> u64:\n"
        for i,c in enumerate(word.encode()):text+="    store(w,at+"+str(i)+","+str(c)+")\n"
        text+="    return at+"+str(len(word))+"\n"
    for name,value in sorted({**prior.C,"MAGIC3":MAGIC3,"TYPED":TYPED,"RAW":RAW}.items(),key=lambda x:-len(x[0])):
        text=re.sub(r"\b"+name+r"\b",str(value),text)
    if Path(prior.__file__).read_bytes()!=original:raise ValueError("NDU process author changed")
    return text

def program():
    return prior.document(source_program(),"ndu_rank_process_current")
if __name__=="__main__":
    raw=render_assembly(program()).encode();(ROOT/OUTPUT).write_bytes(raw)
    print(OUTPUT,len(raw),sha256(raw).hexdigest())
