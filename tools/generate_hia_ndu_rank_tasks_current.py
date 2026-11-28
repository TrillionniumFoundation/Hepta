"""NDU current task framing for the explicit sealed-constructor proof owner.

Only the proof process task selects HIANPS03/HIANPT01 and supplies the existing
native-captured NORMALIZER_FD. All other task bodies and frames are unchanged.
"""
from pathlib import Path
from hashlib import sha256
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_ndu_rank_tasks as prior
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_tasks_current.hepta"
PRIOR_SHA256="3cce87e4608ad54441b11cafd0ba67191d46e67b2d2c70f8de96e69e492cc3a1"

def source_program():
    original=Path(prior.__file__).read_bytes()
    if sha256(original).hexdigest()!=PRIOR_SHA256:raise ValueError("fixed NDU task author differs")
    source=prior.source_program()
    values=prior.CONSTANTS
    old="""    if step==1:
        put(o,STEP,2)
        return call(o,PROCESS_ROLE,1,base,128+get(o,INPUT_N),3,META,128,1,get(o,V0),20971520)"""
    new="""    if step==1:
        if get(o,PARAM)==2:
            if get(o,INPUT_N)<64 or get(w,base+184)!=0:
                return finish(o,4)
            put(w,base,PROCESS_CURRENT)
            put(w,base+72,get(o,NORMALIZER_FD))
            if get(w,base+128)==OLD_TYPED:
                put(w,base+128,CURRENT_TYPED)
            elif get(w,base+128)==OLD_RAW:
                put(w,base+128,CURRENT_RAW)
            else:
                return finish(o,4)
        put(o,STEP,2)
        return call(o,PROCESS_ROLE,1,base,128+get(o,INPUT_N),3,META,128,1,get(o,V0),20971520)"""
    import re
    constants={**values,"OLD_TYPED":int.from_bytes(b"HIAPPT01","little"),
               "CURRENT_TYPED":int.from_bytes(b"HIANPT01","little"),
               "OLD_RAW":int.from_bytes(b"HIAPPR01","little"),
               "CURRENT_RAW":int.from_bytes(b"HIANPR01","little"),
               "PROCESS_CURRENT":int.from_bytes(b"HIANPS03","little")}
    resolve=lambda t:re.sub(r"\b[A-Z][A-Z_0-9]*\b",lambda m:str(constants.get(m.group(),m.group())),t)
    old,new=resolve(old),resolve(new)
    if source.count(old)!=1:raise ValueError("NDU process task predecessor differs")
    source=source.replace(old,new,1)
    if Path(prior.__file__).read_bytes()!=original:raise ValueError("task author changed")
    return source

def program():
    return prior.document(source_program(),"ndu_rank_tasks_current")
if __name__=="__main__":
    raw=render_assembly(program()).encode();(ROOT/OUTPUT).write_bytes(raw)
    print(OUTPUT,len(raw),sha256(raw).hexdigest())
