"""NDU proof facade with an explicitly captured sealed constructor descriptor.

The original public facade, frame and whole-image pin remain independent.
HIANPT01 and HIANPR01 carry one descriptor selected by the native NDU process owner.
A fixed HIANRM01 record in this image binds its complete size/mode/SHA256.
Both initial and terminal reads hash the complete captured constructor; all
original proof, timeout, signal, result and image identity checks remain.
"""
from pathlib import Path
from hashlib import sha256
import re
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_public_proof_facade as prior
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_proof_facade.hepta"
PRIOR_SHA256="475eb49f34f0c960752e440989e939e99359d9d87c05c539e4c5bfd28879234f"
META=34048
SAVED_STAT=34112

def resolved(text):
    values={**prior.C,"NDU_TYPED":int.from_bytes(b"HIANPT01","little"),
            "NDU_RAW":int.from_bytes(b"HIANPR01","little"),
            "NDU_RECORD":int.from_bytes(b"HIANRM01","little"),
            "NDU_META":META,"NDU_STAT":SAVED_STAT}
    return re.sub(r"\b[A-Z][A-Z_0-9]*\b",lambda m:str(values.get(m.group(),m.group())),text)

def one(text,old,new):
    old=resolved(old);new=resolved(new)
    if text.count(old)!=1:raise ValueError("NDU facade exact predecessor differs: "+old[:80])
    return text.replace(old,new,1)

def source_program():
    original=Path(prior.__file__).read_bytes()
    if sha256(original).hexdigest()!=PRIOR_SHA256:raise ValueError("fixed public facade author differs")
    source=prior.source_program()
    begin=prior.BEGIN[:prior.BEGIN.index("\ndef start_budget(")]
    begin=begin.replace("tag!=REQUEST and tag!=CALL_REQUEST and tag!=TYPED","tag!=NDU_TYPED and tag!=NDU_RAW")
    begin=begin.replace("    zero(w,256,768)", "    if readword(s,56)<3 or readword(s,56)>2147483647:\n        return 4294967293\n    zero(w,256,768)",1)
    begin=begin.replace("if readword(s,56)!=0 or mode<1", "if mode<1")
    begin=begin.replace("if tag==TYPED:","if tag==NDU_TYPED:")
    begin=begin.replace("        i=56\n","        if readword(s,56)<3 or readword(s,56)>2147483647:\n            return 4294967293\n        i=64\n")
    begin=begin.replace("image_range(w,get(w,96),get(w,104))==False","(get(w,104)!=64 or get(w,96)>get(w,88) or 64>get(w,88)-get(w,96))")
    source=prior.replace_function(source,"begin",resolved(begin))
    source=one(source,"""    if phase==15:
        put(w,488,get(w,96))
        put(w,496,get(w,104))
        return hash_begin(w,20,2,get(w,488),get(w,496),NORMAL_ID,0)""","""    if phase==15:
        if get(w,104)!=64:
            return identity_failure(o,w)
        put(w,0,16)
        put(w,24,get(w,96))
        put(w,32,64)
        put(w,40,NDU_META)
        return 4
    if phase==16:
        if get(w,NDU_META)!=NDU_RECORD or get(w,NDU_META+8)<176 or get(w,NDU_META+8)>8388608 or get(w,NDU_META+16)!=320 or get(w,NDU_META+56)!=0:
            return identity_failure(o,w)
        put(w,496,get(w,NDU_META+8))
        copy(w,NDU_META+24,NORMAL_ID,32)
        return call(o,w,17,72,0,readword(s,56),1030,3,0,0,0)
    if phase==17:
        if failed(result):
            return unavailable(o,w)
        put(w,504,result)
        return call(o,w,18,72,0,result,1034,0,0,0,0)
    if phase==18:
        if result!=15:
            return identity_failure(o,w)
        return call(o,w,19,5,4,get(w,504),STAT,0,0,0,0)
    if phase==19:
        if failed(result) or get(w,STAT+16)!=0 or (get(w,STAT+24)&61440)!=32768 or (get(w,STAT+24)&511)!=320 or get(w,STAT+48)!=get(w,496):
            return identity_failure(o,w)
        copy(w,STAT,NDU_STAT,144)
        return hash_begin(w,30,3,0,get(w,496),HTMP,get(w,504))""")
    capture_start="def capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:\n"
    source=one(source,capture_start,capture_start+"""    if phase==30:
        if equal(w,NORMAL_ID,HTMP,32)==False:
            return identity_failure(o,w)
        put(w,360,get(w,504))
        put(w,504,NONE)
        put(w,480,1)
        put(w,488,choose(get(w,FAMILY)==2,get(w,152),get(w,112)))
        put(w,496,choose(get(w,FAMILY)==2,get(w,160),get(w,120)))
        return hash_begin(w,20,2,get(w,488),get(w,496),ENGINE_ID,0)
""")
    old="""    if phase==104:
        if failed(result) or equal(w,STAT,33024,72)==False or equal(w,STAT+88,33024+88,32)==False:
            put(w,544,13)
            put(w,352,get(w,352)|128)
        return advance(w,102)"""
    new="""    if phase==104:
        if failed(result) or equal(w,STAT,33024,72)==False or equal(w,STAT+88,33024+88,32)==False:
            put(w,544,13)
            put(w,352,get(w,352)|128)
        if get(w,360)!=NONE:
            return call(o,w,115,72,0,get(w,360),1034,0,0,0,0)
        return advance(w,102)
    if phase==115:
        if result!=15:
            put(w,544,13)
            put(w,352,get(w,352)|128)
        return call(o,w,116,5,4,get(w,360),STAT,0,0,0,0)
    if phase==116:
        if failed(result) or equal(w,STAT,NDU_STAT,72)==False or equal(w,STAT+88,NDU_STAT+88,32)==False:
            put(w,544,13)
            put(w,352,get(w,352)|128)
        return hash_begin(w,117,3,0,get(w,NDU_META+8),HTMP,get(w,360))
    if phase==117:
        if equal(w,NORMAL_ID,HTMP,32)==False:
            put(w,544,13)
            put(w,352,get(w,352)|128)
        return advance(w,102)"""
    source=one(source,old,new)
    if Path(prior.__file__).read_bytes()!=original:raise ValueError("facade author changed")
    return source

def program():
    return prior.document(source_program(),"ndu_rank_proof_facade")

if __name__=="__main__":
    raw=render_assembly(program()).encode();(ROOT/OUTPUT).write_bytes(raw)
    print(OUTPUT,len(raw),sha256(raw).hexdigest())
