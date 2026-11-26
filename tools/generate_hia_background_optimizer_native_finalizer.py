"""Fixed native kind-6 retirement adapter.

The one Value finalizer supplies the retained registry capability. The adapter
only acknowledges an actual native object retirement; queue-wide Value work
remains with the enclosing drain, and a self join remains pending.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools.generate_hia_background_optimizer_native_object_construct import HELPERS
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT="HIAVRFQ1",REPLY="HIAVRFR1",STATE="HIABGNC1",
 RAW="HIABGOQ1",RAW_REPLY="HIABGOR1").items()}
C.update(PH=128,FB=136,CHILD=1024,RQ=4096,OUT=1048576)
SOURCE=r'''
def background_native_finalizer(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or length(o)<OUT or length(w)!=512:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        if word_load(s,0)!=INPUT or word_load(s,8)>1 or word_load(s,16)==0 or word_load(s,24)!=6:
            return 4294967293
        if word_load(s,32)==0 or word_load(s,40)==0 or word_load(s,48)==0 or empty(s,56,72)==0:
            return 4294967293
        if get(w,0)!=STATE or get(w,16)==0 or get(w,128)==0 or get(w,136)!=word_load(s,16):
            return reply(o,11,0,0,0)
        if get(w,32)==0 or get(w,40)==0 or get(w,48)!=256 or get(w,168)!=1:
            return reply(o,11,0,0,0)
        zero(o,RQ,192)
        put(o,RQ,RAW)
        put(o,RQ+8,2)
        copy_s(s,32,o,RQ+24,24)
        put(o,PH,1)
        return 16
    if phase==1:
        if get(o,FB)!=0 or get(o,CHILD)!=RAW_REPLY:
            return reply(o,11,0,0,0)
        known=get(o,CHILD+16)
        consumed=get(o,CHILD+88)
        if known>1 or consumed>1 or get(o,CHILD+72)>1 or get(o,CHILD+96)>1 or get(o,CHILD+104)>1:
            return reply(o,11,0,0,0)
        if known==0:
            return reply(o,11,0,0,0)
        if consumed==1:
            if get(o,CHILD+8)!=0 or get(o,CHILD+72)!=0 or get(o,CHILD+96)!=0 or get(o,CHILD+24)!=0:
                return reply(o,11,1,1,1)
            return reply(o,0,1,1,0)
        return reply(o,11,1,0,1)
    return 4294967293
def reply(o:mutbuf,status:u64,known:u64,consumed:u64,pending:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,known)
    put(o,24,consumed)
    put(o,32,pending)
    return 0
def empty(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(s,at+i)!=0:
            return 0
        i=i+1
    return 1
'''
def source_program():return M.render(SOURCE+HELPERS,C,"background_native_finalizer")
def main():
    name="background_optimizer_native_finalizer";d=document(source_program(),name)
    p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
