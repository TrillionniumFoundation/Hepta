"""Managed BG ledger over the real Jobs owner; retained ledger domains stay intact."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_multiversion_background_ledger as original
from tools import hia_background_managed_value_source as M
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),"little")for k,v in dict(
 MAGIC="HIABLM01",MAGIC2="HIABLM02",STATE="HIABLMS1",REPLY="HIABLMR1",
 JOBS_INPUT="HIABJM01",JOBS_REPLY="HIABJMR1").items()})
C.update(D_QUEUE=928,D_MAP=936,D_UNKNOWN=944,D_LOCAL=952)
EXTRA=r'''
def managed_retry(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or get(w,0)!=STATE or get(w,8)!=pid:
            return finish(o,w,6)
        put(o,PID,pid)
        if get(w,224)==0:
            return finish(o,w,0)
        if get(w,224)!=1:
            put(o,D_UNKNOWN,1)
            return finish(o,w,9)
        from_work(w,o,232,GUARD,24)
        request(o,JOBS_INPUT,12)
        return jobs(o,w,701)
    if phase==701:
        if managed_reply(o,0)==0:
            return keep_guard(o,w,2)
        if get(o,D_UNKNOWN)!=0:
            return keep_guard(o,w,2)
        if get(o,D_LOCAL)!=0 or get(o,D_MAP)!=0:
            return keep_guard(o,w,1)
        if get(o,GUARD)==0:
            zero(w,224,32)
            return finish(o,w,0)
        request(o,JOBS_INPUT,11)
        copy_local(o,GUARD,RQ+24,24)
        return jobs(o,w,931)
    return keep_guard(o,w,2)
def managed_reply(o:mutbuf,consuming:u64) -> u64:
    if valid(o,JOBS_REPLY)==0 or get(o,RP+136)!=1 or get(o,RP+128)>1:
        return 0
    if consuming==0 and get(o,RP+128)!=0:
        return 0
    status=get(o,RP+8)
    if status!=0 and status!=1 and status!=5 and status!=6 and status!=9 and status!=11:
        return 0
    # A consumed child reference is cleared before interpreting separate
    # dependency-retirement fields. The input token must never be dropped twice.
    if get(o,RP+128)!=0:
        zero(o,GUARD,24)
    if get(o,RP+144)>1 or get(o,RP+152)>1 or get(o,RP+160)>1 or get(o,RP+168)>1 or get(o,RP+176)!=1 or get(o,RP+184)!=0:
        return 0
    if get(o,RP+152)!=0:
        put(o,D_QUEUE,1)
    put(o,D_LOCAL,get(o,RP+144))
    put(o,D_MAP,get(o,RP+160))
    put(o,D_UNKNOWN,get(o,RP+168))
    if status==0 and consuming==1 and get(o,RP+128)!=1:
        return 0
    return 1
def keep_guard(o:mutbuf,w:mutbuf,kind:u64) -> u32:
    put(w,224,kind)
    to_work(o,w,GUARD,232,24)
    zero(o,GUARD,24)
    if kind==2:
        put(o,D_UNKNOWN,1)
    return finish(o,w,9)
'''
def source_program():
    text=original.SOURCE.replace("def multiversion_background_ledger(","def ledger_managed(")
    text=M.replace(text,"    if phase<900:\n        return 4294967293",
      "    if phase>=700 and phase<710:\n        return managed_retry(o,w,phase)\n    if phase<900:\n        return 4294967293")
    text=M.replace(text,"def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n",
      "def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(s)==128 and readword(s,0)==MAGIC and readword(s,8)==5:\n        at=16\n        while at<128:\n            if readword(s,at)!=0:\n                return 4294967293\n            at=at+8\n        zero(o,64,8128)\n        put(o,OP,5)\n        return system(o,700,39,0,0,0,0,0,0,0)\n")
    text=M.replace(text,"        if get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:",
       "        if get(w,224)!=0:\n            return finish(o,w,6)\n        if get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:")
    text=M.replace(text,"        request(o,JOBS_INPUT,3)","        request(o,JOBS_INPUT,11)")
    text=M.replace(text,"""    if phase==931:
        if valid(o,JOBS_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,9)
        zero(o,GUARD,24)
        return finish(o,w,get(o,ERROR))""",
      """    if phase==931:
        if managed_reply(o,1)==0:
            return keep_guard(o,w,2)
        if get(o,D_UNKNOWN)!=0:
            return keep_guard(o,w,2)
        if get(o,D_LOCAL)!=0 or get(o,D_MAP)!=0 or get(o,GUARD)!=0:
            return keep_guard(o,w,1)
        if get(o,OP)==5:
            zero(w,224,32)
        return finish(o,w,get(o,ERROR))""")
    text=M.replace(text,"    return 0\n\ndef from_work",
       "    put(o,128,get(o,D_QUEUE))\n    put(o,136,get(o,D_MAP))\n    put(o,144,get(o,D_UNKNOWN))\n    put(o,152,get(o,D_LOCAL))\n    put(o,160,choose(get(w,224)!=0,1,0))\n    put(o,168,1)\n    return 0\n\ndef from_work")
    tree=ast.parse(original.JOBS_SOURCE)
    for name in original.HELPERS:
        node=next(n for n in tree.body if n.name==name)
        text+='\n'+ast.get_source_segment(original.JOBS_SOURCE,node)+'\n'
    return M.render(text+EXTRA,C,"ledger_managed")
def main():
    d=document(source_program(),"background_optimizer_ledger_managed")
    p=ROOT/"examples/hia_bootstrap/background_optimizer_ledger_managed.hepta"
    p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
