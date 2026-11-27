"""Private managed queue references, worker, snapshot and shutdown policies.

All lifecycle choices are emitted as HIA. Existing protocol authors keep their
original outputs. These profiles use the single captured Value owner.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import hia_background_managed_value_source as M
from tools import generate_hia_background_optimizer_snapshot as snapshot
from tools import generate_hia_background_optimizer_shutdown as shutdown
from tools import generate_hia_multiversion_background_worker as worker
from tools import generate_hia_multiversion_background_job_refs as refs
ROOT=Path(__file__).resolve().parents[1]
replace=M.replace
def magics(**values):return {k:int.from_bytes(v.encode(),"little")for k,v in values.items()}
COMMON=magics(PUBLIC_INPUT="HIABFP04",PUBLIC_DROP_INPUT="HIABFP04",PUBLIC_REPLY="HIABFRP3",PUBLIC_DROP_REPLY="HIABFRP3",
 JOB_INPUT="HIABJM01",JOB_DROP_INPUT="HIABJM01",JOB_REPLY="HIABJMR1",JOB_DROP_REPLY="HIABJMR1",
 CELL_INPUT="HIABFQ06",CELL_REPLY="HIABFR03",CELL_QUERY_INPUT="HIABFQ06",CELL_QUERY_REPLY="HIABFR03")

def snapshot_source():
    C=dict(snapshot.C);C.update(COMMON);C.update(M.MAGICS)
    C.update(magics(MAGIC="HIABSPQ2",REPLY="HIABSPR2",CONTEXT="HIABSPC2",SUBCTX="HIABSCC3",
                   WQ="HIABGW04",WR="HIABGWO2",JQ="HIABJM01",JR="HIABJMR1",LQ="HIABLM02",LR="HIABLMR1",
                   VALUE_INPUT="HIABVQ01",VALUE_REPLY="HIABVR01"))
    C.update(D_QUEUE=672,D_UNKNOWN=680,D_VOP=688)
    text=snapshot.source_program(symbolic=True)
    text=replace(text,"def snapshot(","def snapshot_managed(")
    text=re.sub(r"\bVQ\b","VALUE_INPUT",text);text=re.sub(r"\bVR\b","VALUE_REPLY",text)
    text=re.sub(r"\bvalue\(","values(",text)
    text=re.sub(r"(take_value\([^\n]*?\))==False",r"\1!=0",text)
    text=replace(text,"get(w,200)<16384","get(w,200)<1064960")
    text=M.apply(text)
    text=replace(text,"    put(o,56,get(o,DETAIL))\n    return 0",
      "    put(o,56,get(o,DETAIL))\n    put(o,64,get(o,D_QUEUE))\n    put(o,72,get(o,VALUE_PENDING))\n    put(o,80,get(o,D_UNKNOWN))\n    put(o,88,1)\n    return 0")
    return M.render(text,C,"snapshot_managed")

def shutdown_source():
    C=dict(shutdown.C);C.update(COMMON);C.update(M.MAGICS)
    C.update(magics(INPUT="HIABSHQ2",REPLY="HIABSHR2",CONTEXT="HIABSHC2",WORKER_INPUT="HIABGW04",WORKER_REPLY="HIABGWO2"))
    C.update(D_QUEUE=312,D_UNKNOWN=320,D_VOP=328,SM_PIN=624,SM_VALUE=648,SM_PIN_AFTER=336,SM_PIN_SLOT=344)
    text=shutdown.source_program(symbolic=True)
    text=replace(text,"def shutdown(","def shutdown_managed(")
    text=M.apply(text)
    # Every raw Future alias used outside the queue condition is accompanied by
    # an actual strong canonical Future pin. The row keeps that pin to retirement.
    text=replace(text,"3,RECORD,72)","3,RECORD,96)")
    text=replace(text,"        request(o,PUBLIC_INPUT,5)\n        from_work(w,o,104,RQ+16,24)\n        within(o,RQ+40,RECORD+48,24)\n        return public_owner(o,w,24)",
       "        if get(o,RECORD+72)==0:\n            return quarantine(o,w,23)\n        request(o,VALUE_INPUT,5)\n        within(o,RQ+24,RECORD+72,24)\n        return values(o,w,230,128)")
    text=replace(text,"    if phase<20:","    if phase>=230 and phase<=232:\n        return managed_pin(o,w,phase)\n    if phase<20:")
    # Current row size already has unused 112..127 only; retain pins in a
    # disjoint bounded array at 3072 and release them after raw cell retirement.
    text=replace(text,"        return finish(o,w)\n    if phase==116:",
        "        put(o,SM_PIN_SLOT,0)\n        return again(o,232)\n    if phase==116:")
    text+=r'''
def managed_pin(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==230:
        at=3072+get(o,INDEX)*24
        if take_value(o,at)!=0:
            return quarantine(o,w,230)
        request(o,PUBLIC_INPUT,5)
        from_work(w,o,104,RQ+16,24)
        within(o,RQ+40,RECORD+48,24)
        return public_owner(o,w,24)
    if phase==231:
        at=3072+get(o,SM_PIN_SLOT)*24
        if release_value(o,at)==0:
            if get(o,DROP_KNOWN)==1:
                return retry_cleanup(o,w,231)
            return quarantine(o,w,231)
        put(o,SM_PIN_SLOT,get(o,SM_PIN_SLOT)+1)
        return again(o,232)
    i=get(o,SM_PIN_SLOT)
    if i>=get(o,COUNT):
        if get(o,VALUE_PENDING)!=0:
            return again(o,115)
        return finish(o,w)
    at=3072+i*24
    if get(o,at)==0:
        put(o,SM_PIN_SLOT,i+1)
        return again(o,232)
    return drop_value(o,w,231,at)
'''
    text=replace(text,"    put(o,56,kind)\n    return 0",
        "    put(o,56,kind)\n    managed_result(o)\n    return 0")
    text=replace(text,"    put(w,184,0)\n    return 0",
        "    put(w,184,0)\n    managed_result(o)\n    return 0")
    text+=r'''
def managed_result(o:mutbuf) -> u64:
    put(o,64,get(o,D_QUEUE))
    put(o,72,get(o,VALUE_PENDING))
    put(o,80,get(o,D_UNKNOWN))
    put(o,88,1)
    return 0
'''
    return M.render(text,C,"shutdown_managed")

def job_refs_source():
    C=dict(refs.C);C.update(magics(CONTEXT="HIABJRC2",JOB_INPUT="HIABJM01",JOB_INPUT3="HIABJM01",JOB_OUTPUT="HIABJMR1",JOB_OUTPUT2="HIABJMR1"))
    text=replace(refs.SOURCE,"def job_refs(","def managed_job_refs(")
    # The queue's existing two reference profiles stay intact. Both bind one
    # private Jobs owner; old raw Jobs cannot pass the new context contract.
    text=replace(text,"choose(special(s)!=0,11,word_load(s,8)+1)",
       "choose(word_load(s,8)==2,11,2)")
    text=replace(text,"        if word_load(o,PROFILE)!=0 and word_load(s,8)==2:",
       "        if word_load(s,8)==2:")
    # Primary consumption is recorded before checking independent diagnostics.
    text=replace(text,"            put(o,PENDING,word_load(o,RP+144))",
       "            put(o,PENDING,word_load(o,RP+144))\n            if word_load(o,RP+152)>1 or word_load(o,RP+160)>1 or word_load(o,RP+168)!=0 or word_load(o,RP+176)!=1:\n                return finish(o,9,0,0,0)")
    text=replace(text,"    return 0\n\ndef special",
       "    put(o,64,word_load(o,RP+152))\n    put(o,72,word_load(o,RP+160))\n    put(o,80,word_load(o,RP+168))\n    put(o,88,1)\n    return 0\n\ndef special")
    return M.render(text,C,"managed_job_refs")

WORKER_EXTRA=r'''
def managed_drain(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,DRAIN_NEXT,next)
    zero(o,RQ,128)
    put(o,RQ,VALUE_PRIVATE)
    put(o,RQ+8,56)
    put(o,PHASE,510)
    return 9
def managed_drained(o:mutbuf,w:mutbuf) -> u32:
    if get(o,SYSRET)!=0 or get(o,RP)!=VALUE_REPLY:
        put(w,208,1)
        put(w,200,1)
    elif get(o,RP+8)!=0:
        put(w,200,1)
    else:
        put(w,200,0)
    next=get(o,DRAIN_NEXT)
    if next==502:
        put(o,ACTIVE,0)
    return queue_call(o,w,next,choose(next==502,2,8))
'''
def worker_source():
    C=dict(worker.C);C.update(magics(INPUT3="HIABGW04",OUTPUT="HIABGWO2",STATE_MAGIC="HIABGWS2",
       HANDLER_INPUT2="HIABGWQ4",HANDLER_REPLY="HIABGWR3",VALUE_PRIVATE="HIABVQ05",VALUE_REPLY="HIABVR01"))
    C.update(DRAIN_NEXT=392,HANDLER_STATUS=400)
    text=replace(worker.SOURCE,"def worker(","def worker_managed(")
    text=replace(text,"    if magic!=INPUT and magic!=INPUT2 and magic!=INPUT3:","    if magic!=INPUT3:")
    text=replace(text," or (magic==INPUT2 and readword(s,8)!=0)","")
    # A public snapshot must observe physical thread completion. Keep the
    # private HIABGW03 query observational; only the bound managed profile
    # shares the existing serialized join when the worker announces exit.
    text=replace(text,"        if op==2:",
       "        if op==2 or (op==3 and get(w,24)==3):")
    text=replace(text,"            zero(w,0,512)",
       "            if readword(s,64)==0 or readword(s,72)==0 or readword(s,80)!=256:\n                return finish(o,4)\n            zero(w,0,512)")
    text=replace(text,"            put(w,104,readword(s,56))",
       "            put(w,104,readword(s,56))\n            put(w,176,readword(s,64))\n            put(w,184,readword(s,72))\n            put(w,192,readword(s,80))")
    text=replace(text,"        if get(w,0)!=STATE_MAGIC or get(w,8)!=pid:",
       "        if get(w,0)!=STATE_MAGIC or get(w,8)!=pid or get(w,176)==0 or get(w,184)==0 or get(w,192)!=256:")
    text=replace(text,"        used=choose(op==0 and at<=56,1,0)","        used=choose(op==0 and at<=80,1,0)")
    text=replace(text,"        if get(o,RP+8)==1:\n            return queue_call(o,w,550,8)\n        put(o,ACTIVE,0)\n        return queue_call(o,w,502,2)",
       "        if get(o,RP+32)>1 or get(o,RP+40)!=0 or get(o,RP+48)!=0 or get(o,RP+56)!=1:\n            return failed(o,503)\n        return managed_drain(o,w,choose(get(o,RP+8)==1,550,502))")
    text=replace(text,"    if phase==530:","    if phase==510:\n        return managed_drained(o,w)\n    if phase==530:")
    text=replace(text,"        put(o,ERR,65)\n        return queue_call(o,w,550,8)",
       "        put(o,ERR,65)\n        return managed_drain(o,w,550)")
    text=replace(text,"    put(o,JOINING,get(w,48))\n    return 0",
       "    put(o,JOINING,get(w,48))\n    put(o,408,get(w,200))\n    put(o,416,get(w,208))\n    return 0")
    text=replace(text,"    put(o,48,get(o,JOINING))\n    return 0",
       "    put(o,48,get(o,JOINING))\n    put(o,56,get(o,408))\n    put(o,64,get(o,416))\n    return 0")
    text+=WORKER_EXTRA
    return M.render(text,C,"worker_managed")

def main():
    for name,source in [
      ("background_optimizer_snapshot_managed",snapshot_source()),
      ("background_optimizer_shutdown_managed",shutdown_source()),
      ("background_optimizer_job_refs_managed",job_refs_source()),
      ("background_optimizer_worker_managed",worker_source())]:
        d=document(source,name);p=ROOT/"examples/hia_bootstrap"/(name+".hepta");p.write_text(render_assembly(d))
        print(p.name,p.stat().st_size,len(d["functions"]),sum(len(f["blocks"])for f in d["functions"]),sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
