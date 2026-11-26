"""Managed execution/accounting using private sole-arena Value dependencies."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_execution_owner as execution
from tools import generate_hia_background_optimizer_account_owner as account
from tools import hia_background_managed_value_source as managed
ROOT=Path(__file__).resolve().parents[1]
replace=managed.replace
def magics(**values):return {k:int.from_bytes(v.encode(),"little")for k,v in values.items()}
COMMON=magics(PUBLIC_INPUT="HIABFP04",PUBLIC_DROP_INPUT="HIABFP04",PUBLIC_REPLY="HIABFRP3",PUBLIC_DROP_REPLY="HIABFRP3",
 JOB_INPUT="HIABJM01",JOB_DROP_INPUT="HIABJM01",JOB_REPLY="HIABJMR1",JOB_DROP_REPLY="HIABJMR1",
 CELL_INPUT="HIABFQ06",CELL_REPLY="HIABFR03",CELL_QUERY_INPUT="HIABFQ06",CELL_QUERY_REPLY="HIABFR03",
 REPORT_REPLY="HIABRR02",REPORT_CONTEXT="HIABRC02",REPORT_OBSERVE="HIABROQ2",REPORT_RETRY="HIABRP05")

REPORT_HELPER=r'''
def managed_report(o:mutbuf) -> u64:
    if get(o,REPORT_OUT+96)>1 or get(o,REPORT_OUT+104)>2 or get(o,REPORT_OUT+112)>1:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,REPORT_OUT+120)>1 or get(o,REPORT_OUT+144)>1 or get(o,REPORT_OUT+152)>1 or get(o,REPORT_OUT+160)!=1:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,REPORT_OUT+120)!=0:
        put(o,D_QUEUE,1)
    if get(o,REPORT_OUT+96)!=0:
        kind=get(o,REPORT_OUT+104)
        if kind==0:
            kind=2
        put(o,R_PENDING,kind)
        return 0
    if get(o,REPORT_OUT+104)!=0 or get(o,REPORT_OUT+112)!=0 or get(o,REPORT_OUT+144)!=0 or get(o,REPORT_OUT+152)!=0:
        put(o,D_UNKNOWN,1)
        return 0
    return 1
'''
def account_source():
    C=dict(account.C);C.update(COMMON);C.update(managed.MAGICS)
    C.update(magics(MAGIC="HIABACQ3",REPLY="HIABACR3",CONTEXT="HIABACC3",REPORT_INPUT="HIABRP04",
      FREEZE_INPUT="HIABFZQ3",FREEZE_REPLY="HIABFZR3",FREEZE_CONTEXT="HIABFZC3",LEDGER_INPUT="HIABLM01",LEDGER_REPLY="HIABLMR1"))
    C.update(D_QUEUE=856,D_UNKNOWN=864,D_VOP=872,R_PENDING=880,R_MODE=888,L_PENDING=896)
    text=account.source_program(symbolic=True).replace("def account_owner(","def account_managed(")
    text=replace(text,"length(w)<4096","length(w)<36864")
    text=replace(text,"zero(o,REPORT_WORK,128)","zero(o,REPORT_WORK,32768)")
    text=replace(text,"            from_work(w,o,3200,ERR,896)",
        "            from_work(w,o,3200,ERR,896)\n            from_work(w,o,4096,REPORT_WORK,32768)")
    text=replace(text,"    to_work(o,w,ERR,3200,896)",
        "    to_work(o,w,ERR,3200,896)\n    to_work(o,w,REPORT_WORK,4096,32768)")
    text=replace(text,"        if rc!=0 or get(o,REPORT_OUT)!=REPORT_REPLY:\n            return fail(o,7,rc)\n        status=get(o,REPORT_OUT+8)",
        "        if rc!=0 or get(o,REPORT_OUT)!=REPORT_REPLY:\n            return bound_quarantine(o,w,2,201)\n        if managed_report(o)==0:\n            return bound_quarantine(o,w,choose(get(o,R_PENDING)==1,1,2),201)\n        if get(o,R_MODE)!=0:\n            if get(o,REPORT_OUT+24)!=0 or get(o,REPORT_OUT+48)!=0 or get(o,REPORT_OUT+72)!=0:\n                return bound_quarantine(o,w,2,201)\n            put(o,R_PENDING,0)\n            put(o,R_MODE,0)\n            return again(o,700)\n        status=get(o,REPORT_OUT+8)")
    text=replace(text,"    if phase==700:\n        if get(o,DROP_ACTIVE)!=0",
        "    if phase==700:\n        if get(o,R_PENDING)!=0:\n            if get(o,OP)!=1 or get(o,R_PENDING)!=1:\n                return bound_quarantine(o,w,choose(get(o,R_PENDING)==1,1,2),201)\n            zero(o,REPORT_SOURCE,128)\n            put(o,REPORT_SOURCE,REPORT_RETRY)\n            put(o,REPORT_SOURCE+8,2)\n            put(o,REPORT_OUT+128,0)\n            put(o,R_MODE,1)\n            return again(o,200)\n        if get(o,DROP_ACTIVE)!=0")
    text=replace(text,"        status=get(o,FREEZE_OUT+8)",
        "        if managed_pending(o,FREEZE_OUT,128,136,144,152)==0:\n            return bound_quarantine(o,w,2,301)\n        status=get(o,FREEZE_OUT+8)")
    text=replace(text,"        if get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:",
        "        if managed_pending(o,FREEZE_OUT,128,136,144,152)==0:\n            return bound_quarantine(o,w,2,701)\n        if get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:")
    text=text.replace("FREEZE_OUT+128","FREEZE_OUT+256")
    # Restore the new receipt's queue field; only error bytes move to 256.
    text=text.replace("managed_pending(o,FREEZE_OUT,256,136,144,152)","managed_pending(o,FREEZE_OUT,128,136,144,152)")
    text=replace(text,"    if status==1:\n        within(o,128,ERR,get(o,ERRN))",
        "    put(o,128,get(o,D_QUEUE))\n    put(o,136,get(o,VALUE_PENDING))\n    put(o,144,get(o,D_UNKNOWN))\n    put(o,152,1)\n    if status==1:\n        within(o,256,ERR,get(o,ERRN))")

    text=text.replace("if valid(o,RP,LEDGER_REPLY)==0:","if valid(o,RP,LEDGER_REPLY)==0 or managed_ledger(o)==0:")
    text=replace(text,"    if phase==700:\n        if get(o,R_PENDING)!=0:",
      "    if phase==780:\n        if valid(o,RP,LEDGER_REPLY)==0 or managed_ledger(o)==0 or get(o,RP+8)!=0:\n            return bound_quarantine(o,w,choose(get(o,L_PENDING)==1,1,2),780)\n        put(o,L_PENDING,0)\n        return again(o,700)\n    if phase==700:\n        if get(o,L_PENDING)!=0:\n            if get(o,OP)!=1 or get(o,L_PENDING)!=1:\n                return bound_quarantine(o,w,choose(get(o,L_PENDING)==1,1,2),780)\n            request(o,LEDGER_INPUT,5)\n            return ledger(o,w,780)\n        if get(o,R_PENDING)!=0:")
    text+=r'''
def managed_ledger(o:mutbuf) -> u64:
    if get(o,RP+128)>1 or get(o,RP+136)>1 or get(o,RP+144)>1 or get(o,RP+152)>1 or get(o,RP+160)>1 or get(o,RP+168)!=1:
        put(o,L_PENDING,2)
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,RP+128)!=0:
        put(o,D_QUEUE,1)
    if get(o,RP+160)!=0:
        put(o,L_PENDING,choose(get(o,RP+144)==0,1,2))
        return 0
    if get(o,RP+136)!=0 or get(o,RP+144)!=0 or get(o,RP+152)!=0:
        put(o,L_PENDING,2)
        put(o,D_UNKNOWN,1)
        return 0
    return 1
'''
    text=managed.apply(text)+REPORT_HELPER
    return managed.render(text,C,"account_managed")

def execution_source(entry):
    C=dict(execution.C);C.update(COMMON);C.update(managed.MAGICS)
    C.update(magics(MAGIC="HIABEXQ3",REPLY="HIABER03",CONTEXT="HIABEXC3",REPORT_INPUT="HIABRP03",
      IO_INPUT="HIABIQ03",IO_REPLY="HIABIO03",IO_CONTEXT="HIABIC03"))
    C.update(D_QUEUE=1168,D_UNKNOWN=1176,D_VOP=1184,R_PENDING=1192,R_MODE=1200)
    parts={}
    for oldentry in ("execute_owner","publish_owner"):
        source=execution.source_program(oldentry,symbolic=True)
        for node in ast.parse(source).body:
            if isinstance(node,ast.FunctionDef)and node.name not in parts:parts[node.name]=ast.get_source_segment(source,node)
    text="\n\n".join(parts.values())+"\n"
    text=text.replace("def execute_owner(","def execute_managed(").replace("def publish_owner(","def publish_managed(")
    text=text.replace("length(w)<16384","length(w)<49152")
    text=replace(text,"            from_work(w,o,8576,IO_WORK,256)",
        "            from_work(w,o,8576,IO_WORK,256)\n            from_work(w,o,16384,REPORT_WORK,32768)")
    text=replace(text,"    to_work(o,w,IO_WORK,8576,256)",
        "    to_work(o,w,IO_WORK,8576,256)\n    to_work(o,w,REPORT_WORK,16384,32768)")
    text=replace(text,"        if get(o,REPORT_OUT+8)!=0:\n            return fail(o,choose(get(o,REPORT_OUT+8)==5,5,7),get(o,REPORT_OUT+8))",
        "        if managed_report(o)==0:\n            return bound_quarantine(o,w,choose(get(o,R_PENDING)==1,1,2),1201)\n        if get(o,R_MODE)!=0:\n            if get(o,REPORT_OUT+24)!=0 or get(o,REPORT_OUT+48)!=0 or get(o,REPORT_OUT+72)!=0:\n                return bound_quarantine(o,w,2,1201)\n            put(o,R_PENDING,0)\n            put(o,R_MODE,0)\n            return again(o,2000)\n        if get(o,REPORT_OUT+8)!=0:\n            return fail(o,choose(get(o,REPORT_OUT+8)==5,5,7),get(o,REPORT_OUT+8))")
    text=replace(text,"    if phase==2000:\n        if get(o,PROVIDER_PENDING)!=0:",
        "    if phase==2000:\n        if get(o,R_PENDING)!=0:\n            if get(o,OP)!=1 or get(o,R_PENDING)!=1:\n                return bound_quarantine(o,w,choose(get(o,R_PENDING)==1,1,2),1201)\n            zero(o,REPORT_SOURCE,128)\n            put(o,REPORT_SOURCE,REPORT_RETRY)\n            put(o,REPORT_SOURCE+8,2)\n            put(o,REPORT_OUT+128,0)\n            put(o,R_MODE,1)\n            return again(o,1200)\n        if get(o,PROVIDER_PENDING)!=0:")
    text=replace(text,"        status=get(o,IO_OUT+8)",
        "        if managed_pending(o,IO_OUT,72,80,88,96)==0:\n            return bound_quarantine(o,w,2,1502)\n        status=get(o,IO_OUT+8)")
    text=replace(text,"        if get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0 or get(o,IO_WORK+88)!=0 or get(o,IO_WORK+96)!=0 or get(o,IO_WORK+104)!=0:\n            return bound_quarantine(o,w,2,1982)",
        "        if managed_pending(o,IO_OUT,72,80,88,96)==0:\n            return bound_quarantine(o,w,2,1982)\n        if get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0 or get(o,IO_WORK+88)!=0 or get(o,IO_WORK+96)!=0 or get(o,IO_WORK+104)!=0:\n            return bound_quarantine(o,w,2,1982)")
    text=replace(text,"    put(o,88,get(o,ERROR_FORMAT))",
        "    put(o,88,get(o,ERROR_FORMAT))\n    put(o,128,get(o,D_QUEUE))\n    put(o,136,get(o,VALUE_PENDING))\n    put(o,144,get(o,D_UNKNOWN))\n    put(o,152,1)")
    text=managed.apply(text)+REPORT_HELPER
    return managed.render(text,C,entry)

def main():
    for name,source in [("account_managed",account_source()),("execution_managed",execution_source("execute_managed")),
                         ("execution_managed_publication",execution_source("publish_managed"))]:
        doc=document(source,"background_optimizer_"+name)
        path=ROOT/("examples/hia_bootstrap/background_optimizer_"+name+".hepta");path.write_text(render_assembly(doc))
        print(path.name,path.stat().st_size,len(doc["functions"]),sum(len(f["blocks"])for f in doc["functions"]),sum(len(b["ops"])for f in doc["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
