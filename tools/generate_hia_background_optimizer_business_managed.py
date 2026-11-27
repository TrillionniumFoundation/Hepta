"""Managed native BackgroundOptimizer business and failure policies.

New Q4/Q5 context domain; old business owner sources remain byte-identical.
Canonical Future and metadata edges are moved together with real queue rows.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_business_owner as original
from tools import hia_background_managed_value_source as managed
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C);C.update(managed.MAGICS)
C.update({k:int.from_bytes(v.encode(),"little")for k,v in dict(
 INPUT2="HIABGWQ4",CLEAN_INPUT="HIABGWQ5",CONTEXT="HIABWBC3",
 REPLY="HIABGWR3",CLEAN_REPLY="HIABGWR4",
 EXEC_INPUT="HIABEXQ3",EXEC_REPLY="HIABER03",
 ACCOUNT_INPUT="HIABACQ3",ACCOUNT_REPLY="HIABACR3",
 PUBLIC_INPUT="HIABFP04",PUBLIC_DROP_INPUT="HIABFP04",PUBLIC_REPLY="HIABFRP3",PUBLIC_DROP_REPLY="HIABFRP3",
 JOB_INPUT="HIABJM01",JOB_DROP_INPUT="HIABJM01",JOB_REPLY="HIABJMR1",JOB_DROP_REPLY="HIABJMR1",
 CELL_QUERY_INPUT="HIABFQ06",CELL_QUERY_REPLY="HIABFR03",
 REPORT_INPUT="HIABRP03",REPORT_REPLY="HIABRR02",REPORT_CONTEXT="HIABRC02",REPORT_RETRY="HIABRP05").items()})
C.update(D_QUEUE=1200,D_UNKNOWN=1208,D_VOP=1216,MW_STATUS=1224,
 MW_PAIR=1232,MW_RETURN=1240,MW_PENDING_NEXT=1248,MW_PAIR_DONE=1256,MW_CLOSING=1264,
 MW_GLOBAL_PENDING=1272,MW_REPORT_PENDING=1280,MW_REPORT_MODE=1288,MW_ROOT_CHECKED=1296,
 MW_BG=4864,MW_EDGE=4888,MW_PIN=4912,MW_WORK_ROOT=4936,MW_ROOT_ZERO=4960)
replace=managed.replace
replace_def=managed.replace_def

def source_template():
    parts={}
    for entry in ("business","business_failure"):
        text=original.source_program(entry,symbolic=True)
        for node in ast.parse(text).body:
            if isinstance(node,ast.FunctionDef)and node.name not in parts:
                parts[node.name]=ast.get_source_segment(text,node)
    text="\n\n".join(parts.values())+"\n"
    text=replace(text,"    zero(o,128,8064)\n    zero(o,ROWS,1152)",
        "    if get(w,544)==0 or (get(w,552)==0 and get(w,560)==0):\n        return 4294967293\n    zero(o,128,8064)\n    zero(o,ROWS,1728)")
    text=replace(text,"    phase=get(o,PHASE)\n    if phase==0:",
        "    phase=get(o,PHASE)\n    if phase>=5000:\n        return 4294967293\n    if phase==0:")
    text=replace(text,"get(w,232)<16384","get(w,232)<49152")
    text=replace(text,"get(w,256)<4096","get(w,256)<36864")
    # Failure entry owns the same continuation family and retained workspace.
    text=replace(text,"    phase=get(o,PHASE)\n    if phase>=300 and phase<700:",
        "    phase=get(o,PHASE)\n    if phase>=5000:\n        return 4294967293\n    if phase>=300 and phase<700:")
    text=replace(text,"        put(o,PID,pid)\n        request(o,QUEUE_INPUT,10)\n        return queue_owner(o,w,2)",
        "        put(o,PID,pid)\n        request(o,D_PRIVATE,80)\n        from_work(w,o,544,RQ+24,24)\n        put(o,RQ+104,1)\n        return values(o,w,5000,128)")
    text=replace(text,"        within(o,G_FUTURE,ROW+48,24)\n        if get(o,OP)==2:",
        "        within(o,G_FUTURE,ROW+48,24)\n        within(o,MW_EDGE,ROW+72,24)\n        if get(o,MW_EDGE)==0:\n            return quarantine(o,w,3)\n        request(o,VALUE_INPUT,5)\n        within(o,RQ+24,MW_EDGE,24)\n        return values(o,w,5001,128)\n    if phase==7:\n        if get(o,OP)==2:")
    # Queue storage remains 128 bytes; the carried tuple grows from 72 to 96.
    text=text.replace(",3,ROW,72)",",3,ROW,96)")
    text=text.replace("zero(o,ROW,72)","zero(o,ROW,96)")
    text=text.replace("get(o,SLOT)*128,72)","get(o,SLOT)*128,96)")
    text=text.replace("get(o,dest+104)*128,72)","get(o,dest+104)*128,96)")
    text=text.replace("ROWS+i*128","ROWS+i*192").replace("ROWS+n*128","ROWS+n*192")
    text=text.replace("ROWS+get(o,DRAIN_INDEX)*128","ROWS+get(o,DRAIN_INDEX)*192")
    text=text.replace("ROWS+row*128+sub*24","ROWS+row*192+choose(sub<4,sub*24,112+(sub-4)*24)")
    text=replace(text,"        within(o,dest+24,ROW+24,48)",
        "        within(o,dest+24,ROW+24,48)\n        within(o,dest+112,ROW+72,24)")
    text=replace(text,"            zero(o,G_FUTURE,24)\n            put(o,DRAIN_FOUND,1)",
        "            zero(o,G_FUTURE,24)\n            zero(o,MW_EDGE,24)\n            within(o,dest+136,MW_PIN,24)\n            zero(o,MW_PIN,24)\n            put(o,DRAIN_FOUND,1)")
    text=replace(text,"            within(o,dest+72,RESULT,24)\n            put(o,dest+96,get(o,KERNEL))",
        "            within(o,dest+72,RESULT,24)\n            within(o,dest+112,MW_EDGE,24)\n            within(o,dest+136,MW_PIN,24)\n            zero(o,MW_EDGE,24)\n            zero(o,MW_PIN,24)\n            put(o,dest+96,get(o,KERNEL))")
    text=replace(text,"        within(o,RESULT,src+72,24)\n        put(o,KERNEL,get(o,src+96))",
        "        within(o,RESULT,src+72,24)\n        within(o,MW_EDGE,src+112,24)\n        within(o,MW_PIN,src+136,24)\n        put(o,KERNEL,get(o,src+96))")
    text=replace(text,"        zero(o,src,96)","        zero(o,src,96)\n        zero(o,src+112,48)")
    text=replace(text,"        put(o,OWNED_CURRENT,1)\n        request(o,JOB_INPUT,6)",
        "        put(o,OWNED_CURRENT,1)\n        if get(o,MW_EDGE)==0:\n            return quarantine(o,w,400)\n        if get(o,MW_PIN)==0:\n            request(o,VALUE_INPUT,5)\n            within(o,RQ+24,MW_EDGE,24)\n            return values(o,w,5002,128)\n        return again(o,5003)\n    if phase==499:\n        request(o,JOB_INPUT,6)")
    text=replace(text,"        if at>=CAP_END:\n            put(o,CURRENT_EXISTS,0)\n            put(o,OWNED_CURRENT,0)\n            put(o,DRAIN_INDEX,get(o,DRAIN_INDEX)+1)\n            return again(o,400)",
        "        if at>=CAP_END:\n            put(o,MW_PAIR,0)\n            put(o,MW_RETURN,400)\n            put(o,MW_PENDING_NEXT,5010)\n            return again(o,4060)")
    text=replace(text,"        if sub>=4:","        if sub>=6:")
    text=replace(text,"    if get(o,OWNED_CURRENT)==0:\n        zero(o,G_JOB,24)",
        "    if get(o,OWNED_CURRENT)==0:\n        zero(o,MW_EDGE,24)\n        zero(o,G_JOB,24)")
    # A real retained failure dictionary becomes a BG-owned edge before publication.
    text=replace(text,"    if phase==315:\n        request(o,QUEUE_INPUT,10)",
        "    if phase==315:\n        if get(o,MW_BG)!=0:\n            request(o,D_PRIVATE,77)\n            within(o,RQ+24,MW_BG,24)\n            within(o,RQ+48,FAIL_COPY,24)\n            return values(o,w,5004,128)\n        return again(o,317)\n    if phase==317:\n        request(o,QUEUE_INPUT,10)")
    text=replace(text,"        if get(o,POST_EXIT)!=0:\n            put(w,464,0)",
        "        if get(o,MW_PENDING_NEXT)!=0:\n            next=get(o,MW_PENDING_NEXT)\n            put(o,MW_PENDING_NEXT,0)\n            return again(o,next)\n        if get(o,MW_PAIR_DONE)==0:\n            put(o,MW_PAIR,0)\n            put(o,MW_RETURN,4060)\n            return again(o,5010)\n        if get(o,POST_EXIT)!=0:\n            put(w,464,0)")
    # Check the work batch only after real settlement and local cleanup.
    # Enqueue and the last settlement use the same queue transaction, so a
    # concurrent submit either reuses the current root or installs a new one.
    text=replace(text,"def terminal(o:mutbuf,w:mutbuf,status:u64) -> u32:\n    zero(o,0,128)",
        "def terminal(o:mutbuf,w:mutbuf,status:u64) -> u32:\n"
        "    if get(w,464)==0 and get(o,MW_BG)!=0 and get(o,MW_ROOT_CHECKED)==0:\n"
        "        if get(o,LOCK)!=0:\n            return quarantine(o,w,5020)\n"
        "        put(o,MW_STATUS,status)\n        request(o,QUEUE_INPUT,10)\n        return queue_owner(o,w,5020)\n"
        "    if get(w,464)==0 and get(o,MW_WORK_ROOT)!=0:\n"
        "        put(o,MW_STATUS,status)\n        return drop_value(o,w,5014,MW_WORK_ROOT)\n"
        "    if get(w,464)==0 and get(o,MW_BG)!=0:\n"
        "        put(o,MW_STATUS,status)\n        return drop_value(o,w,5012,MW_BG)\n"
        "    zero(o,0,128)")
    text=replace(text,"    put(o,24,get(o,DETAIL))\n    if get(w,464)==0:",
        "    put(o,24,get(o,DETAIL))\n    put(o,32,get(o,D_QUEUE))\n    put(o,40,get(o,VALUE_PENDING))\n    put(o,48,get(o,D_UNKNOWN))\n    put(o,56,1)\n    put(o,64,get(o,MW_GLOBAL_PENDING))\n    if get(w,464)==0:")
    # Report continuation has a fixed third policy, preserving the original budget.
    branch="    if phase>=1200 and phase<1300:\n        return report_task(o,w,phase)\n"
    assert text.count(branch)==2
    text=text.replace(branch,"")
    text=replace(text,"    if get(o,DROP_ACTIVE)==1 and get(o,DROP_KNOWN)==1:\n        return 1",
        "    if get(o,MW_REPORT_PENDING)==1:\n        return 1\n    if get(o,DROP_ACTIVE)==1 and get(o,DROP_KNOWN)==1:\n        return 1")
    text=replace(text,"    if phase==4000:\n        if get(o,LOCK)!=0:",
        "    if phase==4000:\n        if get(o,MW_REPORT_PENDING)!=0:\n            if get(o,LOCK)!=0 or get(o,POST_EXIT)!=1 or get(o,MW_REPORT_PENDING)!=1:\n                return bound_quarantine(o,w,choose(get(o,MW_REPORT_PENDING)==1,1,2),1201)\n            zero(o,REPORT_SOURCE,128)\n            put(o,REPORT_SOURCE,REPORT_RETRY)\n            put(o,REPORT_SOURCE+8,2)\n            put(o,REPORT_OUT+128,0)\n            put(o,MW_REPORT_MODE,1)\n            return again(o,1200)\n        if get(o,LOCK)!=0:")
    text=replace(text,"        if get(o,REPORT_OUT+8)!=0:\n            return fail(o,choose(get(o,REPORT_OUT+8)==5,5,7),get(o,REPORT_OUT+8))",
        "        if managed_report(o)==0:\n            return bound_quarantine(o,w,choose(get(o,MW_REPORT_PENDING)==1,1,2),1201)\n        if get(o,MW_REPORT_MODE)!=0:\n            if get(o,REPORT_OUT+24)!=0 or get(o,REPORT_OUT+48)!=0 or get(o,REPORT_OUT+72)!=0:\n                return bound_quarantine(o,w,2,1201)\n            put(o,MW_REPORT_PENDING,0)\n            put(o,MW_REPORT_MODE,0)\n            return again(o,4000)\n        if get(o,REPORT_OUT+8)!=0:\n            return fail(o,choose(get(o,REPORT_OUT+8)==5,5,7),get(o,REPORT_OUT+8))")
    text=managed.apply(text)
    text+=MANAGED
    return text

MANAGED=r'''
def managed_lifecycle(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<16384 or get(w,0)!=CONTEXT:
        return 4294967293
    phase=get(o,PHASE)
    if phase>=1200 and phase<1300:
        return report_task(o,w,phase)
    if phase<5000:
        return 4294967293
    return managed_step(s,o,w,phase)
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
        put(o,MW_REPORT_PENDING,kind)
        return 0
    if get(o,REPORT_OUT+104)!=0 or get(o,REPORT_OUT+112)!=0 or get(o,REPORT_OUT+144)!=0 or get(o,REPORT_OUT+152)!=0:
        put(o,D_UNKNOWN,1)
        return 0
    return 1
def managed_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==5000:
        if valid(o,RP,VALUE_REPLY)==0:
            return quarantine(o,w,5000)
        status=get(o,RP+8)
        if status==0:
            if get(o,RP+48)!=6 or take_value(o,MW_BG)!=0:
                return quarantine(o,w,5000)
        elif status==6 and get(o,RP+24)==0:
            put(o,MW_CLOSING,1)
        else:
            return quarantine(o,w,5000)
        request(o,QUEUE_INPUT,10)
        return queue_owner(o,w,2)
    if phase==5001:
        if take_value(o,MW_PIN)!=0:
            return quarantine(o,w,5001)
        return again(o,7)
    if phase==5002:
        if take_value(o,MW_PIN)!=0:
            return quarantine(o,w,5002)
        return again(o,5003)
    if phase==5003:
        return again(o,499)
    if phase==5004:
        if valid(o,RP,VALUE_DROP_REPLY)==0 or get(o,RP+88)!=1 or get(o,RP+96)!=1 or get(o,RP+8)!=0:
            return quarantine(o,w,5004)
        if get(o,RP+80)>1 or get(o,RP+104)!=0 or get(o,RP+112)!=0 or get(o,RP+120)!=0:
            return quarantine(o,w,5004)
        if get(o,RP+80)!=0:
            put(o,MW_GLOBAL_PENDING,1)
        return again(o,317)
    if phase==5010:
        i=get(o,MW_PAIR)
        if i>=2:
            next=get(o,MW_RETURN)
            if next==400:
                put(o,CURRENT_EXISTS,0)
                put(o,OWNED_CURRENT,0)
                put(o,DRAIN_INDEX,get(o,DRAIN_INDEX)+1)
            else:
                put(o,MW_PAIR_DONE,1)
            return again(o,next)
        at=choose(i==0,MW_EDGE,MW_PIN)
        if get(o,at)==0:
            put(o,MW_PAIR,i+1)
            return again(o,5010)
        if i==0 and get(o,OWNED_CURRENT)==0:
            return quarantine(o,w,5010)
        put(o,SAVED,at)
        return drop_value(o,w,5011,at)
    if phase==5011:
        if cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,5011)
        if get(o,VALUE_PENDING)!=0:
            put(o,MW_PENDING_NEXT,5010)
            return again(o,4060)
        put(o,MW_PAIR,get(o,MW_PAIR)+1)
        return again(o,5010)
    if phase==5012:
        if cleared(o,MW_BG)==0:
            return quarantine(o,w,5012)
        if get(o,VALUE_PENDING)!=0:
            put(o,MW_PENDING_NEXT,5013)
            return again(o,4060)
        return again(o,5013)
    if phase==5013:
        return terminal(o,w,get(o,MW_STATUS))
    if phase==5014:
        if cleared(o,MW_WORK_ROOT)==0:
            return quarantine(o,w,5014)
        if get(o,VALUE_PENDING)!=0:
            put(o,MW_PENDING_NEXT,5013)
            return again(o,4060)
        return again(o,5013)
    if phase==5020:
        if queue_valid(o)==0 or get(o,RP+56)!=0 or get(o,RP+64)!=0:
            return quarantine(o,w,5020)
        put(o,LOCK,1)
        if get(o,RP+32)!=0:
            return again(o,5023)
        if get(o,RP+40)!=0 or get(o,RP+48)!=MAX or get(o,MW_WORK_ROOT)!=0:
            return quarantine(o,w,5020)
        return memory(o,5021,0,get(w,320)+888,3,MW_WORK_ROOT,24)
    if phase==5021:
        if get(o,MW_WORK_ROOT)==0:
            if get(o,MW_WORK_ROOT+8)!=0 or get(o,MW_WORK_ROOT+16)!=0:
                return quarantine(o,w,5021)
            return again(o,5023)
        if get(o,MW_WORK_ROOT+8)==0 and get(o,MW_WORK_ROOT+16)==0:
            return quarantine(o,w,5021)
        zero(o,MW_ROOT_ZERO,24)
        return memory(o,5022,3,MW_ROOT_ZERO,0,get(w,320)+888,24)
    if phase==5022:
        return again(o,5023)
    if phase==5023:
        request(o,QUEUE_INPUT,11)
        return queue_owner(o,w,5024)
    if phase==5024:
        if queue_valid(o)==0:
            return quarantine(o,w,5024)
        put(o,LOCK,0)
        put(o,MW_ROOT_CHECKED,1)
        return terminal(o,w,get(o,MW_STATUS))
    return quarantine(o,w,phase)
'''
def source_program(entry="business"):
    return managed.render(source_template(),C,entry)
def main():
    for entry,suffix in (("business",""),("business_failure","_failure"),("managed_lifecycle","_lifecycle")):
        doc=document(source_program(entry),"background_optimizer_business_managed"+suffix)
        path=ROOT/("examples/hia_bootstrap/background_optimizer_business_managed"+suffix+".hepta")
        path.write_text(render_assembly(doc))
        print(path.name,path.stat().st_size,len(doc["functions"]),sum(len(f["blocks"])for f in doc["functions"]),sum(len(b["ops"])for f in doc["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
