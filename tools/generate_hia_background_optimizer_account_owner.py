"""Receipt accounting profile using explicit native freeze retirement."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_account as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABACQ2',REPLY='HIABACR2',CONTEXT='HIABACC2',
 FREEZE_INPUT='HIABFZQ2',FREEZE_REPLY='HIABFZR2',FREEZE_CONTEXT='HIABFZC2').items()})
C.update(BOUND_QUARANTINE=848)
def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)
def source_program(symbolic=False):
    text=replace(original.SOURCE,'def account(', 'def account_owner(')
    text=replace(text,"""            put(o,QUARANTINED,0)
            put(o,OP,1)""","""            put(o,QUARANTINED,0)
            put(o,BOUND_QUARANTINE,0)
            put(o,OP,1)""")
    text=replace(text,"""        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0:
            return fail(o,7,get(o,FEEDBACK))
        status=get(o,FREEZE_OUT+8)""",
"""        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0:
            return bound_quarantine(o,w,2,301)
        if get(o,FREEZE_OUT+56)!=0:
            return bound_quarantine(o,w,freeze_kind(o),301)
        status=get(o,FREEZE_OUT+8)""")
    text=replace(text,"""        if get(o,FREEZE_WORK+96)!=0:
            request(o,FREEZE_INPUT,1)""",
"""        if get(o,FREEZE_WORK+96)!=0:
            kind=choose(get(o,FREEZE_WORK+104)==1,1,2)
            if get(o,OP)!=1 or kind!=1:
                return bound_quarantine(o,w,kind,701)
            request(o,FREEZE_INPUT,1)""")
    text=replace(text,"""        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0 or get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:
            return quarantine(o,w,701)""",
"""        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0:
            return bound_quarantine(o,w,2,701)
        if get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:
            return bound_quarantine(o,w,freeze_kind(o),701)""")
    text=replace(text,"""    put(o,QUARANTINE_KIND,kind)
    put(o,QUARANTINED,1)""",
"""    if get(o,BOUND_QUARANTINE)!=0:
        kind=choose(get(o,BOUND_QUARANTINE)==1,1,2)
    put(o,BOUND_QUARANTINE,0)
    put(o,QUARANTINE_KIND,kind)
    put(o,QUARANTINED,1)""")
    text=replace(text,"""    put(o,96,get(o,UCP))
    if status==1:""",
"""    put(o,96,get(o,UCP))
    if get(o,QUARANTINED)!=0:
        put(o,104,get(o,QUARANTINE_KIND))
        put(o,112,account_pending(o))
    if status==1:""")
    text+="""
def account_pending(o:mutbuf) -> u64:
    if get(o,VALUE_PENDING)!=0:
        return 1
    if get(o,FUTURE_PENDING)!=0:
        return 1
    if get(o,JOB_PENDING)!=0:
        return 1
    return choose(get(o,FREEZE_WORK+112)!=0,1,0)
def bound_quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,BOUND_QUARANTINE,kind)
    return quarantine(o,w,detail)
def freeze_kind(o:mutbuf) -> u64:
    kind=get(o,FREEZE_OUT+104)
    if get(o,FREEZE_OUT+56)!=1 or (kind!=1 and kind!=2) or get(o,FREEZE_OUT+112)>1:
        return 2
    return kind
"""
    present={n.name for n in ast.parse(original.SOURCE).body if isinstance(n,ast.FunctionDef)}
    for node in ast.parse(original.source_program(symbolic=symbolic)).body:
        if isinstance(node,ast.FunctionDef)and node.name not in present:
            text+=chr(10)+ast.unparse(node)+chr(10)
    if not symbolic:
        for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
            text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    doc=document(source_program(),'background_optimizer_account_owner')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_account_owner.hepta';p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
