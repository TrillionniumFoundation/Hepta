"""Submission policy for the same-arena native BG owner.

The retained standalone submission source remains unchanged. This profile
consumes the explicit retirement protocols for typed trees, freeze and Runtime.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_submission as original
from tools import hia_background_provider_retirement_source as provider
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABSQ02',CONTEXT='HIABSSC2',FREEZE_INPUT='HIABFZQ2',FREEZE_REPLY='HIABFZR2',
 TINPUT='HIABTC03',TRETRY='HIABTC04',TCONTEXT='HIABVC02',TREPLY='HIABTV02',
 PROVIDER_INPUT='HIAMVBQ3',PROVIDER_REPLY='HIAMVBO2',PROVIDER_TYPED_REPLY='HIAMVBO2').items()})
C.update(PROVIDER_PENDING=496,BOUND_QUARANTINE=504)

def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)

def source_template():
    text=original.SOURCE
    text=replace(text,'def submission(', 'def submission_owner(')
    text=replace(text,'get(w,168)<1024','get(w,168)<768')
    text=replace(text,"""            put(o,OP,1)
            put(w,792,0)""","""            put(o,OP,1)
            put(o,BOUND_QUARANTINE,0)
            put(w,792,0)""")
    text=replace(text,"""        if status==3:
            put(o,T_STUCK,1)
            if get(o,OP)==1:
                return quarantine(o,w,get(o,INFO+104))
            return fail(o,9,get(o,INFO+104))""",
"""        if status==3:
            kind=get(o,INFO+112)
            if (kind!=1 and kind!=2) or get(o,INFO+120)>1:
                kind=2
            put(o,T_STUCK,kind)
            return bound_quarantine(o,w,kind,162)""")
    text=replace(text,"""        status=get(o,FREEZE_OUT+8)
        if status!=0:""",
"""        status=get(o,FREEZE_OUT+8)
        if get(o,FREEZE_OUT+56)!=0:
            kind=get(o,FREEZE_OUT+104)
            if get(o,FREEZE_OUT+56)!=1 or (kind!=1 and kind!=2) or get(o,FREEZE_OUT+112)>1:
                kind=2
            return bound_quarantine(o,w,kind,201)
        if status!=0:""")
    text=replace(text,"""        status=get(o,RP+8)
        if get(o,RP+40)!=0:
            within(o,PROVIDER,RP+40,24)
        if status!=0:""",
"""        status=get(o,RP+8)
        if get(o,RP+40)!=0:
            within(o,PROVIDER,RP+40,24)
        if provider_typed_valid(o)==False or get(o,RP+80)!=0 or get(o,RP+72)!=1:
            return bound_quarantine(o,w,2,301)
        if get(o,RP+88)!=0:
            put(o,PROVIDER_PENDING,1)
            return bound_quarantine(o,w,1,301)
        if status!=0:""")
    text=replace(text,"""    if phase==700:
        if get(o,DROP_ACTIVE)!=0""",
"""    if phase==700:
        if get(o,PROVIDER_PENDING)!=0:
            if get(o,OP)!=1:
                return bound_quarantine(o,w,1,765)
            request(o,PROVIDER_INPUT,6)
            return provider_owner(o,w,765)
        if get(o,DROP_ACTIVE)!=0""")
    text=replace(text,"""        if get(o,T_STUCK)!=0:
            if get(o,OP)==1 and get(o,T_STUCK)==1 and get(o,T_SRC)!=0 and get(o,T_OUT)!=0:
                return memory(o,702,0,get(o,T_SRC),3,INFO,128)
            return quarantine(o,w,700)
        if get(o,FREEZE_WORK+96)!=0:
            request(o,FREEZE_INPUT,1)""",
"""        if get(o,T_STUCK)!=0:
            if get(o,OP)==1 and get(o,T_STUCK)==1 and get(o,T_SRC)!=0 and get(o,T_OUT)!=0:
                return memory(o,702,0,get(o,T_SRC),3,INFO,128)
            return bound_quarantine(o,w,choose(get(o,T_STUCK)==1,1,2),700)
        if get(o,FREEZE_WORK+96)!=0:
            kind=get(o,FREEZE_WORK+104)
            if get(o,OP)!=1 or kind!=1:
                return bound_quarantine(o,w,choose(kind==1,1,2),701)
            request(o,FREEZE_INPUT,1)""")
    text=replace(text,"""        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0 or get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:
            return quarantine(o,w,701)""",
"""        if valid(o,FREEZE_OUT,FREEZE_REPLY)==0:
            return bound_quarantine(o,w,2,701)
        if get(o,FREEZE_WORK+96)!=0 or get(o,FREEZE_OUT+56)!=0:
            kind=get(o,FREEZE_OUT+104)
            if get(o,FREEZE_OUT+56)!=1 or (kind!=1 and kind!=2) or get(o,FREEZE_OUT+112)>1:
                kind=2
            return bound_quarantine(o,w,kind,701)""")
    text=replace(text,"""        if phase==713:
            done=release_future(o,get(o,SAVED))""",
"""        if phase==711:
            kind=provider_release(o,get(o,SAVED))
            if kind!=0:
                return bound_quarantine(o,w,kind,711)
            done=1
        elif phase==713:
            done=release_future(o,get(o,SAVED))""")
    text=replace(text,"""    if phase==764:
        if release_value_retry(o)==0:
            return quarantine(o,w,764)
        return again(o,760)
    return quarantine(o,w,phase)""",
"""    if phase==764:
        if release_value_retry(o)==0:
            return quarantine(o,w,764)
        return again(o,760)
    if phase==765:
        kind=provider_release_retry(o)
        if kind!=0:
            return bound_quarantine(o,w,kind,765)
        put(o,BOUND_QUARANTINE,0)
        return again(o,700)
    return quarantine(o,w,phase)""")
    text=replace(text,"""    put(o,QUARANTINE_KIND,kind)
    if get(o,ERROR)==0:""",
"""    if get(o,BOUND_QUARANTINE)!=0:
        kind=choose(get(o,BOUND_QUARANTINE)==1,1,2)
    put(o,BOUND_QUARANTINE,0)
    put(o,QUARANTINE_KIND,kind)
    if get(o,ERROR)==0:""")
    text+="""
def bound_quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,BOUND_QUARANTINE,kind)
    return quarantine(o,w,detail)
"""
    present={n.name for n in ast.parse(original.SOURCE).body if isinstance(n,ast.FunctionDef)}
    for node in ast.parse(original.source_program()).body:
        if isinstance(node,ast.FunctionDef)and node.name not in present:
            text+=chr(10)+ast.unparse(node)+chr(10)
    text+=chr(10)+provider.SOURCE
    return text

def source_program():
    text=source_template()
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text

def main():
    doc=document(source_program(),'background_optimizer_submission_owner')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_submission_owner.hepta'
    p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
