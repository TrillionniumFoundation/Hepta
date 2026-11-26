"""Native business worker profile for the bound public BG composition."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_business_worker as original
from tools import hia_background_provider_retirement_source as provider
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 CONTEXT='HIABWBC2',EXEC_INPUT='HIABEXQ2',
 ACCOUNT_INPUT='HIABACQ2',ACCOUNT_REPLY='HIABACR2',
 PROVIDER_INPUT='HIAMVBQ3',PROVIDER_REPLY='HIAMVBO2',PROVIDER_TYPED_REPLY='HIAMVBO2').items()})
C.update(PROVIDER_PENDING=1184,BOUND_QUARANTINE=1192)
def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)
def source_program(entry='business',symbolic=False):
    text=replace(original.SOURCE,'get(w,56)<1024','get(w,56)<768')
    text=replace(text,"""    if get(o,LOCK)!=0 or get(o,EXEC_NESTED)!=0 or get(o,ACCOUNT_NESTED)!=0:
        return 4294967293
    if get(o,DROP_ACTIVE)!=1 or get(o,DROP_KNOWN)!=1 or get(o,DRAIN_COUNT)>9 or get(o,OWNED_CURRENT)>1:
        return 4294967293""",
"""    if get(o,LOCK)!=0 or get(o,EXEC_NESTED)>1 or get(o,ACCOUNT_NESTED)>1:
        return 4294967293
    if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
        return 4294967293
    if get(o,DRAIN_COUNT)>9 or get(o,OWNED_CURRENT)>1 or recovery_owned(o)==0:
        return 4294967293""")
    text=replace(text,"""        if valid(o,CHILD_OUT,EXEC_REPLY)==0 or get(o,CHILD_OUT+72)!=0:
            return quarantine(o,w,11)""",
"""        if execution_valid(o)==0:
            return quarantine(o,w,11)""")
    text=replace(text,"""def account_valid(o:mutbuf) -> u64:
    return choose(valid(o,CHILD_OUT,ACCOUNT_REPLY)!=0 and get(o,CHILD_OUT+56)==0,1,0)""",
"""def account_valid(o:mutbuf) -> u64:
    if valid(o,CHILD_OUT,ACCOUNT_REPLY)==0:
        put(o,BOUND_QUARANTINE,2)
        return 0
    if get(o,CHILD_OUT+56)!=0:
        kind=nested_kind(o,56,104,112)
        put(o,ACCOUNT_NESTED,kind)
        put(o,BOUND_QUARANTINE,kind)
        return 0
    return 1""")
    text=replace(text,"""    put(w,480,kind)
    put(w,504,get(o,PHASE))""",
"""    if get(o,BOUND_QUARANTINE)!=0:
        kind=choose(get(o,BOUND_QUARANTINE)==1,1,2)
    put(o,BOUND_QUARANTINE,0)
    put(w,480,kind)
    put(w,504,get(o,PHASE))""")
    text=replace(text,"""    if phase==4000:
        if get(o,LOCK)!=0 or get(o,EXEC_NESTED)!=0 or get(o,ACCOUNT_NESTED)!=0:
            return quarantine(o,w,4000)""",
"""    if phase==4000:
        if get(o,LOCK)!=0:
            return quarantine(o,w,4000)
        if get(o,EXEC_NESTED)!=0:
            if get(o,POST_EXIT)!=1 or get(o,EXEC_NESTED)!=1:
                return bound_quarantine(o,w,choose(get(o,EXEC_NESTED)==1,1,2),4080)
            request(o,EXEC_INPUT,1)
            return invoke(o,4080,get(w,216),51,RQ,128,CHILD_OUT,524288,get(w,224),get(w,232))
        if get(o,ACCOUNT_NESTED)!=0:
            if get(o,POST_EXIT)!=1 or get(o,ACCOUNT_NESTED)!=1:
                return bound_quarantine(o,w,choose(get(o,ACCOUNT_NESTED)==1,1,2),4081)
            request(o,ACCOUNT_INPUT,1)
            return invoke(o,4081,get(w,240),51,RQ,128,CHILD_OUT,524288,get(w,248),get(w,256))""")
    text=replace(text,"""    if phase==4050:
        if get(o,PROVIDER)!=0:""",
"""    if phase==4050:
        if get(o,PROVIDER_PENDING)!=0:
            if get(o,POST_EXIT)!=1:
                return bound_quarantine(o,w,1,4053)
            request(o,PROVIDER_INPUT,6)
            return provider_owner(o,w,4053)
        if get(o,PROVIDER)!=0:""")
    text=replace(text,"""        if valid(o,RP,PROVIDER_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,4051)
        zero(o,PROVIDER,24)""",
"""        kind=provider_release(o,PROVIDER)
        if kind!=0:
            return bound_quarantine(o,w,kind,4051)""")
    text=replace(text,"""    if phase==4052:
        put(o,DREQ,0)
        return again(o,4050)
    if phase==4060:""",
"""    if phase==4052:
        put(o,DREQ,0)
        return again(o,4050)
    if phase==4053:
        kind=provider_release_retry(o)
        if kind!=0:
            return bound_quarantine(o,w,kind,4053)
        return again(o,4050)
    if phase==4060:""")
    text=replace(text,"""    if phase==4073:
        if cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,4073)
        put(o,ROW_CLEAN_SUB,get(o,ROW_CLEAN_SUB)+1)
        return again(o,4070)
    return quarantine(o,w,phase)""",
"""    if phase==4073:
        if cleared(o,get(o,SAVED))==0:
            return quarantine(o,w,4073)
        put(o,ROW_CLEAN_SUB,get(o,ROW_CLEAN_SUB)+1)
        return again(o,4070)
    if phase==4080:
        if execution_valid(o)==0:
            return quarantine(o,w,4080)
        if get(o,CHILD_OUT+24)!=0 or get(o,CHILD_OUT+48)!=0:
            return bound_quarantine(o,w,2,4080)
        put(o,EXEC_NESTED,0)
        return again(o,4000)
    if phase==4081:
        if account_valid(o)==0:
            return quarantine(o,w,4081)
        put(o,ACCOUNT_NESTED,0)
        return again(o,4000)
    return quarantine(o,w,phase)""")
    text+="""
def bound_quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,BOUND_QUARANTINE,kind)
    return quarantine(o,w,detail)
def nested_kind(o:mutbuf,retained:u64,kind:u64,pending:u64) -> u64:
    value=get(o,CHILD_OUT+kind)
    if get(o,CHILD_OUT+8)!=9 or get(o,CHILD_OUT+retained)!=1 or (value!=1 and value!=2) or get(o,CHILD_OUT+pending)>1:
        return 2
    return value
def execution_valid(o:mutbuf) -> u64:
    if valid(o,CHILD_OUT,EXEC_REPLY)==0:
        put(o,BOUND_QUARANTINE,2)
        return 0
    if get(o,CHILD_OUT+72)!=0:
        kind=nested_kind(o,72,96,104)
        put(o,EXEC_NESTED,kind)
        put(o,BOUND_QUARANTINE,kind)
        return 0
    return 1
def recovery_owned(o:mutbuf) -> u64:
    if get(o,DROP_ACTIVE)==1 and get(o,DROP_KNOWN)==1:
        return 1
    if get(o,EXEC_NESTED)==1 or get(o,ACCOUNT_NESTED)==1:
        return 1
    if get(o,PROVIDER_PENDING)!=0 or get(o,VALUE_PENDING)!=0:
        return 1
    if get(o,FUTURE_PENDING)!=0 or get(o,JOB_PENDING)!=0:
        return 1
    return 0
"""
    text+=chr(10)+provider.SOURCE
    base=original.E.SOURCE
    base=replace(base,"""        if valid(o,RP,PROVIDER_REPLY)==0:
            return fail(o,7,1301)
        if get(o,RP+40)!=0:
            within(o,PROVIDER,RP+40,24)
        status=get(o,RP+8)""",
"""        if valid(o,RP,PROVIDER_REPLY)==0:
            return bound_quarantine(o,w,2,1301)
        if get(o,RP+40)!=0:
            within(o,PROVIDER,RP+40,24)
        if provider_typed_valid(o)==False or get(o,RP+80)!=0 or get(o,RP+72)!=1:
            return bound_quarantine(o,w,2,1301)
        if get(o,RP+88)!=0:
            put(o,PROVIDER_PENDING,1)
            return bound_quarantine(o,w,1,1301)
        status=get(o,RP+8)""")
    base=replace(base,"""        if valid(o,RP,PROVIDER_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,1391)
        zero(o,PROVIDER,24)""",
"""        kind=provider_release(o,PROVIDER)
        if kind!=0:
            return bound_quarantine(o,w,kind,1391)""")
    saved=(original.SOURCE,original.C,original.E.SOURCE)
    try:
        original.SOURCE=text;original.C=C;original.E.SOURCE=base
        return original.source_program(entry,symbolic=symbolic)
    finally:
        original.SOURCE,original.C,original.E.SOURCE=saved
def main():
    for entry,suffix in [('business',''),('business_failure','_failure')]:
        doc=document(source_program(entry),'background_optimizer_business_owner'+suffix)
        p=ROOT/('examples/hia_bootstrap/background_optimizer_business_owner'+suffix+'.hepta');p.write_text(render_assembly(doc))
        print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
