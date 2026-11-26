"""Execution profile with explicit same-arena provider and nested retirement."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_execution as original
from tools import hia_background_provider_retirement_source as provider
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABEXQ2',CONTEXT='HIABEXC2',PROVIDER_INPUT='HIAMVBQ3',
 PROVIDER_REPLY='HIAMVBO2',PROVIDER_TYPED_REPLY='HIAMVBO2',
 IO_INPUT='HIABIQ02',IO_REPLY='HIABIO02',IO_CONTEXT='HIABIC02',
 DECISION_INPUT='HIABDO02',DECISION_REPLY='HIABDRP2').items()})
C.update(PROVIDER_PENDING=1144,BOUND_QUARANTINE=1152,NESTED_PENDING=1160)

def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)

def source_program(entry='execute_owner',symbolic=False):
    text=original.SOURCE
    text=replace(text,'def execute(', 'def execute_owner(')
    text=replace(text,'def publish_continue(', 'def publish_owner(')
    text=replace(text,'get(w,56)<1024','get(w,56)<768')
    text=replace(text,"""            put(o,OP,1)
            put(w,464,0)""","""            put(o,OP,1)
            put(o,BOUND_QUARANTINE,0)
            put(w,464,0)""")
    text=replace(text,"""        if valid(o,RP,PROVIDER_REPLY)==0:
            put(o,PUB_STATUS,7)
            put(o,DETAIL,241)
        else:
            if get(o,RP+40)!=0:
                within(o,PROVIDER,RP+40,24)
            put(o,PUB_STATUS,get(o,RP+8))""",
"""        if valid(o,RP,PROVIDER_REPLY)==0:
            return bound_quarantine(o,w,2,241)
        else:
            if get(o,RP+40)!=0:
                within(o,PROVIDER,RP+40,24)
            if provider_typed_valid(o)==False or get(o,RP+80)!=0 or get(o,RP+72)!=1:
                return bound_quarantine(o,w,2,241)
            if get(o,RP+88)!=0:
                put(o,PROVIDER_PENDING,1)
                return bound_quarantine(o,w,1,241)
            put(o,PUB_STATUS,get(o,RP+8))""")
    text=replace(text,"""        if valid(o,RP,PROVIDER_REPLY)==0:
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
    text=replace(text,"""        if valid(o,RP,PROVIDER_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,1391)
        zero(o,PROVIDER,24)""",
"""        kind=provider_release(o,PROVIDER)
        if kind!=0:
            return bound_quarantine(o,w,kind,1391)""")
    text=replace(text,"""        if get(o,DECISION_OUT+88)!=0:
            return quarantine(o,w,106)""",
"""        if get(o,DECISION_OUT+88)!=0:
            return bound_quarantine(o,w,nested_kind(o,DECISION_OUT,88,112,120),106)""")
    text=replace(text,"""        if valid(o,DECISION_OUT,DECISION_REPLY)==0 or get(o,DECISION_OUT+88)!=0:
            return quarantine(o,w,1980)""",
"""        if valid(o,DECISION_OUT,DECISION_REPLY)==0:
            return bound_quarantine(o,w,2,1980)
        if get(o,DECISION_OUT+88)!=0:
            return bound_quarantine(o,w,nested_kind(o,DECISION_OUT,88,112,120),1980)""")
    text=replace(text,"""        if valid(o,IO_OUT,IO_REPLY)==0:
            return quarantine(o,w,1502)
        status=get(o,IO_OUT+8)""",
"""        if valid(o,IO_OUT,IO_REPLY)==0:
            return bound_quarantine(o,w,2,1502)
        if get(o,IO_OUT+48)!=0:
            return bound_quarantine(o,w,nested_kind(o,IO_OUT,48,56,64),1502)
        status=get(o,IO_OUT+8)""")
    text=replace(text,"""        fd=get(o,FD)
        put(o,FD,MAX)
        return system(o,1504,3,0,fd,0,0,0,0,0)
    if phase==1504:
        if get(o,FEEDBACK)>=NEGATIVE:
            return fail(o,8,get(o,FEEDBACK))
        return again(o,get(o,RESUME))""",
"""        fd=get(o,FD)
        return system(o,1504,436,0,fd,fd,0,0,0,0)
    if phase==1504:
        if get(o,FEEDBACK)!=0:
            return fail(o,8,get(o,FEEDBACK))
        put(o,FD,MAX)
        return again(o,get(o,RESUME))""")
    text=replace(text,"""        if valid(o,IO_OUT,IO_REPLY)==0 or get(o,IO_OUT+48)!=0 or get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0:
            return quarantine(o,w,1982)""",
"""        if valid(o,IO_OUT,IO_REPLY)==0:
            return bound_quarantine(o,w,2,1982)
        if get(o,IO_OUT+48)!=0:
            return bound_quarantine(o,w,nested_kind(o,IO_OUT,48,56,64),1982)
        if get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0 or get(o,IO_WORK+88)!=0 or get(o,IO_WORK+96)!=0 or get(o,IO_WORK+104)!=0:
            return bound_quarantine(o,w,2,1982)""")
    text=replace(text,"""    if phase==2000:
        if get(o,DROP_ACTIVE)!=0""",
"""    if phase==2000:
        if get(o,PROVIDER_PENDING)!=0:
            if get(o,OP)!=1:
                return bound_quarantine(o,w,1,2243)
            request(o,PROVIDER_INPUT,6)
            return provider_owner(o,w,2243)
        if get(o,DROP_ACTIVE)!=0""")
    text=replace(text,"""        if get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0:
            request(o,IO_INPUT,1)""",
"""        if get(o,IO_WORK+32)!=0 or get(o,IO_WORK+40)!=0 or get(o,IO_WORK+64)!=0 or get(o,IO_WORK+88)!=0 or get(o,IO_WORK+96)!=0 or get(o,IO_WORK+104)!=0:
            kind=choose(get(o,IO_WORK+88)==1,1,2)
            if kind!=1 or get(o,OP)!=1:
                return bound_quarantine(o,w,kind,1982)
            request(o,IO_INPUT,1)""")
    text=replace(text,"""    if phase==2101 or phase==2102:
        magic=choose(phase==2101,PAYLOAD_REPLY,PROVIDER_REPLY)
        if valid(o,RP,magic)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,phase)
        zero(o,get(o,SAVED),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,2100)""",
"""    if phase==2101 or phase==2102:
        if phase==2102:
            kind=provider_release(o,get(o,SAVED))
            if kind!=0:
                return bound_quarantine(o,w,kind,phase)
        else:
            if valid(o,RP,PAYLOAD_REPLY)==0 or get(o,RP+8)!=0:
                return quarantine(o,w,phase)
            zero(o,get(o,SAVED),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,2100)""")
    text=replace(text,"""        fd=get(o,FD)
        put(o,FD,MAX)
        if fd!=MAX:
            return system(o,2211,3,0,fd,0,0,0,0,0)
        return again(o,2220)
    if phase==2211:
        if get(o,FEEDBACK)>=NEGATIVE:
            if get(o,ERROR)==0:
                put(o,ERROR,8)
        return again(o,2220)""",
"""        fd=get(o,FD)
        if fd!=MAX:
            return system(o,2211,436,0,fd,fd,0,0,0,0)
        return again(o,2220)
    if phase==2211:
        if get(o,FEEDBACK)!=0:
            return bound_quarantine(o,w,1,2211)
        put(o,FD,MAX)
        return again(o,2220)""")
    text=replace(text,"""    if phase==2242:
        if release_value_retry(o)==0:
            return quarantine(o,w,2242)
        return again(o,2240)
    return quarantine(o,w,phase)""",
"""    if phase==2242:
        if release_value_retry(o)==0:
            return quarantine(o,w,2242)
        return again(o,2240)
    if phase==2243:
        kind=provider_release_retry(o)
        if kind!=0:
            return bound_quarantine(o,w,kind,2243)
        put(o,BOUND_QUARANTINE,0)
        return again(o,2000)
    return quarantine(o,w,phase)""")
    text=replace(text,"""    put(w,480,kind)
    to_work(o,w,128,512,8064)""",
"""    if get(o,BOUND_QUARANTINE)!=0:
        kind=choose(get(o,BOUND_QUARANTINE)==1,1,2)
    put(o,BOUND_QUARANTINE,0)
    put(w,480,kind)
    to_work(o,w,128,512,8064)""")
    text=replace(text,"""    put(o,88,get(o,ERROR_FORMAT))
    return 0""","""    put(o,88,get(o,ERROR_FORMAT))
    if get(w,464)!=0:
        put(o,96,get(w,480))
        put(o,104,execution_pending(o))
    return 0""")
    text+="""
def execution_pending(o:mutbuf) -> u64:
    if get(o,PROVIDER_PENDING)!=0:
        return 1
    if get(o,VALUE_PENDING)!=0:
        return 1
    if get(o,JOB_PENDING)!=0:
        return 1
    return choose(get(o,NESTED_PENDING)!=0,1,0)
def bound_quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,BOUND_QUARANTINE,kind)
    return quarantine(o,w,detail)
def nested_kind(o:mutbuf,at:u64,retained:u64,kind:u64,pending:u64) -> u64:
    value=get(o,at+kind)
    if get(o,at+retained)!=1 or (value!=1 and value!=2) or get(o,at+pending)>1:
        return 2
    put(o,NESTED_PENDING,get(o,at+pending))
    return value
"""
    present={n.name for n in ast.parse(original.SOURCE).body if isinstance(n,ast.FunctionDef)}
    for oldentry in ('execute','publish_continue'):
        for node in ast.parse(original.source_program(oldentry,symbolic=symbolic)).body:
            if isinstance(node,ast.FunctionDef)and node.name not in present:
                text+=chr(10)+ast.unparse(node)+chr(10);present.add(node.name)
    text+=chr(10)+provider.SOURCE
    if not symbolic:
        for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
            text=re.sub(r'\b'+key+r'\b',str(value),text)
    tree=ast.parse(text);functions={x.name:x for x in tree.body if isinstance(x,ast.FunctionDef)}
    chosen=set();todo=[entry]
    while todo:
        name=todo.pop()
        if name in chosen:continue
        chosen.add(name)
        todo.extend(x.func.id for x in ast.walk(functions[name]) if isinstance(x,ast.Call)and isinstance(x.func,ast.Name)and x.func.id in functions and x.func.id not in chosen)
    order=[entry]+[x.name for x in tree.body if isinstance(x,ast.FunctionDef)and x.name in chosen and x.name!=entry]
    return '\n\n'.join(ast.get_source_segment(text,functions[name])for name in order)+'\n'

def main():
    for entry,suffix in [('execute_owner',''),('publish_owner','_publication')]:
        doc=document(source_program(entry),'background_optimizer_execution_owner'+suffix)
        p=ROOT/('examples/hia_bootstrap/background_optimizer_execution_owner'+suffix+'.hepta')
        p.write_text(render_assembly(doc))
        print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
