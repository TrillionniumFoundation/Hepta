"""Bound decision owner retaining every nested retirement obligation."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_decision_owner as original
from tools import hia_background_retirement_source as retirement
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C);C.update(retirement.MAGICS)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABDO02',REPLY='HIABDRP2',CONTEXT='HIABDOC2',
 FREQUEST='HIABFZQ2',FREPLY='HIABFZR2',FCONTEXT='HIABFZC2',
 IREQUEST='HIABIQ02',IREPLY='HIABIO02',ICONTEXT='HIABIC02',
 YREQUEST='HIABVFY3',YREPLY='HIABVFR2',YCONTEXT='HIABVYC2').items()})
C.update(DROP_ACTIVE=2504,DROP_KNOWN=2512,VALUE_PENDING=2520,
 QUARANTINE_KIND=2528,BOUND_QUARANTINE=2536,NESTED_PENDING=2544)
def replace(text,before,after):
    assert text.count(before)==1,before
    return text.replace(before,after)
def source_program():
    text=replace(original.SOURCE,'def decision_owner(', 'def decision_bound(')
    text=replace(text,"""            from_work(w,o,256,256,3840)
            put(w,184,0)""",
"""            from_work(w,o,256,256,3840)
            if get(o,QUARANTINE_KIND)!=1:
                put(o,QUAR,1)
                return finish(o,9)
            put(o,QUARANTINE_KIND,0)
            put(o,BOUND_QUARANTINE,0)
            put(w,184,0)""")
    for before,after in [
 ("""        if get(o,HEAD+48)!=0:
            put(o,IOACTIVE,1)
            return quarantine(o,w,602)
        put(o,IOACTIVE,0)""",
"""        if get(o,HEAD+48)!=0:
            kind=nested_kind(o,48,56,64)
            put(o,IOACTIVE,kind)
            return bound_quarantine(o,w,kind,602)
        put(o,IOACTIVE,0)
        put(o,NESTED_PENDING,0)"""),
 ("""        if get(o,HEAD+56)!=0 or get(w,4192)!=0:
            put(o,FZACTIVE,1)
            return quarantine(o,w,1002)
        put(o,FZACTIVE,0)""",
"""        if get(o,HEAD+56)!=0 or get(w,4192)!=0:
            kind=nested_kind(o,56,104,112)
            put(o,FZACTIVE,kind)
            return bound_quarantine(o,w,kind,1002)
        put(o,FZACTIVE,0)
        put(o,NESTED_PENDING,0)"""),
 ("""        if get(o,HEAD+56)!=0 or get(w,6296)!=0:
            put(o,VERIFYACTIVE,1)
            return quarantine(o,w,1202)
        put(o,VERIFYACTIVE,0)""",
"""        if get(o,HEAD+56)!=0 or get(w,6296)!=0:
            kind=nested_kind(o,56,64,72)
            put(o,VERIFYACTIVE,kind)
            return bound_quarantine(o,w,kind,1202)
        put(o,VERIFYACTIVE,0)
        put(o,NESTED_PENDING,0)""")]:
        text=replace(text,before,after)
    assert text.count('request(o,VREQUEST,6)')==3
    text=text.replace('request(o,VREQUEST,6)','release_begin(o)\n        request(o,VALUE_DROP_INPUT,29)')
    for phase,cap,nextbody in [
        (905,'CKEY','        return again(o,get(o,GCAFTER))'),
        (1513,'CNUM','        put(o,ERRINDEX,get(o,ERRINDEX)+1)\n        return again(o,1510)'),
        (3011,'get(o,DESTROY_AT)','        put(o,CLEAN,get(o,CLEAN)+1)\n        return again(o,3010)')]:
        old=f"""    if phase=={phase}:
        if value_ok(o)==False:
            return quarantine(o,w,get(o,RP+8))
        zero(o,{cap},24)
{nextbody}"""
        new=f"""    if phase=={phase}:
        if release_value(o,{cap})==0 or get(o,VALUE_PENDING)!=0:
            return release_blocked(o,w,{phase})
{nextbody}"""
        text=replace(text,old,new)
    text=replace(text,"""    if phase==3000:
        if get(o,IOACTIVE)!=0:""",
"""    if phase==3000:
        if get(o,DROP_ACTIVE)!=0 and get(o,DROP_KNOWN)!=1:
            return bound_quarantine(o,w,2,3000)
        if get(o,VALUE_PENDING)!=0:
            if get(o,OP)!=1:
                return bound_quarantine(o,w,1,3050)
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return value(o,w,3050,128)
        if get(o,IOACTIVE)!=0:""")
    for slot,phase in [('IOACTIVE',3000),('FZACTIVE',3001),('VERIFYACTIVE',3002)]:
        text=replace(text,f"""            if get(o,OP)!=1 or get(o,{slot})!=1:
                return quarantine(o,w,{phase})""",
f"""            if get(o,OP)!=1 or get(o,{slot})!=1:
                return bound_quarantine(o,w,choose(get(o,{slot})==1,1,2),{phase})""")
    text=replace(text,"""    if phase==3021:
        if payload_ok(o)==False:
            return quarantine(o,w,get(o,RP+8))""",
"""    if phase==3021:
        if payload_ok(o)==False:
            kind=2
            if get(o,FEEDBACK)==0 and get(o,RP)==BREPLY:
                status=get(o,RP+8)
                if status==1 or status==5 or status==6:
                    kind=1
            return bound_quarantine(o,w,kind,3021)""")
    text=replace(text,"""        fd=get(o,at)-1
        put(o,at,0)
        return system(o,3031,3,0,fd,0,0,0,0,0)
    if phase==3031:
        if get(o,FEEDBACK)!=0:
            put(o,ERROR,8)
            put(o,DETAIL,get(o,FEEDBACK))
        put(o,CLEAN,get(o,CLEAN)+1)""",
"""        fd=get(o,at)-1
        put(o,DESTROY_AT,at)
        return system(o,3031,436,0,fd,fd,0,0,0,0)
    if phase==3031:
        if get(o,FEEDBACK)!=0:
            return bound_quarantine(o,w,1,3031)
        put(o,get(o,DESTROY_AT),0)
        put(o,CLEAN,get(o,CLEAN)+1)""")
    text=replace(text,"""    if phase==3041:
        if get(o,FEEDBACK)!=0:
            return quarantine(o,w,get(o,FEEDBACK))""",
"""    if phase==3041:
        if get(o,FEEDBACK)!=0:
            return bound_quarantine(o,w,1,3041)""")
    text=replace(text,"""        put(o,get(o,DESTROY_KIND),0)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,3040)
    return fail(o,9,phase)""",
"""        put(o,get(o,DESTROY_KIND),0)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,3040)
    if phase==3050:
        if release_value_retry(o)==0:
            return release_blocked(o,w,3050)
        return again(o,3000)
    return fail(o,9,phase)""")
    text=replace(text,"""    put(o,88,get(o,QUAR))
    put(o,96,get(o,DETAIL))
    return 0""",
"""    put(o,88,get(o,QUAR))
    put(o,96,get(o,DETAIL))
    if get(o,QUAR)!=0:
        put(o,112,get(o,QUARANTINE_KIND))
        put(o,120,decision_pending(o))
    return 0""")
    text=replace(text,"""    to_work(o,w,256,256,3840)
    put(w,184,1)""",
"""    put(o,QUARANTINE_KIND,choose(get(o,BOUND_QUARANTINE)==1,1,2))
    put(o,BOUND_QUARANTINE,0)
    to_work(o,w,256,256,3840)
    put(w,184,1)""")
    text+="""
def bound_quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,BOUND_QUARANTINE,kind)
    return quarantine(o,w,detail)
def release_blocked(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    return bound_quarantine(o,w,choose(get(o,DROP_KNOWN)==1,1,2),detail)
def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,at)==magic,1,0)
def decision_pending(o:mutbuf) -> u64:
    if get(o,VALUE_PENDING)!=0:
        return 1
    return choose(get(o,NESTED_PENDING)!=0,1,0)
def nested_kind(o:mutbuf,retained:u64,kind:u64,pending:u64) -> u64:
    value=get(o,HEAD+kind)
    if get(o,HEAD+retained)!=1 or (value!=1 and value!=2) or get(o,HEAD+pending)>1:
        return 2
    put(o,NESTED_PENDING,get(o,HEAD+pending))
    return value
"""
    present={n.name for n in ast.parse(original.SOURCE).body if isinstance(n,ast.FunctionDef)}
    for node in ast.parse(original.source_program()).body:
        if isinstance(node,ast.FunctionDef)and node.name not in present:
            text+=chr(10)+ast.unparse(node)+chr(10)
    text+=chr(10)+retirement.selected('release_begin','release_value','release_value_retry')
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    doc=document(source_program(),'background_optimizer_decision_bound')
    p=ROOT/'examples/hia_bootstrap/background_optimizer_decision_bound.hepta';p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
