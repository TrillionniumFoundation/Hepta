"""Explicit private deferred nested BG capture domains.

TC05/TC06, IQ03, and FZQ3 retain the original checking and freezing policies.
Only their fixed Value calls use the independently qualified deferred domains.
The original TC01..TC04, IQ01/2, and FZQ1/2 authors remain unchanged.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_background_optimizer_value_structure as structure
from tools import generate_hia_background_optimizer_value_transport as transport
from tools import generate_hia_background_optimizer_value_freeze as freezer
from tools.hia_background_deferred_value_source import (
    MAGICS,replace,replace_def,deferred_policy)
ROOT=Path(__file__).resolve().parents[1]
NAMES={
 "structure":"background_optimizer_value_structure_deferred",
 "transport":"background_optimizer_value_transport_deferred",
 "freeze":"background_optimizer_value_freeze_deferred"}
def magic(s):return int.from_bytes(s.encode(),"little")
def render(text,constants):
    for key,value in sorted(constants.items(),key=lambda x:-len(x[0])):
        text=re.sub(r"\b"+key+r"\b",str(value),text)
    return text
def structure_program():
    c=dict(structure.C)
    for key,value in tuple(c.items()):
        if 128<=value<=480:c[key]=value+128
    c.update(REQUEST=magic("HIABTC05"),NEW_REQUEST=magic("HIABTC05"),
             RETRY_REQUEST=magic("HIABTC06"),NEW_RETRY=magic("HIABTC06"),
             REPLY=magic("HIABTV03"),NEW_REPLY=magic("HIABTV03"),
             CONTEXT=magic("HIABVC03"),NEW_CONTEXT=magic("HIABVC03"),
             LIVE_ERROR=1664,D_QUEUE=616,D_UNKNOWN=624,D_VOP=632)
    c.update(MAGICS)
    text=replace(structure.SOURCE,"def background_optimizer_value_structure(",
                 "def background_optimizer_value_structure_deferred(")
    text=text.replace("put(o,512,","put(o,768,").replace("get(o,512)","get(o,768)")
    text=text.replace("zero(o,0,128)","zero(o,0,192)")
    text=replace(text,'''    if phase==10:
        if value_ok(o)==False:
            return provider_failure(o,0)
        within(o,NODES,RP+24,24)
        put(o,ALLOCATED,1)''','''    if phase==10:
        accepted=deferred_take(o,NODES)
        if get(o,NODES)!=0:
            put(o,ALLOCATED,1)
        if accepted==0:
            return provider_failure(o,0)''')
    text=replace_def(text,"request",r'''
def request(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    return deferred_packet(o,op)
''')
    text=replace(text,'''def finish(o:mutbuf) -> u32:
    put(o,768,0)''','''def finish(o:mutbuf) -> u32:
    if get(o,D_UNKNOWN)!=0 or get(o,VALUE_PENDING)!=0:
        put(o,CLEANUP_ERRORS,1)
        put(o,QUARANTINE_KIND,choose(get(o,D_UNKNOWN)!=0,2,1))
    put(o,768,0)''')
    text=replace(text,'''        put(o,120,get(o,VALUE_PENDING))
    return 0

def node''','''        put(o,120,get(o,VALUE_PENDING))
    put(o,128,get(o,D_QUEUE))
    put(o,136,get(o,VALUE_PENDING))
    put(o,144,get(o,D_UNKNOWN))
    put(o,152,1)
    return 0

def node''')
    text=deferred_policy(text)
    helpers=[]
    for f in ast.parse(structure.structural).body:
        if f.name in {"read64","get","put","zero","choose"}:
            helpers.append(ast.unparse(f))
        if f.name=="utf8_width":
            helpers.append(ast.unparse(f).replace("utf8_width","typed_utf8_width")
                           .replace("s: readbuf","s: mutbuf"))
    text+="\n"+"\n".join(helpers)+"\n"
    text=replace(text,"    if phase==40:\n",
        "    if phase==42:\n        if get(o,PASS)!=1 and get(o,SIZE)>MAX_BYTES:\n"
        "            return fail(o,7)\n        return descend(o,w)\n    if phase==40:\n")
    return render(text,c)
def transport_program():
    c=dict(transport.C)
    c.update(MAGIC=magic("HIABIQ03"),NEW_MAGIC=magic("HIABIQ03"),
             REPLY=magic("HIABIO03"),NEW_REPLY=magic("HIABIO03"),
             CONTEXT=magic("HIABIC03"),NEW_CONTEXT=magic("HIABIC03"),
             D_QUEUE=368,D_UNKNOWN=376,D_VOP=384)
    c.update(MAGICS)
    text=replace(transport.SOURCE,"def value_transport(","def value_transport_deferred(")
    text=replace(text,'''    at=choose(modern,112,88)
    while at<256:''','''    if get(w,112)>1 or get(w,120)>1:
        return 4294967293
    at=128
    while at<256:''')
    text=replace(text,'''                put(o,NEW,get(w,104))
                zero(w,88,24)''','''                put(o,NEW,get(w,104))
                put(o,D_QUEUE,get(w,112))
                put(o,D_UNKNOWN,get(w,120))
                zero(w,88,40)''')
    text=replace(text,'''    if phase==2:
        if value_ok(o)==False:
            return fail(o,7,get(o,VP+8))
        within(o,OWN,VP+24,24)''','''    if phase==2:
        if deferred_take(o,OWN)==0:
            return fail(o,7,get(o,VP+8))''')
    text=replace(text,'''    if phase==700:
        if get(o,MODERN)!=0 and get(o,VALUE_PENDING)!=0:''','''    if phase==700:
        if get(o,D_UNKNOWN)!=0:
            put(o,QUARANTINE_KIND,2)
            return quarantine(o,w,7,2)
        if get(o,MODERN)!=0 and get(o,VALUE_PENDING)!=0:''')
    text=replace(text,'''        put(w,104,get(o,NEW))
    put(w,32,get(o,CURRENT))''','''        put(w,104,get(o,NEW))
        put(w,112,get(o,D_QUEUE))
        put(w,120,get(o,D_UNKNOWN))
    put(w,32,get(o,CURRENT))''')
    text=replace_def(text,"packet",r'''
def packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    return deferred_packet(o,op)
''')
    text=replace(text,'''        put(o,64,get(o,VALUE_PENDING))
    return 0
def again''','''        put(o,64,get(o,VALUE_PENDING))
    put(o,72,get(o,D_QUEUE))
    put(o,80,get(o,VALUE_PENDING))
    put(o,88,get(o,D_UNKNOWN))
    put(o,96,1)
    return 0
def again''')
    return render(deferred_policy(text),c)
def freeze_program():
    c=dict(freezer.C)
    for key,value in tuple(c.items()):
        if 128<=value<=400:c[key]=value+128
    c.update(MAGIC=magic("HIABFZQ3"),NEW_MAGIC=magic("HIABFZQ3"),
             REPLY=magic("HIABFZR3"),NEW_REPLY=magic("HIABFZR3"),
             CONTEXT=magic("HIABFZC3"),NEW_CONTEXT=magic("HIABFZC3"),
             IO_REQUEST=magic("HIABIQ03"),NEW_IO_REQUEST=magic("HIABIQ03"),
             IO_REPLY=magic("HIABIO03"),NEW_IO_REPLY=magic("HIABIO03"),
             IO_CONTEXT=magic("HIABIC03"),NEW_IO_CONTEXT=magic("HIABIC03"),
             FEEDBACK=592,ST=640,D_QUEUE=536,D_UNKNOWN=544)
    text=replace(freezer.SOURCE,"def freeze_value(","def freeze_value_deferred(")
    text=replace(text,"from_work(w,o,128,128,320)","from_work(w,o,128,256,320)")
    text=replace(text,"to_work(o,w,128,128,320)","to_work(o,w,256,128,320)")
    text=replace(text,"    zero(o,0,128)\n","    zero(o,0,192)\n")
    text=replace(text,"        within(o,128,ERR,n)","        within(o,256,ERR,n)")
    text=replace_def(text,"io_response",IO_RESPONSE)
    text=replace(text,'''    if status==1:
        n=get(o,ERRN)''','''    put(o,128,get(o,D_QUEUE))
    put(o,136,get(o,VALUE_PENDING))
    put(o,144,get(o,D_UNKNOWN))
    put(o,152,1)
    if status==1:
        n=get(o,ERRN)''')
    return render(text,c)
IO_RESPONSE=r'''
def io_response(o:mutbuf) -> u64:
    put(o,QUARANTINE_KIND,2)
    if get(o,FEEDBACK)!=0 or get(o,IOO)!=NEW_IO_REPLY:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,IOO+48)>1 or get(o,IOO+56)>2 or get(o,IOO+64)>1:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,IOO+72)>1 or get(o,IOO+80)>1 or get(o,IOO+88)>1 or get(o,IOO+96)!=1:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,IOO+72)!=0:
        put(o,D_QUEUE,1)
    if get(o,IOO+80)!=0:
        put(o,VALUE_PENDING,1)
    if get(o,IOO+88)!=0:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,IOO+104)!=0 or get(o,IOO+112)!=0 or get(o,IOO+120)!=0:
        put(o,D_UNKNOWN,1)
        return 0
    retained=get(o,IOO+48)
    kind=get(o,IOO+56)
    pending=get(o,IOO+64)
    if pending!=get(o,IOO+80):
        put(o,D_UNKNOWN,1)
        return 0
    if retained==0:
        if kind!=0 or pending!=0 or get(o,IOC+32)!=0 or get(o,IOC+40)!=0 or get(o,IOC+64)!=0:
            return 0
        if get(o,IOC+88)!=0 or get(o,IOC+96)!=0 or get(o,IOC+104)!=0:
            return 0
        if get(o,IOC+112)!=0 or get(o,IOC+120)!=0:
            return 0
        put(o,QUARANTINE_KIND,0)
        put(o,VALUE_PENDING,0)
        return 1
    if kind==0:
        return 0
    put(o,QUARANTINE_KIND,kind)
    put(o,VALUE_PENDING,pending)
    return 0
'''
def source_program(kind):return globals()[kind+"_program"]()
def main():
    for kind,name in NAMES.items():
        d=document(source_program(kind),name)
        p=ROOT/"examples/hia_bootstrap"/(name+".hepta")
        p.write_text(render_assembly(d))
        print(p.name,p.stat().st_size,len(d["functions"]),
              sum(len(f["blocks"])for f in d["functions"]),
              sum(len(b["ops"])for f in d["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
