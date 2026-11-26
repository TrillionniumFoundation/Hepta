"""HIA-only managed Value policy shared by the new private BG profiles."""
import ast,re
from tools import hia_background_deferred_value_source as deferred
MAGICS=dict(deferred.MAGICS)
MAGICS["D_IMPORT"]=int.from_bytes(b"HIABVQ10","little")
def replace(text,a,b):return deferred.replace(text,a,b)
def replace_def(text,name,body):return deferred.replace_def(text,name,body)
def closure(text,entry):
    tree=ast.parse(text);functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    chosen=set();todo=[entry]
    while todo:
        name=todo.pop()
        if name in chosen:continue
        chosen.add(name)
        todo.extend(n.func.id for n in ast.walk(functions[name])if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id in functions and n.func.id not in chosen)
    order=[entry]+[n.name for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in chosen and n.name!=entry]
    return "\n\n".join(ast.get_source_segment(text,functions[name])for name in order)+"\n"
def render(text,constants,entry):
    for key,value in sorted(constants.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return closure(text,entry)
def apply(text):
    text=deferred.deferred_policy(text).replace("VREPLY","VALUE_REPLY")
    text=replace_def(text,"deferred_packet",PACKET)
    if "def take_value("in text or "def value_take("in text:
        take_name="take_value"if "def take_value("in text else"value_take"
        text=replace_def(text,take_name,TAKE.replace("def take_value(","def "+take_name+"("))
    else:
        text+=TAKE
    text=replace(text,"    if get(o,RP+8)!=0 and get(o,RP+112)==0:", "    if get(o,RP+8)==6 and get(o,RP+112)!=0:\n        put(o,D_UNKNOWN,1)\n        return 0\n    if get(o,RP+8)!=0 and get(o,RP+8)!=6 and get(o,RP+112)==0:")
    request=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=="request")
    body=ast.get_source_segment(text,request)
    body=replace(body,"    return 0","    if magic==VALUE_INPUT or magic==VALUE_DROP_INPUT:\n        deferred_packet(o,op)\n    return 0")
    text=replace_def(text,"request",body)
    text=replace(text,"def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:\n    return invoke",
        "def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:\n    managed_packet(o)\n    return invoke")
    text+=HELPERS
    functions={n.name for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
    for name,at,queue,mapping,unknown,marker in [
        ("release_job","RP",152,160,168,176),
        ("release_job_retry","RP",152,160,168,176),
        ("release_future","PUBLIC_OUT",136,128,144,0),
        ("release_future_retry","PUBLIC_OUT",136,128,144,0),
        ("release_cell_query","RP",160,168,0,0)]:
        if name not in functions:continue
        text=replace(text,"def "+name+"(","def original_"+name+"(")
        arg=",at:u64"if name in("release_job","release_future")else""
        call=",at"if arg else""
        text+="\ndef "+name+"(o:mutbuf"+arg+") -> u64:\n"
        text+="    done=original_"+name+"(o"+call+")\n"
        text+="    flags=managed_pending(o,"+at+","+str(queue)+","+str(mapping)+","+str(unknown)+","+str(marker)+")\n"
        text+="    if flags==0:\n        put(o,DROP_KNOWN,2)\n        return 0\n    return done\n"
    return text
PACKET=r'''
def deferred_packet(o:mutbuf,op:u64) -> u64:
    actual=op
    magic=D_QUERY
    if op==1:
        magic=D_IMPORT
    elif op==5:
        magic=D_PRIVATE
        actual=91
    elif op==6 or op==29:
        magic=D_PRIVATE
        actual=78
    elif op==22 or op==30:
        magic=D_PRIVATE
        actual=92
    elif op==31:
        magic=D_PRIVATE
        actual=93
    elif op==23:
        magic=D_SNAPSHOT
    elif op==3 or op==12 or op==16 or op==18 or op==24:
        magic=D_FIXED
    put(o,RQ,magic)
    put(o,RQ+8,actual)
    put(o,D_VOP,actual)
    return 0
'''
TAKE=r'''
def take_value(o:mutbuf,at:u64) -> u64:
    if get(o,D_VOP)==91:
        return choose(deferred_take(o,at)!=0,0,1)
    if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+24)==0 or get(o,at)!=0:
        return 1
    within(o,at,RP+24,24)
    return 0
'''
HELPERS=r'''
def managed_packet(o:mutbuf) -> u64:
    magic=get(o,RQ)
    op=get(o,RQ+8)
    if magic==VALUE_INPUT or magic==VALUE_DROP_INPUT:
        return deferred_packet(o,op)
    put(o,D_VOP,op)
    return 0
def managed_pending(o:mutbuf,at:u64,queue:u64,mapping:u64,unknown:u64,marker:u64) -> u64:
    if get(o,at+queue)>1 or get(o,at+mapping)>1:
        put(o,D_UNKNOWN,1)
        return 0
    if marker!=0 and get(o,at+marker)!=1:
        put(o,D_UNKNOWN,1)
        return 0
    if unknown!=0 and get(o,at+unknown)!=0:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,at+queue)!=0:
        put(o,D_QUEUE,1)
    if get(o,at+mapping)!=0:
        put(o,VALUE_PENDING,1)
    return 1
'''
