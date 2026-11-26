"""Private deferred Value custody for fixed native BG owners.

This author emits HIA policy. It never runs at a product boundary. Original
Q01/Q02 and retained background protocol domains remain unchanged.
"""
import ast

MAGICS = {k:int.from_bytes(v.encode(),"little") for k,v in {
    "D_PRIVATE":"HIABVQ05","D_QUERY":"HIABVQ06","D_FIXED":"HIABVQ07",
    "D_SNAPSHOT":"HIABVQ09"}.items()}

def replace(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)

def replace_def(text, name, body):
    lines=text.splitlines(True)
    node=next(n for n in ast.parse(text).body
              if isinstance(n,ast.FunctionDef) and n.name==name)
    return "".join(lines[:node.lineno-1])+body.strip()+"\n"+"".join(lines[node.end_lineno:])

def deferred_policy(text):
    for name in ("release_value_reply","release_value","release_value_retry"):
        text=replace_def(text,name,FUNCTIONS[name])
    return text+"\n"+EXTRA

FUNCTIONS={
"release_value_reply":r'''
def release_value_reply(o:mutbuf,op:u64) -> u64:
    if valid(o,RP,VALUE_DROP_REPLY)==0 or get(o,RP+88)!=1 or get(o,RP+96)>1:
        return 0
    status=get(o,RP+8)
    consumed=get(o,RP+96)
    if status!=0 and status!=1 and status!=6 and status!=11:
        return 0
    if op==31 and (status==1 or consumed!=0):
        return 0
    if consumed!=0 and status!=0 and status!=11:
        return 0
    if status==0 and consumed!=choose(op==31,0,1):
        return 0
    at=16
    while at<80:
        if get(o,RP+at)!=0:
            return 0
        at=at+8
    return 1
''',
"release_value":r'''
def release_value(o:mutbuf,at:u64) -> u64:
    if release_value_reply(o,29)==0:
        put(o,D_UNKNOWN,1)
        return 0
    put(o,DROP_KNOWN,1)
    consumed=get(o,RP+96)
    if consumed!=0:
        zero(o,at,24)
    if deferred_snapshot(o)==0:
        put(o,DROP_KNOWN,2)
        return 0
    if consumed==0:
        return 0
    if get(o,RP+8)==11 and get(o,RP+80)==0:
        put(o,D_UNKNOWN,1)
        put(o,DROP_KNOWN,2)
        return 0
    put(o,DROP_ACTIVE,0)
    return 1
''',
"release_value_retry":r'''
def release_value_retry(o:mutbuf) -> u64:
    if release_value_reply(o,31)==0:
        put(o,D_UNKNOWN,1)
        return 0
    put(o,DROP_KNOWN,1)
    if deferred_snapshot(o)==0:
        put(o,DROP_KNOWN,2)
        return 0
    if get(o,RP+104)!=0:
        return 0
    if get(o,RP+8)!=0 and get(o,RP+112)==0:
        if get(o,RP+8)==11:
            put(o,DROP_KNOWN,2)
            put(o,D_UNKNOWN,1)
        return 0
    put(o,VALUE_PENDING,0)
    put(o,DROP_ACTIVE,0)
    return 1
''',
}

EXTRA=r'''
def deferred_packet(o:mutbuf,op:u64) -> u64:
    magic=D_QUERY
    actual=op
    if op==5:
        magic=D_PRIVATE
        actual=91
    elif op==6:
        magic=D_PRIVATE
        actual=78
        release_begin(o)
    elif op==31:
        magic=D_PRIVATE
        actual=93
        release_begin(o)
    elif op==23:
        magic=D_SNAPSHOT
    elif op==3 or op==12 or op==16 or op==18 or op==24:
        magic=D_FIXED
    put(o,RQ,magic)
    put(o,RQ+8,actual)
    put(o,D_VOP,actual)
    return 0

def deferred_snapshot(o:mutbuf) -> u64:
    if get(o,RP+80)>1 or get(o,RP+104)>1 or get(o,RP+112)>1 or get(o,RP+120)!=1:
        put(o,D_UNKNOWN,1)
        return 0
    pending=choose(get(o,RP+104)!=0 or get(o,RP+112)!=0,1,0)
    if get(o,RP+80)!=pending:
        put(o,D_UNKNOWN,1)
        return 0
    if get(o,RP+112)!=0:
        put(o,D_QUEUE,1)
    if get(o,RP+104)!=0:
        put(o,VALUE_PENDING,1)
    return 1

def deferred_take(o:mutbuf,at:u64) -> u64:
    if valid(o,RP,VREPLY)==0 or get(o,RP+88)!=1 or get(o,RP+96)>1:
        put(o,D_UNKNOWN,1)
        return 0
    delivered=get(o,RP+96)
    if delivered!=0:
        if get(o,RP+24)==0 or get(o,at)!=0:
            put(o,D_UNKNOWN,1)
            return 0
        within(o,at,RP+24,24)
    if deferred_snapshot(o)==0:
        return 0
    status=get(o,RP+8)
    if status!=0 and status!=11:
        if delivered!=0:
            put(o,D_UNKNOWN,1)
        return 0
    if status==11 and get(o,RP+80)==0:
        put(o,D_UNKNOWN,1)
        return 0
    if delivered==0 or get(o,VALUE_PENDING)!=0:
        return 0
    return 1
'''
