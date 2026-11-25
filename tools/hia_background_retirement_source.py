"""Shared HIA response policy for explicit background retirement.

Author-time text only. The generated owners call the actual fixed dependencies;
no Python code is part of a runtime closure. New dependency profiles still need
native qualification together before any generated consumer is admitted.
"""

import ast

MAGICS = {
    'VALUE_DROP_INPUT': int.from_bytes(b'HIABVQ02', 'little'),
    'VALUE_DROP_REPLY': int.from_bytes(b'HIABVR02', 'little'),
    'JOB_DROP_INPUT': int.from_bytes(b'HIABJO03', 'little'),
    'JOB_DROP_REPLY': int.from_bytes(b'HIABJOR2', 'little'),
    'PUBLIC_DROP_INPUT': int.from_bytes(b'HIABFP03', 'little'),
    'PUBLIC_DROP_REPLY': int.from_bytes(b'HIABFRP2', 'little'),
    'CELL_QUERY_INPUT': int.from_bytes(b'HIABFQ04', 'little'),
    'CELL_QUERY_REPLY': int.from_bytes(b'HIABFR02', 'little'),
}

SOURCE = r'''
def release_begin(o:mutbuf) -> u64:
    put(o,DROP_ACTIVE,1)
    put(o,DROP_KNOWN,0)
    return 0
def release_value_reply(o:mutbuf) -> u64:
    if valid(o,RP,VALUE_DROP_REPLY)==0 or get(o,RP+88)!=1 or get(o,RP+96)>1 or get(o,RP+80)>1:
        return 0
    status=get(o,RP+8)
    if status!=0 and status!=1 and status!=5 and status!=6 and status!=11:
        return 0
    at=16
    while at<128:
        if at<80 or at>=104:
            if get(o,RP+at)!=0:
                return 0
        at=at+8
    return 1
def release_value(o:mutbuf,at:u64) -> u64:
    if release_value_reply(o)==0:
        return 0
    status=get(o,RP+8)
    consumed=get(o,RP+96)
    pending=get(o,RP+80)
    if (status==0 and (consumed!=1 or pending!=0)) or (consumed==1 and status!=0 and status!=11):
        return 0
    put(o,DROP_KNOWN,1)
    if pending!=0:
        put(o,VALUE_PENDING,1)
    if consumed==0:
        return 0
    zero(o,at,24)
    if status!=0 and pending==0:
        put(o,DROP_KNOWN,2)
        return 0
    put(o,DROP_ACTIVE,0)
    return 1
def release_job(o:mutbuf,at:u64) -> u64:
    if valid(o,RP,JOB_DROP_REPLY)==0 or get(o,RP+136)!=1 or get(o,RP+128)>1 or get(o,RP+144)>1:
        return 0
    status=get(o,RP+8)
    if status!=0 and status!=1 and status!=5 and status!=6 and status!=9:
        return 0
    if status==0 and (get(o,RP+128)!=1 or get(o,RP+144)!=0):
        return 0
    put(o,DROP_KNOWN,1)
    if get(o,RP+144)!=0:
        put(o,JOB_PENDING,1)
    if get(o,RP+128)==0:
        return 0
    zero(o,at,24)
    if status!=0 and get(o,RP+144)==0:
        put(o,DROP_KNOWN,2)
        return 0
    put(o,DROP_ACTIVE,0)
    return 1
def release_future(o:mutbuf,at:u64) -> u64:
    if valid(o,PUBLIC_OUT,PUBLIC_DROP_REPLY)==0 or get(o,PUBLIC_OUT+104)!=1 or get(o,PUBLIC_OUT+96)>1:
        return 0
    status=get(o,PUBLIC_OUT+8)
    kind=get(o,PUBLIC_OUT+16)
    if (status==0 and (kind!=0 or get(o,PUBLIC_OUT+96)!=1)) or (status!=0 and status!=1 and status!=3):
        return 0
    if status!=0 and kind!=107:
        return 0
    if get(o,PUBLIC_OUT+72)!=0 or get(o,PUBLIC_OUT+80)!=0 or get(o,PUBLIC_OUT+88)!=0:
        return 0
    if status==3 and get(o,PUBLIC_OUT+96)!=0:
        return 0
    put(o,DROP_KNOWN,1)
    if get(o,PUBLIC_OUT+96)==0:
        return 0
    zero(o,at,24)
    if status!=0 or get(o,PUBLIC_OUT+120)!=0:
        put(o,FUTURE_PENDING,1)
    put(o,DROP_ACTIVE,0)
    return 1
def release_job_retry(o:mutbuf) -> u64:
    if valid(o,RP,JOB_DROP_REPLY)==0 or get(o,RP+136)!=1 or get(o,RP+128)!=0 or get(o,RP+144)>1:
        return 0
    status=get(o,RP+8)
    if status!=0 and status!=1 and status!=5 and status!=6 and status!=9:
        return 0
    put(o,DROP_KNOWN,1)
    if status!=0 or get(o,RP+144)!=0:
        return 0
    put(o,JOB_PENDING,0)
    put(o,DROP_ACTIVE,0)
    return 1
def release_value_retry(o:mutbuf) -> u64:
    if release_value_reply(o)==0 or get(o,RP+96)!=0:
        return 0
    put(o,DROP_KNOWN,1)
    if get(o,RP+8)!=0 or get(o,RP+80)!=0:
        if get(o,RP+8)==11 and get(o,RP+80)==0:
            put(o,DROP_KNOWN,2)
        return 0
    put(o,VALUE_PENDING,0)
    put(o,DROP_ACTIVE,0)
    return 1
def release_future_retry(o:mutbuf) -> u64:
    if valid(o,PUBLIC_OUT,PUBLIC_REPLY)==0:
        return 0
    status=get(o,PUBLIC_OUT+8)
    if status!=0 and status!=1 and status!=3:
        return 0
    if get(o,PUBLIC_OUT+72)!=0 or get(o,PUBLIC_OUT+80)!=0 or get(o,PUBLIC_OUT+88)!=0:
        return 0
    put(o,DROP_KNOWN,1)
    return 1
def release_cell_query(o:mutbuf) -> u64:
    if valid(o,RP,CELL_QUERY_REPLY)==0 or get(o,RP+128)!=0 or get(o,RP+136)>1 or get(o,RP+144)>1 or get(o,RP+152)!=0:
        return 0
    if get(o,RP+144)!=1:
        return 0
    put(o,DROP_KNOWN,1)
    if get(o,RP+8)!=0 or get(o,RP+136)!=0:
        return 0
    put(o,FUTURE_PENDING,0)
    put(o,DROP_ACTIVE,0)
    return 1
'''

def selected(*roots):
    """Emit only the requested HIA functions and their HIA helper closure."""
    tree = ast.parse(SOURCE)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    needed = set()
    todo = list(roots)
    while todo:
        name = todo.pop()
        if name in needed:
            continue
        needed.add(name)
        todo.extend(node.func.id for node in ast.walk(functions[name])
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in functions and node.func.id not in needed)
    return '\n\n'.join(ast.get_source_segment(SOURCE, node) for node in tree.body
                       if isinstance(node, ast.FunctionDef) and node.name in needed) + '\n'
