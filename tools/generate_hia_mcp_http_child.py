"""Derive HTTP-only MCP framing and global-slot scheduling owners.

The parent supplies a private length frame after HTTP syntax/SDK admission.
The existing stdio roles and controller/audit protocol are unchanged.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_http_common import authored
from tools.generate_hia_mcp_service_stream import SOURCE as STREAM
from tools.generate_hia_mcp_service_scheduler import SOURCE as SCHEDULER

FRAME = int.from_bytes(b'HIAHCI01','little')

CONSUME = r"""
def consume(o:mutbuf, w:mutbuf) -> u32:
    cursor = get(w, 216)
    end = get(w, 208)
    while cursor < end:
        if get(w, H_CHILD_FRAME_OPEN) == 0:
            used = get(w, H_CHILD_HEADER_USED)
            take = 64 - used
            if take > end - cursor:
                take = end - cursor
            copy_state(w, READ_CHUNK + cursor, H_CHILD_HEADER + used, take)
            cursor = cursor + take
            used = used + take
            put(w, H_CHILD_HEADER_USED, used)
            if used == 64:
                if frame_begin(w) == False:
                    return 0
        else:
            take = get(w, H_CHILD_BODY_N) - get(w, 200)
            if take > end - cursor:
                take = end - cursor
            copy_state(w, READ_CHUNK + cursor, REQUEST + get(w, 200), take)
            put(w, 200, get(w, 200) + take)
            cursor = cursor + take
            if get(w, 200) == get(w, H_CHILD_BODY_N):
                put(w, 216, cursor)
                put(w, H_CHILD_FRAME_OPEN, 0)
                put(w, H_CHILD_HEADER_USED, 0)
                return pure(o, w, 11, P_SDK, REQUEST, get(w, 200), PURE_OUTPUT, 160, PURE_WORK, 32768)
    put(w, 216, cursor)
    if get(w, 224) == 1:
        if get(w, H_CHILD_FRAME_OPEN) != 0 or get(w, H_CHILD_HEADER_USED) != 0:
            return 0
        return enter(w, 6, 100)
    return read_more(o, w)

def frame_begin(w:mutbuf) -> bool:
    if get(w, H_CHILD_HEADER) != FRAME_MAGIC:
        return False
    size = get(w, H_CHILD_HEADER + 8)
    slot = get(w, H_CHILD_HEADER + 16)
    generation = get(w, H_CHILD_HEADER + 24)
    mode = get(w, H_CHILD_HEADER + 32)
    if size == 0 or size > 4194304 or mode > 1:
        return False
    if slot != NONE and (slot >= TASK_COUNT or generation == 0):
        return False
    if slot == NONE and generation != 0:
        return False
    if get(w, H_CHILD_HEADER + 40) != 0 or get(w, H_CHILD_HEADER + 48) != 0 or get(w, H_CHILD_HEADER + 56) != 0:
        return False
    put(w, H_CHILD_BODY_N, size)
    put(w, H_ASSIGNED_SLOT, slot)
    put(w, H_ASSIGNED_GENERATION, generation)
    put(w, H_CHILD_MODE, mode)
    put(w, H_CHILD_FRAME_OPEN, 1)
    put(w, 200, 0)
    if mode == 1 and get(w, SESSION_PHASE) == 0:
        put(w, SESSION_PHASE, 2)
        put(w, SESSION_PHASE + 184, 1)
    return True
"""

SLOT = r"""
def free_slot(w:mutbuf) -> u64:
    slot = get(w, H_ASSIGNED_SLOT)
    if slot >= TASK_COUNT or get(w, H_ASSIGNED_GENERATION) == 0:
        return NONE
    row = TASK_TABLE + slot * TASK_BYTES
    if get(w, row) != 0:
        return NONE
    return row
"""

def replace_function(source, name, replacement):
    nodes=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name==name]
    if len(nodes)!=1: raise ValueError(name)
    return source.replace(ast.get_source_segment(source,nodes[0]),replacement.strip(),1)

OUTPUT=r"""
def output_header(w:mutbuf,slot:u64,generation:u64,size:u64,kind:u64) -> u64:
    put(w,H_CHILD_OUTPUT,OUTPUT_MAGIC)
    put(w,H_CHILD_OUTPUT+8,size)
    put(w,H_CHILD_OUTPUT+16,slot)
    put(w,H_CHILD_OUTPUT+24,generation)
    put(w,H_CHILD_OUTPUT+32,kind)
    put(w,H_CHILD_OUTPUT+40,0)
    if kind==1 and slot<TASK_COUNT:
        put(w,H_CHILD_OUTPUT+40,get(w,TASK_TABLE+slot*TASK_BYTES))
    put(w,H_CHILD_OUTPUT+48,0)
    put(w,H_CHILD_OUTPUT+56,0)
    put(w,H_CHILD_OUTPUT_USED,0)
    put(w,H_CHILD_OUTPUT_N,size)
    return 0

def output_write(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    used=get(w,H_CHILD_OUTPUT_USED)
    return call(o,w,phase,1,1,H_CHILD_OUTPUT+used,64-used,0,0,0,12)

def output_ready(w:mutbuf,result:u64) -> u64:
    if result==NEG4:
        return 0
    if failed(result) or result==0 or result>64-get(w,H_CHILD_OUTPUT_USED):
        return 2
    put(w,H_CHILD_OUTPUT_USED,get(w,H_CHILD_OUTPUT_USED)+result)
    return choose(get(w,H_CHILD_OUTPUT_USED)==64,1,0)
"""

def stream_source():
    value=replace_function(STREAM,'consume',CONSUME)
    value=value.replace('    put(w, H_CHILD_FRAME_OPEN, 1)\n',
        '    put(w, H_CHILD_FRAME_OPEN, 1)\n    put(w,H_CHILD_SENT,0)\n')
    value=value.replace('        put(w, FRAME_DISCARD, 0)\n',
        '        put(w, FRAME_DISCARD, 0)\n        put(w, H_CHILD_HEADER_USED, 0)\n        put(w, H_CHILD_FRAME_OPEN, 0)\n',1)
    old="""        if result == 0:
            put(w, 200, 0)
            return consume(o, w)"""
    assert value.count(old)==2
    value=value.replace(old,'''        if result == 0:
            return enter(w,2,30)''')
    old="""    if phase == 19:
        return write_more(o, w)"""
    new="""    if phase == 19:
        if get(w,184)==1:
            return write_more(o,w)
        put(w,H_CHILD_SENT,1)
        output_header(w,get(w,H_ASSIGNED_SLOT),get(w,H_ASSIGNED_GENERATION),get(w,240),0)
        return output_write(o,w,18)
    if phase == 18:
        ready=output_ready(w,result)
        if ready==2:
            return 0
        if ready==0:
            return output_write(o,w,18)
        if get(w,H_CHILD_OUTPUT_N)==0:
            return enter(w,2,30)
        return write_more(o,w)"""
    assert value.count(old)==1;value=value.replace(old,new)
    old='''        put(w, 200, 0)
        put(w, 64, get(w, 176))
        return consume(o, w)'''
    new='''        if get(w,H_CHILD_SENT)==0:
            put(w,H_CHILD_SENT,1)
            kind=choose(get(w,SDK_DESCRIPTOR+8)==1,1,2)
            output_header(w,get(w,H_ASSIGNED_SLOT),get(w,H_ASSIGNED_GENERATION),0,kind)
            return output_write(o,w,18)
        put(w, 200, 0)
        put(w, 64, get(w, 176))
        return consume(o, w)'''
    assert value.count(old)==1;value=value.replace(old,new)
    old='''        return pure(o, w, 10, P_SESSION, REQUEST, get(w, 200), SESSION_OUT, 16777728, SESSION_WORK, W_SESSION)'''
    new='''        if result==160 and get(w,SDK_DESCRIPTOR+8)==1 and get(w,SDK_DESCRIPTOR+16)==1 and get(w,SESSION_PHASE)==0:
            return enter(w,HTTP_CONTEXT,0)
        return enter(w,2,12)
    if phase==12:
        return pure(o,w,10,P_SESSION,REQUEST,get(w,200),SESSION_OUT,16777728,SESSION_WORK,W_SESSION)'''
    assert value.count(old)==1;value=value.replace(old,new)
    old='''                copy_state(w, SESSION_OUT, SCHEDULE_DESCRIPTOR, 96)
                return enter(w, 6, 0)'''
    new='''                copy_state(w, SESSION_OUT, SCHEDULE_DESCRIPTOR, 96)
                if get(w,SESSION_OUT+8)==2:
                    return enter(w,HTTP_CONTEXT,50)
                return enter(w,6,0)'''
    assert value.count(old)==1;value=value.replace(old,new)
    return authored(ast.unparse(ast.parse(value+OUTPUT)),extra={
        'DISPATCH_MAGIC':int.from_bytes(b'HIAMSQ01','little'),
        'FRAME_MAGIC':FRAME,'OUTPUT_MAGIC':int.from_bytes(b'HIAHCO01','little')})

def scheduler_source():
    value=replace_function(SCHEDULER,'free_slot',SLOT)
    previous="""        if get(w, 440) == NONE:
            return 0
        put(w, 440, get(w, 440) + 1)
        put(w, 448, get(w, 440))
        put(w, 432, (get(w, 1560) - TASK_TABLE) // TASK_BYTES)"""
    updated="""        slot = get(w, H_ASSIGNED_SLOT)
        generation = get(w, H_ASSIGNED_GENERATION)
        if slot >= TASK_COUNT or generation == 0:
            return 0
        if get(w, 1560) != TASK_TABLE + slot * TASK_BYTES:
            return 0
        put(w, 448, generation)
        put(w, 432, slot)"""
    if value.count(previous)!=1: raise ValueError('scheduler assignment changed')
    value=value.replace(previous,updated)
    value=value.replace('        put(w, row + 64, get(w, 1672))',
        '        put(w, row + 64, get(w, 1672))\n        put(w,row+72,get(w,448))')
    needle='    if phase >= 120 and phase <= 129:'
    value=value.replace(needle,'''    if phase == 119:
        ready=output_ready(w,result)
        if ready==2:
            return 0
        if ready==0:
            return output_write(o,w,119)
        return write_result(o,w)
'''+needle)
    old='''        put(w, 1648, 0)
        return write_result(o, w)'''
    new='''        put(w, 1648, 0)
        row=get(w,1624)
        output_header(w,(row-TASK_TABLE)//TASK_BYTES,get(w,row+72),get(w,1640),0)
        return output_write(o,w,119)'''
    assert value.count(old)==1;value=value.replace(old,new)
    return authored(ast.unparse(ast.parse(value+OUTPUT)),text={
      'response':'hia-mcp-response','failure':'hia-mcp-failure',
      'error_prefix':'{"jsonrpc":"2.0","id":',
      'error_suffix':',"error":{"code":-32603,"message":"Native HIA request observation unavailable; repeat only the original request"}}\n',
      'cancel_suffix':',"error":{"code":-32800,"message":"Request cancelled"}}\n'},
      extra={'OUTPUT_MAGIC':int.from_bytes(b'HIAHCO01','little')})

def render():
    return {name:render_assembly(document(source(),'mcp_http_'+name)) for name,source in (
        ('stream',stream_source),('scheduler',scheduler_source))}

if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    for name,raw in render().items():
        path=root/'examples/hia_bootstrap'/('mcp_http_'+name+'.hepta')
        path.write_text(raw);print(path.name,len(raw.encode()))
