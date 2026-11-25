"""HTTP parent session records and shared audit-slot allocation."""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_http_common import authored
SOURCE=r"""
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,0)
    result=get(w,8)
    if phase==100:
        put(w,H_LOOKUP_INDEX,0)
        return lookup_next(o,w)
    if phase==101:
        if get(w,SR_STATUS)==1 and get(w,H_QUERY_N)==36 and equal(w,H_QUERY_TEXT,SR_UUID,36):
            put(w,H_S_FOUND,1)
            return enter(w,get(w,H_LOOKUP_MODULE),get(w,H_LOOKUP_PHASE))
        put(w,H_LOOKUP_INDEX,get(w,H_LOOKUP_INDEX)+1)
        return lookup_next(o,w)
    if phase==900:
        return save_write(o,w)
    if phase==901:
        if result==NEG4:
            return save_write(o,w)
        if failed(result) or result==0 or result>SESSION_BYTES-get(w,H_S_TRANSFER):
            return 0
        put(w,H_S_TRANSFER,get(w,H_S_TRANSFER)+result)
        if get(w,H_S_TRANSFER)!=SESSION_BYTES:
            return save_write(o,w)
        return enter(w,get(w,H_S_RETURN_MODULE),get(w,H_S_RETURN_PHASE))
    if phase==910:
        return load_read(o,w)
    if phase==911:
        if result==NEG4:
            return load_read(o,w)
        if failed(result) or result==0 or result>SESSION_BYTES-get(w,H_S_TRANSFER):
            return 0
        put(w,H_S_TRANSFER,get(w,H_S_TRANSFER)+result)
        if get(w,H_S_TRANSFER)!=SESSION_BYTES:
            return load_read(o,w)
        return enter(w,get(w,H_S_RETURN_MODULE),get(w,H_S_RETURN_PHASE))
    return 0

def lookup_next(o:mutbuf,w:mutbuf) -> u32:
    if get(w,H_LOOKUP_INDEX)==get(w,H_SESSION_COUNT) or get(w,H_QUERY_N)!=36:
        put(w,H_S_FOUND,0)
        return enter(w,get(w,H_LOOKUP_MODULE),get(w,H_LOOKUP_PHASE))
    return load_session(w,get(w,H_LOOKUP_INDEX),HTTP_REGISTRY,101)

def save_write(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_S_TRANSFER)
    return call(o,w,901,18,get(w,H_SESSIONS),H_SESSION+used,SESSION_BYTES-used,get(w,H_S_CURRENT)*SESSION_BYTES+used,0,0,12)

def load_read(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_S_TRANSFER)
    return call(o,w,911,17,get(w,H_SESSIONS),H_SESSION+used,SESSION_BYTES-used,get(w,H_S_CURRENT)*SESSION_BYTES+used,0,0,12)
"""
def source(): return authored(ast.unparse(ast.parse(SOURCE)))
def render(): return render_assembly(document(source(),'mcp_http_registry'))
if __name__=='__main__':
 p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/mcp_http_registry.hepta'
 raw=render();p.write_text(raw);print(p.name,len(raw.encode()))
