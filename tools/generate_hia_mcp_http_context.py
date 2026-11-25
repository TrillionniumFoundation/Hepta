"""Native per-session capability capture and first HIA-tool local workdir policy."""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_http_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,0)
    result=get(w,8)
    if phase==100:
        put(w,H_C_ROOTS_FD,NONE)
        put(w,H_C_ROOTS_N,0)
        return decode(o,w,101,318767104,get(w,1728))
    if phase==101:
        if result>=4294967292:
            return 0
        node=workspace_roots(w)
        if node==NONE:
            store(w,H_INPUT,91)
            store(w,H_INPUT+1,93)
            put(w,H_C_RAW,H_INPUT)
            put(w,H_C_ROOTS_N,2)
        else:
            if get(w,node)!=5 or get(w,node+64)>8388608:
                return 0
            put(w,H_C_RAW,get(w,72)+get(w,node+56))
            put(w,H_C_ROOTS_N,get(w,node+64))
        end=text_roots(w,H_IO)
        store(w,end,0)
        return call(o,w,102,319,H_IO,3,0,0,0,0,3)
    if phase==102:
        if failed(result):
            return 0
        put(w,H_C_ROOTS_FD,result)
        put(w,H_C_USED,0)
        return roots_write(o,w)
    if phase==103:
        if result==NEG4:
            return roots_write(o,w)
        if failed(result) or result==0 or result>get(w,H_C_ROOTS_N)-get(w,H_C_USED):
            return 0
        put(w,H_C_USED,get(w,H_C_USED)+result)
        if get(w,H_C_USED)!=get(w,H_C_ROOTS_N):
            return roots_write(o,w)
        return call(o,w,104,72,get(w,H_C_ROOTS_FD),1033,15,0,0,0,0)
    if phase==104:
        if failed(result):
            return 0
        return enter(w,HTTP_BOOT,0)
    if phase==0:
        put(w,H_C_NEXT,0)
        return capabilities(o,w)
    if phase==50:
        if get(w,H_CHILD_WORKDIR_APPLIED)==1:
            return enter(w,6,0)
        put(w,H_CHILD_WORKDIR_APPLIED,1)
        put(w,H_C_NEXT,1)
        return capabilities(o,w)
    if phase==1:
        if result!=128 or get(w,H_META_RESULT)!=META_OUT or get(w,H_META_RESULT+8)!=0:
            return 0
        if get(w,H_C_NEXT)==0 or get(w,H_META_RESULT+64)!=0:
            put(w,H_C_CANDIDATE_N,0)
        span=get(w,H_META_RESULT+72)
        if span==0:
            return candidate_ready(o,w)
        at=span&16777215
        end=(span>>24)&16777215
        if at==0 or end<at-1 or end>get(w,200):
            return 0
        return decode(o,w,2,REQUEST+at-1,end-at+1)
    if phase==2:
        if result>=4294967292 or get(w,ARENA+64)!=4:
            return 0
        size=get(w,ARENA+96)
        put(w,H_C_CANDIDATE_N,0)
        if size<4096:
            at=ARENA+get(w,ARENA+88)
            if has_zero(w,at,size)==False:
                copy_state(w,at,H_CHILD_CWD,size)
                store(w,H_CHILD_CWD+size,0)
                put(w,H_C_CANDIDATE_N,size)
        return candidate_ready(o,w)
    if phase==10:
        if result==NEG4:
            return candidate_open(o,w)
        if failed(result):
            return enter(w,6,0)
        put(w,H_C_CANDIDATE_FD,result)
        proc_path(w,result)
        return call(o,w,11,89,H_C_PROC,H_C_CANONICAL,4096,0,0,0,15)
    if phase==11:
        put(w,H_C_CANONICAL_N,0)
        if failed(result)==False and result>0 and result<4096:
            put(w,H_C_CANONICAL_N,result)
        return call(o,w,12,3,get(w,H_C_CANDIDATE_FD),0,0,0,0,0,0)
    if phase==12:
        put(w,H_C_CANDIDATE_FD,NONE)
        if get(w,H_C_CANONICAL_N)==0:
            return enter(w,6,0)
        put(w,H_C_USED,0)
        return roots_read(o,w)
    if phase==20:
        if result==NEG4:
            return roots_read(o,w)
        if failed(result) or result==0 or result>get(w,H_C_ROOTS_N)-get(w,H_C_USED):
            return 0
        put(w,H_C_USED,get(w,H_C_USED)+result)
        if get(w,H_C_USED)!=get(w,H_C_ROOTS_N):
            return roots_read(o,w)
        return decode(o,w,21,H_INPUT,get(w,H_C_ROOTS_N))
    if phase==21:
        if result>=4294967292 or get(w,ARENA+64)!=5:
            return 0
        put(w,H_C_ROOT_NODE,get(w,ARENA+88))
        return next_root(o,w)
    if phase==30:
        if result==NEG4:
            return root_open(o,w)
        if failed(result):
            return enter(w,6,0)
        put(w,H_C_ROOT_FD,result)
        proc_path(w,result)
        return call(o,w,31,89,H_C_PROC,H_C_ROOT_CANONICAL,4096,0,0,0,15)
    if phase==31:
        put(w,H_C_ROOT_CANONICAL_N,0)
        if failed(result)==False and result>0 and result<4096:
            put(w,H_C_ROOT_CANONICAL_N,result)
        return call(o,w,32,3,get(w,H_C_ROOT_FD),0,0,0,0,0,0)
    if phase==32:
        put(w,H_C_ROOT_FD,NONE)
        if get(w,H_C_ROOT_CANONICAL_N)==0:
            return enter(w,6,0)
        if under_root(w):
            size=get(w,H_C_CANDIDATE_N)
            copy_state(w,H_CHILD_CWD,H_C_ACCEPTED,size)
            store(w,H_C_ACCEPTED+size,0)
            put(w,H_C_ACCEPTED_N,size)
            return enter(w,6,0)
        return next_root(o,w)
    return 0

def capabilities(o:mutbuf,w:mutbuf) -> u32:
    put(w,H_META_INPUT,META_IN)
    put(w,H_META_INPUT+8,2)
    put(w,H_META_INPUT+16,0)
    put(w,H_META_INPUT+24,0)
    put(w,H_META_INPUT+32,get(w,200))
    put(w,H_META_INPUT+40,160)
    put(w,H_META_INPUT+48,0)
    put(w,H_META_INPUT+56,0)
    end=copy_state(w,REQUEST,H_META_INPUT+64,get(w,200))
    end=copy_state(w,SDK_DESCRIPTOR,end,160)
    return pure(o,w,1,P_HTTP_METADATA,H_META_INPUT,end-H_META_INPUT,H_META_RESULT,8388608,PURE_WORK,46137344)

def candidate_ready(o:mutbuf,w:mutbuf) -> u32:
    if get(w,H_C_NEXT)==0:
        return enter(w,2,12)
    if get(w,H_C_CANDIDATE_N)==0 or byte(w,H_CHILD_CWD)!=47:
        return enter(w,6,0)
    return candidate_open(o,w)

def candidate_open(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,10,257,NONE-99,H_CHILD_CWD,2686976,0,0,0,12)

def roots_write(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_C_USED)
    return call(o,w,103,18,get(w,H_C_ROOTS_FD),get(w,H_C_RAW)+used,get(w,H_C_ROOTS_N)-used,used,0,0,12)

def roots_read(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_C_USED)
    return call(o,w,20,17,get(w,H_C_ROOTS_FD),H_INPUT+used,get(w,H_C_ROOTS_N)-used,used,0,0,12)

def has_zero(w:mutbuf,at:u64,size:u64) -> bool:
    index=0
    while index<size:
        if byte(w,at+index)==0:
            return True
        index=index+1
    return False

def next_root(o:mutbuf,w:mutbuf) -> u32:
    ordinal=get(w,H_C_ROOT_NODE)
    if ordinal==NONE:
        return enter(w,6,0)
    row=ARENA+64+ordinal*72
    put(w,H_C_ROOT_NODE,get(w,row+16))
    if get(w,row)!=4:
        return 0
    size=get(w,row+32)
    at=ARENA+get(w,row+24)
    if size==0 or size>=4096 or has_zero(w,at,size):
        return enter(w,6,0)
    copy_state(w,at,H_C_ROOT_PATH,size)
    store(w,H_C_ROOT_PATH+size,0)
    return root_open(o,w)

def root_open(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,30,257,NONE-99,H_C_ROOT_PATH,2621440,0,0,0,12)

def proc_path(w:mutbuf,fd:u64) -> u64:
    end=text_proc(w,H_C_PROC)
    end=decimal(w,end,fd)
    store(w,end,0)
    return end

def workspace_roots(w:mutbuf) -> u64:
    if get(w,ARENA+64)!=6:
        return NONE
    end=text_workspace_key(w,H_C_ROOT_PATH)
    size=end-H_C_ROOT_PATH
    ordinal=get(w,ARENA+88)
    found=NONE
    while ordinal!=NONE:
        row=ARENA+64+ordinal*72
        if get(w,row+48)==size and equal(w,ARENA+get(w,row+40),H_C_ROOT_PATH,size):
            found=row
        ordinal=get(w,row+16)
    return found

def under_root(w:mutbuf) -> bool:
    size=get(w,H_C_ROOT_CANONICAL_N)
    candidate=get(w,H_C_CANONICAL_N)
    if size>candidate or equal(w,H_C_CANONICAL,H_C_ROOT_CANONICAL,size)==False:
        return False
    return size==candidate or size==1 or byte(w,H_C_CANONICAL+size)==47
'''
def source():
    return authored(ast.unparse(ast.parse(SOURCE)),text={'roots':'hia-http-workspace-roots','proc':'/proc/self/fd/','workspace_key':'controller_workspace_roots'},
        extra={'META_IN':int.from_bytes(b'HIAHMD01','little'),'META_OUT':int.from_bytes(b'HIAHMO01','little')})
def render():
    return render_assembly(document(source(),'mcp_http_context'))
if __name__=='__main__':
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/mcp_http_context.hepta'
    raw=render();p.write_text(raw);print(p.name,len(raw.encode()))
