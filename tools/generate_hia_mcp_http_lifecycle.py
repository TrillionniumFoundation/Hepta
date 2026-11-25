"""HTTP connection waiters, SSE keepalive and owned-session shutdown."""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_http_common import authored
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,0)
    result=get(w,8)
    if phase==0:
        put(w,H_L_MODE,0)
        put(w,H_L_SCAN,0)
        return next_connection(w)
    if phase==10:
        if get(w,CR_STATUS)==6 and free_available(w):
            return load_session(w,get(w,CR_SESSION),HTTP_LIFECYCLE,11)
        if get(w,CR_STATUS)==4 and get(w,CR_FLAGS)&256!=0 and get(w,H_NOW)>=get(w,CR_DEADLINE):
            return enter(w,HTTP_EVENTS,300)
        return enter(w,HTTP_LIFECYCLE,12)
    if phase==11:
        if get(w,SR_STATUS)!=1:
            end=text_not_found(w,H_OUTPUT)
            return respond_after(w,404,H_OUTPUT,end-H_OUTPUT,0,0,HTTP_LIFECYCLE,12)
        copy_state(w,CR_SDK,H_REQUEST_DESCRIPTOR,160)
        put(w,H_LEGACY,choose(get(w,CR_FLAGS)&32!=0,0,1))
        return enter(w,HTTP_POST,50)
    if phase==12:
        put(w,H_L_SCAN,get(w,H_L_SCAN)+1)
        return next_connection(w)
    if phase==20:
        put(w,H_L_SESSION_SCAN,0)
        return next_session(w)
    if phase==21:
        if get(w,SR_STATUS)==1 and get(w,H_NOW)>=get(w,SR_LAST_NS):
            age=get(w,H_NOW)-get(w,SR_LAST_NS)
            if (get(w,SR_INIT_DONE)==0 and age>=60000000000) or age>=300000000000:
                return end_session(w,22)
        return enter(w,HTTP_LIFECYCLE,22)
    if phase==22:
        put(w,H_L_SESSION_SCAN,get(w,H_L_SESSION_SCAN)+1)
        return next_session(w)
    if phase==900:
        put(w,H_STOP,1)
        put(w,H_READY,0)
        fd=get(w,H_LISTENER)
        put(w,H_LISTENER,NONE)
        if fd!=NONE:
            return call(o,w,901,3,fd,0,0,0,0,0,0)
        return enter(w,HTTP_LIFECYCLE,901)
    if phase==901:
        put(w,H_L_MODE,1)
        put(w,H_L_SESSION_SCAN,0)
        return next_session(w)
    if phase==902:
        if get(w,SR_STATUS)!=NONE and get(w,SR_PID)>1:
            return end_session(w,903)
        return enter(w,HTTP_LIFECYCLE,903)
    if phase==903:
        put(w,H_L_SESSION_SCAN,get(w,H_L_SESSION_SCAN)+1)
        return next_session(w)
    if phase==910:
        put(w,H_L_SCAN,0)
        return next_connection(w)
    if phase==911:
        if get(w,CR_STATUS)!=NONE:
            return close_conn_to(w,HTTP_LIFECYCLE,912)
        return enter(w,HTTP_LIFECYCLE,912)
    if phase==912:
        put(w,H_L_SCAN,get(w,H_L_SCAN)+1)
        return next_connection(w)
    if phase==990:
        return call(o,w,999,60,0,0,0,0,0,0,0)
    return 0

def next_connection(w:mutbuf) -> u32:
    index=get(w,H_L_SCAN)
    if index<get(w,H_CONN_COUNT):
        phase=choose(get(w,H_L_MODE)==1,911,10)
        return load_conn(w,index,HTTP_LIFECYCLE,phase)
    if get(w,H_L_MODE)==1:
        return enter(w,HTTP_LIFECYCLE,990)
    return enter(w,HTTP_LIFECYCLE,20)

def next_session(w:mutbuf) -> u32:
    index=get(w,H_L_SESSION_SCAN)
    if index<get(w,H_SESSION_COUNT):
        phase=choose(get(w,H_L_MODE)==1,902,21)
        return load_session(w,index,HTTP_LIFECYCLE,phase)
    if get(w,H_L_MODE)==1:
        return enter(w,HTTP_LIFECYCLE,910)
    return enter(w,HTTP_IO,3)

def end_session(w:mutbuf,phase:u64) -> u32:
    put(w,H_D_RETURN_MODULE,HTTP_LIFECYCLE)
    put(w,H_D_RETURN_PHASE,phase)
    return enter(w,HTTP_DELIVERY,900)

def free_available(w:mutbuf) -> bool:
    slot=0
    while slot<32:
        if get(w,task_row(slot))==0:
            return True
        slot=slot+1
    return False
'''
def source():
    return authored(ast.unparse(ast.parse(SOURCE)),text={'not_found':'Not Found: Session not found'})
def render():return render_assembly(document(source(),'mcp_http_lifecycle'))
if __name__=='__main__':
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/mcp_http_lifecycle.hepta'
    raw=render();p.write_text(raw);print(p.name,len(raw.encode()))
