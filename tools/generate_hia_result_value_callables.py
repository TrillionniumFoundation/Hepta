"""Private native resource edges and actual weak identities for the unique Value arena."""
from tools.generate_hia_result_value_common import ROOT, document, render_assembly, resolve
from tools.generate_hia_result_value_core import SOURCE as CORE

SOURCE=r'''
def result_value_callables(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        return callable_graph_prepare(s,o,w)
    if phase==1:
        random=allocate(w,16)
        if random==0:
            return callable_graph_growth(o,w)
        put(o,G_RANDOM,random)
        put(o,G_RN,16)
        put(o,G_RUSED,0)
        put(o,G_PHASE,2)
        return 5
    if phase==2:
        result=get(o,G_FEEDBACK)
        if result==MAX-3:
            return 5
        if result==0 or result>=18446744073709547521 or result>16-get(o,G_RUSED):
            return callable_graph_finish(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+result)
        if get(o,G_RUSED)!=16:
            return 5
        put(o,G_PHASE,3)
    if get(o,G_PHASE)==3:
        obj=get(o,G_A)
        if publish_one(o,w,obj)!=0:
            return callable_graph_growth(o,w)
        if get(o,G_OP)==80:
            put(o,G_N,get(w,get(w,obj+24)+56))
        elif get(o,G_OP)==91:
            put(o,P_DROP_CONSUMED,1)
        return callable_graph_finish(o,w,0)
    return callable_graph_finish(o,w,11)

def callable_graph_finish(o:mutbuf,w:mutbuf,status:u64) -> u64:
    deallocate(w,get(o,G_RANDOM))
    put(o,G_RANDOM,0)
    put(o,2008,get(w,1056))
    return done(o,status)

def callable_graph_growth(o:mutbuf,w:mutbuf) -> u64:
    action=growth(o,w)
    if action==0:
        return callable_graph_finish(o,w,get(o,P_ERROR))
    return action

def callable_graph_owner(w:mutbuf,o:mutbuf,obj:u64,queued:bool) -> u64:
    if native_resource(w,obj)==False:
        return 2
    data=get(w,obj+24)
    if get(w,data+112)!=get(o,1960) or get(o,1952)!=1:
        return 6
    if queued==False and get(w,data+88)!=0:
        return 6
    return 0

def callable_graph_weak(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    mode=readword(s,104)
    obj=0
    if mode==0:
        obj=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if obj==0:
            return callable_graph_finish(o,w,1)
    else:
        cursor=get(w,96)
        while cursor!=0 and obj==0:
            if cursor==readword(s,24):
                obj=cursor
            cursor=get(w,cursor+88)
        if obj==0 or native_resource(w,obj)==False:
            return callable_graph_finish(o,w,3)
        data=get(w,obj+24)
        if get(w,data+120)!=readword(s,32) or get(w,data+128)!=readword(s,40):
            return callable_graph_finish(o,w,3)
    status=callable_graph_owner(w,o,obj,False)
    if status!=0:
        return callable_graph_finish(o,w,status)
    put(o,G_A,obj)
    data=get(w,obj+24)
    if mode==0:
        put(o,G_KIND,8)
        put(o,G_CAP,obj)
        put(o,G_TAG0,get(w,data+120))
        put(o,G_TAG1,get(w,data+128))
        put(o,G_N,get(w,data+56))
        put(o,G_ID0,obj)
        put(o,G_ID1,get(w,40))
        return callable_graph_finish(o,w,0)
    put(o,G_PHASE,1)
    return 10

def callable_graph_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    put(w,16,0)
    op=readword(s,8)
    put(o,G_OP,op)
    if op==80:
        return callable_graph_weak(s,o,w)
    if op==91:
        obj=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if obj==0:
            return callable_graph_finish(o,w,1)
        put(o,G_A,obj)
        put(o,G_PHASE,1)
        return 10
    if op==78 or op==92:
        node=cap_lookup_node(w,readword(s,24),readword(s,32),readword(s,40))
        if node==0 or (op==78 and get(w,node+8)==0) or (op==92 and get(w,node+8)!=0):
            return callable_graph_finish(o,w,1)
        cap_drop(w,node)
        put(o,P_DROP_CONSUMED,1)
        return callable_graph_finish(o,w,0)
    owner=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
    if owner==0:
        return callable_graph_finish(o,w,1)
    status=callable_graph_owner(w,o,owner,False)
    if status!=0:
        return callable_graph_finish(o,w,status)
    node=cap_lookup_node(w,readword(s,48),readword(s,56),readword(s,64))
    if node==0 or get(w,node+8)==0:
        return callable_graph_finish(o,w,1)
    if node==readword(s,24):
        return callable_graph_finish(o,w,2)
    current=get(w,node+40)
    if op==77:
        if current==owner:
            put(o,P_DROP_CONSUMED,1)
            return callable_graph_finish(o,w,0)
        if current!=0:
            return callable_graph_finish(o,w,6)
        cap_adopt(w,node,owner)
    elif op==79:
        if current!=owner:
            return callable_graph_finish(o,w,6)
        cap_managed_unlink(w,node)
        obj=get(w,node+8)
        put(w,obj+64,get(w,obj+64)+1)
    else:
        return callable_graph_finish(o,w,11)
    put(o,P_DROP_CONSUMED,1)
    return callable_graph_finish(o,w,0)
'''

def source_program():
    return resolve('result_value_callables', SOURCE+'\n'+CORE)

def program():
    return document(source_program(), 'result_value_callables')

if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/result_value_callables.hepta'
    path.write_text(render_assembly(program()))
    print(path.name,path.stat().st_size,flush=True)
