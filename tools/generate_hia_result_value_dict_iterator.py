"""Live native dict iterators; next reads the current value under the value mutex."""
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve
SOURCE=r'''
def result_value_dict_iterator(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,G_PHASE)
    if phase==0:
        return iterator_prepare(s,o,w)
    if phase==10:
        count=get(o,G_COUNT)
        random=allocate(w,count*16)
        if random==0:
            return growth(o,w)
        put(o,G_RANDOM,random)
        put(o,G_RN,count*16)
        put(o,G_RUSED,0)
        put(o,G_PHASE,11)
        return 5
    if phase==11:
        n=get(o,G_FEEDBACK)
        if n==MAX-3:
            return 5
        if n==0 or n>=18446744073709547521 or n>get(o,G_RN)-get(o,G_RUSED):
            return iterator_done(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+n)
        if get(o,G_RUSED)!=get(o,G_RN):
            return 5
        put(o,G_PHASE,20)
    if get(o,G_PHASE)==20:
        result=0
        if get(o,G_OP)==27:
            result=iterator_create(s,o,w)
        else:
            result=iterator_next(o,w)
        if result==1 or result==10:
            return result
        return iterator_done(o,w,get(o,P_ERROR))
    return iterator_done(o,w,11)

def iterator_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    put(w,16,0)
    op=readword(s,8)
    put(o,G_OP,op)
    if op!=27 and op!=28:
        return done(o,7)
    if get(w,112)>=4096:
        collect(w)
    put(w,112,get(w,112)+1)
    obj=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
    if obj==0:
        return done(o,1)
    put(o,G_A,obj)
    if op==27:
        if get(w,obj+8)!=6:
            return done(o,2)
        if readword(s,104)>2:
            return done(o,7)
        put(o,G_COUNT,1)
        put(o,G_PHASE,10)
        return 10
    if get(w,obj+8)!=9:
        return done(o,2)
    object_kind_size(o,w,obj)
    put(o,G_N,0)
    put(o,G_BYTES,0)
    data=get(w,obj+24)
    state=get(w,data+40)
    if state==2:
        return done(o,0)
    if state==1:
        return done(o,14)
    if state!=0 or get(w,data)==0:
        return done(o,11)
    dict=get(w,data)
    if get(w,dict+8)!=6:
        return done(o,11)
    if get(w,data+8)!=get(w,dict+16):
        put(w,data+40,1)
        return done(o,14)
    pos=get(w,data+16)
    count=get(w,dict+112)
    entries=get(w,dict+24)
    while pos<count and get(w,entries+pos*32)==0:
        pos=pos+1
    if pos==count or pos>count:
        return iterator_exhaust(o,w,obj,0)
    if get(w,data+24)==0:
        return iterator_exhaust(o,w,obj,15)
    mode=get(w,data+32)
    if mode>2:
        return done(o,11)
    put(o,G_FOUND,pos)
    put(o,G_B,get(w,entries+pos*32))
    put(o,G_C,get(w,entries+pos*32+8))
    put(o,G_MODE,mode)
    put(o,G_PLAN,1)
    put(o,G_REQUIRED,8256)
    if length(o)<8256:
        return done(o,13)
    put(o,G_COUNT,choose(mode==1,2,1))
    put(o,G_PHASE,10)
    return 10

def iterator_done(o:mutbuf,w:mutbuf,status:u64) -> u64:
    deallocate(w,get(o,G_RANDOM))
    put(o,G_RANDOM,0)
    return done(o,status)

def iterator_exhaust(o:mutbuf,w:mutbuf,obj:u64,status:u64) -> u64:
    data=get(w,obj+24)
    dict=get(w,data)
    put(w,data,0)
    put(w,data+40,2)
    edge_drop(w,dict)
    put(o,G_PLAN,0)
    return done(o,status)

def iterator_publish_one(o:mutbuf,w:mutbuf,obj:u64) -> u64:
    if cap_reserve(w,1)==False:
        return 1
    random=get(o,G_RANDOM)
    t0=get(w,random)
    t1=get(w,random+8)
    cap=cap_new_unpublished(w,obj,t0,t1)
    if cap==0:
        return 1
    cap_publish(w,cap)
    put(o,G_CAP,cap)
    put(o,G_TAG0,t0)
    put(o,G_TAG1,t1)
    object_kind_size(o,w,obj)
    put(o,G_N,0)
    put(o,G_BYTES,0)
    return 0

def iterator_create(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if cap_reserve(w,1)==False:
        return growth(o,w)
    obj=object_new(w,9)
    if obj==0:
        return growth(o,w)
    data=allocate(w,64)
    if data==0:
        object_release(w,obj)
        return growth(o,w)
    zero(w,data,64)
    dict=get(o,G_A)
    put(w,data,dict)
    put(w,data+8,get(w,dict+16))
    put(w,data+24,get(w,dict+16))
    put(w,data+32,readword(s,104))
    put(w,obj+24,data)
    put(w,obj+32,64)
    random=get(o,G_RANDOM)
    put(w,obj+56,(obj^get(w,random)^get(w,random+8))*11400714819323198485)
    edge_add(w,dict)
    if iterator_publish_one(o,w,obj)!=0:
        object_release(w,obj)
        return growth(o,w)
    return done(o,0)

def iterator_clone(o:mutbuf,w:mutbuf,obj:u64,index:u64,head:u64,out:u64) -> u64:
    random=get(o,G_RANDOM)+index*16
    t0=get(w,random)
    t1=get(w,random+8)
    cap=cap_new_unpublished(w,obj,t0,t1)
    if cap==0:
        return 0
    put(w,cap+72,head)
    put(o,out,cap)
    put(o,out+8,t0)
    put(o,out+16,t1)
    return cap

def iterator_rollback(w:mutbuf,head:u64) -> u64:
    while head!=0:
        next=get(w,head+72)
        deallocate(w,head)
        head=next
    return 0

def iterator_next(o:mutbuf,w:mutbuf) -> u64:
    if cap_reserve(w,get(o,G_COUNT))==False:
        return growth(o,w)
    mode=get(o,G_MODE)
    zero(o,8192,64)
    put(o,8192,get(o,G_FOUND))
    selected=get(o,G_B)
    if mode!=0:
        selected=get(o,G_C)
    put(o,8200,get(w,selected+8))
    head=0
    index=0
    if mode!=2:
        head=iterator_clone(o,w,get(o,G_B),index,head,8208)
        if head==0:
            return growth(o,w)
        index=index+1
    if mode!=0:
        value=iterator_clone(o,w,get(o,G_C),index,head,8232)
        if value==0:
            iterator_rollback(w,head)
            return growth(o,w)
        head=value
    while head!=0:
        next=get(w,head+72)
        cap_publish(w,head)
        head=next
    data=get(w,get(o,G_A)+24)
    put(w,data+16,get(o,G_FOUND)+1)
    put(w,data+24,get(w,data+24)-1)
    return done(o,0)
'''
def source_program():return resolve('result_value_dict_iterator',SOURCE)
def program():return document(source_program(),'result_value_dict_iterator')
if __name__=='__main__':
    tree=program();p=ROOT/'examples/hia_bootstrap/result_value_dict_iterator.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
