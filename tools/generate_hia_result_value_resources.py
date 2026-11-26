"""Native owner-bound resources, real inherited values and generation identity.
Q05 is a separate private lifecycle. Its binding is captured by the sole owner.
"""
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve
from tools.generate_hia_result_value_core import SOURCE as CORE
from tools.generate_hia_result_value_classes import SOURCE as CLASSES,catalog_source
from tools.generate_hia_result_value_records import SOURCE as RECORDS
from tools.generate_hia_result_value_information import SOURCE as INFORMATION

SOURCE=r'''
def result_value_resources(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(o,1800)!=0:
        return information_child_step(o,w)
    phase=get(o,G_PHASE)
    if phase==60:
        return resources_information_prepare(s,o,w)
    if phase==0:
        return resources_prepare(s,o,w)
    if phase==1:
        if class_catalog(w)==False:
            return resources_growth(o,w)
        put(o,G_PHASE,10)
    if get(o,G_PHASE)==10:
        random=allocate(w,16)
        if random==0:
            return resources_growth(o,w)
        put(o,G_RANDOM,random)
        put(o,G_RN,16)
        put(o,G_RUSED,0)
        put(o,G_PHASE,11)
        return 5
    if get(o,G_PHASE)==11:
        raw=get(o,G_FEEDBACK)
        if raw==MAX-3:
            return 5
        if raw==0 or raw>=18446744073709547521 or raw>16-get(o,G_RUSED):
            return resources_finish(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+raw)
        if get(o,G_RUSED)!=16:
            return 5
        put(o,G_PHASE,20)
    if get(o,G_PHASE)==20:
        return resources_execute(s,o,w)
    return resources_finish(o,w,11)

def resources_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    zero(o,256,448)
    zero(o,768,128)
    put(w,16,0)
    op=readword(s,8)
    put(o,G_OP,op)
    if op==51 or op==52:
        put(o,G_N,get(w,88))
        put(o,G_INDEX,get(w,1056))
        put(o,G_PLAN,get(o,1968))
        if op==52 and (get(w,88)!=0 or get(w,1056)!=0 or get(o,1968)!=1):
            return done(o,6)
        return done(o,0)
    if op==58:
        return resources_claim(o,w)
    if op==59:
        return resources_ack(s,o,w)
    if op==53 or op==56:
        return done(o,0)
    if op==57:
        put(o,G_PHASE,1)
        return 10
    if op==60:
        put(o,G_PHASE,60)
        return 10
    a=0
    if readword(s,24)!=0 or readword(s,32)!=0 or readword(s,40)!=0:
        a=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if a==0:
            return done(o,1)
    elif op!=48:
        return done(o,1)
    put(o,G_A,a)
    if op==49:
        if native_resource(w,a)==False:
            return done(o,2)
        data=get(w,a+24)
        if get(w,data+112)!=get(o,1960) or get(w,data+88)!=0:
            return done(o,6)
        kind=get(w,data+56)
        if readword(s,104)!=0 and readword(s,104)!=kind:
            return done(o,2)
        put(o,G_KIND,kind)
        put(o,G_CAP,get(w,data+64))
        put(o,G_TAG0,get(w,data+72))
        put(o,G_TAG1,get(w,data+80))
        return done(o,0)
    if op==48 or op==50:
        i=0
        while i<2:
            at=48+i*24
            child=0
            if readword(s,at)!=0 or readword(s,at+8)!=0 or readword(s,at+16)!=0:
                child=cap_lookup(w,readword(s,at),readword(s,at+8),readword(s,at+16))
                if child==0:
                    return done(o,1)
            put(o,G_B+i*8,child)
            i=i+1
        if op==48:
            if get(o,1952)!=1 or get(o,1960)==0:
                return done(o,6)
            if (get(o,2056)&(1<<readword(s,104)))==0:
                return done(o,6)
            if readword(s,104)==4 and get(o,G_C)==0:
                return done(o,2)
        else:
            if get(w,a+8)!=10:
                return done(o,2)
            if get(w,get(w,a+24)+40)!=0:
                return done(o,18)
            layout=get(w,get(w,a+24)+32)
            base=get(o,G_C)
            kind=get(w,base+8)
            wanted=resources_base_kind(layout)
            if wanted==MAX or (wanted!=0 and (base==0 or kind!=wanted)) or (wanted==0 and base!=0):
                return done(o,2)
    if op==54 or op==55:
        if get(o,1952)!=1 or (readword(s,104)==0 and readword(s,112)==0):
            return done(o,6)
        generation=a
        if op==55:
            if get(w,a+8)!=12 or get(w,a+48)!=30:
                return done(o,2)
            generation=get(w,get(w,a+24))
        if get(w,generation+8)!=2:
            return done(o,2)
        put(o,G_B,generation)
    if get(w,112)>=4096:
        collect(w)
    put(w,112,get(w,112)+1)
    put(o,G_PHASE,1)
    return 10

def resources_base_kind(layout:u64) -> u64:
    if layout==0:
        return 0
    if layout==3:
        return 2
    if layout==5:
        return 3
    if layout==6:
        return 4
    if layout==7:
        return 7
    if layout==8:
        return 5
    if layout==9:
        return 6
    if layout==28:
        return 11
    return MAX

def resources_copy_dict(w:mutbuf,base:u64) -> u64:
    obj=object_new(w,6)
    if obj==0:
        return 0
    i=0
    while i<get(w,base+112):
        at=get(w,base+24)+i*32
        key=get(w,at)
        if key!=0:
            if dict_reserve(w,obj)==False:
                object_release(w,obj)
                return 0
            dict_insert(w,obj,key,get(w,at+8))
        i=i+1
    return obj

def resources_create(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    resource=get(o,G_OP)==48
    cls=get(o,G_A)
    base=get(o,G_C)
    env=get(o,G_B)
    bound=0
    kind=0
    layout=0
    ownbase=False
    if resource:
        kind=readword(s,104)
        id=choose(kind==1,20,29+kind)
        cls=get(w,160+(id-1)*8)
        env=get(o,G_A)
        base=get(o,G_B)
        bound=get(o,G_C)
    else:
        layout=get(w,get(w,cls+24)+32)
        if layout==8:
            base=class_clone_list(w,get(w,base+24),0,get(w,base+16))
            ownbase=True
        elif layout==9:
            base=resources_copy_dict(w,base)
            ownbase=True
        if ownbase and base==0:
            return resources_growth(o,w)
    if env==0:
        env=get(w,128)
    obj=object_new(w,8)
    if obj==0:
        if ownbase:
            object_release(w,base)
        return resources_growth(o,w)
    data=allocate(w,choose(resource,144,64))
    if data==0:
        object_unlink(w,obj)
        if ownbase:
            object_release(w,base)
        return resources_growth(o,w)
    zero(w,data,choose(resource,144,64))
    put(w,obj+24,data)
    put(w,data+8,choose(resource,0,resources_base_kind(layout)))
    put(w,data+16,env)
    put(w,data+24,base)
    put(w,data+32,choose(resource,get(w,get(w,cls+24)),bound))
    put(w,data+40,cls)
    if resource==False and base!=0:
        put(w,obj+16,get(w,base+16))
        put(w,obj+32,get(w,base+32))
        put(w,obj+56,get(w,base+56))
    else:
        put(w,obj+56,(obj^get(w,get(o,G_RANDOM)))*11400714819323198485)
    if resource:
        put(w,data+56,kind)
        put(w,data+64,readword(s,128))
        put(w,data+72,readword(s,136))
        put(w,data+80,readword(s,144))
        put(w,data+112,get(o,1960))
        put(w,data+120,get(w,get(o,G_RANDOM)))
        put(w,data+128,get(w,get(o,G_RANDOM)+8))
        put(w,data+136,bound)
    if publish_one(o,w,obj)!=0:
        object_unlink(w,obj)
        if ownbase:
            object_release(w,base)
        return resources_growth(o,w)
    class_links(w,obj)
    if resource:
        put(w,data+48,3544424519840123208)
        put(o,P_DROP_CONSUMED,1)
    return resources_finish(o,w,0)

def resources_find_info(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    entry=get(w,1032)
    while entry!=0:
        if get(w,entry+8)==readword(s,104) and get(w,entry+16)==readword(s,112):
            obj=get(w,entry)
            generation=get(w,get(w,obj+24))
            if key_equal(w,generation,get(o,G_B)):
                return obj
        entry=get(w,entry+32)
    return 0

def resources_info(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    obj=resources_find_info(s,o,w)
    entry=0
    if obj==0:
        if get(o,G_OP)==54:
            return resources_finish(o,w,3)
        obj=get(o,G_A)
        if get(w,obj+112)!=0:
            return resources_finish(o,w,2)
        entry=allocate(w,64)
        if entry==0:
            return resources_growth(o,w)
    if publish_one(o,w,obj)!=0:
        deallocate(w,entry)
        return resources_growth(o,w)
    if entry!=0:
        zero(w,entry,64)
        put(w,entry,obj)
        put(w,entry+8,readword(s,104))
        put(w,entry+16,readword(s,112))
        next=get(w,1032)
        put(w,entry+32,next)
        if next!=0:
            put(w,next+24,entry)
        put(w,1032,entry)
        put(w,obj+112,entry)
    return resources_finish(o,w,0)

def resources_execute(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    if op==48 or op==50:
        return resources_create(s,o,w)
    if op==60:
        return resources_information(s,o,w)
    if op==54 or op==55:
        return resources_info(s,o,w)
    if op==57:
        obj=get(w,160+(readword(s,104)-1)*8)
        if publish_one(o,w,obj)!=0:
            return resources_growth(o,w)
        return resources_finish(o,w,0)
    return resources_finish(o,w,11)

def resources_claim(o:mutbuf,w:mutbuf) -> u64:
    zero(o,4096,256)
    put(o,1992,0)
    put(o,2008,get(w,1056))
    obj=get(w,1040)
    while obj!=0:
        data=get(w,obj+24)
        state=get(w,data+88)
        if state==1 or state==3:
            put(o,1992,obj)
            put(o,4096,3553698900420413768)
            put(o,4104,choose(state==3,1,0))
            put(o,4112,get(w,data+112))
            put(o,4120,get(w,data+56))
            put(o,4128,get(w,data+64))
            put(o,4136,get(w,data+72))
            put(o,4144,get(w,data+80))
            put(o,2024,state)
            put(w,data+88,2)
            return done(o,0)
        obj=get(w,data+96)
    return done(o,0)

def resources_ack(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,1992)
    if obj==0 or native_resource(w,obj)==False:
        return done(o,11)
    data=get(w,obj+24)
    if get(w,data+88)!=2:
        return done(o,11)
    rc=get(o,2032)
    valid=rc==0 and get(o,4224)==3553980375397124424
    status=get(o,4232)
    known=get(o,4240)
    consumed=get(o,4248)
    pending=get(o,4256)
    if known>1 or consumed>1 or pending>1 or known==0:
        valid=False
    at=4296
    while at<4352:
        if get(o,at)!=0:
            valid=False
        at=at+8
    if status==0 and (pending!=0 or (consumed==0 and get(o,2024)!=3)):
        valid=False
    if valid==False:
        put(w,data+88,4)
        put(o,2008,get(w,1056))
        return done(o,11)
    if (consumed==1 or get(o,2024)==3) and pending==0 and status==0:
        resource_remove(w,obj)
        put(w,data+48,0)
        edge_drop(w,obj)
        collect(w)
        put(o,1992,0)
        put(o,2008,get(w,1056))
        return done(o,0)
    if consumed==1:
        put(w,data+88,choose(pending==1,3,4))
    elif get(o,2024)==3:
        put(w,data+88,choose(pending==1,3,4))
    else:
        put(w,data+88,1)
    put(o,2008,get(w,1056))
    return done(o,11)

def resources_finish(o:mutbuf,w:mutbuf,status:u64) -> u64:
    if get(o,2208)!=0:
        cap_drop(w,get(o,2208))
        put(o,2208,0)
    else:
        object_release(w,get(o,1920))
    put(o,1920,0)
    i=0
    while i<3:
        offset=1832
        if i==1:
            offset=1936
        elif i==2:
            offset=1944
        if get(o,offset)!=0:
            cap_drop(w,get(o,offset))
            put(o,offset,0)
        i=i+1
    deallocate(w,get(o,1816))
    put(o,1816,0)
    put(o,1800,0)
    return class_finish(o,w,status)

def resources_growth(o:mutbuf,w:mutbuf) -> u64:
    action=growth(o,w)
    if action==0:
        return resources_finish(o,w,get(o,P_ERROR))
    return action

'''
def source_program():
    return resolve('result_value_resources',SOURCE+'\n'+INFORMATION+'\n'+RECORDS+'\n'+CLASSES+'\n'+catalog_source()+'\n'+CORE)
def program():return document(source_program(),'result_value_resources')
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/result_value_resources.hepta'
    p.write_text(render_assembly(program()))
    print(p.name,p.stat().st_size,flush=True)
