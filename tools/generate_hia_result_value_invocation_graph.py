"""Lock-held preparation and custody for actual source-bound Value invocations."""

SOURCE=r'''
def invocation_graph(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=readword(s,8)
    phase=get(o,G_PHASE)
    if phase==0:
        zero(o,256,448)
        put(o,G_OP,op)
        put(w,16,0)
        if op>=94 and op<=96:
            return invocation_token(s,o,w)
        if op==85 or op==89 or op==90:
            return invocation_scoped(s,o,w)
        zero(o,7040,160)
        zero(o,7208,192)
        if get(o,7200)!=1:
            return done(o,6)
        put(o,G_PHASE,100)
    if get(o,G_PHASE)==100:
        if class_catalog(w)==False:
            return invocation_growth(o,w)
        status=invocation_validate(s,o,w)
        if status!=0:
            return invocation_finish(o,w,status)
        put(o,G_PHASE,101)
    if get(o,G_PHASE)==101:
        random=allocate(w,80)
        if random==0:
            return invocation_growth(o,w)
        put(o,G_RANDOM,random)
        put(o,G_RN,80)
        put(o,G_RUSED,0)
        put(o,G_PHASE,102)
        return 5
    if get(o,G_PHASE)==102:
        raw=get(o,G_FEEDBACK)
        if raw==MAX-3:
            return 5
        if raw==0 or raw>=18446744073709547521 or raw>80-get(o,G_RUSED):
            return invocation_finish(o,w,11)
        put(o,G_RUSED,get(o,G_RUSED)+raw)
        if get(o,G_RUSED)!=80:
            return 5
        put(o,G_PHASE,103)
    if get(o,G_PHASE)==103:
        if invocation_build(s,o,w)==False:
            return invocation_growth(o,w)
        put(o,G_WANT,get(o,7048))
        put(o,G_PHASE,104)
        return 6
    if get(o,G_PHASE)==104:
        address=get(o,G_FEEDBACK)
        if address==0 or address>=18446744073709547521:
            invocation_cancel(o,w)
            return invocation_finish(o,w,5)
        token=get(o,7056)
        put(w,token+80,address)
        put(w,token+88,get(o,7048))
        put(o,7040,address)
        return invocation_finish(o,w,0)
    return invocation_finish(o,w,11)

def invocation_finish(o:mutbuf,w:mutbuf,status:u64) -> u64:
    deallocate(w,get(o,G_RANDOM))
    put(o,G_RANDOM,0)
    put(o,2104,get(w,1104))
    return done(o,status)

def invocation_growth(o:mutbuf,w:mutbuf) -> u64:
    action=growth(o,w)
    if action==0:
        return invocation_finish(o,w,get(o,P_ERROR))
    return action

def invocation_optional(w:mutbuf,s:readbuf,at:u64) -> u64:
    if readword(s,at)==0 and readword(s,at+8)==0 and readword(s,at+16)==0:
        return get(w,128)
    return cap_lookup(w,readword(s,at),readword(s,at+8),readword(s,at+16))

def invocation_function(w:mutbuf,o:mutbuf,obj:u64) -> u64:
    status=callable_graph_owner(w,o,obj,False)
    if status!=0:
        return status
    kind=get(w,get(w,obj+24)+56)
    if kind<3 or kind>5:
        return 2
    if (get(o,2056)&(1<<kind))==0:
        return 6
    return 0

def invocation_validate(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    a=invocation_optional(w,s,24)
    b=invocation_optional(w,s,48)
    c=invocation_optional(w,s,72)
    if a==0 or b==0 or c==0:
        return 1
    none=get(w,128)
    put(o,7296,a)
    put(o,7304,a)
    put(o,7312,none)
    put(o,7320,none)
    put(o,7328,none)
    put(o,7336,b)
    if op==68:
        if b!=none and get(w,b+8)!=4:
            return 2
        put(o,7296,none)
        put(o,7344,none)
        put(o,7048,65536+((length(s)-128+4095)&18446744073709547520))
        return 0
    status=invocation_function(w,o,a)
    if status!=0:
        return status
    data=get(w,a+24)
    copy_arena_to_output(w,o,7176,data+64,24)
    put(o,7304,get(w,data+16))
    if op==69:
        if b==none:
            return 2
        put(o,7312,b)
        put(o,7336,a)
        put(o,7344,a)
        put(o,7048,65536)
        return 0
    args=native_base(w,b)
    if get(w,args+8)!=11:
        return 2
    kwargs=native_base(w,c)
    if kwargs!=none and get(w,kwargs+8)!=6:
        return 2
    if kwargs!=none:
        i=0
        while i<get(w,kwargs+112):
            key=get(w,get(w,kwargs+24)+i*32)
            if key!=0 and get(w,native_base(w,key)+8)!=4:
                return 2
            i=i+1
    depth=0
    current=a
    while get(w,get(w,current+24)+56)==4:
        depth=depth+1
        if depth>get(w,104):
            return 11
        current=get(w,get(w,current+24)+136)
        if current==0:
            return 11
        status=invocation_function(w,o,current)
        if status!=0:
            return status
    put(o,7344,current)
    put(o,7352,depth)
    put(o,7304,get(w,get(w,current+24)+16))
    if depth!=0:
        put(o,7312,get(w,data+24))
    put(o,7320,args)
    put(o,7328,kwargs)
    put(o,7336,get(w,get(w,current+24)+136))
    put(o,7048,65536)
    return 0

def copy_arena_to_output(w:mutbuf,o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(w,at+i))
        i=i+1
    return 0

def invocation_tuple(w:mutbuf,n:u64) -> u64:
    if n>1152921504606846975:
        put(w,16,MAX)
        return 0
    obj=object_new(w,11)
    if obj==0:
        return 0
    data=allocate(w,choose(n==0,8,n*8))
    if data==0:
        object_unlink(w,obj)
        return 0
    zero(w,data,choose(n==0,8,n*8))
    put(w,obj+24,data)
    put(w,obj+16,n)
    put(w,obj+40,get(w,376))
    put(w,obj+48,28)
    put(w,obj+56,(obj^get(w,40))*11400714819323198485)
    edge_add(w,get(w,376))
    return obj

def invocation_tuple_put(w:mutbuf,obj:u64,index:u64,child:u64) -> u64:
    put(w,get(w,obj+24)+index*8,child)
    edge_add(w,child)
    return 0

def invocation_name(w:mutbuf) -> u64:
    obj=object_new(w,4)
    if obj==0:
        return 0
    data=allocate(w,2)
    if data==0:
        object_unlink(w,obj)
        return 0
    store(w,data,102)
    store(w,data+1,48)
    put(w,obj+24,data)
    put(w,obj+16,2)
    put(w,obj+32,2)
    put(w,obj+56,bytes_hash(w,data,2))
    return obj

def invocation_kwargs(w:mutbuf,source:u64) -> u64:
    obj=object_new(w,6)
    if obj==0:
        return 0
    if source==get(w,128):
        return obj
    i=0
    while i<get(w,source+112):
        at=get(w,source+24)+i*32
        key=get(w,at)
        if key!=0:
            if dict_reserve(w,obj)==False:
                object_release(w,obj)
                return 0
            dict_insert(w,obj,key,get(w,at+8))
        i=i+1
    return obj

def invocation_temps(o:mutbuf,w:mutbuf) -> u64:
    i=0
    while i<5:
        deallocate(w,get(o,7256+i*8))
        put(o,7256+i*8,0)
        i=i+1
    i=0
    while i<4:
        object_release(w,get(o,7224+i*8))
        put(o,7224+i*8,0)
        i=i+1
    return 0

def invocation_build(s:readbuf,o:mutbuf,w:mutbuf) -> bool:
    op=get(o,G_OP)
    none=get(w,128)
    if cap_reserve(w,5)==False:
        return False
    name=get(o,7336)
    if op==68 and name==none:
        name=invocation_name(w)
        if name==0:
            return False
        put(o,7240,name)
    arguments=get(o,7320)
    kwargs=get(o,7328)
    if op==70:
        original=arguments
        n=get(w,original+16)
        depth=get(o,7352)
        if depth>MAX-n:
            put(w,16,MAX)
            invocation_temps(o,w)
            return False
        arguments=invocation_tuple(w,n+depth)
        if arguments==0:
            invocation_temps(o,w)
            return False
        put(o,7224,arguments)
        current=get(o,7296)
        i=0
        while i<depth:
            data=get(w,current+24)
            invocation_tuple_put(w,arguments,depth-i-1,get(w,data+24))
            current=get(w,data+136)
            i=i+1
        i=0
        while i<n:
            invocation_tuple_put(w,arguments,depth+i,get(w,get(w,original+24)+i*8))
            i=i+1
        kwargs=invocation_kwargs(w,kwargs)
        if kwargs==0:
            invocation_temps(o,w)
            return False
        put(o,7232,kwargs)
    frame=invocation_tuple(w,6)
    if frame==0:
        invocation_temps(o,w)
        return False
    put(o,7248,frame)
    invocation_tuple_put(w,frame,0,get(o,7296))
    invocation_tuple_put(w,frame,1,get(o,7304))
    invocation_tuple_put(w,frame,2,get(o,7312))
    invocation_tuple_put(w,frame,3,arguments)
    invocation_tuple_put(w,frame,4,kwargs)
    invocation_tuple_put(w,frame,5,name)
    put(o,7224,0)
    put(o,7232,0)
    put(o,7240,0)
    i=0
    while i<5:
        obj=frame
        if i==1:
            obj=0
        elif i==2:
            obj=get(o,7304)
        elif i==3:
            obj=get(o,7312)
        elif i==4:
            obj=name
        random=get(o,G_RANDOM)+i*16
        cap=cap_new_unpublished(w,obj,get(w,random),get(w,random+8))
        if cap==0:
            invocation_temps(o,w)
            return False
        put(o,7256+i*8,cap)
        i=i+1
    i=0
    while i<5:
        cap=cap_publish(w,get(o,7256+i*8))
        at=7080
        if i==1:
            at=7056
        elif i>=2:
            at=7104+(i-2)*24
        put(o,at,cap)
        put(o,at+8,get(w,cap+16))
        put(o,at+16,get(w,cap+24))
        put(o,7256+i*8,0)
        i=i+1
    token=get(o,7056)
    put(w,token+40,1)
    put(w,token+64,get(w,1096))
    put(w,token+72,get(o,7080))
    put(w,1096,token)
    put(o,7248,0)
    return True

def invocation_unlink_token(w:mutbuf,token:u64) -> u64:
    current=get(w,1096)
    previous=0
    while current!=0 and current!=token:
        previous=current
        current=get(w,current+64)
    if current==0:
        return 11
    if previous==0:
        put(w,1096,get(w,current+64))
    else:
        put(w,previous+64,get(w,current+64))
    if get(w,token+40)!=1:
        put(w,1104,get(w,1104)-1)
    zero(w,token+40,8)
    zero(w,token+64,32)
    return 0

def invocation_cancel(o:mutbuf,w:mutbuf) -> u64:
    token=get(o,7056)
    invocation_unlink_token(w,token)
    i=0
    while i<3:
        cap_drop(w,get(o,7104+i*24))
        i=i+1
    cap_drop(w,get(o,7080))
    cap_drop(w,token)
    zero(o,7040,160)
    return 0

def invocation_find_frame(w:mutbuf,framecap:u64) -> u64:
    token=get(w,1096)
    while token!=0:
        if get(w,token+72)==framecap:
            return token
        token=get(w,token+64)
    return 0

def invocation_scoped(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    at=choose(op==85,48,24)
    node=cap_lookup_node(w,readword(s,at),readword(s,at+8),readword(s,at+16))
    if node==0 or invocation_find_frame(w,node)==0:
        return done(o,1)
    frame=get(w,node+8)
    if frame==0 or get(w,frame+8)!=11 or get(w,frame+16)!=6:
        return done(o,11)
    if op==85:
        value=cap_lookup(w,readword(s,24),readword(s,32),readword(s,40))
        if value==0:
            return done(o,1)
        if readword(s,104)==2:
            if get(w,value+8)!=8:
                return done(o,2)
            cls=get(w,get(w,value+24)+40)
            if cls==0 or class_is_subclass(w,cls,get(w,320))==False:
                return done(o,2)
        put(o,G_A,value)
        put(o,G_PHASE,1)
        return 10
    owner=get(w,get(w,frame+24))
    status=callable_graph_owner(w,o,owner,False)
    if status!=0:
        return done(o,status)
    if op==90 and readword(s,48)==0 and readword(s,56)==0 and readword(s,64)==0:
        current=get(w,owner+112)
        while current!=0:
            next=get(w,current+64)
            if get(w,current+80)==node and get(w,current+88)==frame:
                cap_drop(w,current)
            current=next
        put(o,P_DROP_CONSUMED,1)
        put(o,2008,get(w,1056))
        return done(o,0)
    cap=cap_lookup_node(w,readword(s,48),readword(s,56),readword(s,64))
    if cap==0 or cap==node or get(w,cap+8)==0:
        return done(o,1)
    if op==89:
        if get(w,cap+40)==owner and get(w,cap+80)==node and get(w,cap+88)==frame:
            put(o,P_DROP_CONSUMED,1)
            return done(o,0)
        if get(w,cap+40)!=0 or get(w,cap+80)!=0 or get(w,cap+88)!=0:
            return done(o,6)
        cap_adopt(w,cap,owner)
        put(w,cap+80,node)
        put(w,cap+88,frame)
    else:
        if get(w,cap+40)!=owner or get(w,cap+80)!=node or get(w,cap+88)!=frame:
            return done(o,6)
        cap_drop(w,cap)
    put(o,P_DROP_CONSUMED,1)
    put(o,2008,get(w,1056))
    return done(o,0)

def invocation_token(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=get(o,G_OP)
    if op==94:
        token=get(w,1096)
        while token!=0 and get(w,token+40)!=2:
            token=get(w,token+64)
        if token!=0:
            put(w,token+40,3)
            put(o,G_CAP,token)
            put(o,G_TAG0,get(w,token+16))
            put(o,G_TAG1,get(w,token+24))
            put(o,G_N,get(w,token+80))
            put(o,G_BYTES,get(w,token+88))
        put(o,2104,get(w,1104))
        return done(o,0)
    token=cap_lookup_node(w,readword(s,24),readword(s,32),readword(s,40))
    if token==0 or get(w,token+8)!=0 or get(w,token+40)<1 or get(w,token+40)>3:
        return done(o,1)
    if op==95:
        if get(w,token+40)==1:
            put(w,1104,get(w,1104)+1)
        put(w,token+40,2)
    else:
        frame=get(w,token+72)
        status=invocation_unlink_token(w,token)
        if status!=0:
            return done(o,status)
        cap_drop(w,frame)
        cap_drop(w,token)
    put(o,P_DROP_CONSUMED,1)
    put(o,2008,get(w,1056))
    put(o,2104,get(w,1104))
    return done(o,0)
'''
