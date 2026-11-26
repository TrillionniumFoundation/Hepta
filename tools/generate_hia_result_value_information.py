"""Trusted actual-generation capture into the shared native Value graph.

These are HIA source helpers reached only by the owner-bound Q05 information
operation. No Python object, JSON decoder or callback runs in the native image.
"""
SOURCE=r'''
def resources_information_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    n=readword(s,152)
    if n>MAX-128:
        return resources_finish(o,w,5)
    buf=allocate(w,n+128)
    if buf==0:
        return resources_growth(o,w)
    zero(w,buf,128)
    put(w,buf,MAGIC)
    put(w,buf+8,1)
    put(w,buf+96,n)
    i=0
    while i<n:
        store(w,buf+128+i,byte(s,160+i))
        i=i+1
    put(o,1816,buf)
    put(o,1824,n+128)
    put(o,1928,0)
    put(o,G_PHASE,0)
    return information_child_call(o,w)

def information_child_call(o:mutbuf,w:mutbuf) -> u64:
    put(o,1800,1)
    id=choose(get(o,1928)==2,3,2)
    return role(o,id,1,get(o,1816),get(o,1824),3,0,length(o),1,0,length(w))

def information_child_step(o:mutbuf,w:mutbuf) -> u64:
    if get(o,1800)==2:
        return information_child_call(o,w)
    action=get(o,G_FEEDBACK)
    if action==0:
        status=get(o,P_ERROR)
        if status!=0:
            return resources_finish(o,w,status)
        cap=get(o,G_CAP)
        if cap==0:
            return resources_finish(o,w,11)
        if get(o,1928)==2:
            put(o,1944,cap)
            bytes=get(w,cap+8)
            if get(w,bytes+8)!=7 or get(o,1920)==0:
                return resources_finish(o,w,11)
            information_set(w,get(o,1920),11,bytes)
            put(o,1928,3)
        else:
            put(o,1832,cap)
            put(o,1840,get(w,cap+8))
            put(o,1928,choose(get(o,1928)==4,5,1))
        deallocate(w,get(o,1816))
        put(o,1816,0)
        put(o,1800,0)
        zero(o,256,448)
        put(o,G_OP,choose(get(o,1928)==5,66,60))
        if get(o,1928)==5:
            put(o,G_PHASE,20)
        else:
            put(o,G_PHASE,choose(get(o,1928)==3,10,1))
        return 10
    if action==10:
        return information_child_call(o,w)
    if action==4:
        if get(o,1928)==2:
            return resources_finish(o,w,11)
        copy(o,192,1856,64)
        select=get(o,P_SELECT)
        i=0
        while i<6:
            shift=i*3
            if ((select>>shift)&7)==2:
                select=(select&(MAX^(7<<shift)))|(1<<shift)
                put(o,P_ARG+i*8,get(o,P_ARG+i*8)+get(o,1816))
            i=i+1
        put(o,P_SELECT,select)
        put(o,1800,2)
        return 4
    if action==1 or action==5:
        put(o,1800,2)
        return action
    return resources_finish(o,w,11)

def information_find(o:mutbuf,w:mutbuf,obj:u64,index:u64) -> u64:
    if get(w,obj+8)!=6:
        return 0
    n=11
    if index==15:
        put(o,2176,7598805615236769127)
        put(o,2184,7564911)
    else:
        n=records_name(o,2176,index)
    i=0
    while i<get(w,obj+112):
        at=get(w,obj+24)+i*32
        key=get(w,at)
        if key!=0 and get(w,key+8)==4 and get(w,key+32)==n:
            k=0
            same=True
            while k<n:
                if byte(w,get(w,key+24)+k)!=byte(o,2176+k):
                    same=False
                k=k+1
            if same:
                return get(w,at+8)
        i=i+1
    return 0

def information_blank(w:mutbuf,kind:u64,id:u64,n:u64) -> u64:
    if n>1152921504606846975:
        put(w,16,MAX)
        return 0
    obj=object_new(w,kind)
    if obj==0:
        return 0
    data=allocate(w,choose(n==0,8,n*8))
    if data==0:
        object_unlink(w,obj)
        return 0
    zero(w,data,choose(n==0,8,n*8))
    put(w,obj+24,data)
    put(w,obj+16,n)
    put(w,obj+40,get(w,160+(id-1)*8))
    put(w,obj+48,id)
    put(w,obj+56,(obj^get(w,40))*11400714819323198485)
    edge_add(w,get(w,obj+40))
    return obj

def information_set(w:mutbuf,obj:u64,index:u64,child:u64) -> u64:
    put(w,get(w,obj+24)+index*8,child)
    edge_add(w,child)
    return 0

def information_parameters(w:mutbuf,source:u64) -> u64:
    n=get(w,source+16)
    if n==0 and get(w,1024)!=0:
        return get(w,1024)
    obj=information_blank(w,11,28,n)
    if obj==0:
        return 0
    i=0
    while i<n:
        information_set(w,obj,i,get(w,get(w,source+24)+i*8))
        i=i+1
    if n==0:
        put(w,1024,obj)
        edge_add(w,obj)
    return obj

def information_abi_valid(o:mutbuf,w:mutbuf,source:u64) -> bool:
    if get(w,source+8)!=5 or get(w,source+16)==0 or get(w,source+16)>16:
        return False
    i=0
    while i<get(w,source+16):
        row=get(w,get(w,source+24)+i*8)
        if get(w,row+8)!=6:
            return False
        function=information_find(o,w,row,12)
        parameters=information_find(o,w,row,13)
        result=information_find(o,w,row,14)
        if function==0 or result==0 or parameters==0:
            return False
        if get(w,function+8)!=4 or get(w,result+8)!=4 or get(w,parameters+8)!=5 or get(w,parameters+16)>16:
            return False
        j=0
        while j<get(w,parameters+16):
            if get(w,get(w,get(w,parameters+24)+j*8)+8)!=4:
                return False
            j=j+1
        i=i+1
    return True

def information_abi_build(o:mutbuf,w:mutbuf,source:u64) -> u64:
    obj=information_blank(w,11,28,get(w,source+16))
    if obj==0:
        return 0
    i=0
    while i<get(w,source+16):
        row=get(w,get(w,source+24)+i*8)
        parameters=information_parameters(w,information_find(o,w,row,13))
        if parameters==0:
            object_release(w,obj)
            return 0
        record=information_blank(w,12,29,3)
        if record==0:
            object_release(w,parameters)
            object_release(w,obj)
            return 0
        information_set(w,record,0,information_find(o,w,row,12))
        information_set(w,record,1,parameters)
        information_set(w,record,2,information_find(o,w,row,14))
        information_set(w,obj,i,record)
        i=i+1
    return obj

def information_abi_equal(w:mutbuf,a:u64,b:u64) -> bool:
    if get(w,a+16)!=get(w,b+16):
        return False
    i=0
    while i<get(w,a+16):
        x=get(w,get(w,a+24)+i*8)
        y=get(w,get(w,b+24)+i*8)
        if key_equal(w,get(w,get(w,x+24)),get(w,get(w,y+24)))==False:
            return False
        if key_equal(w,get(w,get(w,x+24)+16),get(w,get(w,y+24)+16))==False:
            return False
        xp=get(w,get(w,x+24)+8)
        yp=get(w,get(w,y+24)+8)
        if get(w,xp+16)!=get(w,yp+16):
            return False
        j=0
        while j<get(w,xp+16):
            if key_equal(w,get(w,get(w,xp+24)+j*8),get(w,get(w,yp+24)+j*8))==False:
                return False
            j=j+1
        i=i+1
    return True

def information_cache_find(s:readbuf,w:mutbuf,head:u64) -> u64:
    entry=get(w,head)
    while entry!=0:
        if get(w,entry+8)==readword(s,104) and get(w,entry+16)==readword(s,112):
            return get(w,entry)
        entry=get(w,entry+32)
    return 0

def information_cache_link(s:readbuf,w:mutbuf,entry:u64,obj:u64,head:u64) -> u64:
    zero(w,entry,64)
    put(w,entry,obj)
    put(w,entry+8,readword(s,104))
    put(w,entry+16,readword(s,112))
    put(w,entry+40,head)
    next=get(w,head)
    put(w,entry+32,next)
    if next!=0:
        put(w,next+24,entry)
    put(w,head,entry)
    put(w,obj+112,entry)
    return 0

def information_key_after(w:mutbuf,a:u64,b:u64) -> bool:
    an=get(w,a+32)
    bn=get(w,b+32)
    i=0
    while i<an and i<bn:
        av=byte(w,get(w,a+24)+i)
        bv=byte(w,get(w,b+24)+i)
        if av!=bv:
            return av>bv
        i=i+1
    return an>bn

def information_sort(w:mutbuf,obj:u64) -> bool:
    if get(w,obj+8)!=6 or get(w,obj+16)!=get(w,obj+112):
        return False
    data=get(w,obj+24)
    i=0
    while i<get(w,obj+112):
        key=get(w,data+i*32)
        if key==0 or get(w,key+8)!=4:
            return False
        k=0
        while k<get(w,key+32):
            if byte(w,get(w,key+24)+k)>127:
                return False
            k=k+1
        at=i
        while at>0 and information_key_after(w,get(w,data+(at-1)*32),get(w,data+at*32)):
            k=0
            while k<4:
                old=get(w,data+(at-1)*32+k*8)
                put(w,data+(at-1)*32+k*8,get(w,data+at*32+k*8))
                put(w,data+at*32+k*8,old)
                k=k+1
            at=at-1
        i=i+1
    dict_rehash(w,obj)
    return True

def information_sort_mapping(w:mutbuf,obj:u64) -> bool:
    if information_sort(w,obj)==False:
        return False
    i=0
    while i<get(w,obj+112):
        child=get(w,get(w,obj+24)+i*32+8)
        if get(w,child+8)==6:
            if information_sort(w,child)==False:
                return False
            j=0
            while j<get(w,child+112):
                row=get(w,get(w,child+24)+j*32+8)
                if get(w,row+8)!=6 or information_sort(w,row)==False:
                    return False
                k=0
                while k<get(w,row+112):
                    value=get(w,get(w,row+24)+k*32+8)
                    if get(w,value+8)!=2 and get(w,value+8)!=4:
                        return False
                    k=k+1
                j=j+1
        elif get(w,child+8)!=1 and get(w,child+8)!=2 and get(w,child+8)!=4:
            return False
        i=i+1
    return True

def information_reset(o:mutbuf,w:mutbuf) -> u64:
    if get(o,2208)!=0:
        cap_drop(w,get(o,2208))
        put(o,2208,0)
    else:
        object_release(w,get(o,1920))
    put(o,1920,0)
    if get(o,1936)!=0:
        cap_drop(w,get(o,1936))
        put(o,1936,0)
    deallocate(w,get(o,1816))
    put(o,1816,0)
    return 0

def information_build(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    root=get(o,1840)
    if get(w,root+8)!=6:
        return resources_finish(o,w,2)
    generation=information_find(o,w,root,0)
    if generation==0 or get(w,generation+8)!=2:
        return resources_finish(o,w,2)
    put(o,G_B,generation)
    prior=resources_find_info(s,o,w)
    if prior!=0:
        if publish_one(o,w,prior)!=0:
            return resources_growth(o,w)
        return resources_finish(o,w,0)
    abi=information_find(o,w,root,5)
    mapping=information_find(o,w,root,11)
    if abi==0 or mapping==0 or information_abi_valid(o,w,abi)==False or information_sort_mapping(w,mapping)==False:
        return resources_finish(o,w,2)
    i=0
    while i<11:
        if i!=5:
            child=information_find(o,w,root,i)
            kind=choose(i==1 or i==2 or i==3 or i==9,4,2)
            if i==8:
                kind=1
            if child==0 or get(w,child+8)!=kind:
                return resources_finish(o,w,2)
        i=i+1
    obj=information_blank(w,12,30,12)
    if obj==0:
        return resources_growth(o,w)
    put(o,1920,obj)
    if publish_one(o,w,obj)!=0:
        information_reset(o,w)
        return resources_growth(o,w)
    put(o,2208,get(o,G_CAP))
    i=0
    while i<11:
        if i!=5:
            information_set(w,obj,i,information_find(o,w,root,i))
        i=i+1
    typed=information_abi_build(o,w,abi)
    if typed==0:
        information_reset(o,w)
        return resources_growth(o,w)
    cached=information_cache_find(s,w,1064)
    if cached!=0:
        same=information_abi_equal(w,typed,cached)
        object_release(w,typed)
        if same==False:
            return resources_finish(o,w,11)
        typed=cached
    information_set(w,obj,5,typed)
    if cached==0:
        entry=allocate(w,64)
        if entry==0:
            information_reset(o,w)
            return resources_growth(o,w)
        information_cache_link(s,w,entry,typed,1064)
    buf=allocate(w,128)
    if buf==0:
        information_reset(o,w)
        return resources_growth(o,w)
    put(o,1816,buf)
    if publish_one(o,w,mapping)!=0:
        information_reset(o,w)
        return resources_growth(o,w)
    put(o,1936,get(o,G_CAP))
    zero(w,buf,128)
    put(w,buf,MAGIC)
    put(w,buf+8,18)
    put(w,buf+24,get(o,G_CAP))
    put(w,buf+32,get(o,G_TAG0))
    put(w,buf+40,get(o,G_TAG1))
    put(o,1824,128)
    deallocate(w,get(o,G_RANDOM))
    put(o,G_RANDOM,0)
    put(o,G_PHASE,0)
    put(o,1928,2)
    return information_child_call(o,w)

def information_publish(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    obj=get(o,1920)
    if obj==0:
        return resources_finish(o,w,11)
    entry=allocate(w,64)
    if entry==0:
        return resources_growth(o,w)
    cap=get(o,2208)
    if cap==0 or get(w,cap+8)!=obj:
        deallocate(w,entry)
        return resources_finish(o,w,11)
    information_cache_link(s,w,entry,obj,1032)
    object_kind_size(o,w,obj)
    put(o,G_CAP,cap)
    put(o,G_TAG0,get(w,cap+16))
    put(o,G_TAG1,get(w,cap+24))
    put(o,2208,0)
    put(o,1920,0)
    return resources_finish(o,w,0)

def resources_information(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if get(o,1928)==1:
        return information_build(s,o,w)
    if get(o,1928)==3:
        return information_publish(s,o,w)
    return resources_finish(o,w,11)
'''
