"""Trusted runtime/generation strong Info edges over actual captured snapshots."""
SOURCE=r'''
def resources_info_identity(s:readbuf,w:mutbuf,info:u64) -> u64:
    weak=get(w,info+112)
    if weak==0:
        return 2
    if get(w,weak)!=info or get(w,weak+8)!=readword(s,104) or get(w,weak+16)!=readword(s,112):
        return 6
    return 0

def resources_runtime_cache_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    source=get(o,G_A)
    if native_resource(w,source)==False:
        return done(o,2)
    data=get(w,source+24)
    if get(w,data+112)!=get(o,1960) or get(w,data+88)!=0:
        return done(o,6)
    kind=get(w,data+56)
    runtime=source
    if kind==2:
        runtime=get(w,data+16)
    elif kind!=1:
        return done(o,2)
    if native_resource(w,runtime)==False:
        return done(o,2)
    data=get(w,runtime+24)
    if get(w,data+56)!=1 or get(w,data+112)!=get(o,1960) or get(w,data+88)!=0:
        return done(o,6)
    info=0
    if readword(s,48)!=0 or readword(s,56)!=0 or readword(s,64)!=0:
        info=cap_lookup(w,readword(s,48),readword(s,56),readword(s,64))
        if info==0:
            return done(o,1)
        if get(w,info+8)!=12 or get(w,info+48)!=30:
            return done(o,2)
        error=resources_info_identity(s,w,info)
        if error!=0:
            return done(o,error)
    cached=get(w,data+24)
    if cached==0 or cached==get(w,128):
        cached=0
        if info==0:
            return done(o,0)
    else:
        if get(w,cached+8)!=11 or get(w,cached+16)!=2:
            return done(o,11)
        abi=get(w,get(w,cached+24))
        infos=get(w,get(w,cached+24)+8)
        if get(w,abi+8)!=11 or get(w,infos+8)!=11 or get(w,infos+16)>64:
            return done(o,11)
        error=resources_info_identity(s,w,abi)
        if error!=0:
            return done(o,error)
        if info!=0 and get(w,get(w,info+24)+40)!=abi:
            return done(o,6)
    put(o,2224,runtime)
    put(o,2232,info)
    put(o,2240,cached)
    put(o,G_PHASE,66)
    return 10

def resources_runtime_cache_import(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    n=readword(s,96)
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
        store(w,buf+128+i,byte(s,128+i))
        i=i+1
    put(o,1816,buf)
    put(o,1824,n+128)
    put(o,1928,4)
    put(o,G_PHASE,0)
    return information_child_call(o,w)

def resources_cache_live(o:mutbuf,w:mutbuf,live:u64,generation:u64) -> bool:
    i=0
    while i<get(w,live+16):
        row=get(w,get(w,live+24)+i*8)
        item=information_find(o,w,row,0)
        if key_equal(w,item,generation):
            return True
        i=i+1
    return False

def resources_runtime_cache_commit(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    live=information_find(o,w,get(o,1840),15)
    if live==0 or get(w,live+8)!=5 or get(w,live+16)>64:
        return resources_finish(o,w,2)
    i=0
    while i<get(w,live+16):
        row=get(w,get(w,live+24)+i*8)
        generation=information_find(o,w,row,0)
        if generation==0 or get(w,generation+8)!=2 or byte(w,get(w,generation+24))==45:
            return resources_finish(o,w,2)
        j=0
        while j<i:
            prior=information_find(o,w,get(w,get(w,live+24)+j*8),0)
            if key_equal(w,generation,prior):
                return resources_finish(o,w,2)
            j=j+1
        i=i+1
    info=get(o,2232)
    cached=get(o,2240)
    abi=0
    previous=0
    if cached!=0:
        abi=get(w,get(w,cached+24))
        previous=get(w,get(w,cached+24)+8)
    else:
        abi=get(w,get(w,info+24)+40)
    count=0
    add=False
    if info!=0:
        add=resources_cache_live(o,w,live,get(w,get(w,info+24)))
    i=0
    n=choose(previous==0,0,get(w,previous+16))
    while i<n:
        item=get(w,get(w,previous+24)+i*8)
        if get(w,item+8)!=12 or get(w,item+48)!=30:
            return resources_finish(o,w,11)
        error=resources_info_identity(s,w,item)
        if error!=0:
            return resources_finish(o,w,error)
        generation=get(w,get(w,item+24))
        if resources_cache_live(o,w,live,generation):
            count=count+1
            if info!=0:
                if key_equal(w,generation,get(w,get(w,info+24))):
                    if item!=info:
                        return resources_finish(o,w,6)
                    add=False
        i=i+1
    count=count+choose(add,1,0)
    if count>64:
        return resources_finish(o,w,11)
    infos=0
    if count==0:
        infos=get(w,1024)
    if infos==0:
        infos=information_blank(w,11,28,count)
        if infos==0:
            return resources_growth(o,w)
        if count==0:
            put(w,1024,infos)
            edge_add(w,infos)
    i=0
    index=0
    while i<n:
        item=get(w,get(w,previous+24)+i*8)
        if resources_cache_live(o,w,live,get(w,get(w,item+24))):
            information_set(w,infos,index,item)
            index=index+1
        i=i+1
    if add:
        information_set(w,infos,index,info)
    replacement=information_blank(w,11,28,2)
    if replacement==0:
        object_release(w,infos)
        return resources_growth(o,w)
    information_set(w,replacement,0,abi)
    information_set(w,replacement,1,infos)
    runtime=get(o,2224)
    data=get(w,runtime+24)
    old=get(w,data+24)
    edge_add(w,replacement)
    put(w,data+24,replacement)
    if old!=0:
        edge_drop(w,old)
    return resources_finish(o,w,0)
'''
