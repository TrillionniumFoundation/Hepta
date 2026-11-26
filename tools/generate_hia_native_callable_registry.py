"""Native metadata registry for actual compiled code and suspended invocations."""
from tools.generate_hia_native_callable_common import ROOT, document, render_assembly, source

SOURCE = r'''
def native_callable_registry(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op=get(o,NR_OP)
    if op==0:
        arena_extend(w,0)
        put(w,0,NC_ARENA)
        return 0
    if op==13:
        if get(w,0)!=NC_ARENA or get(w,8)!=get(o,NC_OLD):
            return 11
        arena_extend(w,get(o,NC_OLD))
        return 0
    if get(w,0)!=NC_ARENA or get(w,8)!=length(w):
        return 11
    put(w,16,0)
    if op==1:
        obj=code_object_new(w,1)
        if obj==0:
            return code_need(o,w)
        put(o,NR_OBJ,obj)
        return 0
    if op==10:
        token=code_lookup(s,w)
        if token==0:
            return 1
        parent=get(w,token+8)
        if get(w,parent+8)!=1 or get(w,parent+104)!=1:
            return 2
        obj=code_object_new(w,2)
        if obj==0:
            return code_need(o,w)
        put(w,parent+24,get(w,parent+24)+1)
        put(w,obj+96,parent)
        put(o,NR_OBJ,obj)
        return 0
    if op==2:
        obj=get(o,NR_OBJ)
        if code_object_valid(w,obj)==False:
            return 11
        field=get(o,NR_FIELD)
        if field==0:
            put(w,obj+32,get(o,NR_ADDRESS))
            put(w,obj+40,get(o,NR_EXTENT))
            put(w,obj+48,get(o,NR_LENGTH))
        elif field==1:
            put(w,obj+56,get(o,NR_ADDRESS))
            put(w,obj+64,get(o,NR_EXTENT))
            put(w,obj+72,get(o,NR_LENGTH))
        elif field==2:
            put(w,obj+80,get(o,NR_ADDRESS))
            put(w,obj+88,get(o,NR_EXTENT))
        else:
            return 11
        return 0
    if op==3:
        obj=get(o,NR_OBJ)
        if code_object_valid(w,obj)==False or get(w,obj+104)!=0 or get(w,obj+24)!=1:
            return 11
        if code_publish(o,w,obj)==False:
            return code_need(o,w)
        put(w,obj+104,1)
        put(w,obj+24,0)
        return 0
    if op==4:
        token=code_lookup(s,w)
        if token==0:
            return 1
        obj=get(w,token+8)
        if get(w,obj+104)!=1 and get(w,obj+104)!=2:
            return 2
        if code_publish(o,w,obj)==False:
            return code_need(o,w)
        return 0
    if op==5:
        token=code_lookup(s,w)
        if token==0:
            return 1
        obj=get(w,token+8)
        if get(o,NC_FINALIZER)!=0 and get(w,obj+8)!=1:
            return 2
        code_token_remove(w,token)
        put(w,obj+16,get(w,obj+16)-1)
        put(o,NC_CONSUMED,1)
        return 0
    if op==6:
        token=code_lookup(s,w)
        if token==0:
            return 1
        code_snapshot(o,w,get(w,token+8))
        return 0
    if op==7:
        obj=get(w,72)
        chosen=0
        pending=0
        while obj!=0:
            if get(w,obj+16)==0:
                pending=1
                if get(w,obj+24)==0 and chosen==0:
                    chosen=obj
            obj=get(w,obj+112)
        put(o,NC_PENDING,pending)
        put(o,NR_OBJ,chosen)
        if chosen!=0:
            code_snapshot(o,w,chosen)
        return 0
    if op==9:
        obj=get(o,NR_OBJ)
        if code_object_valid(w,obj)==False or get(w,obj+16)!=0 or get(w,obj+24)!=0:
            return 11
        if get(w,obj+32)!=0 or get(w,obj+56)!=0 or get(w,obj+80)!=0:
            return 11
        parent=get(w,obj+96)
        if parent!=0:
            if code_object_valid(w,parent)==False or get(w,parent+24)==0:
                return 11
            put(w,parent+24,get(w,parent+24)-1)
        code_object_remove(w,obj)
        return 0
    if op==11:
        token=code_lookup(s,w)
        if readword(s,8)==4:
            token=code_lookup_words(w,get(o,24),get(o,32),get(o,40))
        if token==0:
            return 1
        obj=get(w,token+8)
        if get(w,obj+8)!=2 or get(w,obj+104)!=1 or get(w,obj+24)!=0:
            return 6
        parent=get(w,obj+96)
        if code_object_valid(w,parent)==False or get(w,parent+8)!=1 or get(w,parent+24)==0:
            return 11
        put(w,obj+24,1)
        code_snapshot(o,w,obj)
        put(o,NC_OBJECT_SAVED,obj)
        put(o,NR_CODE,get(w,parent+32))
        put(o,NR_CODE_SIZE,get(w,parent+40))
        put(o,NR_CODE_LENGTH,get(w,parent+48))
        put(o,NC_EXEC,get(w,obj+32))
        put(o,NC_EXEC_BYTES,get(w,obj+40))
        put(o,NC_INPUT_LENGTH,get(w,obj+48))
        return 0
    if op==12:
        obj=get(o,NC_OBJECT_SAVED)
        if code_object_valid(w,obj)==False or get(w,obj+8)!=2 or get(w,obj+24)!=1:
            return 11
        put(w,obj+24,0)
        put(w,obj+72,get(o,NC_BODY_ACTION))
        if get(o,NC_BODY_ACTION)!=1:
            put(w,obj+104,2)
        return 0
    if op==14:
        put(o,48,get(w,80))
        put(o,56,get(w,88))
        obj=get(w,72)
        pending=0
        active=0
        while obj!=0:
            if get(w,obj+16)==0:
                pending=pending+1
            active=active+get(w,obj+24)
            obj=get(w,obj+112)
        put(o,NC_PENDING,choose(pending!=0,1,0))
        put(o,64,active)
        put(o,72,pending)
        return 0
    if op==16:
        obj=get(w,72)
        pending=0
        while obj!=0:
            if get(w,obj+16)==0:
                pending=1
            obj=get(w,obj+112)
        put(o,NC_PENDING,pending)
        return 0
    if op==15:
        obj=get(o,NR_OBJ)
        if code_object_valid(w,obj)==False or get(w,obj+104)!=0 or get(w,obj+24)!=1:
            return 11
        put(w,obj+24,0)
        return 0
    return 11

def code_need(o:mutbuf,w:mutbuf) -> u64:
    if get(w,16)==0 or get(w,16)==MAX:
        return 5
    want=length(w)
    while want<=length(w) or want<get(w,16):
        if want>9223372036854775807:
            return 5
        want=want*2
    put(o,NC_GROW,want)
    return 100

def code_lookup(s:readbuf,w:mutbuf) -> u64:
    at=choose(readword(s,0)==NC_FINAL_REQUEST,32,24)
    return code_lookup_words(w,readword(s,at),readword(s,at+8),readword(s,at+16))

def code_lookup_words(w:mutbuf,requested:u64,tag0:u64,tag1:u64) -> u64:
    token=get(w,64)
    while token!=0:
        if token==requested and get(w,token+16)==tag0 and get(w,token+24)==tag1:
            return token
        token=get(w,token+32)
    return 0

def code_object_valid(w:mutbuf,obj:u64) -> bool:
    current=get(w,72)
    while current!=0:
        if current==obj:
            return True
        current=get(w,current+112)
    return False

def code_object_new(w:mutbuf,kind:u64) -> u64:
    obj=allocate(w,128)
    if obj==0:
        return 0
    zero(w,obj,128)
    put(w,obj,NC_OBJECT)
    put(w,obj+8,kind)
    put(w,obj+24,1)
    first=get(w,72)
    put(w,obj+112,first)
    if first!=0:
        put(w,first+120,obj)
    put(w,72,obj)
    put(w,88,get(w,88)+1)
    return obj

def code_object_remove(w:mutbuf,obj:u64) -> u64:
    previous=get(w,obj+120)
    next=get(w,obj+112)
    if previous==0:
        put(w,72,next)
    else:
        put(w,previous+112,next)
    if next!=0:
        put(w,next+120,previous)
    put(w,88,get(w,88)-1)
    deallocate(w,obj)
    return 0

def code_publish(o:mutbuf,w:mutbuf,obj:u64) -> bool:
    tag0=get(o,NC_RANDOM)
    tag1=get(o,NC_RANDOM+8)
    if tag0==0 and tag1==0:
        put(w,16,MAX)
        return False
    token=allocate(w,64)
    if token==0:
        return False
    zero(w,token,64)
    put(w,token,NC_TOKEN)
    put(w,token+8,obj)
    put(w,token+16,tag0)
    put(w,token+24,tag1)
    first=get(w,64)
    put(w,token+32,first)
    if first!=0:
        put(w,first+40,token)
    put(w,64,token)
    put(w,80,get(w,80)+1)
    put(w,obj+16,get(w,obj+16)+1)
    put(o,16,get(w,obj+8))
    put(o,24,token)
    put(o,32,tag0)
    put(o,40,tag1)
    put(o,NC_CREATED,1)
    return True

def code_token_remove(w:mutbuf,token:u64) -> u64:
    previous=get(w,token+40)
    next=get(w,token+32)
    if previous==0:
        put(w,64,next)
    else:
        put(w,previous+32,next)
    if next!=0:
        put(w,next+40,previous)
    put(w,80,get(w,80)-1)
    deallocate(w,token)
    return 0

def code_snapshot(o:mutbuf,w:mutbuf,obj:u64) -> u64:
    put(o,NR_OBJ,obj)
    put(o,NR_KIND,get(w,obj+8))
    put(o,NR_CODE,get(w,obj+32))
    put(o,NR_CODE_SIZE,get(w,obj+40))
    put(o,NR_CODE_LENGTH,get(w,obj+48))
    put(o,NR_SOURCE,get(w,obj+56))
    put(o,NR_SOURCE_SIZE,get(w,obj+64))
    put(o,NR_SOURCE_LENGTH,get(w,obj+72))
    put(o,NR_WORK,get(w,obj+80))
    put(o,NR_WORK_SIZE,get(w,obj+88))
    put(o,NR_PARENT,get(w,obj+96))
    put(o,NR_STATE,get(w,obj+104))
    return 0
'''


def program():
    return document(source('native_callable_registry', SOURCE), 'native_callable_registry')


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/native_callable_registry.hepta'
    path.write_text(render_assembly(program()))
    print(path.name, path.stat().st_size, flush=True)
