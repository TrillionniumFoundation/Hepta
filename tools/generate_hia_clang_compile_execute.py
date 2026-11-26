"""Real temporary source, actual bounded Clang execution and native ELF inventory."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==300:
        put(w,P_TEMP_ATTEMPTS,0)
        return new_name(o,w)
    if phase==301:
        if failed(r):
            if errno(r)==4:
                return random(o,w)
            return p_fail(w,E_TEMP,errno(r))
        if r==0 or r>64:
            return p_fail(w,E_TEMP,5)
        i=0
        count=get(w,P_RANDOM_N)
        while i<r and count<8:
            value=byte(w,P_RANDOM+i)
            if value<222:
                value=value%37
                c=95
                if value<26:
                    c=97+value
                elif value<36:
                    c=48+value-26
                store(w,P_TEMP_NAME+12+count,c)
                count=count+1
            i=i+1
        put(w,P_RANDOM_N,count)
        if count<8:
            return random(o,w)
        store(w,P_TEMP_NAME+20,0)
        return call(o,w,304,258,get(w,P_PARENT_FD),P_TEMP_NAME,448,0,0,0,12)
    if phase==304:
        if failed(r):
            if errno(r)==17:
                put(w,P_TEMP_ATTEMPTS,get(w,P_TEMP_ATTEMPTS)+1)
                if get(w,P_TEMP_ATTEMPTS)<20:
                    return new_name(o,w)
            return p_fail(w,E_TEMP,errno(r))
        put(w,P_DIR_CREATED,1)
        return call(o,w,305,257,get(w,P_PARENT_FD),P_TEMP_NAME,720896,0,0,0,12)
    if phase==305:
        if failed(r):
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_TEMP,errno(r))
        put(w,P_DIRECTORY_FD,r)
        return p_buffer(w,306,6,get(w,P_SOURCE),get(w,P_SOURCE_N),get(w,P_STRINGS),get(w,P_STRINGS_CAP))
    if phase==306:
        if r!=0:
            return p_fail(w,E_CONTEXT,306)
        source_leaf(w)
        return call(o,w,307,257,get(w,P_DIRECTORY_FD),P_SMALL,655553,438,0,0,12)
    if phase==307:
        if failed(r):
            return p_fail(w,E_TEMP,errno(r))
        put(w,P_SOURCE_FD,r)
        put(w,P_IO_AT,0)
        return write_source(o,w)
    if phase==308:
        if failed(r):
            if errno(r)==4:
                return write_source(o,w)
            return p_fail(w,E_OS,errno(r))
        if r==0 or r>get(w,P_IR_N)-get(w,P_IO_AT):
            return p_fail(w,E_OS,5)
        put(w,P_IO_AT,get(w,P_IO_AT)+r)
        return write_source(o,w)
    if phase==330:
        return p_capture(o,w,400,2)
    if phase==400:
        if get(w,P_ACTUAL_EXIT)!=0:
            return p_fail(w,E_COMPILE,get(w,P_ACTUAL_EXIT))
        return p_file(o,w,401,1,1,get(w,P_ART_OFF),get(w,P_ART_PATH_N),67108864,0,0,0,0)
    if phase==401:
        put(w,P_ART_N,get(w,P_FILE_RESULT+32))
        put(w,P_ART_PTR,get(w,P_FILE_RESULT+40))
        p_saved_copy(w,P_FILE_RESULT+64,P_ART_ID,64)
        p_saved_copy(w,P_FILE_RESULT+128,P_ART_SHA,32)
        if get(w,P_ART_N)==0 or get(w,P_ART_PTR)==0:
            return p_fail(w,E_CONTEXT,401)
        if get(w,P_KIND)==0:
            return p_buffer(w,410,8,get(w,P_SOURCE),get(w,P_SOURCE_N),get(w,P_STRINGS),get(w,P_STRINGS_CAP))
        return p_frame(o,w,64+get(w,P_ART_N)+get(w,P_META_N)-64,420)
    if phase==410:
        if r!=0:
            return p_fail(w,E_CONTEXT,410)
        return p_invoke(w,411,R_SHARED,get(w,P_ART_PTR),get(w,P_ART_N),p_at(w,P_INV_OUT),1574976,p_at(w,P_INV_WORK),1639448)
    if phase==411:
        if r<64 or r>1574976:
            return p_fail(w,E_CONTEXT,411)
        if get(w,P_INV_OUT)!=0 or get(w,P_INV_OUT+16)!=1:
            return p_fail(w,E_INVENTORY,get(w,P_INV_OUT))
        return p_buffer(w,430,9,get(w,P_ART_PTR),get(w,P_ART_N),get(w,P_STRINGS),get(w,P_STRINGS_CAP))
    if phase==420:
        return p_buffer(w,421,7,get(w,P_SOURCE),get(w,P_SOURCE_N),get(w,P_FRAME),get(w,P_FRAME_CAP))
    if phase==421:
        if r!=get(w,P_ART_N)+get(w,P_META_N):
            return p_fail(w,E_CONTEXT,421)
        put(w,P_LAST_FRAME_N,r)
        return p_copy(w,422,get(w,P_ART_PTR),get(w,P_FRAME)+64,get(w,P_ART_N))
    if phase==422:
        if r!=0:
            return p_fail(w,E_CONTEXT,422)
        return jump(w,440)
    if phase==430:
        if r!=0:
            return p_fail(w,E_CONTEXT,430)
        return jump(w,500)
    if phase==440:
        out=get(w,P_OBJ_OUT)
        on=get(w,P_OBJ_OUT_CAP)
        work=get(w,P_OBJ_WORK)
        wn=get(w,P_OBJ_WORK_CAP)
        if out==0:
            out=p_at(w,P_INV_OUT)
            on=2097152
        if work==0:
            work=p_at(w,P_INV_WORK)
            wn=3145728
        return p_invoke(w,441,R_OBJECT,get(w,P_FRAME),get(w,P_LAST_FRAME_N),out,on,work,wn)
    if phase==441:
        put(w,P_OBJ_RESULT,r)
        if r==4294967294:
            ptr=get(w,P_OBJ_WORK)
            if ptr==0:
                ptr=p_at(w,P_INV_WORK)
            return p_copy(w,442,ptr,p_at(w,P_SMALL),32)
        if r<64 or r>64+256*24:
            return p_fail(w,E_CONTEXT,441)
        ptr=get(w,P_OBJ_OUT)
        if ptr==0:
            ptr=p_at(w,P_INV_OUT)
        return p_copy(w,448,ptr,p_at(w,P_INV_OUT),r)
    if phase==442:
        if r!=0:
            return p_fail(w,E_CONTEXT,442)
        put(w,P_OBJ_OUT_NEED,get(w,P_SMALL+16))
        put(w,P_OBJ_WORK_NEED,get(w,P_SMALL+24))
        on=get(w,P_OBJ_OUT_CAP)
        wn=get(w,P_OBJ_WORK_CAP)
        if get(w,P_OBJ_OUT)==0:
            on=2097152
        if get(w,P_OBJ_WORK)==0:
            wn=3145728
        if get(w,P_OBJ_OUT_NEED)<=on and get(w,P_OBJ_WORK_NEED)<=wn:
            return p_fail(w,E_CONTEXT,443)
        if get(w,P_OBJ_OUT_NEED)>on:
            n=grow_size(get(w,P_OBJ_OUT_NEED),on)
            if n==0:
                return p_fail(w,E_MEMORY,12)
            put(w,P_OBJ_NEEDED,n)
            if get(w,P_OBJ_OUT)==0:
                return call(o,w,444,9,0,n,3,34,NONE,0,0)
            return call(o,w,444,25,get(w,P_OBJ_OUT),on,n,1,0,0,0)
        n=grow_size(get(w,P_OBJ_WORK_NEED),wn)
        if n==0:
            return p_fail(w,E_MEMORY,12)
        put(w,P_OBJ_NEEDED,n)
        if get(w,P_OBJ_WORK)==0:
            return call(o,w,445,9,0,n,3,34,NONE,0,0)
        return call(o,w,445,25,get(w,P_OBJ_WORK),wn,n,1,0,0,0)
    if phase==444:
        if failed(r):
            return p_fail(w,E_MEMORY,errno(r))
        put(w,P_OBJ_OUT,r)
        put(w,P_OBJ_OUT_CAP,get(w,P_OBJ_NEEDED))
        return jump(w,440)
    if phase==445:
        if failed(r):
            return p_fail(w,E_MEMORY,errno(r))
        put(w,P_OBJ_WORK,r)
        put(w,P_OBJ_WORK_CAP,get(w,P_OBJ_NEEDED))
        return jump(w,440)
    if phase==448:
        if r!=0 or get(w,P_INV_OUT)!=OBJECT_REPLY:
            return p_fail(w,E_CONTEXT,448)
        if get(w,P_INV_OUT+8)!=0:
            return p_fail(w,E_INVENTORY,get(w,P_INV_OUT+8))
        if get(w,P_OBJ_RESULT)!=64+get(w,P_INV_OUT+16)*24:
            return p_fail(w,E_CONTEXT,449)
        return p_buffer(w,430,9,get(w,P_FRAME),get(w,P_LAST_FRAME_N),get(w,P_STRINGS),get(w,P_STRINGS_CAP))
    return 4294967293

def grow_size(needed:u64,current:u64) -> u64:
    if needed>9223372036854771712 or current>4611686018427385856:
        return 0
    size=2*current
    if needed>size:
        size=needed
    return (size+4095)&18446744073709547520

def random(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,301,318,P_RANDOM,64,0,0,0,0,3)

def new_name(o:mutbuf,w:mutbuf) -> u32:
    prefix(w)
    put(w,P_RANDOM_N,0)
    return random(o,w)

def write_source(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,P_IO_AT)
    n=get(w,P_IR_N)
    if at==n:
        return p_close(o,w,P_SOURCE_FD,330)
    return call(o,w,308,1,get(w,P_SOURCE_FD),p_at(w,P_IR)+at,n-at,0,0,0,0)
'''
def literal(name,text,offset):
 raw=text.encode()+b'\0';return '\n'.join([f'def {name}(w:mutbuf) -> u64:']+[f'    store(w,{offset}+{i},{c})'for i,c in enumerate(raw)]+['    return 0'])
SOURCE+='\n'+literal('prefix','.hia-native-','P_TEMP_NAME')+'\n'+literal('source_leaf','program.ll','P_SMALL')
if __name__=='__main__':write_module('clang_compile_execute',SOURCE)
