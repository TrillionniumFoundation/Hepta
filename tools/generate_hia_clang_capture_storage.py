"""Native bounded stream storage and explicit owned-mapping retirement."""
from tools.generate_hia_clang_capture_common import write_module
SOURCE=r'''
def storage(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    result=get(w,RESULT)
    if phase==400:
        put(w,READ_INDEX,0)
        if get(w,ERROR)!=0:
            put(w,FAILURE_PASS,1)
        return start_read(o,w)
    if phase==401:
        if failed(result):
            return storage_error(w,E_OS,errno(result))
        limit=get(w,OUTPUT_LIMIT+get(w,READ_INDEX)*8)
        if limit>SSIZE_MAX or (get(w,FAILURE_PASS)==0 and limit==SSIZE_MAX):
            return storage_error(w,E_OVERFLOW,0)
        target=limit
        if get(w,FAILURE_PASS)==0:
            target=target+1
        put(w,READ_LIMIT,target)
        slot=RAW_OUT+get(w,READ_INDEX)*24
        put(w,slot+8,0)
        if target==0:
            return raw_finished(o,w)
        if get(w,slot)!=0:
            return read_more(o,w)
        size=choose(target>65536,65536,target)
        size=(size+4095)&18446744073709547520
        put(w,READ_GROW,size)
        return call(o,w,402,9,0,size,3,34,NONE,0,0)
    if phase==402 or phase==404:
        if failed(result):
            return storage_error(w,E_MEMORY,errno(result))
        slot=RAW_OUT+get(w,READ_INDEX)*24
        put(w,slot,result)
        put(w,slot+16,get(w,READ_GROW))
        return read_more(o,w)
    if phase==403:
        if failed(result):
            if errno(result)==4:
                return read_more(o,w)
            return storage_error(w,E_OS,errno(result))
        slot=RAW_OUT+get(w,READ_INDEX)*24
        if result==0:
            return raw_finished(o,w)
        put(w,slot+8,get(w,slot+8)+result)
        if get(w,slot+8)>=get(w,READ_LIMIT):
            return raw_finished(o,w)
        return read_more(o,w)
    if phase==450:
        return start_decode(o,w)
    if phase==451:
        if failed(result):
            return storage_error(w,E_MEMORY,errno(result))
        slot=NORM_OUT+get(w,READ_INDEX)*24
        put(w,slot,result)
        put(w,slot+16,get(w,READ_GROW))
        put(w,PHASE,452)
        return 13
    if phase==452:
        if get(w,STREAM_RESULT)!=0:
            first_error(w,get(w,STREAM_RESULT),0)
            put(w,ERROR_STREAM,get(w,READ_INDEX))
            return jump(w,480)
        put(w,NORM_OUT+get(w,READ_INDEX)*24+8,get(w,STREAM_N))
        return next_decode(w)
    if phase==480:
        put(w,FAILURE_PASS,1)
        return call(o,w,481,5,get(w,OUTPUT_FD),STAT,0,0,0,0,12)
    if phase==481:
        if failed(result):
            return storage_error(w,E_OS,errno(result))
        put(w,OUTPUT_TOTAL,get(w,STAT+48))
        return call(o,w,482,5,get(w,ERROR_FD),STAT,0,0,0,0,12)
    if phase==482:
        if failed(result):
            return storage_error(w,E_OS,errno(result))
        put(w,ERROR_TOTAL,get(w,STAT+48))
        return jump(w,400)
    if phase>=500 and phase<=503:
        return close_files(o,w,phase,result)
    if phase>=700 and phase<=711:
        return retire(o,w,phase,result)
    first_error(w,E_CONTEXT,0)
    return reply(o,w)

def start_read(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,401,8,get(w,OUTPUT_FD+get(w,READ_INDEX)*8),0,0,0,0,0,0)

def read_more(o:mutbuf,w:mutbuf) -> u32:
    slot=RAW_OUT+get(w,READ_INDEX)*24
    n=get(w,slot+8)
    cap=get(w,slot+16)
    if n==cap:
        wanted=cap*2
        if wanted<cap or wanted>get(w,READ_LIMIT):
            wanted=get(w,READ_LIMIT)
        if wanted>SSIZE_MAX-4095:
            return storage_error(w,E_MEMORY,12)
        size=(wanted+4095)&18446744073709547520
        if size<=cap:
            return storage_error(w,E_MEMORY,12)
        put(w,READ_GROW,size)
        return call(o,w,404,25,get(w,slot),cap,size,1,0,0,0)
    count=cap-n
    if count>get(w,READ_LIMIT)-n:
        count=get(w,READ_LIMIT)-n
    return call(o,w,403,0,get(w,OUTPUT_FD+get(w,READ_INDEX)*8),get(w,slot)+n,count,0,0,0,0)

def raw_finished(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,READ_INDEX)
    if get(w,FAILURE_PASS)==0 and get(w,RAW_OUT+i*24+8)>get(w,OUTPUT_LIMIT+i*8):
        first_error(w,E_OUTPUT_SIZE,0)
        return jump(w,480)
    if i==0:
        put(w,READ_INDEX,1)
        return start_read(o,w)
    if get(w,ERROR)!=0:
        return jump(w,500)
    put(w,READ_INDEX,0)
    return jump(w,450)

def start_decode(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,RAW_OUT+get(w,READ_INDEX)*24+8)
    if n==0:
        return next_decode(w)
    if n>SSIZE_MAX-4095:
        return storage_error(w,E_MEMORY,12)
    size=(n+4095)&18446744073709547520
    put(w,READ_GROW,size)
    return call(o,w,451,9,0,size,3,34,NONE,0,0)

def next_decode(w:mutbuf) -> u32:
    if get(w,READ_INDEX)==0:
        put(w,READ_INDEX,1)
        return jump(w,450)
    return jump(w,500)

def storage_error(w:mutbuf,code:u64,number:u64) -> u32:
    if get(w,ERROR)!=0:
        put(w,EVIDENCE_ERROR,code)
        put(w,EVIDENCE_ERRNO,number)
    first_error(w,code,number)
    return jump(w,500)

def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,CLEAN_INDEX)
    while i<5:
        if get(w,INPUT_FD+i*8)!=NONE:
            put(w,CLEAN_INDEX,i)
            return close_fd(o,w,501,get(w,INPUT_FD+i*8),i)
        i=i+1
    put(w,CLEAN_INDEX,5)
    if get(w,PATH_WORK)!=0:
        return call(o,w,503,11,get(w,PATH_WORK),get(w,PATH_CAP),0,0,0,0,0)
    return jump(w,999)

def close_files(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==500:
        put(w,CLEAN_INDEX,0)
        return close_next(o,w)
    if phase==501:
        i=get(w,CLEAN_INDEX)
        put(w,CLEAN_INDEX,i+1)
        if failed(result):
            cleanup_error(w,E_CLEANUP,errno(result))
            first_error(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)|2)
        else:
            put(w,INPUT_FD+i*8,NONE)
        return close_next(o,w)
    if phase==503:
        if failed(result):
            cleanup_error(w,E_CLEANUP,errno(result))
            first_error(w,E_CLEANUP,errno(result))
        else:
            put(w,PATH_WORK,0)
            put(w,PATH_CAP,0)
        return jump(w,999)
    first_error(w,E_CONTEXT,0)
    return reply(o,w)

def retire_fds(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,RELEASE_INDEX)
    while i<6:
        slot=choose(i<5,INPUT_FD+i*8,AUX_FD)
        if get(w,slot)!=NONE:
            if (get(w,UNKNOWN_FDS)&(1<<i))!=0:
                put(w,FD_RETRY_PENDING,1)
            else:
                put(w,RELEASE_INDEX,i)
                put(w,RELEASE_SLOT,slot)
                return close_fd(o,w,711,get(w,slot),i)
        i=i+1
    put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)&18446744073709551613)
    if get(w,FD_RETRY_PENDING)!=0:
        put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)|2)
    put(w,RELEASE_INDEX,0)
    return release_next(o,w)

def release_slot(index:u64) -> u64:
    if index==0:
        return RAW_OUT
    if index==1:
        return RAW_ERR
    if index==2:
        return NORM_OUT
    if index==3:
        return NORM_ERR
    if index==4:
        return PATH_WORK
    return ENV_PATH_BUFFER

def release_cap_slot(index:u64) -> u64:
    if index<4:
        return release_slot(index)+16
    if index==4:
        return PATH_CAP
    return ENV_PATH_ALLOC

def release_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,RELEASE_INDEX)
    while i<6:
        slot=release_slot(i)
        cap=release_cap_slot(i)
        if get(w,slot)!=0:
            put(w,RELEASE_INDEX,i)
            put(w,RELEASE_SLOT,slot)
            put(w,RELEASE_CAP_SLOT,cap)
            return call(o,w,702,11,get(w,slot),get(w,cap),0,0,0,0,0)
        i=i+1
    clear(o,0,256)
    put(o,0,REPLY)
    if get(w,RETIRE_ERROR)!=0:
        put(o,8,E_CLEANUP)
        put(o,16,get(w,RETIRE_ERRNO))
        put(o,136,1)
    elif get(w,CLEAN_PENDING)!=0:
        put(o,8,E_PENDING)
        put(o,136,1)
    else:
        clear(w,0,4096)
    return 0

def retire(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==700:
        put(w,RETIRE_ERROR,0)
        put(w,RETIRE_ERRNO,0)
        put(w,RELEASE_INDEX,0)
        return call(o,w,701,39,0,0,0,0,0,0,0)
    if phase==701:
        if result!=get(w,PARENT_PID) or get(w,SELF)!=get(w,WORK_PTR) or get(w,CONTEXT_MAGIC)!=CTXMAGIC:
            clear(o,0,256)
            put(o,0,REPLY)
            put(o,8,E_CONTEXT)
            return 0
        put(w,FD_RETRY_PENDING,0)
        return retire_fds(o,w)
    if phase==711:
        if failed(result):
            put(w,FD_RETRY_PENDING,1)
            if get(w,RETIRE_ERROR)==0:
                put(w,RETIRE_ERROR,E_OS)
                put(w,RETIRE_ERRNO,errno(result))
        else:
            put(w,get(w,RELEASE_SLOT),NONE)
        put(w,RELEASE_INDEX,get(w,RELEASE_INDEX)+1)
        return retire_fds(o,w)
    if phase==702:
        if failed(result):
            if get(w,RETIRE_ERROR)==0:
                put(w,RETIRE_ERROR,E_OS)
                put(w,RETIRE_ERRNO,errno(result))
        else:
            put(w,get(w,RELEASE_SLOT),0)
            put(w,get(w,RELEASE_CAP_SLOT),0)
            if get(w,RELEASE_INDEX)<4:
                put(w,get(w,RELEASE_SLOT)+8,0)
        put(w,RELEASE_INDEX,get(w,RELEASE_INDEX)+1)
        return release_next(o,w)
    clear(o,0,256)
    put(o,0,REPLY)
    put(o,8,E_CONTEXT)
    return 0
'''
if __name__=='__main__':write_module('clang_capture_storage',SOURCE,'storage')
