"""Native post-fork setup and shell-free exec with actual PATH/FD semantics."""
from tools.generate_hia_clang_capture_common import write_module
SOURCE=r'''
def child(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    result=get(w,RESULT)
    if phase==840:
        i=0
        while i<length(s):
            store(o,i,byte(s,i))
            i=i+1
        store(o,i,0)
        return jump(w,44)
    if phase==850:
        return make_path(s,o,w)
    if phase==800:
        put(w,EXEC_STAGE,2)
        put(w,ITER,0)
        return call(o,w,801,3,get(w,PIPE_READ),0,0,0,0,0,0)
    if phase==801:
        return duplicate(o,w)
    if phase==802:
        if failed(result):
            if errno(result)==4:
                return duplicate(o,w)
            return child_error(o,w,errno(result),2)
        if result!=get(w,ITER):
            return child_error(o,w,5,2)
        put(w,ITER,get(w,ITER)+1)
        if get(w,ITER)<3:
            return duplicate(o,w)
        if get(w,CWD_PRESENT)==1:
            return call(o,w,803,80,get(w,CWD_AT),0,0,0,0,0,1)
        return restore_signals(o,w)
    if phase==803:
        if failed(result):
            return child_error(o,w,errno(result),1)
        return restore_signals(o,w)
    if phase==804:
        if failed(result):
            return child_error(o,w,errno(result),2)
        return call(o,w,805,13,25,SIGACTION,0,8,0,0,12)
    if phase==805:
        if failed(result):
            return child_error(o,w,errno(result),2)
        return call(o,w,806,112,0,0,0,0,0,0,0)
    if phase==806:
        if failed(result):
            return child_error(o,w,errno(result),2)
        return call(o,w,807,436,3,4294967295,4,0,0,0,0)
    if phase==807:
        if failed(result):
            put(w,PROC_FD_NAME,7310238724270485551)
            put(w,PROC_FD_NAME+8,431211112044)
            return call(o,w,820,257,18446744073709551516,PROC_FD_NAME,589824,0,0,0,12)
        return execute(s,o,w)
    if phase>=820 and phase<=829:
        return close_descriptors(s,o,w,phase,result)
    if phase==851:
        put(w,EXEC_STAGE,0)
        return call(o,w,852,59,get(w,PATH_WORK)+get(w,PATH_N)+1,get(w,ARGV),get(w,ENVP),0,0,0,0)
    if phase==852:
        if failed(result):
            number=errno(result)
            if number!=2 and number!=20 and get(w,FIRST_EXEC_ERR)==0:
                put(w,FIRST_EXEC_ERR,number)
            if get(w,PATH_CURSOR)<=get(w,PATH_N):
                put(w,PHASE,850)
                return 15
            number=choose(get(w,FIRST_EXEC_ERR)!=0,get(w,FIRST_EXEC_ERR),number)
            return child_error(o,w,number,0)
        return child_error(o,w,5,0)
    if phase==853:
        return child_error(o,w,choose(failed(result),errno(result),5),0)
    if phase==890:
        if failed(result):
            if errno(result)==4:
                return write_error(o,w)
            return call(o,w,899,60,255,0,0,0,0,0,0)
        if result==0:
            return call(o,w,899,60,255,0,0,0,0,0,0)
        put(w,IO_AT,get(w,IO_AT)+result)
        if get(w,IO_AT)<16:
            return write_error(o,w)
        return call(o,w,899,60,255,0,0,0,0,0,0)
    return call(o,w,899,60,255,0,0,0,0,0,0)

def duplicate(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,802,33,get(w,INPUT_FD+get(w,ITER)*8),get(w,ITER),0,0,0,0,0)

def restore_signals(o:mutbuf,w:mutbuf) -> u32:
    clear(w,SIGACTION,32)
    return call(o,w,804,13,13,SIGACTION,0,8,0,0,12)

def child_error(o:mutbuf,w:mutbuf,number:u64,stage:u64) -> u32:
    put(w,ERROR_PIPE_DATA,number)
    put(w,ERROR_PIPE_DATA+8,stage)
    put(w,IO_AT,0)
    return write_error(o,w)

def write_error(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,890,1,get(w,PIPE_WRITE),ERROR_PIPE_DATA+get(w,IO_AT),16-get(w,IO_AT),0,0,0,12)

def execute(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,PATH_WORK)==0:
        return call(o,w,853,59,get(w,SOURCE_PTR)+get(w,ARG0_AT),get(w,ARGV),get(w,ENVP),0,0,0,0)
    put(w,PATH_CURSOR,0)
    put(w,PHASE,850)
    return 15

def make_path(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n=get(w,PATH_N)
    at=get(w,PATH_CURSOR)
    end=at
    while end<n and byte(o,end)!=58:
        end=end+1
    dest=n+1
    i=at
    while i<end:
        store(o,dest,byte(o,i))
        dest=dest+1
        i=i+1
    if end!=at:
        store(o,dest,47)
        dest=dest+1
    i=0
    while i<get(w,ARG0_N):
        store(o,dest,byte(s,get(w,ARG0_AT)+i))
        dest=dest+1
        i=i+1
    store(o,dest,0)
    put(w,PATH_CURSOR,end+1)
    return jump(w,851)

def close_descriptors(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==820:
        if failed(result):
            put(w,CLOSE_MODE,1)
            put(w,FD_INDEX,3)
            return call(o,w,828,97,7,STAT,0,0,0,0,12)
        put(w,CHILD_DIR,result)
        put(w,CLOSE_MODE,0)
        return call(o,w,821,217,result,DENTS,2048,0,0,0,12)
    if phase==821:
        if failed(result):
            if errno(result)==4:
                return call(o,w,821,217,get(w,CHILD_DIR),DENTS,2048,0,0,0,12)
            return child_error(o,w,errno(result),2)
        if result==0:
            return call(o,w,829,3,get(w,CHILD_DIR),0,0,0,0,0,0)
        put(w,DENT_N,result)
        put(w,DENT_AT,0)
        return next_descriptor(s,o,w)
    if phase==826:
        if failed(result) and errno(result)!=9:
            if errno(result)==4:
                return call(o,w,826,72,get(w,FD_INDEX),2,1,0,0,0,0)
            return child_error(o,w,errno(result),2)
        if get(w,CLOSE_MODE)==1:
            put(w,FD_INDEX,get(w,FD_INDEX)+1)
        return next_descriptor(s,o,w)
    if phase==828:
        if failed(result):
            return child_error(o,w,errno(result),2)
        put(w,FD_LIMIT,choose(get(w,STAT)>2147483647,2147483647,get(w,STAT)))
        return next_descriptor(s,o,w)
    if phase==829:
        return execute(s,o,w)
    return child_error(o,w,5,2)

def next_descriptor(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,CLOSE_MODE)==1:
        at=get(w,FD_INDEX)
        while at<get(w,FD_LIMIT):
            if at!=get(w,PIPE_WRITE):
                put(w,FD_INDEX,at)
                return call(o,w,826,72,at,2,1,0,0,0,0)
            at=at+1
        return execute(s,o,w)
    at=get(w,DENT_AT)
    n=get(w,DENT_N)
    while at<n:
        if n-at<20:
            return child_error(o,w,5,2)
        size=byte(w,DENTS+at+16)|(byte(w,DENTS+at+17)<<8)
        if size<20 or size>n-at:
            return child_error(o,w,5,2)
        i=19
        fd=0
        valid=1
        while i<size and byte(w,DENTS+at+i)!=0:
            ch=byte(w,DENTS+at+i)
            if ch<48 or ch>57 or fd>214748364:
                valid=0
            if valid==1:
                fd=fd*10+ch-48
            i=i+1
        if i==19 or i==size or fd>2147483647:
            valid=0
        at=at+size
        put(w,DENT_AT,at)
        if valid==1 and fd>=3 and fd!=get(w,PIPE_WRITE) and fd!=get(w,CHILD_DIR):
            put(w,FD_INDEX,fd)
            return call(o,w,826,72,fd,2,1,0,0,0,0)
    return call(o,w,821,217,get(w,CHILD_DIR),DENTS,2048,0,0,0,12)
'''
if __name__=='__main__':write_module('clang_capture_child',SOURCE,'child')
