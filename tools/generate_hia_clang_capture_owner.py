"""Native Linux bounded capture: live ownership, one group signal, exact reap."""
from tools.generate_hia_clang_capture_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    result=get(w,RESULT)
    if phase==0:
        put(w,SELF,get(w,WORK_PTR))
        put(w,CONTEXT_MAGIC,CTXMAGIC)
        i=0
        while i<5:
            put(w,INPUT_FD+i*8,NONE)
            i=i+1
        put(w,AUX_FD,NONE)
        return call(o,w,1,39,0,0,0,0,0,0,0)
    if phase==1:
        put(w,PARENT_PID,result)
        return 11
    if phase==20:
        clear(w,SIGACTION,32)
        return call(o,w,21,13,17,0,SIGACTION,8,0,0,48)
    if phase==21:
        if failed(result) or get(w,SIGACTION)!=0:
            first_error(w,E_OWNERSHIP,choose(failed(result),errno(result),0))
            return reply(o,w)
        clear(w,SIGINFO,128)
        return call(o,w,22,247,1,get(w,PARENT_PID),SIGINFO,16777221,0,0,48)
    if phase==22:
        if result!=18446744073709551606:
            first_error(w,E_OWNERSHIP,choose(failed(result),errno(result),0))
            return reply(o,w)
        if get(w,EXPLICIT_ENV)==0:
            put(w,PHASE,24)
            return 5
        return prepare_path(s,o,w)
    if phase>=24 and phase<=29:
        return environment(s,o,w,phase,result)
    if phase==30:
        if failed(result) and errno(result)==38:
            put(w,CLOSE_METHOD,1)
            return call(o,w,31,3,get(w,CLOSE_TARGET),0,0,0,0,0,0)
        return jump(w,get(w,CLOSE_AFTER))
    if phase==31:
        if failed(result):
            put(w,UNKNOWN_FDS,get(w,UNKNOWN_FDS)|(1<<get(w,CLOSE_INDEX)))
        return jump(w,get(w,CLOSE_AFTER))
    if phase==40:
        if failed(result):
            first_error(w,E_MEMORY,errno(result))
            return jump(w,500)
        put(w,PATH_WORK,result)
        put(w,PHASE,840)
        return 14
    if phase==44:
        return begin_files(o,w)
    if phase>=50 and phase<=69:
        return launch(s,o,w,phase,result)
    if phase>=100 and phase<=105:
        return poll_process(o,w,phase,result)
    if phase>=200 and phase<=209:
        return terminate(o,w,phase,result)
    if phase>=300 and phase<=302:
        return final_sizes(o,w,phase,result)
    if phase>=400 and phase<800:
        return 16
    if phase>=800 and phase<900:
        return 12
    if phase==999:
        return reply(o,w)
    first_error(w,E_CONTEXT,0)
    return reply(o,w)

def peek(o:mutbuf,w:mutbuf,phase:u64,pointer:u64,width:u64) -> u32:
    put(w,PHASE,phase)
    put(o,0,pointer)
    put(o,8,width)
    return 6

def direct_path(s:readbuf,w:mutbuf) -> bool:
    i=0
    while i<get(w,ARG0_N):
        if byte(s,get(w,ARG0_AT)+i)==47:
            return True
        i=i+1
    return False

def environment(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==24:
        put(w,ENVP,result)
        put(w,ENV_SOURCE,result)
        if direct_path(s,w) or result==0:
            return prepare_path(s,o,w)
        put(w,ENV_INDEX,0)
        return peek(o,w,25,result,8)
    if phase==25:
        if result==0:
            return prepare_path(s,o,w)
        put(w,ENV_ELEMENT,result)
        put(w,ENV_CHARACTER,0)
        return peek(o,w,26,result,1)
    if phase==26:
        at=get(w,ENV_CHARACTER)
        expected=(263206486352>>(at*8))&255
        if result!=expected:
            put(w,ENV_INDEX,get(w,ENV_INDEX)+1)
            return peek(o,w,25,get(w,ENV_SOURCE)+get(w,ENV_INDEX)*8,8)
        at=at+1
        put(w,ENV_CHARACTER,at)
        if at<5:
            return peek(o,w,26,get(w,ENV_ELEMENT)+at,1)
        put(w,PATH_PTR,get(w,ENV_ELEMENT)+5)
        put(w,PATH_N,0)
        put(w,ENV_PATH_CAPTURE,1)
        return peek(o,w,27,get(w,PATH_PTR),1)
    if phase==27:
        if result==0:
            return prepare_path(s,o,w)
        n=get(w,PATH_N)
        if n>=SSIZE_MAX:
            first_error(w,E_MEMORY,12)
            return jump(w,500)
        put(w,PATH_N,n+1)
        return peek(o,w,27,get(w,PATH_PTR)+n+1,1)
    first_error(w,E_CONTEXT,0)
    return jump(w,500)

def prepare_path(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if direct_path(s,w):
        return begin_files(o,w)
    if get(w,ENV_PATH_CAPTURE)==0:
        put(w,DEFAULT_PATH,8319607814643868207)
        put(w,DEFAULT_PATH+8,474214444914)
        put(w,PATH_PTR,get(w,WORK_PTR)+DEFAULT_PATH)
        put(w,PATH_N,13)
    n=get(w,PATH_N)
    a=get(w,ARG0_N)
    if a>SSIZE_MAX-8192 or n>(SSIZE_MAX-a-8192)//2:
        first_error(w,E_MEMORY,12)
        return jump(w,500)
    size=(n*2+a+3+4095)&18446744073709547520
    put(w,PATH_CAP,size)
    return call(o,w,40,9,0,size,3,34,NONE,0,0)

def begin_files(o:mutbuf,w:mutbuf) -> u32:
    put(w,TEMP_NAME,8390313184382249320)
    put(w,TEMP_NAME+8,6648437)
    put(w,ITER,0)
    return call(o,w,50,319,TEMP_NAME,1,0,0,0,0,3)

def normalize_fd(o:mutbuf,w:mutbuf) -> u32:
    fd=get(w,INPUT_FD+get(w,ITER)*8)
    if fd<3:
        return call(o,w,52,72,fd,1030,3,0,0,0,0)
    return fd_ready(o,w)

def fd_ready(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,ITER)+1
    put(w,ITER,i)
    if i<3:
        return call(o,w,50,319,TEMP_NAME,1,0,0,0,0,3)
    if i==3:
        put(w,IO_AT,0)
        return write_input(o,w)
    if i==4:
        return normalize_fd(o,w)
    return call(o,w,65,57,0,0,0,0,0,0,0)

def write_input(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,IO_AT)
    if at==get(w,INPUT_N):
        return call(o,w,60,8,get(w,INPUT_FD),0,0,0,0,0,0)
    return call(o,w,55,1,get(w,INPUT_FD),get(w,INPUT_AT)+at,get(w,INPUT_N)-at,0,0,0,4)

def launch(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==50:
        if failed(result):
            first_error(w,E_OS,errno(result))
            return jump(w,500)
        put(w,INPUT_FD+get(w,ITER)*8,result)
        return normalize_fd(o,w)
    if phase==52:
        if failed(result):
            first_error(w,E_OS,errno(result))
            return jump(w,500)
        put(w,CLOSE_STAGE,result)
        put(w,AUX_FD,get(w,INPUT_FD+get(w,ITER)*8))
        return close_fd(o,w,53,get(w,AUX_FD),5)
    if phase==53:
        put(w,INPUT_FD+get(w,ITER)*8,get(w,CLOSE_STAGE))
        if failed(result):
            first_error(w,E_OS,errno(result))
            cleanup_error(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)|2)
            return jump(w,500)
        put(w,AUX_FD,NONE)
        return fd_ready(o,w)
    if phase==55:
        if failed(result):
            if errno(result)==4:
                return write_input(o,w)
            first_error(w,E_OS,errno(result))
            return jump(w,500)
        if result==0:
            first_error(w,E_OS,5)
            return jump(w,500)
        put(w,IO_AT,get(w,IO_AT)+result)
        return write_input(o,w)
    if phase==60:
        if failed(result):
            first_error(w,E_OS,errno(result))
            return jump(w,500)
        return call(o,w,62,293,PIPE_FDS,524288,0,0,0,0,3)
    if phase==62:
        if failed(result):
            first_error(w,E_OS,errno(result))
            return jump(w,500)
        both=get(w,PIPE_FDS)
        put(w,PIPE_READ,both&4294967295)
        put(w,PIPE_WRITE,both>>32)
        put(w,ITER,3)
        return normalize_fd(o,w)
    if phase==65:
        if failed(result):
            first_error(w,E_EXEC,errno(result))
            return jump(w,500)
        if result==0:
            return jump(w,800)
        put(w,PID,result)
        put(w,SPAWNED,1)
        return close_fd(o,w,66,get(w,PIPE_WRITE),4)
    if phase==66:
        if failed(result):
            cleanup_error(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)|2)
            return failed_run(o,w,E_OS,errno(result))
        put(w,PIPE_WRITE,NONE)
        put(w,ERROR_PIPE_USED,0)
        return read_startup(o,w)
    if phase==67:
        if failed(result):
            if errno(result)==4:
                return read_startup(o,w)
            return failed_run(o,w,E_EXEC,errno(result))
        if result==0:
            if get(w,ERROR_PIPE_USED)==0:
                return close_fd(o,w,69,get(w,PIPE_READ),3)
            return failed_run(o,w,E_EXEC,5)
        put(w,ERROR_PIPE_USED,get(w,ERROR_PIPE_USED)+result)
        if get(w,ERROR_PIPE_USED)<16:
            return read_startup(o,w)
        put(w,EXEC_ERROR,get(w,ERROR_PIPE_DATA))
        put(w,EXEC_STAGE,get(w,ERROR_PIPE_DATA+8))
        first_error(w,E_EXEC,get(w,EXEC_ERROR))
        put(w,SPAWNED,2)
        return call(o,w,68,61,get(w,PID),STAT,0,0,0,0,12)
    if phase==68:
        if failed(result) and errno(result)==4:
            return call(o,w,68,61,get(w,PID),STAT,0,0,0,0,12)
        if result==get(w,PID):
            reap_status(w)
        else:
            cleanup_error(w,E_CLEANUP,choose(failed(result),errno(result),5))
            put(w,CLEAN_PENDING,1)
        return jump(w,500)
    if phase==69:
        if failed(result):
            cleanup_error(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)|2)
            return failed_run(o,w,E_OS,errno(result))
        put(w,PIPE_READ,NONE)
        return call(o,w,100,228,1,CLOCK,0,0,0,0,12)
    return failed_run(o,w,E_CONTEXT,0)

def read_startup(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,67,0,get(w,PIPE_READ),ERROR_PIPE_DATA+get(w,ERROR_PIPE_USED),16-get(w,ERROR_PIPE_USED),0,0,0,12)

def failed_run(o:mutbuf,w:mutbuf,code:u64,number:u64) -> u32:
    first_error(w,code,number)
    if get(w,SPAWNED)==1 and get(w,GROUP_ATTEMPTED)==0:
        return jump(w,200)
    return jump(w,300)

def observe(o:mutbuf,w:mutbuf,next:u64) -> u32:
    clear(w,SIGINFO,128)
    return call(o,w,next,247,1,get(w,PID),SIGINFO,16777221,0,0,48)

def terminal(w:mutbuf) -> bool:
    code=get(w,SIGINFO+8)&4294967295
    return code==1 or code==2 or code==3

def clock_value(w:mutbuf) -> u64:
    return get(w,CLOCK)*1000000000+get(w,CLOCK+8)

def poll_process(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==100:
        if failed(result):
            return failed_run(o,w,E_OS,errno(result))
        put(w,DEADLINE,clock_value(w)+get(w,TIMEOUT))
        return observe(o,w,101)
    if phase==101:
        if failed(result):
            if errno(result)==4:
                return observe(o,w,101)
            return failed_run(o,w,E_OWNERSHIP,errno(result))
        pid=get(w,SIGINFO+16)&4294967295
        if pid!=0 and pid!=get(w,PID):
            return failed_run(o,w,E_OWNERSHIP,0)
        if pid==get(w,PID) and terminal(w):
            return jump(w,200)
        return call(o,w,102,5,get(w,OUTPUT_FD),STAT,0,0,0,0,12)
    if phase==102:
        if failed(result):
            return failed_run(o,w,E_OS,errno(result))
        if get(w,STAT+48)>get(w,OUTPUT_LIMIT):
            return failed_run(o,w,E_OUTPUT_SIZE,0)
        return call(o,w,103,5,get(w,ERROR_FD),STAT,0,0,0,0,12)
    if phase==103:
        if failed(result):
            return failed_run(o,w,E_OS,errno(result))
        if get(w,STAT+48)>get(w,ERROR_LIMIT):
            return failed_run(o,w,E_OUTPUT_SIZE,0)
        return call(o,w,104,228,1,CLOCK,0,0,0,0,12)
    if phase==104:
        if failed(result):
            return failed_run(o,w,E_OS,errno(result))
        now=clock_value(w)
        if now>=get(w,DEADLINE):
            return failed_run(o,w,E_TIMEOUT,0)
        ns=get(w,DEADLINE)-now
        if ns>10000000:
            ns=10000000
        if ns<1000000:
            ns=1000000
        put(w,SLEEP,0)
        put(w,SLEEP+8,ns)
        return call(o,w,105,35,SLEEP,0,0,0,0,0,3)
    if phase==105:
        if failed(result) and errno(result)!=4:
            return failed_run(o,w,E_OS,errno(result))
        return observe(o,w,101)
    return failed_run(o,w,E_CONTEXT,0)

def reap_status(w:mutbuf) -> u64:
    status=get(w,STAT)&4294967295
    if (status&127)==0:
        put(w,RETURN_CODE,(status>>8)&255)
    else:
        put(w,RETURN_CODE,0-(status&127))
    put(w,RETURN_KNOWN,1)
    return 0

def cleanup_failed(w:mutbuf,code:u64,number:u64) -> u64:
    cleanup_error(w,code,number)
    first_error(w,code,number)
    return 0

def after_reap(w:mutbuf) -> u32:
    reap_status(w)
    if get(w,GROUP_ERRNO)!=0:
        cleanup_failed(w,E_CLEANUP,get(w,GROUP_ERRNO))
    return jump(w,300)

def terminate(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==200:
        if get(w,GROUP_ATTEMPTED)!=0:
            cleanup_failed(w,E_OWNERSHIP,0)
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        put(w,GROUP_ATTEMPTED,1)
        return observe(o,w,201)
    if phase==201:
        if failed(result):
            if errno(result)==4:
                return observe(o,w,201)
            cleanup_failed(w,E_OWNERSHIP,errno(result))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        pid=get(w,SIGINFO+16)&4294967295
        if pid!=0 and pid!=get(w,PID):
            cleanup_failed(w,E_OWNERSHIP,0)
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        is_terminal=pid==get(w,PID) and terminal(w)
        put(w,STREAM_RESULT,choose(is_terminal,1,0))
        return call(o,w,202,62,0-get(w,PID),9,0,0,0,0,0)
    if phase==202:
        if failed(result):
            if errno(result)!=3 or get(w,STREAM_RESULT)==0:
                put(w,GROUP_ERRNO,errno(result))
        return call(o,w,203,61,get(w,PID),STAT,1,0,0,0,12)
    if phase==203:
        if failed(result):
            if errno(result)==4:
                return call(o,w,203,61,get(w,PID),STAT,1,0,0,0,12)
            cleanup_failed(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        if result==get(w,PID):
            return after_reap(w)
        if result!=0:
            cleanup_failed(w,E_OWNERSHIP,0)
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        return call(o,w,204,62,get(w,PID),9,0,0,0,0,0)
    if phase==204:
        if failed(result) and errno(result)!=3:
            cleanup_failed(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        return call(o,w,205,228,1,CLOCK,0,0,0,0,12)
    if phase==205:
        if failed(result):
            cleanup_failed(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        put(w,REAP_DEADLINE,clock_value(w)+3000000000)
        return call(o,w,206,61,get(w,PID),STAT,1,0,0,0,12)
    if phase==206:
        if failed(result):
            if errno(result)==4:
                return call(o,w,206,61,get(w,PID),STAT,1,0,0,0,12)
            cleanup_failed(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        if result==get(w,PID):
            return after_reap(w)
        if result!=0:
            cleanup_failed(w,E_OWNERSHIP,0)
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        return call(o,w,207,228,1,CLOCK,0,0,0,0,12)
    if phase==207:
        if failed(result) or clock_value(w)>=get(w,REAP_DEADLINE):
            cleanup_failed(w,E_CLEANUP,choose(failed(result),errno(result),110))
            put(w,CLEAN_PENDING,1)
            return jump(w,300)
        ns=get(w,REAP_DEADLINE)-clock_value(w)
        if ns>10000000:
            ns=10000000
        put(w,SLEEP,0)
        put(w,SLEEP+8,ns)
        return call(o,w,208,35,SLEEP,0,0,0,0,0,3)
    if phase==208:
        return call(o,w,206,61,get(w,PID),STAT,1,0,0,0,12)
    cleanup_failed(w,E_CONTEXT,0)
    put(w,CLEAN_PENDING,1)
    return jump(w,300)

def final_sizes(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==300:
        if get(w,SPAWNED)!=1 or get(w,OUTPUT_FD)==NONE or get(w,ERROR_FD)==NONE:
            return jump(w,500)
        return call(o,w,301,5,get(w,OUTPUT_FD),STAT,0,0,0,0,12)
    if failed(result):
        if get(w,ERROR)!=0:
            put(w,EVIDENCE_ERROR,E_OS)
            put(w,EVIDENCE_ERRNO,errno(result))
        first_error(w,E_OS,errno(result))
        return jump(w,500)
    if phase==301:
        put(w,OUTPUT_TOTAL,get(w,STAT+48))
        if get(w,OUTPUT_TOTAL)>get(w,OUTPUT_LIMIT):
            first_error(w,E_OUTPUT_SIZE,0)
        return call(o,w,302,5,get(w,ERROR_FD),STAT,0,0,0,0,12)
    put(w,ERROR_TOTAL,get(w,STAT+48))
    if get(w,ERROR_TOTAL)>get(w,ERROR_LIMIT):
        first_error(w,E_OUTPUT_SIZE,0)
    return jump(w,400)
'''
if __name__=='__main__':write_module('clang_capture_owner',SOURCE,'advance')
