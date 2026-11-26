"""Fixed native owner of HIA-compiled code and suspended invocation capabilities."""
from tools.generate_hia_native_callable_common import ROOT, document, render_assembly, source

SOURCE = r'''
def native_callable_code_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<NC_MIN_OUTPUT or length(w)!=256:
        return 4294967293
    phase=get(o,NC_PHASE)
    if phase==0:
        return code_begin(s,o,w)
    if phase<20:
        return code_admit(s,o,w,phase)
    if phase<100:
        return code_operate(s,o,w,phase)
    if phase<180:
        return code_execute(s,o,w,phase)
    if phase<240:
        return code_cleanup(s,o,w,phase)
    return code_release(s,o,w,phase)

def code_begin(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if length(s)<128:
        return 4294967293
    finalizer=readword(s,0)==NC_FINAL_REQUEST
    if finalizer:
        if length(s)!=128 or readword(s,8)>1 or get(w,128)==0 or readword(s,16)!=get(w,128):
            return 4294967293
        kind=readword(s,24)
        if kind<3 or kind>5:
            return 4294967293
        i=56
        while i<128:
            if readword(s,i)!=0:
                return 4294967293
            i=i+8
    else:
        if readword(s,0)!=NC_REQUEST or readword(s,16)!=0 or readword(s,96)!=length(s)-128:
            return 4294967293
        op=readword(s,8)
        if op>11 or readword(s,120)!=0:
            return 4294967293
        i=48
        while i<96:
            if readword(s,i)!=0:
                return 4294967293
            i=i+8
        if readword(s,112)!=0 or (op!=9 and readword(s,104)!=0) or readword(s,104)>4294967295:
            return 4294967293
        hascap=op==2 or op==3 or op==4 or op==8 or op==9
        if hascap==False and (readword(s,24)!=0 or readword(s,32)!=0 or readword(s,40)!=0):
            return 4294967293
        n=readword(s,96)
        if (op!=1 and op!=4 and n!=0) or n>NC_LIMIT or (op==1 and n==0):
            return 4294967293
    self=get(o,NC_SELF)
    zero(o,0,NC_MIN_OUTPUT)
    put(o,NC_SELF,self)
    put(o,NC_KNOWN,1)
    if finalizer:
        put(o,NC_FINALIZER,1)
        put(o,NC_FINAL_MODE,readword(s,8))
        put(o,NC_PENDING,1)
    return code_system(o,1,39,0,0,0,0,0,0,0)

def code_operation(s:readbuf) -> u64:
    op=readword(s,8)
    if readword(s,0)==NC_FINAL_REQUEST:
        return choose(op==0,3,5)
    return op

def code_admit(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==1:
        pid=get(o,NC_FEEDBACK)
        if pid==0 or pid>=18446744073709547521:
            return code_finish(o,w,11)
        put(o,NC_PID,pid)
        if code_operation(s)==0:
            if get(w,0)==NC_STATE and get(w,8)==pid and get(w,88)==get(o,NC_SELF) and get(w,24)==0:
                return code_atom(o,2,10,32,0,1)
            if get(w,0)!=0:
                return code_finish(o,w,6)
            i=8
            while i<256:
                if get(w,i)!=0:
                    return code_finish(o,w,6)
                i=i+8
            return code_atom(o,2,2,0,0,NC_STATE)
        if get(w,0)!=NC_STATE or get(w,8)!=pid or get(w,88)!=get(o,NC_SELF):
            return code_finish(o,w,6)
        op=code_operation(s)
        state=get(w,24)
        if state==3 and (op==5 or op==6 or op==7 or op==10):
            if get(o,NC_FINALIZER)!=0 and get(o,NC_FINAL_MODE)==1:
                put(o,NC_RETRY_ACK,1)
            put(o,NC_PENDING,0)
            return code_finish(o,w,0)
        if state==1 and op!=5 and op!=6:
            return code_finish(o,w,6)
        if state==4 and op!=3 and op!=5 and op!=6 and op!=7 and op!=8 and op!=10 and op!=11:
            return code_finish(o,w,6)
        if state!=0 and state!=1 and state!=4:
            return code_finish(o,w,6)
        if get(o,NC_FINALIZER)!=0 and get(o,NC_FINAL_MODE)==1:
            put(o,NC_RETRY_ACK,1)
        return code_atom(o,2,10,32,0,1)
    if phase==2:
        if get(o,NC_FEEDBACK)!=0:
            return code_finish(o,w,6)
        put(w,8,get(o,NC_PID))
        put(w,88,get(o,NC_SELF))
        put(w,24,2)
        put(w,32,1)
        put(o,NC_HELD,1)
        put(o,NC_RANDOM_USED,0)
        return code_system(o,12,318,2,NC_RANDOM,8,0,0,0,0)
    if phase==3:
        address=get(o,NC_FEEDBACK)
        if address==0 or address>=18446744073709547521:
            return code_init_failure(o,w,5)
        put(w,16,address)
        put(w,40,65536)
        return code_registry_call(o,4,0)
    if phase==4:
        if get(o,NC_FEEDBACK)!=0:
            put(w,24,1)
            return code_unlock(o,w,11,0)
        put(w,24,0)
        put(o,48,get(w,128))
        return code_unlock(o,w,0,0)
    if phase==10:
        if get(o,NC_FEEDBACK)!=0:
            return code_system(o,11,202,1,32,128,1,0,0,0)
        put(o,NC_HELD,1)
        if get(w,8)!=get(o,NC_PID) or get(w,88)!=get(o,NC_SELF):
            return code_unlock(o,w,6,0)
        if get(w,24)==1:
            return code_system(o,231,11,0,get(w,16),get(w,40),0,0,0,0)
        state=get(w,24)
        op=code_operation(s)
        if state==4 and op!=3 and op!=5 and op!=6 and op!=7 and op!=8 and op!=10 and op!=11:
            return code_unlock(o,w,6,0)
        if state!=0 and state!=4:
            return code_unlock(o,w,6,0)
        return code_dispatch(s,o,w)
    if phase==11:
        result=get(o,NC_FEEDBACK)
        if result==0 or result==MAX-3 or result==MAX-10:
            return code_atom(o,2,10,32,0,1)
        return code_finish(o,w,11)
    if phase==12:
        result=get(o,NC_FEEDBACK)
        used=get(o,NC_RANDOM_USED)
        if result==MAX-3:
            return code_system(o,12,318,2,NC_RANDOM+used,8-used,0,0,0,0)
        if result==0 or result>=18446744073709547521 or result>8-used:
            return code_init_failure(o,w,11)
        used=used+result
        put(o,NC_RANDOM_USED,used)
        if used!=8:
            return code_system(o,12,318,2,NC_RANDOM+used,8-used,0,0,0,0)
        nonce=get(o,NC_RANDOM)
        if nonce==0:
            return code_init_failure(o,w,11)
        put(w,128,nonce)
        return code_system(o,3,9,0,0,65536,3,34,MAX,0)
    if phase==13:
        return code_finish(o,w,get(o,NC_STATUS))
    return code_unlock(o,w,11,0)

def code_init_failure(o:mutbuf,w:mutbuf,status:u64) -> u64:
    zero(w,8,128)
    put(o,NC_HELD,0)
    put(o,NC_STATUS,status)
    return code_atom(o,3,13,0,0,0)

def code_dispatch(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    op=code_operation(s)
    if op==0:
        put(o,48,get(w,128))
        return code_unlock(o,w,0,0)
    if op==1:
        return code_registry_call(o,30,1)
    if op==4:
        return code_registry_call(o,40,10)
    if op==2:
        put(o,NC_RANDOM_USED,0)
        put(o,NC_DISPATCH,2)
        return code_random(o)
    if op==3:
        return code_registry_call(o,61,5)
    if op==5:
        return code_cleanup_start(o,0,0)
    if op==6:
        return code_registry_call(o,70,14)
    if op==7:
        return code_registry_call(o,71,14)
    if op==8:
        return code_registry_call(o,62,6)
    if op==9:
        return code_registry_call(o,90,11)
    if op==10:
        return code_registry_call(o,72,14)
    if op==11:
        if get(w,24)!=4:
            return code_unlock(o,w,6,0)
        put(w,24,0)
        return code_unlock(o,w,0,0)
    return code_unlock(o,w,6,0)

def code_operate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    result=get(o,NC_FEEDBACK)
    if phase==20:
        if result==0 or result>=18446744073709547521:
            return code_build_abort(o,w,5)
        put(w,16,result)
        put(w,40,get(o,NC_GROW))
        return code_registry_call(o,21,13)
    if phase==21:
        if result!=0:
            return code_build_abort(o,w,11)
        return code_registry_call(o,get(o,NC_CONTINUE),get(o,NC_DISPATCH))
    if phase==30:
        if result==100:
            return code_grow(o,w,30,1)
        if result!=0:
            return code_unlock(o,w,result,0)
        put(o,NC_BUILDER,get(o,NR_OBJ))
        n=(readword(s,96)+4095)&18446744073709547520
        put(o,NR_SOURCE_SIZE,n)
        return code_system(o,31,9,0,0,n,3,34,MAX,0)
    if phase==31:
        if result==0 or result>=18446744073709547521:
            return code_build_abort(o,w,5)
        put(o,NR_SOURCE,result)
        put(o,NR_SOURCE_LENGTH,readword(s,96))
        return code_fields(o,32,1,result,get(o,NR_SOURCE_SIZE),readword(s,96))
    if phase==32:
        if result!=0:
            return code_build_abort(o,w,11)
        return code_buffer_call(o,33,0,get(o,NR_SOURCE),get(o,NR_SOURCE_SIZE))
    if phase==33:
        if result!=0:
            return code_build_abort(o,w,result)
        return code_system(o,34,10,0,get(o,NR_SOURCE),get(o,NR_SOURCE_SIZE),1,0,0,0)
    if phase==34:
        if result!=0:
            return code_build_abort(o,w,11)
        return code_system(o,35,9,0,0,NC_LIMIT,3,34,MAX,0)
    if phase==35:
        if result==0 or result>=18446744073709547521:
            return code_build_abort(o,w,5)
        put(o,NR_WORK,result)
        put(o,NR_WORK_SIZE,NC_LIMIT)
        return code_fields(o,36,2,result,NC_LIMIT,0)
    if phase==36:
        if result!=0:
            return code_build_abort(o,w,11)
        return code_system(o,37,9,0,0,NC_LIMIT,3,34,MAX,0)
    if phase==37:
        if result==0 or result>=18446744073709547521:
            return code_build_abort(o,w,5)
        put(o,NR_CODE,result)
        put(o,NR_CODE_SIZE,NC_LIMIT)
        return code_fields(o,38,0,result,NC_LIMIT,0)
    if phase==38:
        if result!=0:
            return code_build_abort(o,w,11)
        put(o,NC_PHASE,50)
        return 5
    if phase==50:
        if result==0 or result>NC_LIMIT:
            return code_build_abort(o,w,3)
        put(o,NR_CODE_LENGTH,result)
        return code_fields(o,51,0,get(o,NR_CODE),NC_LIMIT,result)
    if phase==51:
        if result!=0:
            return code_build_abort(o,w,11)
        return code_system(o,52,10,0,get(o,NR_CODE),NC_LIMIT,5,0,0,0)
    if phase==52:
        if result!=0:
            return code_build_abort(o,w,11)
        return code_system(o,53,11,0,get(o,NR_WORK),NC_LIMIT,0,0,0,0)
    if phase==53:
        if result!=0:
            return code_build_abort(o,w,11)
        put(o,NR_WORK,0)
        put(o,NR_WORK_SIZE,0)
        return code_fields(o,54,2,0,0,0)
    if phase==54:
        if result!=0:
            return code_build_abort(o,w,11)
        put(o,NC_RANDOM_USED,0)
        put(o,NC_DISPATCH,1)
        return code_random(o)
    if phase==40:
        if result==100:
            return code_grow(o,w,40,10)
        if result!=0:
            return code_unlock(o,w,result,0)
        put(o,NC_BUILDER,get(o,NR_OBJ))
        return code_system(o,41,9,0,0,NC_EXEC_SIZE,3,34,MAX,0)
    if phase==41:
        if result==0 or result>=18446744073709547521:
            return code_build_abort(o,w,5)
        put(o,NC_EXEC,result)
        put(o,NC_EXEC_BYTES,NC_EXEC_SIZE)
        return code_fields(o,42,0,result,NC_EXEC_SIZE,readword(s,96))
    if phase==42:
        if result!=0:
            return code_build_abort(o,w,11)
        return code_buffer_call(o,43,1,get(o,NC_EXEC),NC_EXEC_SIZE)
    if phase==43:
        if result!=0:
            return code_build_abort(o,w,result)
        return code_system(o,44,10,0,get(o,NC_EXEC),NC_LIMIT,1,0,0,0)
    if phase==44:
        if result!=0:
            return code_build_abort(o,w,11)
        put(o,NC_RANDOM_USED,0)
        put(o,NC_DISPATCH,4)
        return code_random(o)
    if phase==60:
        if result==MAX-3:
            return code_random(o)
        left=16-get(o,NC_RANDOM_USED)
        if result==0 or result>=18446744073709547521 or result>left:
            return code_build_abort(o,w,11)
        put(o,NC_RANDOM_USED,get(o,NC_RANDOM_USED)+result)
        if get(o,NC_RANDOM_USED)!=16:
            return code_random(o)
        if get(o,NC_RANDOM)==0 and get(o,NC_RANDOM+8)==0:
            return code_build_abort(o,w,11)
        op=choose(get(o,NC_DISPATCH)==2,4,3)
        return code_registry_call(o,63,op)
    if phase==63:
        if result==100:
            op=choose(code_operation(s)==2,4,3)
            return code_grow(o,w,63,op)
        if result!=0:
            return code_build_abort(o,w,result)
        put(o,NC_BUILDER,0)
        if code_operation(s)==4:
            return code_registry_call(o,90,11)
        return code_unlock(o,w,0,0)
    if phase==61:
        if result!=0:
            return code_unlock(o,w,result,0)
        return code_cleanup_start(o,0,0)
    if phase==62:
        if result!=0:
            return code_unlock(o,w,result,0)
        put(o,16,get(o,NR_KIND))
        put(o,48,get(o,NR_CODE_LENGTH))
        put(o,56,get(o,NR_SOURCE_LENGTH))
        put(o,64,get(o,NR_STATE))
        return code_unlock(o,w,0,0)
    if phase==70:
        if result!=0:
            return code_unlock(o,w,result,0)
        if get(o,48)!=0 or get(w,48)!=0:
            return code_unlock(o,w,6,0)
        return code_cleanup_start(o,0,1)
    if phase==71:
        return code_unlock(o,w,result,0)
    if phase==72:
        if result!=0:
            return code_unlock(o,w,result,0)
        if get(o,48)!=0 or get(o,56)!=0 or get(o,64)!=0 or get(w,48)!=0:
            return code_unlock(o,w,6,0)
        put(w,24,4)
        return code_unlock(o,w,0,0)
    if phase==90:
        if result!=0:
            return code_unlock(o,w,result,0)
        put(w,48,get(w,48)+1)
        if code_operation(s)==9:
            return code_buffer_call(o,91,3,get(o,NC_EXEC),get(o,NC_EXEC_BYTES))
        return code_unlock(o,w,0,1)
    if phase==91:
        if result!=0:
            put(o,NC_MAIN_STATUS,result)
            put(o,NC_BODY_ACTION,2)
            return code_registry_call(o,113,12)
        return code_unlock(o,w,0,1)
    return code_build_abort(o,w,11)

def code_execute(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==100:
        put(o,NC_PHASE,101)
        return 6
    if phase==101:
        put(o,NC_BODY_ACTION,get(o,NC_FEEDBACK))
        return code_atom(o,2,110,32,0,1)
    if phase==110:
        if get(o,NC_FEEDBACK)!=0:
            return code_system(o,111,202,1,32,128,1,0,0,0)
        put(o,NC_HELD,1)
        return code_buffer_call(o,112,2,get(o,NC_EXEC),get(o,NC_EXEC_BYTES))
    if phase==111:
        result=get(o,NC_FEEDBACK)
        if result==0 or result==MAX-3 or result==MAX-10:
            return code_atom(o,2,110,32,0,1)
        put(o,NC_CLEANUP_STATUS,11)
        return code_atom(o,2,110,32,0,1)
    if phase==112:
        put(o,NC_MAIN_STATUS,get(o,NC_FEEDBACK))
        return code_registry_call(o,113,12)
    if phase==113:
        if get(o,NC_FEEDBACK)!=0:
            put(o,NC_CLEANUP_STATUS,11)
            return code_unlock(o,w,11,0)
        put(w,48,get(w,48)-1)
        return code_unlock(o,w,get(o,NC_MAIN_STATUS),0)
    return code_unlock(o,w,11,0)

def code_build_abort(o:mutbuf,w:mutbuf,status:u64) -> u64:
    if get(o,NC_BUILDER)==0:
        return code_unlock(o,w,status,0)
    put(o,NC_MAIN_STATUS,status)
    put(o,NR_OBJ,get(o,NC_BUILDER))
    put(o,NC_BUILDER,0)
    return code_registry_call(o,180,15)

def code_cleanup_start(o:mutbuf,status:u64,destroy:u64) -> u64:
    put(o,NC_MAIN_STATUS,status)
    put(o,NC_DISPATCH,destroy)
    return code_registry_call(o,200,7)

def code_cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    result=get(o,NC_FEEDBACK)
    if phase==180:
        if result!=0:
            return code_unlock(o,w,11,0)
        return code_cleanup_start(o,get(o,NC_MAIN_STATUS),0)
    if phase==200:
        if result!=0:
            return code_unlock(o,w,11,0)
        if get(o,NR_OBJ)==0:
            if get(o,NC_DISPATCH)==1:
                if get(o,NC_PENDING)!=0:
                    return code_unlock(o,w,6,0)
                put(w,24,1)
                return code_system(o,231,11,0,get(w,16),get(w,40),0,0,0,0)
            return code_unlock(o,w,get(o,NC_MAIN_STATUS),0)
        if get(o,NR_WORK)!=0:
            put(o,NR_FIELD,2)
            return code_system(o,201,11,0,get(o,NR_WORK),get(o,NR_WORK_SIZE),0,0,0,0)
        if get(o,NR_CODE)!=0:
            put(o,NR_FIELD,0)
            return code_system(o,201,11,0,get(o,NR_CODE),get(o,NR_CODE_SIZE),0,0,0,0)
        if get(o,NR_SOURCE)!=0:
            put(o,NR_FIELD,1)
            return code_system(o,201,11,0,get(o,NR_SOURCE),get(o,NR_SOURCE_SIZE),0,0,0,0)
        return code_registry_call(o,203,9)
    if phase==201:
        if result!=0:
            put(o,NC_PENDING,1)
            put(o,NC_CLEANUP_STATUS,11)
            status=get(o,NC_MAIN_STATUS)
            return code_unlock(o,w,choose(status==0,11,status),0)
        return code_fields(o,202,get(o,NR_FIELD),0,0,0)
    if phase==202 or phase==203:
        if result!=0:
            return code_unlock(o,w,11,0)
        return code_registry_call(o,200,7)
    if phase==239:
        if result!=0:
            put(o,NC_PENDING,1)
            put(o,NC_CLEANUP_STATUS,11)
            if get(o,NC_STATUS)==0:
                put(o,NC_STATUS,11)
        return code_atom(o,3,240,32,0,0)
    if phase==231:
        if result!=0:
            put(o,NC_PENDING,1)
            put(o,NC_CLEANUP_STATUS,11)
            return code_unlock(o,w,11,0)
        put(w,16,0)
        put(w,40,0)
        put(w,24,3)
        put(o,NC_PENDING,0)
        return code_unlock(o,w,0,0)
    return code_unlock(o,w,11,0)

def code_release(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==240:
        put(o,NC_HELD,0)
        return code_system(o,241,202,1,32,129,2147483647,0,0,0)
    if phase==241:
        if get(o,NC_FEEDBACK)>=18446744073709547521:
            put(o,NC_CLEANUP_STATUS,11)
            if get(o,NC_STATUS)==0:
                put(o,NC_STATUS,11)
        if get(o,NC_AFTER_UNLOCK)==1:
            put(o,NC_PHASE,100)
            return 10
        return code_finish(o,w,get(o,NC_STATUS))
    return code_finish(o,w,11)

def code_unlock(o:mutbuf,w:mutbuf,status:u64,after:u64) -> u64:
    put(o,NC_STATUS,status)
    put(o,NC_AFTER_UNLOCK,after)
    if get(o,NC_HELD)==0:
        return code_finish(o,w,status)
    if get(w,16)!=0 and get(w,24)!=1:
        return code_registry_call(o,239,16)
    return code_atom(o,3,240,32,0,0)

def code_finish(o:mutbuf,w:mutbuf,status:u64) -> u64:
    if get(o,NC_FINALIZER)!=0:
        zero(o,0,128)
        put(o,0,NC_FINAL_REPLY)
        put(o,8,status)
        put(o,16,get(o,NC_KNOWN))
        put(o,24,choose(get(o,NC_RETRY_ACK)!=0,1,get(o,NC_CONSUMED)))
        put(o,32,get(o,NC_PENDING))
        put(o,40,status)
        put(o,64,get(o,NC_CLEANUP_STATUS))
        return 0
    put(o,0,NC_REPLY)
    put(o,8,status)
    put(o,80,get(o,NC_PENDING))
    put(o,88,get(o,NC_KNOWN))
    put(o,96,choose(get(o,NC_CREATED)!=0,1,get(o,NC_CONSUMED)))
    put(o,112,get(o,NC_CLEANUP_STATUS))
    put(o,120,get(w,24))
    return 0

def code_registry_call(o:mutbuf,phase:u64,op:u64) -> u64:
    put(o,NC_PHASE,phase)
    put(o,NR_OP,op)
    return 4

def code_fields(o:mutbuf,phase:u64,field:u64,address:u64,extent:u64,n:u64) -> u64:
    put(o,NR_FIELD,field)
    put(o,NR_ADDRESS,address)
    put(o,NR_EXTENT,extent)
    put(o,NR_LENGTH,n)
    return code_registry_call(o,phase,2)

def code_buffer_call(o:mutbuf,phase:u64,op:u64,address:u64,n:u64) -> u64:
    put(o,NC_PHASE,phase)
    put(o,NR_OP,op)
    put(o,NC_BUFFER,address)
    put(o,NC_BUFFER_BYTES,n)
    return 7

def code_random(o:mutbuf) -> u64:
    return code_system(o,60,318,2,NC_RANDOM+get(o,NC_RANDOM_USED),16-get(o,NC_RANDOM_USED),0,0,0,0)

def code_grow(o:mutbuf,w:mutbuf,phase:u64,op:u64) -> u64:
    put(o,NC_OLD,get(w,40))
    put(o,NC_CONTINUE,phase)
    put(o,NC_DISPATCH,op)
    return code_system(o,20,25,0,get(w,16),get(w,40),get(o,NC_GROW),1,0,0)

def code_atom(o:mutbuf,action:u64,phase:u64,offset:u64,expected:u64,value:u64) -> u64:
    put(o,NC_PHASE,phase)
    put(o,NC_ARG,offset)
    put(o,NC_ARG+8,expected)
    put(o,NC_ARG+16,value)
    return action

def code_system(o:mutbuf,phase:u64,n:u64,selectors:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u64:
    put(o,NC_PHASE,phase)
    put(o,NC_ROLE,n)
    put(o,NC_SELECT,selectors)
    put(o,NC_ARG,a)
    put(o,NC_ARG+8,b)
    put(o,NC_ARG+16,c)
    put(o,NC_ARG+24,d)
    put(o,NC_ARG+32,e)
    put(o,NC_ARG+40,f)
    return 1
'''


def program():
    return document(source('native_callable_code_owner', SOURCE), 'native_callable_code_owner')


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/native_callable_code_owner.hepta'
    path.write_text(render_assembly(program()))
    print(path.name, path.stat().st_size, flush=True)
